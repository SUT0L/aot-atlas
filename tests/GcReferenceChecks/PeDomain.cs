using System.Buffers.Binary;
using System.Globalization;
using System.Reflection.PortableExecutable;

internal readonly record struct ReferenceMethod(uint Begin, uint End, uint GcAddress, int FileOffset, int BlobLength);

internal sealed class PeDomain : IDisposable {
    private readonly PEReader reader;
    internal readonly byte[] Bytes;
    internal readonly uint NativeGcVersion;
    internal readonly ReferenceMethod[] Methods;

    internal PeDomain(string path) {
        Bytes = File.ReadAllBytes(path);
        reader = new PEReader(new MemoryStream(Bytes, writable: false));
        if (reader.PEHeaders.CoffHeader.Machine != Machine.Amd64)
            throw new InvalidDataException($"{path}: GC reference check requires an AMD64 PE.");
        NativeGcVersion = ReadGcVersion();

        (uint managedStart, uint managedEnd) = ManagedRegion(path);
        var directory = reader.PEHeaders.PEHeader!.ExceptionTableDirectory;
        if (directory.Size == 0 || directory.Size % 12 != 0)
            throw new InvalidDataException("PE runtime function table is empty or truncated.");
        int table = FileOffset((uint)directory.RelativeVirtualAddress, directory.Size);
        var methods = new List<(uint Begin, uint End, uint Gc)>();
        var unwindHeaders = new SortedSet<uint>();

        // CoffNativeCodeManager.cpp: GetUnwindDataBlob, FindMethodInfo and
        // GetCodeOffset define this PE/NativeAOT boundary; no Atlas results enter it.
        for (int row = 0; row < directory.Size; row += 12) {
            uint begin = UInt32(table + row);
            uint end = UInt32(table + row + 4);
            uint unwind = UInt32(table + row + 8);
            if ((unwind & 1) == 0)
                unwindHeaders.Add(unwind);
            if (begin < managedStart || begin >= managedEnd)
                continue;
            if (end <= begin || end > managedEnd || (unwind & 1) != 0)
                throw new InvalidDataException("Managed runtime function has invalid bounds or indirect unwind data.");

            int offset = FileOffset(unwind, 4);
            int flags = Bytes[offset] >> 3;
            if ((Bytes[offset] & 7) is not (1 or 2) || (flags & ~3) != 0)
                throw new InvalidDataException("Managed runtime function has unsupported unwind flags.");
            int length = 4 + Bytes[offset + 2] * 2;
            if ((flags & 3) != 0)
                length = ((length + 3) & ~3) + 4;
            int trailer = FileOffset(checked(unwind + (uint)length), 1);
            byte nativeFlags = Bytes[trailer];
            if ((nativeFlags & ~31) != 0 || (nativeFlags & 3) == 3)
                throw new InvalidDataException("Managed runtime function has invalid NativeAOT flags.");

            if ((nativeFlags & 3) == 0) {
                uint gc = checked(unwind + (uint)length + 1);
                if ((nativeFlags & 16) != 0)
                    gc = checked(gc + 4);
                if ((nativeFlags & 4) != 0)
                    gc = checked(gc + 4);
                methods.Add((begin, end, gc));
            } else {
                if (methods.Count == 0)
                    throw new InvalidDataException("Managed funclet has no preceding root.");
                var root = methods[^1];
                methods[^1] = (root.Begin, end, root.Gc);
            }
        }
        if (methods.Count == 0)
            throw new InvalidDataException("Independent PE method universe is empty.");

        uint[] boundaries = [.. unwindHeaders];
        Methods = new ReferenceMethod[methods.Count];
        for (int index = 0; index < methods.Count; ++index) {
            var method = methods[index];
            int offset = FileOffset(method.Gc, 1);
            int length = SectionBytesRemaining(method.Gc);
            int next = Array.BinarySearch(boundaries, method.Gc);
            if (next >= 0)
                throw new InvalidDataException("GC data overlaps an unwind header.");
            next = ~next;
            if (next < boundaries.Length)
                length = (int)Math.Min((uint)length, boundaries[next] - method.Gc);
            Methods[index] = new(method.Begin, method.End, method.Gc, offset, length);
        }
    }

    private (uint Start, uint End) ManagedRegion(string path) {
        (uint Start, uint End)? found = null;
        foreach (var entry in reader.ReadDebugDirectory()) {
            if ((int)entry.Type != 13)
                continue;
            int offset = checked(entry.DataPointer + 4);
            int end = checked(entry.DataPointer + entry.DataSize);
            while (offset < end) {
                if (end - offset < 9)
                    throw new InvalidDataException("Truncated POGO contribution.");
                uint rva = UInt32(offset);
                uint size = UInt32(offset + 4);
                int nameStart = offset + 8;
                int nameEnd = Array.IndexOf(Bytes, (byte)0, nameStart, end - nameStart);
                if (nameEnd < 0)
                    throw new InvalidDataException("Unterminated POGO contribution name.");
                if (Bytes.AsSpan(nameStart, nameEnd - nameStart).SequenceEqual(".managedcode$I"u8)) {
                    if (found is not null)
                        throw new InvalidDataException("Multiple managed POGO contributions.");
                    found = (rva, checked(rva + size));
                }
                offset = checked((nameEnd + 4) & ~3);
            }
        }
        if (found is not null)
            return found.Value;

        foreach (var section in reader.PEHeaders.SectionHeaders) {
            if (section.Name == ".managed")
                return ((uint)section.VirtualAddress, checked((uint)(section.VirtualAddress + section.VirtualSize)));
        }
        string map = Path.ChangeExtension(path, ".map");
        if (!File.Exists(map))
            throw new InvalidDataException("GC reference check needs a managed POGO contribution, .managed section, or adjacent linker map.");

        uint? timestamp = null;
        ulong? imageBase = null;
        foreach (string line in File.ReadLines(map)) {
            string[] fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length >= 3 && fields[0] == "Timestamp" && fields[1] == "is") {
                timestamp = uint.Parse(fields[2], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            } else if (fields.Length == 5 && fields[0] == "Preferred" && fields[1] == "load"
                && fields[2] == "address" && fields[3] == "is") {
                imageBase = ulong.Parse(fields[4], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            } else if (fields.Length == 4 && fields[2] == ".managedcode$I" && fields[3] == "CODE") {
                if (found is not null)
                    throw new InvalidDataException("Multiple managed linker contributions.");
                string[] address = fields[0].Split(':');
                if (address.Length != 2 || !fields[1].EndsWith('H'))
                    throw new InvalidDataException("Invalid managed linker contribution.");
                int sectionIndex = int.Parse(address[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture) - 1;
                if ((uint)sectionIndex >= reader.PEHeaders.SectionHeaders.Length)
                    throw new InvalidDataException("Managed linker contribution has no PE section.");
                var section = reader.PEHeaders.SectionHeaders[sectionIndex];
                uint offset = uint.Parse(address[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                uint size = uint.Parse(fields[1].AsSpan(0, fields[1].Length - 1), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                if ((section.SectionCharacteristics & SectionCharacteristics.MemExecute) == 0
                    || (ulong)offset + size > (uint)section.VirtualSize)
                    throw new InvalidDataException("Managed linker contribution exceeds executable PE storage.");
                uint start = checked((uint)section.VirtualAddress + offset);
                found = (start, checked(start + size));
            }
        }
        if (timestamp != unchecked((uint)reader.PEHeaders.CoffHeader.TimeDateStamp)
            || imageBase != reader.PEHeaders.PEHeader!.ImageBase || found is null)
            throw new InvalidDataException("Adjacent linker map does not identify this PE's managed code contribution.");
        return found.Value;
    }

    private uint ReadGcVersion() {
        int matches = 0;
        uint version = 0;
        foreach (var section in reader.PEHeaders.SectionHeaders) {
            if ((section.SectionCharacteristics & SectionCharacteristics.MemExecute) != 0)
                continue;
            ReadOnlySpan<byte> data = Bytes.AsSpan(section.PointerToRawData, section.SizeOfRawData);
            for (int offset = 0; offset <= data.Length - 16; ++offset) {
                if (!data.Slice(offset, 4).SequenceEqual("RTR\0"u8))
                    continue;
                int count = BinaryPrimitives.ReadUInt16LittleEndian(data[(offset + 12)..]);
                int rowSize = data[offset + 14];
                if (count == 0 || rowSize is not (16 or 24) || data[offset + 15] != 1
                    || count > (data.Length - offset - 16) / rowSize)
                    continue;
                int major = BinaryPrimitives.ReadUInt16LittleEndian(data[(offset + 4)..]);
                // GCInfoToken::ReadyToRunVersionToGcInfoVersion treats v2/v3
                // alike. The pinned decoder does not cover future GCINFO v5.
                if (major < 9 || major >= 21)
                    throw new InvalidDataException($"RTR {major} is outside the pinned GCINFO decoder domain.");
                version = major >= 11 ? 4U : 3U;
                ++matches;
            }
        }
        if (matches != 1)
            throw new InvalidDataException($"Expected one NativeAOT RTR header, found {matches}.");
        return version;
    }

    private int FileOffset(uint rva, int length) {
        foreach (var section in reader.PEHeaders.SectionHeaders) {
            long relative = (long)rva - section.VirtualAddress;
            if (relative >= 0 && relative + length <= section.SizeOfRawData)
                return checked(section.PointerToRawData + (int)relative);
        }
        throw new InvalidDataException($"RVA 0x{rva:X} is outside file-backed PE storage.");
    }

    private int SectionBytesRemaining(uint rva) {
        foreach (var section in reader.PEHeaders.SectionHeaders) {
            long relative = (long)rva - section.VirtualAddress;
            if (relative >= 0 && relative < section.SizeOfRawData)
                return section.SizeOfRawData - (int)relative;
        }
        throw new InvalidDataException($"RVA 0x{rva:X} is outside file-backed PE storage.");
    }

    private uint UInt32(int offset) => BinaryPrimitives.ReadUInt32LittleEndian(Bytes.AsSpan(offset, 4));

    public void Dispose() => reader.Dispose();
}
