using System.Buffers.Binary;
using System.Text;

namespace Atlas;

public readonly struct PeDirectory(uint rva, uint size) {
    public readonly uint Rva = rva, Size = size;
}

public readonly struct PeSection(string name, uint rva, uint virtualSize, int fileOffset,
    int fileSize, uint characteristics) {
    public readonly string Name = name;
    public readonly uint Rva = rva;
    public readonly uint VirtualSize = virtualSize == 0 ? (uint)fileSize : virtualSize;
    public readonly int FileOffset = fileOffset;
    public readonly int FileSize = (int)Math.Min(virtualSize == 0 ? (uint)fileSize : virtualSize, (uint)fileSize);
    public readonly uint Characteristics = characteristics;
    public bool Executable => (Characteristics & 0x20000000) != 0;
    public bool Writable => (Characteristics & 0x80000000) != 0;
}

public sealed class PeImage {
    public readonly byte[] FileData;
    public readonly ulong ImageBase;
    public readonly uint ImageSize;
    public readonly uint HeaderSize;
    public readonly PeSection[] Sections;
    public readonly PeDirectory[] Directories;
    public uint ExceptionRva => Directories[3].Rva;
    public uint ExceptionSize => Directories[3].Size;

    public PeImage(byte[] data) {
        FileData = data;
        var file = data.AsSpan();
        if (file.Length < 64 || !file[..2].SequenceEqual("MZ"u8))
            throw new InvalidDataException("Missing DOS header.");

        uint ntOffset = BinaryPrimitives.ReadUInt32LittleEndian(file[60..]);
        if (ntOffset > file.Length - 24)
            throw new InvalidDataException("Truncated PE header.");

        int nt = (int)ntOffset;
        if (!file.Slice(nt, 4).SequenceEqual("PE\0\0"u8))
            throw new InvalidDataException("Missing PE signature.");

        if (BinaryPrimitives.ReadUInt16LittleEndian(file[(nt + 4)..]) != 0x8664)
            throw new NotSupportedException("Only AMD64 PE images are supported.");

        int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(file[(nt + 6)..]);
        int optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(file[(nt + 20)..]);
        int optional = nt + 24;
        if (optionalSize < 112 || optionalSize > file.Length - optional)
            throw new InvalidDataException("Truncated PE optional header.");

        if (BinaryPrimitives.ReadUInt16LittleEndian(file[optional..]) != 0x20B)
            throw new NotSupportedException("Only PE32+ images are supported.");

        ImageBase = BinaryPrimitives.ReadUInt64LittleEndian(file[(optional + 24)..]);
        ImageSize = BinaryPrimitives.ReadUInt32LittleEndian(file[(optional + 56)..]);
        HeaderSize = BinaryPrimitives.ReadUInt32LittleEndian(file[(optional + 60)..]);
        if (ImageSize == 0 || ImageBase > ulong.MaxValue - ImageSize)
            throw new InvalidDataException("Invalid PE image extent.");
        if (HeaderSize > file.Length || HeaderSize > ImageSize)
            throw new InvalidDataException("Invalid PE header extent.");

        uint directoryCount = BinaryPrimitives.ReadUInt32LittleEndian(file[(optional + 108)..]);
        if (directoryCount > (optionalSize - 112) / 8)
            throw new InvalidDataException("Truncated PE data directories.");

        Directories = new PeDirectory[Math.Max(16, directoryCount)];
        for (int i = 0; i < directoryCount; ++i) {
            int offset = optional + 112 + i * 8;
            Directories[i] = new PeDirectory(BinaryPrimitives.ReadUInt32LittleEndian(file[offset..]),
                BinaryPrimitives.ReadUInt32LittleEndian(file[(offset + 4)..]));
        }

        int table = optional + optionalSize;
        if (sectionCount > (file.Length - table) / 40)
            throw new InvalidDataException("Truncated PE section table.");

        Sections = new PeSection[sectionCount];
        ulong previousEnd = HeaderSize;
        for (int i = 0; i < sectionCount; ++i) {
            var row = file.Slice(table + i * 40, 40);
            var nameBytes = row[..8];
            int terminator = nameBytes.IndexOf((byte)0);
            string name = Encoding.ASCII.GetString(terminator < 0 ? nameBytes : nameBytes[..terminator]);
            uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(row[8..]);
            uint rva = BinaryPrimitives.ReadUInt32LittleEndian(row[12..]);
            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(row[16..]);
            uint rawOffset = BinaryPrimitives.ReadUInt32LittleEndian(row[20..]);
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(row[36..]);
            if (rawSize != 0 && ((ulong)rawOffset + rawSize > (ulong)file.Length))
                throw new InvalidDataException($"Truncated PE section {name}.");

            ulong end = (ulong)rva + (virtualSize == 0 ? rawSize : virtualSize);
            if (rva < previousEnd || end > ImageSize)
                throw new InvalidDataException($"Overlapping or out-of-image PE section {name}.");

            previousEnd = end;
            Sections[i] = new PeSection(name, rva, virtualSize,
                rawSize == 0 ? 0 : (int)rawOffset, (int)rawSize, flags);
        }
    }

    public int FindSection(ulong va) {
        if (va < ImageBase || va - ImageBase >= ImageSize)
            return -1;
        uint rva = (uint)(va - ImageBase);
        int low = 0, high = Sections.Length - 1;
        while (low <= high) {
            int mid = low + ((high - low) >> 1);
            ref readonly var section = ref Sections[mid];
            if (rva < section.Rva)
                high = mid - 1;
            else if ((ulong)rva >= (ulong)section.Rva + section.VirtualSize)
                low = mid + 1;
            else
                return mid;
        }

        return -1;
    }

    public bool IsMapped(ulong va, ulong size) {
        if (va >= ImageBase && va - ImageBase < HeaderSize)
            return size <= HeaderSize - (va - ImageBase);

        int index = FindSection(va);
        if (index < 0)
            return false;
        ref readonly var section = ref Sections[index];
        return size <= section.VirtualSize - (va - ImageBase - section.Rva);
    }

    public bool IsExecutable(ulong va) {
        int index = FindSection(va);
        return index >= 0 && Sections[index].Executable;
    }

    // A span proves the whole read is backed by one mapped region
    // Checking only its first byte could read linker padding as runtime metadata
    public ReadOnlySpan<byte> FileSpan(ulong va, int length)
        => FileMemory(va, length).Span;

    public ReadOnlyMemory<byte> FileMemory(ulong va, int length) {
        var range = FileRange(va);
        if (length < 0 || length > range.Count)
            throw new InvalidDataException($"Read outside file-backed region at 0x{va:X}, length {length}.");

        return FileData.AsMemory(range.Start, length);
    }

    public IndexRange FileRange(ulong va) {
        if (va >= ImageBase && va - ImageBase < HeaderSize) {
            int offset = (int)(va - ImageBase);
            return new IndexRange(offset, (int)HeaderSize - offset);
        }

        int index = FindSection(va);
        if (index < 0)
            throw new InvalidDataException($"Unmapped file read at 0x{va:X}.");

        ref readonly var section = ref Sections[index];
        ulong delta = va - ImageBase - section.Rva;
        if (delta > (ulong)section.FileSize)
            throw new InvalidDataException($"Read outside file-backed section at 0x{va:X}.");

        return new IndexRange(section.FileOffset + (int)delta, section.FileSize - (int)delta);
    }
}
