using System.Buffers.Binary;

namespace Atlas;

public enum ImportIdentitySource : byte {
    LookupTable, UnboundAddressTable, BoundAddressTable, DelayAddressTable
}

public enum ImportKind : byte {
    Unknown, Name, Ordinal
}

public struct PeImportModule {
    public ulong Descriptor, Lookup, AddressTable, Handle;
    public IndexRange Name, Imports;
    public uint Timestamp;
    public ImportIdentitySource IdentitySource;
    public bool DelayLoaded;
}

public struct PeImport {
    public ulong LookupCell, AddressCell, EncodedValue;
    public IndexRange Name;
    public ushort Ordinal, Hint;
    public ImportKind Kind;
}

public enum ExportKind : byte {
    Unused, Code, Data, Forwarder, Unmapped
}

public struct PeExport {
    public ulong AddressCell, Address;
    public uint Ordinal, Rva;
    public ExportKind Kind;
    public IndexRange Names, Forwarder;
}

public readonly struct PeExportName(IndexRange name, ulong pointerCell, ulong ordinalCell) {
    public readonly IndexRange Name = name;
    public readonly ulong PointerCell = pointerCell, OrdinalCell = ordinalCell;
}

public sealed class PeLinkage {
    public readonly List<PeImportModule> Modules = new(32);
    public readonly List<PeImport> Imports = new(512);
    public readonly PeExport[] Exports = [];
    public readonly PeExportName[] ExportNames = [];
    public readonly IndexRange ExportModule;

    public PeLinkage(PeImage image) {
        foreach (int directoryIndex in new[] { 1, 13 }) {
            var directory = image.Directories[directoryIndex];
            if (directory.Rva == 0 && directory.Size == 0)
                continue;

            bool delay = directoryIndex == 13;
            int stride = delay ? 32 : 20;
            if (directory.Rva == 0 || directory.Size < stride)
                throw new InvalidDataException("Truncated import directory.");

            var data = image.FileSpan(image.ImageBase + directory.Rva, checked((int)directory.Size));
            bool terminated = false;
            for (int position = 0; position <= data.Length - stride; position += stride) {
                var row = data.Slice(position, stride);
                if (!row.ContainsAnyExcept((byte)0)) {
                    terminated = true;
                    break;
                }

                uint name, lookup, address;
                ulong pointerBase = image.ImageBase;
                PeImportModule module = new() {
                    Descriptor = image.ImageBase + directory.Rva + (uint)position,
                    DelayLoaded = delay
                };
                if (delay) {
                    uint attributes = BinaryPrimitives.ReadUInt32LittleEndian(row);
                    pointerBase = (attributes & 1) != 0 ? image.ImageBase : 0;
                    name = BinaryPrimitives.ReadUInt32LittleEndian(row[4..]);
                    uint handle = BinaryPrimitives.ReadUInt32LittleEndian(row[8..]);
                    address = BinaryPrimitives.ReadUInt32LittleEndian(row[12..]);
                    lookup = BinaryPrimitives.ReadUInt32LittleEndian(row[16..]);
                    module.Timestamp = BinaryPrimitives.ReadUInt32LittleEndian(row[28..]);
                    module.Handle = handle == 0 ? 0 : pointerBase + handle;
                    if (module.Handle != 0 && !image.IsMapped(module.Handle, 8))
                        throw new InvalidDataException("Delay import module handle is outside mapped storage.");
                } else {
                    lookup = BinaryPrimitives.ReadUInt32LittleEndian(row);
                    module.Timestamp = BinaryPrimitives.ReadUInt32LittleEndian(row[4..]);
                    name = BinaryPrimitives.ReadUInt32LittleEndian(row[12..]);
                    address = BinaryPrimitives.ReadUInt32LittleEndian(row[16..]);
                }

                if (name == 0 || address == 0)
                    throw new InvalidDataException("Import descriptor has no module name or address table.");

                module.Name = Ascii(image, pointerBase + name);
                module.AddressTable = pointerBase + address;
                module.Lookup = lookup == 0 ? module.AddressTable : pointerBase + lookup;

                // Bound and delayed IATs contain targets, not import names
                // Only an unbound eager IAT retains the lookup encoding
                module.IdentitySource = lookup != 0 ? ImportIdentitySource.LookupTable
                    : delay ? ImportIdentitySource.DelayAddressTable
                    : module.Timestamp != 0 ? ImportIdentitySource.BoundAddressTable
                    : ImportIdentitySource.UnboundAddressTable;
                bool namesKnown = module.IdentitySource is ImportIdentitySource.LookupTable or ImportIdentitySource.UnboundAddressTable;
                var range = image.FileRange(module.Lookup);
                var thunks = image.FileData.AsSpan(range.Start, range.Count);
                int first = Imports.Count;
                int offset = 0;
                for (; offset <= thunks.Length - 8; offset += 8) {
                    ulong value = BinaryPrimitives.ReadUInt64LittleEndian(thunks[offset..]);
                    if (value == 0)
                        break;

                    PeImport entry = new() {
                        LookupCell = module.Lookup + (uint)offset,
                        AddressCell = module.AddressTable + (uint)offset,
                        EncodedValue = value
                    };
                    if (namesKnown) {
                        if ((value & 0x8000000000000000) != 0) {
                            if ((value & 0x7FFFFFFFFFFF0000) != 0)
                                throw new InvalidDataException("Import ordinal contains reserved bits.");

                            entry.Ordinal = (ushort)value;
                            entry.Kind = ImportKind.Ordinal;
                        } else {
                            if (value > (delay && pointerBase == 0 ? uint.MaxValue : 0x7FFFFFFFUL))
                                throw new InvalidDataException("Import name pointer contains reserved bits.");

                            ulong nameAddress = pointerBase + value;
                            entry.Hint = BinaryPrimitives.ReadUInt16LittleEndian(image.FileSpan(nameAddress, 2));
                            entry.Name = Ascii(image, nameAddress + 2);
                            entry.Kind = ImportKind.Name;
                        }
                    }

                    Imports.Add(entry);
                }

                if (offset > thunks.Length - 8)
                    throw new InvalidDataException("Import lookup table has no terminator in its file-backed region.");
                if (!image.IsMapped(module.AddressTable, (uint)offset + 8UL))
                    throw new InvalidDataException("Import address table exceeds mapped storage.");

                module.Imports = new IndexRange(first, Imports.Count - first);
                Modules.Add(module);
            }

            if (!terminated)
                throw new InvalidDataException("Import directory has no complete null descriptor.");
        }

        var exportDirectory = image.Directories[0];
        if (exportDirectory.Rva == 0 && exportDirectory.Size == 0)
            return;
        if (exportDirectory.Rva == 0 || exportDirectory.Size < 40
            || (ulong)exportDirectory.Rva + exportDirectory.Size > image.ImageSize)
            throw new InvalidDataException("Truncated export directory.");

        var header = image.FileSpan(image.ImageBase + exportDirectory.Rva, 40);
        ExportModule = Ascii(image, image.ImageBase + BinaryPrimitives.ReadUInt32LittleEndian(header[12..]));
        uint ordinalBase = BinaryPrimitives.ReadUInt32LittleEndian(header[16..]);
        int count = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(header[20..]));
        int nameCount = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(header[24..]));
        ulong addresses = image.ImageBase + BinaryPrimitives.ReadUInt32LittleEndian(header[28..]);
        ulong names = image.ImageBase + BinaryPrimitives.ReadUInt32LittleEndian(header[32..]);
        ulong ordinals = image.ImageBase + BinaryPrimitives.ReadUInt32LittleEndian(header[36..]);
        var addressData = count == 0 ? default : image.FileSpan(addresses, checked(count * 4));
        var nameData = nameCount == 0 ? default : image.FileSpan(names, checked(nameCount * 4));
        var ordinalData = nameCount == 0 ? default : image.FileSpan(ordinals, checked(nameCount * 2));
        ulong exportEnd = checked(image.ImageBase + exportDirectory.Rva + exportDirectory.Size);
        Exports = new PeExport[count];
        for (int i = 0; i < count; ++i) {
            uint rva = BinaryPrimitives.ReadUInt32LittleEndian(addressData[(i * 4)..]);
            ref var entry = ref Exports[i];
            entry.Rva = rva;
            entry.Ordinal = checked(ordinalBase + (uint)i);
            entry.AddressCell = addresses + (uint)i * 4UL;
            if (rva == 0)
                continue;

            ulong address = checked(image.ImageBase + rva);
            if (rva >= exportDirectory.Rva && address < exportEnd) {
                entry.Kind = ExportKind.Forwarder;
                entry.Forwarder = Ascii(image, address, checked((int)(exportEnd - address)));
            } else {
                entry.Address = address;
                entry.Kind = image.IsExecutable(address) ? ExportKind.Code
                    : image.IsMapped(address, 1) ? ExportKind.Data : ExportKind.Unmapped;
            }
        }

        int[] counts = new int[count];
        for (int i = 0; i < nameCount; ++i) {
            int index = BinaryPrimitives.ReadUInt16LittleEndian(ordinalData[(i * 2)..]);
            if (index >= count)
                throw new InvalidDataException("Export name ordinal exceeds its address table.");

            ++counts[index];
        }

        int cursor = 0;
        for (int i = 0; i < count; ++i) {
            Exports[i].Names = new IndexRange(cursor, counts[i]);
            cursor += counts[i];
            counts[i] = 0;
        }

        ExportNames = new PeExportName[nameCount];
        ReadOnlySpan<byte> previousName = default;
        for (int i = 0; i < nameCount; ++i) {
            int index = BinaryPrimitives.ReadUInt16LittleEndian(ordinalData[(i * 2)..]);
            var name = Ascii(image, image.ImageBase + BinaryPrimitives.ReadUInt32LittleEndian(nameData[(i * 4)..]));
            var bytes = image.FileData.AsSpan(name.Start, name.Count);
            if (previousName.SequenceCompareTo(bytes) > 0)
                throw new InvalidDataException("Export names are not in runtime lookup order.");

            previousName = bytes;
            ExportNames[Exports[index].Names.Start + counts[index]++] = new PeExportName(name, names + (uint)i * 4UL, ordinals + (uint)i * 2UL);
        }
    }

    private static IndexRange Ascii(PeImage image, ulong address, int limit = int.MaxValue) {
        var range = image.FileRange(address);
        var bytes = image.FileData.AsSpan(range.Start, Math.Min(range.Count, limit));
        int end = bytes.IndexOf((byte)0);
        if (end <= 0 || bytes[..end].ContainsAnyInRange((byte)128, (byte)255))
            throw new InvalidDataException($"Missing, empty, or non-ASCII PE linkage name at 0x{address:X}.");

        return new IndexRange(range.Start, end);
    }
}
