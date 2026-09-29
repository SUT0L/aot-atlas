using System.Buffers.Binary;

namespace Atlas;

public readonly struct RtrSection(int id, uint flags, ulong start, ulong length) {
    public readonly int Id = id;
    public readonly uint Flags = flags;
    public readonly ulong Start = start;
    public readonly ulong Length = length;
}

public sealed class ReadyToRun {
    public readonly int FileOffset;
    public readonly ushort Major;
    public readonly ushort Minor;
    public readonly uint Flags;
    public readonly byte EntrySize;
    public readonly byte EntryType;
    public readonly RtrSection[] Sections;
    public int MetadataHandleBits => Major < 12 ? 8 : 7;
    public bool EmbeddedDehydrationLength => Major > 18 || (Major == 18 && Minor >= 4);

    private ReadyToRun(PeImage image, int offset) {
        FileOffset = offset;
        var header = image.FileData.AsSpan(offset, 16);
        Major = BinaryPrimitives.ReadUInt16LittleEndian(header[4..]);
        Minor = BinaryPrimitives.ReadUInt16LittleEndian(header[6..]);
        Flags = BinaryPrimitives.ReadUInt32LittleEndian(header[8..]);
        int count = BinaryPrimitives.ReadUInt16LittleEndian(header[12..]);
        EntrySize = header[14];
        EntryType = header[15];
        if ((Major, Minor) is not ((9, 1) or (10, 1) or (12, 0) or (16, 0) or (18, 4) or (18, 5)))
            throw new NotSupportedException($"Unsupported RTR version {Major}.{Minor}.");

        if (EntrySize != (EmbeddedDehydrationLength ? 16 : 24) || EntryType != 1)
            throw new NotSupportedException($"Unsupported RTR row format {EntrySize}/{EntryType} for {Major}.{Minor}.");

        Sections = new RtrSection[count];
        for (int i = 0; i < count; ++i) {
            var row = image.FileData.AsSpan(offset + 16 + i * EntrySize, EntrySize);
            int id = BinaryPrimitives.ReadInt32LittleEndian(row);
            uint flagsOrLength = BinaryPrimitives.ReadUInt32LittleEndian(row[4..]);
            ulong start = BinaryPrimitives.ReadUInt64LittleEndian(row[8..]);
            ulong length = flagsOrLength;
            if (EntrySize == 24) {
                ulong end = BinaryPrimitives.ReadUInt64LittleEndian(row[16..]);
                length = end == 0 ? 0 : end - start;
            }

            Sections[i] = new RtrSection(id, EntrySize == 24 ? flagsOrLength : 0, start, length);
        }
    }

    public RtrSection Find(int id) {
        foreach (ref readonly var section in Sections.AsSpan())
            if (section.Id == id)
                return section;
        return default;
    }

    public static ReadyToRun Read(PeImage image) {
        int found = -1;
        foreach (ref readonly var section in image.Sections.AsSpan()) {
            if (section.Executable || section.FileSize < 16)
                continue;
            var bytes = image.FileData.AsSpan(section.FileOffset, section.FileSize);
            int next = 0;
            while (next <= bytes.Length - 16) {
                int relative = bytes[next..].IndexOf("RTR\0"u8);
                if (relative < 0)
                    break;
                int offset = next + relative;
                next = offset + 4;
                if (offset > bytes.Length - 16)
                    break;
                var header = bytes.Slice(offset, 16);
                int count = BinaryPrimitives.ReadUInt16LittleEndian(header[12..]);
                int size = header[14];
                if (count == 0 || (size != 16 && size != 24) || count > (bytes.Length - offset - 16) / size)
                    continue;
                bool valid = true;
                int previousId = 0;
                for (int i = 0; i < count; ++i) {
                    var row = bytes.Slice(offset + 16 + i * size, size);
                    int id = BinaryPrimitives.ReadInt32LittleEndian(row);
                    ulong start = BinaryPrimitives.ReadUInt64LittleEndian(row[8..]);
                    ulong length = BinaryPrimitives.ReadUInt32LittleEndian(row[4..]);
                    if (size == 24) {
                        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(row[4..]);
                        ulong end = BinaryPrimitives.ReadUInt64LittleEndian(row[16..]);
                        if (flags > 1 || (flags == 0 && end != 0) || (flags == 1 && end < start)) {
                            valid = false;
                            break;
                        }

                        length = end == 0 ? 0 : unchecked(end - start);
                    }

                    // NativeAOTs header emitter sorts IDs, and every nonempty row must describe storage the loader can actually map
                    if (id <= previousId || start == 0 || !image.IsMapped(start, length)) {
                        valid = false;
                        break;
                    }

                    previousId = id;
                }

                if (!valid)
                    continue;
                if (found >= 0)
                    throw new InvalidDataException("Multiple valid RTR headers; module selection is required.");

                found = section.FileOffset + offset;
            }
        }

        if (found < 0)
            throw new InvalidDataException("No structurally valid NativeAOT RTR header.");

        return new ReadyToRun(image, found);
    }
}
