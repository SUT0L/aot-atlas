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

    public ushort Major => Format.Major;
    public ushort Minor => Format.Minor;
    public readonly uint Flags;

    public readonly byte EntrySize;
    public readonly byte EntryType;

    private readonly PeSection[] sourceSections;
    private readonly RtrSection[] sections;
    public ReadOnlySpan<RtrSection> Sections => sections;

    public readonly NativeAotFormat Format;
    public int MetadataHandleBits => Format.MetadataHandleBits;
    public bool EmbeddedDehydrationLength => Format.EmbeddedDehydrationLength;

    private ReadyToRun(PeImage image, int offset) {
        sourceSections = image.Sections;
        FileOffset = offset;
        var header = image.FileData.AsSpan(offset, 16);

        Format = NativeAotFormat.ForVersion(
            BinaryPrimitives.ReadUInt16LittleEndian(header[4..]),
            BinaryPrimitives.ReadUInt16LittleEndian(header[6..]));
        Flags = BinaryPrimitives.ReadUInt32LittleEndian(header[8..]);

        int count = BinaryPrimitives.ReadUInt16LittleEndian(header[12..]);
        EntrySize = header[14];
        EntryType = header[15];

        if (EntrySize != (EmbeddedDehydrationLength ? 16 : 24) || EntryType != 1)
            throw new NotSupportedException($"Unsupported RTR row format {EntrySize}/{EntryType} for {Major}.{Minor}.");

        sections = new RtrSection[count];

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

            sections[i] = new RtrSection(id, EntrySize == 24 ? flagsOrLength : 0, start, length);
        }
    }

    // The source image owns immutable section metadata, so its array supplies
    // identity without retaining the image bytes. Cloned images may reuse this
    // header only when their own validated header has the same format and rows.
    internal ReadyToRun ValidateSource(PeImage image) {
        if (ReferenceEquals(sourceSections, image.Sections))
            return this;

        var actual = Read(image);

        if (FileOffset != actual.FileOffset
            || Major != actual.Major
            || Minor != actual.Minor
            || Flags != actual.Flags
            || EntrySize != actual.EntrySize
            || EntryType != actual.EntryType
            || sections.Length != actual.sections.Length)
            throw new ArgumentException("The RTR header does not match the selected image.", nameof(image));

        for (int i = 0; i < sections.Length; ++i) {
            var expected = sections[i];
            var current = actual.sections[i];

            if (expected.Id != current.Id
                || expected.Flags != current.Flags
                || expected.Start != current.Start
                || expected.Length != current.Length)
                throw new ArgumentException("The RTR header does not match the selected image.", nameof(image));
        }

        return actual;
    }

    public RtrSection Find(RtrSectionId id) => Find((int)id);

    public RtrSection Find(int id) {
        int low = 0;
        int high = sections.Length - 1;

        while (low <= high) {
            int middle = low + (high - low) / 2;
            ref readonly var section = ref sections[middle];

            if (section.Id == id)
                return section;

            if (section.Id < id)
                low = middle + 1;
            else
                high = middle - 1;
        }

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

                if (count == 0
                    || (size != 16 && size != 24)
                    || count > (bytes.Length - offset - 16) / size)
                    continue;

                bool valid = true;
                int previousId = 0;

                for (int i = 0; i < count; ++i) {
                    var row = bytes.Slice(offset + 16 + i * size, size);
                    int id = BinaryPrimitives.ReadInt32LittleEndian(row);

                    ulong start = BinaryPrimitives.ReadUInt64LittleEndian(row[8..]);
                    ulong length = BinaryPrimitives.ReadUInt32LittleEndian(row[4..]);
                    bool hasLength = size == 16;

                    if (size == 24) {
                        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(row[4..]);
                        ulong end = BinaryPrimitives.ReadUInt64LittleEndian(row[16..]);
                        hasLength = flags == 1;

                        if (flags > 1
                            || (flags == 0 && end != 0)
                            || (flags == 1 && end < start)) {
                            valid = false;
                            break;
                        }

                        length = end == 0 ? 0 : unchecked(end - start);
                    }

                    bool mapped = image.IsMapped(start, length);

                    // Empty sized blobs can begin just past a mapped region; unsized symbols must still map.
                    if (!mapped && hasLength && length == 0 && start != 0)
                        mapped = image.IsMapped(start - 1, 1);

                    // NativeAOT's header emitter sorts IDs.
                    if (id <= previousId || start == 0 || !mapped) {
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
