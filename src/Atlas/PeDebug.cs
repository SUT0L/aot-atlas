using System.Buffers.Binary;
using System.Text.Unicode;

namespace Atlas;

public readonly struct PeContribution(uint rva, uint length, int fileOffset, IndexRange name) {
    public readonly uint Rva = rva, Length = length;
    public readonly int FileOffset = fileOffset;
    public readonly IndexRange Name = name;
}

public struct PeCodeView {
    public int RecordFileOffset;
    public uint Rva, Age;
    public IndexRange Data, Path;
    public Guid Guid;
    public bool Rsds, PathUtf8Valid;
}

public sealed class PeDebug {
    public readonly List<PeContribution> Entries = new();
    public readonly List<PeCodeView> CodeViews = new();

    public PeDebug(PeImage image) {
        var directory = image.Directories[6];
        if (directory.Rva == 0 && directory.Size == 0)
            return;
        if (directory.Rva == 0 || directory.Size == 0 || directory.Size % 28 != 0)
            throw new InvalidDataException("Truncated PE debug directory.");

        int directoryOffset = image.FileRange(image.ImageBase + directory.Rva).Start;
        var records = image.FileSpan(image.ImageBase + directory.Rva, checked((int)directory.Size));
        for (int offset = 0; offset < records.Length; offset += 28) {
            var row = records.Slice(offset, 28);
            uint kind = BinaryPrimitives.ReadUInt32LittleEndian(row[12..]);
            if (kind is not (2 or 13))
                continue;

            uint length = BinaryPrimitives.ReadUInt32LittleEndian(row[16..]);
            uint rva = BinaryPrimitives.ReadUInt32LittleEndian(row[20..]);
            uint fileOffset = BinaryPrimitives.ReadUInt32LittleEndian(row[24..]);
            if (length < 4 || (ulong)fileOffset + length > (ulong)image.FileData.Length)
                throw new InvalidDataException("Truncated PE debug data.");

            var data = image.FileData.AsSpan((int)fileOffset, (int)length);
            if (rva != 0 && !image.FileSpan(image.ImageBase + rva, (int)length).SequenceEqual(data))
                throw new InvalidDataException("PE debug file and image addresses disagree.");

            if (kind == 2) {
                PeCodeView entry = new() {
                    RecordFileOffset = checked(directoryOffset + offset), Rva = rva,
                    Data = new IndexRange((int)fileOffset, (int)length),
                    Rsds = data[..4].SequenceEqual("RSDS"u8)
                };
                if (entry.Rsds) {
                    if (data.Length < 25)
                        throw new InvalidDataException("Truncated CodeView RSDS record.");
                    int pathLength = data[24..].IndexOf((byte)0);
                    if (pathLength < 0)
                        throw new InvalidDataException("Unterminated CodeView PDB path.");

                    entry.Guid = new Guid(data.Slice(4, 16));
                    entry.Age = BinaryPrimitives.ReadUInt32LittleEndian(data[20..]);
                    entry.Path = new IndexRange(checked((int)fileOffset + 24), pathLength);
                    entry.PathUtf8Valid = Utf8.IsValid(data.Slice(24, pathLength));
                }
                CodeViews.Add(entry);
                continue;
            }

            uint signature = BinaryPrimitives.ReadUInt32LittleEndian(data);
            if (signature is not (0 or 0x4C544347 or 0x50474900 or 0x50475500 or 0x5350474F))
                throw new NotSupportedException($"Unsupported POGO signature 0x{signature:X8}.");

            Entries.EnsureCapacity(checked(Entries.Count + (data.Length - 4) / 12));
            for (int position = 4; position < data.Length;) {
                int start = position;
                if (data.Length - position < 9)
                    throw new InvalidDataException("Truncated POGO contribution.");
                uint begin = BinaryPrimitives.ReadUInt32LittleEndian(data[position..]);
                uint size = BinaryPrimitives.ReadUInt32LittleEndian(data[(position + 4)..]);
                position += 8;
                int nameLength = data[position..].IndexOf((byte)0);
                if (nameLength < 0 || data.Slice(position, nameLength).ContainsAnyInRange((byte)128, byte.MaxValue))
                    throw new InvalidDataException("Unterminated or non-ASCII POGO contribution name.");
                var name = new IndexRange(checked((int)fileOffset + position), nameLength);
                position = checked((position + nameLength + 4) & ~3);
                if (position > data.Length || (size != 0 && !image.IsMapped(image.ImageBase + begin, size)))
                    throw new InvalidDataException("POGO contribution exceeds its storage.");

                if (begin != 0 || nameLength != 0)
                    Entries.Add(new PeContribution(begin, size, checked((int)fileOffset + start), name));
            }
        }
    }
}
