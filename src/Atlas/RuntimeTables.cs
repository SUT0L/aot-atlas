using System.Buffers.Binary;

namespace Atlas;

public readonly struct RuntimeFunction(uint begin, uint end, uint unwind) {
    public readonly uint Begin = begin;
    public readonly uint End = end;
    public readonly uint Unwind = unwind;
}

public static class RuntimeTables {
    public static ulong[] Fixups(PeImage image, RtrSection section) {
        if (section.Length == 0)
            return [];
        if ((section.Length & 3) != 0)
            throw new InvalidDataException($"RTR section {section.Id} contains a partial relptr32.");

        var source = image.FileSpan(section.Start, checked((int)section.Length));
        ulong[] result = new ulong[source.Length / 4];
        long address = checked((long)section.Start);
        for (int i = 0, offset = 0; i < result.Length; ++i, offset += 4)
            result[i] = checked((ulong)(address + offset + BinaryPrimitives.ReadInt32LittleEndian(source[offset..])));
        return result;
    }

    public static RuntimeFunction[] Functions(PeImage image) {
        if (image.ExceptionSize == 0 && image.ExceptionRva == 0)
            return [];
        if (image.ExceptionSize == 0 || image.ExceptionRva == 0 || (image.ExceptionRva & 3) != 0 || image.ExceptionSize % 12 != 0)
            throw new InvalidDataException("PE exception directory contains a partial RUNTIME_FUNCTION.");

        var source = image.FileSpan(image.ImageBase + image.ExceptionRva, checked((int)image.ExceptionSize));
        RuntimeFunction[] result = new RuntimeFunction[source.Length / 12];
        uint previous = 0;
        for (int i = 0, offset = 0; i < result.Length; ++i, offset += 12) {
            var row = source.Slice(offset, 12);
            uint begin = BinaryPrimitives.ReadUInt32LittleEndian(row);
            uint end = BinaryPrimitives.ReadUInt32LittleEndian(row[4..]);
            uint unwind = BinaryPrimitives.ReadUInt32LittleEndian(row[8..]);
            if (begin >= end || (i != 0 && begin < previous)
                || !image.IsMapped(image.ImageBase + begin, end - begin)
                || !image.IsExecutable(image.ImageBase + begin)
                || unwind == 0 || (unwind & 2) != 0 || !image.IsMapped(image.ImageBase + (unwind & ~1U), 4))
                throw new InvalidDataException($"Invalid RUNTIME_FUNCTION at exception row {i}.");

            result[i] = new RuntimeFunction(begin, end, unwind);
            previous = begin;
        }

        return result;
    }
}
