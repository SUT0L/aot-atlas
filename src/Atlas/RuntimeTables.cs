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
        if (image.ExceptionSize == 0 || image.ExceptionRva == 0)
            throw new InvalidDataException($"Incomplete PE exception directory: RVA 0x{image.ExceptionRva:X8}, size 0x{image.ExceptionSize:X8}.");
        if ((image.ExceptionRva & 3) != 0)
            throw new InvalidDataException($"PE exception directory RVA 0x{image.ExceptionRva:X8} is not DWORD aligned.");
        if (image.ExceptionSize % 12 != 0)
            throw new InvalidDataException($"PE exception directory at RVA 0x{image.ExceptionRva:X8} has size 0x{image.ExceptionSize:X8}, which contains a partial RUNTIME_FUNCTION.");

        var source = image.FileSpan(image.ImageBase + image.ExceptionRva, checked((int)image.ExceptionSize));
        RuntimeFunction[] result = new RuntimeFunction[source.Length / 12];
        uint previous = 0;
        for (int i = 0, offset = 0; i < result.Length; ++i, offset += 12) {
            var row = source.Slice(offset, 12);
            uint begin = BinaryPrimitives.ReadUInt32LittleEndian(row);
            uint end = BinaryPrimitives.ReadUInt32LittleEndian(row[4..]);
            uint unwind = BinaryPrimitives.ReadUInt32LittleEndian(row[8..]);
            RuntimeFunction function = new(begin, end, unwind);
            uint rowRva = checked(image.ExceptionRva + (uint)offset);
            ValidateFunction(image, rowRva, function, directoryRow: i, previousBegin: previous);
            result[i] = function;
            previous = begin;
        }

        return result;
    }

    internal static void ValidateFunction(PeImage image, uint recordRva, RuntimeFunction function,
        int? directoryRow = null, uint previousBegin = 0) {
        uint begin = function.Begin;
        uint end = function.End;
        uint unwind = function.Unwind;
        if (begin >= end)
            throw InvalidFunction(image, recordRva, function, directoryRow, previousBegin,
                "BeginAddress is not below EndAddress");
        if (directoryRow is > 0 && begin < previousBegin)
            throw InvalidFunction(image, recordRva, function, directoryRow, previousBegin,
                "BeginAddress is below the previous BeginAddress");

        if (begin >= image.ImageSize || !image.IsMapped(image.ImageBase + begin, end - begin))
            throw InvalidFunction(image, recordRva, function, directoryRow, previousBegin,
                $"Code range is not mapped within one region (begin: {DescribeRva(image, begin)}; end: {DescribeRva(image, end - 1)})");

        if (!image.IsExecutable(image.ImageBase + begin))
            throw InvalidFunction(image, recordRva, function, directoryRow, previousBegin,
                $"BeginAddress is not executable ({DescribeRva(image, begin)})");

        if (unwind == 0)
            throw InvalidFunction(image, recordRva, function, directoryRow, previousBegin,
                "UnwindInfoAddress is zero");

        if ((unwind & 2) != 0)
            throw InvalidFunction(image, recordRva, function, directoryRow, previousBegin,
                "UnwindInfoAddress has reserved bit 1 set");

        uint unwindRva = unwind & ~1U;
        if (unwindRva >= image.ImageSize || !image.IsMapped(image.ImageBase + unwindRva, 4))
            throw InvalidFunction(image, recordRva, function, directoryRow, previousBegin,
                $"Unwind information header is not mapped ({DescribeRva(image, unwindRva)})");
    }

    private static InvalidDataException InvalidFunction(PeImage image, uint recordRva, RuntimeFunction function,
        int? directoryRow, uint previousBegin, string reason) {
        string location = directoryRow.HasValue
            ? $"exception row {directoryRow.Value} (directory RVA 0x{image.ExceptionRva:X8}, row RVA 0x{recordRva:X8})"
            : $"indirect or chained record at RVA 0x{recordRva:X8}";
        string previous = directoryRow is > 0 ? $", PreviousBegin=0x{previousBegin:X8}" : "";
        return new InvalidDataException($"Invalid RUNTIME_FUNCTION at {location}: Begin=0x{function.Begin:X8}, End=0x{function.End:X8}, Unwind=0x{function.Unwind:X8}{previous}; {reason}");
    }

    private static string DescribeRva(PeImage image, uint rva) {
        if (rva < image.HeaderSize)
            return $"PE headers at RVA 0x{rva:X8}";
        if (rva >= image.ImageSize)
            return $"RVA 0x{rva:X8} outside image size 0x{image.ImageSize:X8}";

        int index = image.FindSection(image.ImageBase + rva);
        if (index < 0)
            return $"RVA 0x{rva:X8} in an unmapped image gap";

        ref readonly var section = ref image.Sections[index];
        ulong end = (ulong)section.Rva + section.VirtualSize;
        return $"section \"{section.Name}\" RVA 0x{section.Rva:X8}-0x{end:X8}, characteristics 0x{section.Characteristics:X8}";
    }
}
