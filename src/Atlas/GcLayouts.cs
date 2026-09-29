using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Atlas;

public readonly struct GcRun(uint offset, uint count, long encodedSize) {
    public readonly uint Offset = offset;
    public readonly uint Count = count;
    public readonly long EncodedSize = encodedSize;
}

public struct GcLayout {
    public int TypeIndex;
    public long SeriesCount;
    public uint RepeatStride;
    public IndexRange Runs;
}

public sealed class GcLayouts {
    public readonly List<GcLayout> Layouts = new(32768);
    public readonly List<GcRun> Runs = new(65536);
    public readonly List<int> Unproven = new(8192);

    public void Read(MethodTables types, RuntimeMemory memory, bool legacy) {
        uint pointerFlag = legacy ? 0x00200000U : 0x01000000U;
        Layouts.EnsureCapacity(types.Types.Count);

        for (int index = 0; index < types.Types.Count; ++index) {
            ref readonly var type = ref CollectionsMarshal.AsSpan(types.Types)[index];
            if ((type.Flags & pointerFlag) == 0)
                continue;

            // Necessary EETypes retain HasPointers but omit GCDesc
            // Frozen allocations and virtual slots establish construction
            // @Incomplete: Allocation sites or live objects can establish construction for zero-slot types
            if (type.VtableCount == 0 && (type.Evidence & TypeEvidence.FrozenObject) == 0) {
                Unproven.Add(index);
                continue;
            }

            long seriesCount = BinaryPrimitives.ReadInt64LittleEndian(memory.Read(checked(type.Address - 8), 8));
            if (seriesCount == 0)
                throw new InvalidDataException($"Empty GCDesc on pointer-containing type 0x{type.Address:X}.");

            ulong magnitude = seriesCount < 0 ? unchecked((ulong)-seriesCount) : (ulong)seriesCount;
            if (magnitude > int.MaxValue / 16)
                throw new InvalidDataException($"GCDesc count {seriesCount} at 0x{type.Address:X} exceeds addressable storage (flags 0x{type.Flags:X}).");

            int count = (int)magnitude;
            int length = checked(seriesCount < 0 ? 16 + 8 * count : 8 + 16 * count);
            var bytes = memory.Read(checked(type.Address - (uint)length), length);
            bool array = type.Kind == 2 && type.ElementType is 0x17 or 0x18;

            GcLayout layout = new() {
                TypeIndex = index,
                SeriesCount = seriesCount,
                RepeatStride = array ? (uint)type.ComponentSize : 0,
                Runs = new IndexRange(Runs.Count, count)
            };
            if (seriesCount < 0) {
                if (!array || type.ComponentSize == 0)
                    throw new InvalidDataException("Repeating GCDesc requires an array component size.");

                ulong start = BinaryPrimitives.ReadUInt64LittleEndian(bytes[^16..]);
                ulong position = start;
                Runs.EnsureCapacity(checked(Runs.Count + count));

                for (int i = 0; i < count; ++i) {
                    var item = bytes.Slice(length - 24 - i * 8, 8);
                    uint pointers = BinaryPrimitives.ReadUInt32LittleEndian(item);
                    uint skip = BinaryPrimitives.ReadUInt32LittleEndian(item[4..]);
                    if (pointers == 0 || (position & 7) != 0 || (skip & 7) != 0)
                        throw new InvalidDataException("Invalid pointer run in repeating GCDesc.");

                    Runs.Add(new GcRun(checked((uint)position), pointers, skip));
                    position = checked(position + 8UL * pointers + skip);
                }

                if (position - start != (uint)type.ComponentSize)
                    throw new InvalidDataException("Repeating GCDesc does not cover exactly one array component.");
            } else if (array) {
                // This encoding scans the variable-length payload as one pointer run
                // Emit one components pattern and its stride
                long encodedSize = BinaryPrimitives.ReadInt64LittleEndian(bytes);
                ulong offset = BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]);
                if (count != 1 || encodedSize != -(long)type.BaseSize || offset != type.BaseSize - 8
                    || type.ComponentSize == 0 || (type.ComponentSize & 7) != 0)
                    throw new InvalidDataException("Invalid all-reference array GCDesc.");

                Runs.Add(new GcRun(checked((uint)offset), (uint)type.ComponentSize / 8, encodedSize));
            } else {
                ReadObjectRuns(bytes, type.BaseSize, Runs);
            }

            Layouts.Add(layout);
        }
    }

    internal static IndexRange ReadObjectRuns(ReadOnlySpan<byte> bytes, uint baseSize, List<GcRun> runs) {
        int count = (bytes.Length - 8) / 16;
        var range = new IndexRange(runs.Count, count);
        runs.EnsureCapacity(checked(runs.Count + count));

        for (int i = 0; i < count; ++i) {
            var item = bytes.Slice(bytes.Length - 24 - i * 16, 16);
            long encodedSize = BinaryPrimitives.ReadInt64LittleEndian(item);
            ulong offset = BinaryPrimitives.ReadUInt64LittleEndian(item[8..]);
            long size = checked(encodedSize + baseSize);
            if (size <= 0 || (size & 7) != 0 || (offset & 7) != 0 || offset < 8
                || offset > baseSize - 8 || (ulong)size > baseSize - 8 - offset)
                throw new InvalidDataException("GCDesc run exceeds the object layout.");

            runs.Add(new GcRun(checked((uint)offset), checked((uint)(size / 8)), encodedSize));
        }

        return range;
    }
}
