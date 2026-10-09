using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Atlas;

public readonly struct GcRun(uint offset, uint count, long? encodedSize) {
    public readonly uint Offset = offset;
    public readonly uint Count = count;
    public readonly long? EncodedSize = encodedSize;
}

public enum GcLayoutSource : byte {
    Descriptor,
    ExactValueShape,
    ExactArrayShape,
    ExactObjectShape,
    ExactInheritedShape,
    ExactArrayElementShape
}

public struct GcLayout {
    internal int TypeIndex;
    public long? SeriesCount;
    public GcLayoutSource Source;
    public uint RepeatStride;
    public IndexRange Runs;
}

public struct InheritedGcRuns {
    internal int TypeIndex;
    internal int BaseTypeIndex;
    public IndexRange Runs;
}

public sealed class GcLayouts {
    internal readonly List<GcLayout> Layouts;
    internal readonly List<GcRun> Runs;
    internal readonly List<int> Unproven;
    internal readonly List<InheritedGcRuns> Inherited = new();

    public ReadOnlySpan<GcLayout> LayoutEntries => CollectionsMarshal.AsSpan(Layouts);
    public ReadOnlySpan<GcRun> RunEntries => CollectionsMarshal.AsSpan(Runs);
    public ReadOnlySpan<InheritedGcRuns> InheritedEntries => CollectionsMarshal.AsSpan(Inherited);
    public int UnprovenTypeCount => Unproven.Count;

    public GcLayouts(int initialTypeCapacity = 0) {
        Layouts = new(initialTypeCapacity);
        Runs = new(checked(initialTypeCapacity * 2));
        Unproven = new(Math.Min(initialTypeCapacity, 8192));
    }

    private static bool IsUnproven(in MethodTable type) =>
        type.VtableCount == 0 && (type.Evidence & TypeEvidence.FrozenObject) == 0;

    private static GcLayoutSource? ExactShape(in MethodTable type) {
        if (type.Kind == 0 && type.ElementType == 0x10 && !type.HasComponentSize
            && !type.ByrefLike && (long)type.BaseSize - 16 - type.ValuePadding == 8)
            return GcLayoutSource.ExactValueShape;

        if (type.Kind == 0 && type.ElementType == 0x14 && !type.HasComponentSize
            && !type.ByrefLike && type.BaseSize == 24)
            return GcLayoutSource.ExactObjectShape;

        if (type.Kind == 2 && type.ElementType is 0x17 or 0x18 && type.ComponentSize == 8 && type.BaseSize >= 24)
            return GcLayoutSource.ExactArrayShape;

        return null;
    }

    private static int PointerBase(in MethodTable type, MethodTables types, uint pointerFlag) {
        if (type.Kind != 0 || type.ElementType != 0x14 || type.HasComponentSize
            || type.ByrefLike || !types.Index.TryGetValue(type.RelatedType, out int parent))
            return -1;

        ref readonly var baseType = ref CollectionsMarshal.AsSpan(types.Types)[parent];
        return baseType.Kind == 0 && baseType.ElementType == 0x14 && !baseType.HasComponentSize
            && !baseType.ByrefLike && (baseType.Flags & pointerFlag) != 0
            && baseType.BaseSize <= type.BaseSize ? parent : -1;
    }

    private static int ValueArrayElement(in MethodTable type, MethodTables types, uint pointerFlag) {
        // Boxed BaseSize includes the sync block and MethodTable pointer.
        const int boxedHeaderBytes = 16;

        if (type.Kind != 2 || type.ElementType is not (0x17 or 0x18)
            || !types.Index.TryGetValue(type.RelatedType, out int element))
            return -1;

        ref readonly var elementType = ref CollectionsMarshal.AsSpan(types.Types)[element];
        return elementType.Kind == 0 && elementType.ElementType is 0x10 or 0x12
            && !elementType.ByrefLike && !elementType.HasComponentSize
            && (elementType.Flags & pointerFlag) != 0
            && type.ComponentSize == (long)elementType.BaseSize - boxedHeaderBytes ? element : -1;
    }

    internal void Read(MethodTables types, RuntimeMemory memory, bool legacy, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        uint pointerFlag = NativeAotFormat.PointerFlag(legacy);

        int proven = 0;
        int unproven = 0;
        int directlyInherited = 0;
        int directArrayLayouts = 0;
        bool hasInheritedRuns = false;

        foreach (ref readonly var type in CollectionsMarshal.AsSpan(types.Types)) {
            if ((type.Flags & pointerFlag) == 0)
                continue;

            if (IsUnproven(type) && ExactShape(type) is null) {
                ++unproven;
                int element = ValueArrayElement(type, types, pointerFlag);
                if (element >= 0) {
                    ref readonly var elementType = ref CollectionsMarshal.AsSpan(types.Types)[element];
                    if (!IsUnproven(elementType) || ExactShape(elementType) is not null)
                        ++directArrayLayouts;
                }

                int parent = PointerBase(type, types, pointerFlag);
                if (parent >= 0) {
                    ref readonly var baseType = ref CollectionsMarshal.AsSpan(types.Types)[parent];
                    if (!IsUnproven(baseType) || ExactShape(baseType) is not null) {
                        hasInheritedRuns = true;
                        if (baseType.BaseSize == type.BaseSize)
                            ++directlyInherited;
                    }
                }
            } else {
                ++proven;
            }
        }

        Layouts.EnsureCapacity(checked(Layouts.Count + proven + directlyInherited + directArrayLayouts));
        Runs.EnsureCapacity(checked(Runs.Count + proven));
        Unproven.EnsureCapacity(checked(Unproven.Count + unproven));

        for (int index = 0; index < types.Types.Count; ++index) {
            cancellationToken.ThrowIfCancellationRequested();

            ref readonly var type = ref CollectionsMarshal.AsSpan(types.Types)[index];
            if ((type.Flags & pointerFlag) == 0)
                continue;

            if (IsUnproven(type)) {
                // HasPointers guarantees at least one aligned pointer. A payload or
                // component of exactly one pointer leaves only one possible GC shape.
                // This does not prove construction or the presence of a GCDesc.
                if (ExactShape(type) is GcLayoutSource source) {
                    bool arrayShape = source == GcLayoutSource.ExactArrayShape;
                    Layouts.Add(new GcLayout {
                        TypeIndex = index,
                        Source = source,
                        RepeatStride = arrayShape ? 8U : 0,
                        Runs = new IndexRange(Runs.Count, 1)
                    });
                    Runs.Add(new GcRun(arrayShape ? type.BaseSize - 8 : 8, 1, null));
                    continue;
                }

                Unproven.Add(index);
                continue;
            }

            long seriesCount = BinaryPrimitives.ReadInt64LittleEndian(
                memory.Read(checked(type.Address - 8), 8));
            if (seriesCount == 0)
                throw new InvalidDataException($"Empty GCDesc on pointer-containing type 0x{type.Address:X}.");

            ulong magnitude = seriesCount < 0
                ? unchecked((ulong)-seriesCount)
                : (ulong)seriesCount;
            if (magnitude > int.MaxValue / 16)
                throw new InvalidDataException(
                    $"GCDesc count {seriesCount} at 0x{type.Address:X} exceeds addressable storage (flags 0x{type.Flags:X}).");

            int count = (int)magnitude;
            int length = checked(seriesCount < 0
                ? 16 + 8 * count
                : 8 + 16 * count);
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
                    if (pointers == 0
                        || (position & 7) != 0
                        || (skip & 7) != 0)
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
                if (count != 1
                    || encodedSize != -(long)type.BaseSize
                    || offset != type.BaseSize - 8
                    || type.ComponentSize == 0
                    || (type.ComponentSize & 7) != 0)
                    throw new InvalidDataException("Invalid all-reference array GCDesc.");

                Runs.Add(new GcRun(checked((uint)offset), (uint)type.ComponentSize / 8, encodedSize));
            } else {
                ReadObjectRuns(bytes, type.BaseSize, Runs);
            }

            Layouts.Add(layout);
        }

        if (!hasInheritedRuns && directArrayLayouts == 0)
            return;

        int[] layoutAtType = new int[types.Types.Count];
        Array.Fill(layoutAtType, -1);

        for (int i = 0; i < Layouts.Count; ++i)
            layoutAtType[Layouts[i].TypeIndex] = i;

        if (directArrayLayouts != 0) {
            int remainingUnproven = 0;

            for (int position = 0; position < Unproven.Count; ++position) {
                cancellationToken.ThrowIfCancellationRequested();
                int index = Unproven[position];
                ref readonly var arrayType = ref CollectionsMarshal.AsSpan(types.Types)[index];
                int elementIndex = ValueArrayElement(arrayType, types, pointerFlag);

                if (elementIndex < 0 || layoutAtType[elementIndex] < 0) {
                    Unproven[remainingUnproven++] = index;
                    continue;
                }

                GcLayout elementLayout = Layouts[layoutAtType[elementIndex]];

                // Boxed values and array components use the same field GC map.
                // Move the payload past the array header without inventing a GCDesc.
                uint arrayDataOffset = arrayType.BaseSize - 8;
                IndexRange runs = new(Runs.Count, elementLayout.Runs.Count);
                Runs.EnsureCapacity(checked(Runs.Count + runs.Count));

                for (int i = elementLayout.Runs.Start; i < elementLayout.Runs.End; ++i) {
                    GcRun elementRun = Runs[i];
                    uint offset = checked(arrayDataOffset + elementRun.Offset - 8);
                    Runs.Add(new GcRun(offset, elementRun.Count, null));
                }

                Layouts.Add(new GcLayout {
                    TypeIndex = index,
                    Source = GcLayoutSource.ExactArrayElementShape,
                    RepeatStride = (uint)arrayType.ComponentSize,
                    Runs = runs
                });
            }

            Unproven.RemoveRange(remainingUnproven, Unproven.Count - remainingUnproven);
        }

        if (!hasInheritedRuns)
            return;

        var path = new List<int>(8);

        foreach (int index in Unproven) {
            cancellationToken.ThrowIfCancellationRequested();
            path.Clear();
            int current = index;

            while (layoutAtType[current] == -1) {
                cancellationToken.ThrowIfCancellationRequested();
                layoutAtType[current] = -2;
                path.Add(current);

                ref readonly var type = ref CollectionsMarshal.AsSpan(types.Types)[current];
                int parent = PointerBase(type, types, pointerFlag);
                if (parent < 0)
                    break;

                current = parent;
            }

            if (layoutAtType[current] < 0)
                continue;

            int inherited = layoutAtType[current];
            foreach (int typeIndex in path)
                layoutAtType[typeIndex] = inherited;
        }

        int remaining = 0;
        Dictionary<int, IndexRange>? inferredRuns = null;

        for (int i = 0; i < Unproven.Count; ++i) {
            int index = Unproven[i];
            if (layoutAtType[index] < 0) {
                Unproven[remaining++] = index;
                continue;
            }

            GcLayout inherited = Layouts[layoutAtType[index]];
            if (types.Types[index].BaseSize != types.Types[inherited.TypeIndex].BaseSize) {
                // These slots are certain, but the derived tail can add GC runs.
                // Keep partial evidence outside the complete layout collection.
                Inherited.Add(new InheritedGcRuns {
                    TypeIndex = index,
                    BaseTypeIndex = inherited.TypeIndex,
                    Runs = inherited.Runs
                });
                Unproven[remaining++] = index;
                continue;
            }

            // X64 fields start after the base's unaligned instance bytes. A new
            // aligned GC pointer increases its pointer-aligned allocation size.
            // Equal-sized pointer-containing classes therefore keep the base map.
            IndexRange runs = inherited.Runs;

            if (inherited.Source == GcLayoutSource.Descriptor) {
                inferredRuns ??= new();
                if (!inferredRuns.TryGetValue(layoutAtType[index], out runs)) {
                    runs = new IndexRange(Runs.Count, inherited.Runs.Count);

                    for (int run = inherited.Runs.Start; run < inherited.Runs.End; ++run) {
                        GcRun baseRun = Runs[run];
                        Runs.Add(new GcRun(baseRun.Offset, baseRun.Count, null));
                    }

                    inferredRuns.Add(layoutAtType[index], runs);
                }
            }

            Layouts.Add(new GcLayout {
                TypeIndex = index,
                Source = GcLayoutSource.ExactInheritedShape,
                Runs = runs
            });
        }

        Unproven.RemoveRange(remaining, Unproven.Count - remaining);
    }

    internal static IndexRange ReadObjectRuns(
        ReadOnlySpan<byte> bytes,
        uint baseSize,
        List<GcRun> runs) {
        int count = (bytes.Length - 8) / 16;
        var range = new IndexRange(runs.Count, count);
        runs.EnsureCapacity(checked(runs.Count + count));

        for (int i = 0; i < count; ++i) {
            var item = bytes.Slice(bytes.Length - 24 - i * 16, 16);
            long encodedSize = BinaryPrimitives.ReadInt64LittleEndian(item);
            ulong offset = BinaryPrimitives.ReadUInt64LittleEndian(item[8..]);

            long size = checked(encodedSize + baseSize);
            if (size <= 0
                || (size & 7) != 0
                || (offset & 7) != 0
                || offset < 8
                || offset > baseSize - 8
                || (ulong)size > baseSize - 8 - offset)
                throw new InvalidDataException("GCDesc run exceeds the object layout.");

            runs.Add(new GcRun(
                checked((uint)offset),
                checked((uint)(size / 8)),
                encodedSize));
        }

        return range;
    }
}
