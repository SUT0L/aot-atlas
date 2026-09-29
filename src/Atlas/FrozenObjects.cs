using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Atlas;

public enum FrozenKind : byte {
    Object, Box, Array, String
}

public struct FrozenObject {
    public int Offset, TypeIndex, Count, AllocationSize;
    public FrozenKind Kind;
    public IndexRange Data, References;
    public bool UnpairedSurrogate;
}

public readonly struct FrozenReference(uint offset, int target) {
    public readonly uint Offset = offset;
    public readonly int Target = target;
}

public sealed class FrozenObjects {
    public readonly ulong Start;
    public readonly ReadOnlyMemory<byte> Data;
    public readonly List<FrozenObject> Objects = new(16384);
    public readonly List<FrozenReference> References = new(4096);
    public readonly Dictionary<ulong, int> Index = new(16384);
    public int NullReferences;

    public FrozenObjects(RtrSection section, RuntimeMemory memory, MethodTables tables) {
        if (section.Length == 0)
            return;
        if ((section.Start & 7) != 0 || (section.Length & 7) != 0)
            throw new InvalidDataException("Frozen object region is not pointer aligned.");

        Start = section.Start;
        Data = memory.ReadMemory(Start, checked((int)section.Length));
        var bytes = Data.Span;
        if (BinaryPrimitives.ReadUInt64LittleEndian(bytes[^8..]) != 0)
            throw new InvalidDataException("Frozen object region has no terminal zero pointer.");

        var headers = new Dictionary<ulong, (uint Flags, uint Size, int Type)>(1024);
        int position = 0;
        while (position < bytes.Length - 8) {
            if (bytes.Length - position < 32 || BinaryPrimitives.ReadUInt64LittleEndian(bytes[position..]) != 0)
                throw new InvalidDataException($"Invalid frozen object header at 0x{Start + (uint)position:X}.");

            ulong address = BinaryPrimitives.ReadUInt64LittleEndian(bytes[(position + 8)..]);
            ref var header = ref CollectionsMarshal.GetValueRefOrAddDefault(headers, address, out bool known);
            if (!known) {
                var raw = memory.Read(address, 8);
                header = (BinaryPrimitives.ReadUInt32LittleEndian(raw), BinaryPrimitives.ReadUInt32LittleEndian(raw[4..]),
                    tables.Add(address, TypeEvidence.FrozenObject));
            }

            int kind = (int)((header.Flags >> 16) & 3);
            int element = (int)((header.Flags >> 26) & 31);
            bool variable = (header.Flags & 0x80000000) != 0;
            int component = variable ? (int)(header.Flags & 0xFFFF) : 0;
            bool array = kind == 2 && element is 0x17 or 0x18;
            // Only arrays and strings have components
            // The EEType kind distinguishes them without consulting a display name
            bool text = kind == 0 && variable;
            if ((kind != 0 && !array) || element == 0x15 || (variable && component == 0)
                || (text && (component != 2 || header.Size != 22 || element != 0x14))
                || (!text && (header.Size < 24 || (header.Size & 7) != 0)) || (array && !variable))
                throw new InvalidDataException($"Frozen object has a non-allocatable MethodTable at 0x{address:X}.");

            int count = variable ? BinaryPrimitives.ReadInt32LittleEndian(bytes[(position + 16)..]) : 0;
            if (count < 0)
                throw new InvalidDataException("Negative component count in a frozen object.");

            long allocation = ((long)header.Size + (long)count * component + 7) & ~7L;
            if (allocation > bytes.Length - 8 - position)
                throw new InvalidDataException("Frozen allocation exceeds its registered region.");

            FrozenObject entry = new() {
                Offset = position + 8,
                TypeIndex = header.Type,
                Count = count,
                AllocationSize = (int)allocation,
                Kind = text ? FrozenKind.String : array ? FrozenKind.Array : FrozenKind.Object,
                Data = new IndexRange(position + 16, (int)allocation - 16)
            };
            if (text) {
                entry.Data = new IndexRange(position + 20, checked(count * 2));
                if (BinaryPrimitives.ReadUInt16LittleEndian(bytes[entry.Data.End..]) != 0)
                    throw new InvalidDataException("Frozen string has no trailing NUL code unit.");

                var characters = MemoryMarshal.Cast<byte, char>(bytes.Slice(entry.Data.Start, entry.Data.Count));
                for (int i = 0; i < characters.Length; ++i) {
                    if (!char.IsSurrogate(characters[i]))
                        continue;
                    if (char.IsHighSurrogate(characters[i]) && i + 1 < characters.Length && char.IsLowSurrogate(characters[i + 1]))
                        ++i;
                    else
                        entry.UnpairedSurrogate = true;
                }
            } else if (array) {
                entry.Data = new IndexRange(checked(position + (int)header.Size), checked(count * component));
                if (element == 0x17) {
                    int rank = checked(((int)header.Size - 24) / 8);
                    if (rank is < 1 or > 32)
                        throw new InvalidDataException("Invalid rank in frozen multidimensional array.");

                    long product = 1;
                    for (int i = 0; i < rank; ++i) {
                        int length = BinaryPrimitives.ReadInt32LittleEndian(bytes[(position + 24 + i * 4)..]);
                        if (length < 0)
                            throw new InvalidDataException("Negative frozen array dimension.");
                        product = checked(product * length);
                    }
                    if (product != count)
                        throw new InvalidDataException("Frozen array dimensions disagree with its component count.");
                } else if (header.Size != 24)
                    throw new InvalidDataException("Frozen vector has an invalid base size.");
            }

            Index.Add(Start + (uint)entry.Offset, Objects.Count);
            Objects.Add(entry);
            position += entry.AllocationSize;
        }

        if (position != bytes.Length - 8)
            throw new InvalidDataException("Frozen allocations do not end at the region terminator.");
    }

    public void Bind(MethodTables tables, GcLayouts gc) {
        var layouts = new int[tables.Types.Count];
        for (int i = 0; i < gc.Layouts.Count; ++i)
            layouts[gc.Layouts[i].TypeIndex] = i + 1;

        foreach (ref var entry in CollectionsMarshal.AsSpan(Objects)) {
            ref readonly var type = ref CollectionsMarshal.AsSpan(tables.Types)[entry.TypeIndex];
            if (entry.Kind == FrozenKind.Array) {
                ref readonly var element = ref CollectionsMarshal.AsSpan(tables.Types)[tables.Index[type.RelatedType]];
                uint stride = element.IsValueType ? element.ValueSize : 8;
                if (stride != (uint)type.ComponentSize)
                    throw new InvalidDataException("Frozen array stride disagrees with its element MethodTable.");
            }

            if (type.IsValueType) {
                entry.Kind = FrozenKind.Box;
                entry.Data = new IndexRange(entry.Offset + 8, checked((int)type.ValueSize));
            }

            int layoutIndex = layouts[entry.TypeIndex];
            if (layoutIndex == 0)
                continue;

            ref readonly var layout = ref CollectionsMarshal.AsSpan(gc.Layouts)[layoutIndex - 1];
            int start = References.Count;
            int repeats = layout.RepeatStride == 0 ? 1 : entry.Count;
            for (int repeat = 0; repeat < repeats; ++repeat) {
                for (int i = layout.Runs.Start; i < layout.Runs.End; ++i) {
                    ref readonly var run = ref CollectionsMarshal.AsSpan(gc.Runs)[i];
                    uint offset = checked((uint)repeat * layout.RepeatStride + run.Offset);
                    for (uint j = 0; j < run.Count; ++j, offset += 8) {
                        ulong target = BinaryPrimitives.ReadUInt64LittleEndian(Data.Span[(entry.Offset + checked((int)offset))..]);
                        if (target == 0) {
                            ++NullReferences;
                            continue;
                        }

                        if (!Index.TryGetValue(target, out int targetIndex))
                            throw new NotSupportedException($"Frozen GC reference at 0x{Start + (uint)entry.Offset + offset:X} points outside the registered object boundaries.");

                        References.Add(new FrozenReference(offset, targetIndex));
                    }
                }
            }

            entry.References = new IndexRange(start, References.Count - start);
        }
    }
}
