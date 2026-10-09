using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Atlas;

public enum FrozenKind : byte {
    Object,
    Box,
    Array,
    String
}

public struct FrozenObject {
    public int Offset;
    internal int TypeIndex;
    public int Count;
    public int AllocationSize;

    public FrozenKind Kind;
    public IndexRange Data;
    public IndexRange References;
    public bool UnpairedSurrogate;
}

public readonly struct FrozenReference(uint offset, int target) {
    public readonly uint Offset = offset;
    public readonly int Target = target;
}

public readonly record struct FrozenRuntimeType {
    public readonly int ObjectIndex;
    internal readonly int TypeIndex;

    internal FrozenRuntimeType(int objectIndex, int typeIndex) {
        ObjectIndex = objectIndex;
        TypeIndex = typeIndex;
    }
}

public sealed class FrozenObjects {
    public readonly ulong Start;
    internal readonly ReadOnlyMemory<byte> Data;
    internal readonly List<FrozenObject> Objects = new(16384);
    internal readonly List<FrozenReference> References = new(4096);
    internal readonly Dictionary<ulong, int> Index = new(16384);
    public int NullReferences { get; internal set; }
    internal readonly List<FrozenRuntimeType> RuntimeTypes = new();

    public ReadOnlySpan<byte> Bytes => Data.Span;
    public ReadOnlySpan<FrozenObject> ObjectEntries => CollectionsMarshal.AsSpan(Objects);
    public ReadOnlySpan<FrozenReference> ReferenceEntries => CollectionsMarshal.AsSpan(References);
    public ReadOnlySpan<FrozenRuntimeType> RuntimeTypeEntries => CollectionsMarshal.AsSpan(RuntimeTypes);

    internal FrozenObjects(RtrSection section, RuntimeMemory memory, MethodTables tables, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

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
            cancellationToken.ThrowIfCancellationRequested();

            if (bytes.Length - position < 32 || BinaryPrimitives.ReadUInt64LittleEndian(bytes[position..]) != 0)
                throw new InvalidDataException($"Invalid frozen object header at 0x{Start + (uint)position:X}.");

            ulong address = BinaryPrimitives.ReadUInt64LittleEndian(bytes[(position + 8)..]);
            ref var header = ref CollectionsMarshal.GetValueRefOrAddDefault(headers, address, out bool known);
            if (!known) {
                var raw = memory.Read(address, 8);
                header = (
                    BinaryPrimitives.ReadUInt32LittleEndian(raw),
                    BinaryPrimitives.ReadUInt32LittleEndian(raw[4..]),
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
            if ((kind != 0 && !array)
                || element == 0x15
                || (variable && component == 0)
                || (text && (component != 2 || header.Size != 22 || element != 0x14))
                || (!text && (header.Size < 24 || (header.Size & 7) != 0))
                || (array && !variable))
                throw new InvalidDataException($"Frozen object has a non-allocatable MethodTable at 0x{address:X}.");

            int count = variable
                ? BinaryPrimitives.ReadInt32LittleEndian(bytes[(position + 16)..])
                : 0;
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
                Kind = text
                    ? FrozenKind.String
                    : array
                        ? FrozenKind.Array
                        : FrozenKind.Object,
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

                    if (char.IsHighSurrogate(characters[i])
                        && i + 1 < characters.Length
                        && char.IsLowSurrogate(characters[i + 1]))
                        ++i;
                    else
                        entry.UnpairedSurrogate = true;
                }
            } else if (array) {
                entry.Data = new IndexRange(
                    checked(position + (int)header.Size),
                    checked(count * component));
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

    internal void ReadRuntimeTypes(
        PeImage image,
        ReadyToRun header,
        RuntimeMemory memory,
        MethodTables tables,
        CancellationToken cancellationToken = default) {
        tables.Read(image, header, memory, cancellationToken);
        if (Objects.Count == 0)
            return;

        var owners = new HashSet<int>();

        foreach (ref readonly var type in CollectionsMarshal.AsSpan(tables.Types)) {
            cancellationToken.ThrowIfCancellationRequested();

            if (!TryCachedObject(memory, type.WritableData, out ulong address)
                || !Index.TryGetValue(address, out int objectIndex))
                continue;

            ref readonly var entry = ref CollectionsMarshal.AsSpan(Objects)[objectIndex];
            if (entry.Kind != FrozenKind.Object || entry.Data.Count != 16)
                continue;

            var body = Data.Span.Slice(entry.Data.Start, 16);
            if (BinaryPrimitives.ReadUInt64LittleEndian(body) != type.Address
                || BinaryPrimitives.ReadUInt64LittleEndian(body[8..]) != 0)
                continue;

            // FrozenRuntimeTypeNode and EETypeNode.WritableDataNode emit this reciprocal pair.
            owners.Add(entry.TypeIndex);
        }

        if (owners.Count == 0)
            return;

        if (owners.Count != 1)
            throw new InvalidDataException("Frozen runtime types have inconsistent object owners.");

        var bindings = new List<FrozenRuntimeType>(RuntimeTypes.Count);

        for (int i = 0; i < Objects.Count; ++i) {
            cancellationToken.ThrowIfCancellationRequested();

            ref readonly var entry = ref CollectionsMarshal.AsSpan(Objects)[i];
            if (!owners.Contains(entry.TypeIndex))
                continue;

            if (entry.Kind != FrozenKind.Object || entry.Data.Count != 16)
                throw new InvalidDataException("Frozen runtime type has an invalid instance layout.");

            var body = Data.Span.Slice(entry.Data.Start, 16);
            if (BinaryPrimitives.ReadUInt64LittleEndian(body[8..]) != 0)
                throw new InvalidDataException("Frozen runtime type has an initialized runtime handle.");

            int typeIndex = tables.Add(BinaryPrimitives.ReadUInt64LittleEndian(body), TypeEvidence.FrozenRuntimeType);
            bindings.Add(new FrozenRuntimeType(i, typeIndex));
        }

        tables.Read(image, header, memory);

        foreach (var binding in bindings) {
            ref readonly var type = ref CollectionsMarshal.AsSpan(tables.Types)[binding.TypeIndex];
            ulong address = Start + (uint)Objects[binding.ObjectIndex].Offset;
            if (!TryCachedObject(memory, type.WritableData, out ulong cached) || cached != address)
                throw new InvalidDataException("Frozen runtime type does not match its EEType cache.");
        }

        RuntimeTypes.EnsureCapacity(bindings.Count);
        RuntimeTypes.Clear();
        RuntimeTypes.AddRange(bindings);
    }

    private static bool TryCachedObject(RuntimeMemory memory, ulong address, out ulong cached) {
        cached = 0;
        if (address == 0)
            return false;

        int index = memory.Find(address);
        if (index < 0)
            return false; // An uninitialized cache can reside in zero-filled storage.

        ref readonly var region = ref memory.Regions[index];
        int offset = checked((int)(address - region.Start));
        if (region.Data.Length - offset < 8)
            throw new InvalidDataException("Truncated runtime type cache.");

        cached = BinaryPrimitives.ReadUInt64LittleEndian(region.Data.Span[offset..]);

        return cached != 0;
    }

    internal void Bind(MethodTables tables, GcLayouts gc, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        var layouts = new int[tables.Types.Count];

        for (int i = 0; i < gc.Layouts.Count; ++i)
            layouts[gc.Layouts[i].TypeIndex] = i + 1;

        foreach (ref var entry in CollectionsMarshal.AsSpan(Objects)) {
            cancellationToken.ThrowIfCancellationRequested();

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
                        ulong target = BinaryPrimitives.ReadUInt64LittleEndian(
                            Data.Span[(entry.Offset + checked((int)offset))..]);
                        if (target == 0) {
                            ++NullReferences;
                            continue;
                        }

                        if (!Index.TryGetValue(target, out int targetIndex))
                            throw new NotSupportedException(
                                $"Frozen GC reference at 0x{Start + (uint)entry.Offset + offset:X} points outside the registered object boundaries.");

                        References.Add(new FrozenReference(offset, targetIndex));
                    }
                }
            }

            entry.References = new IndexRange(start, References.Count - start);
        }
    }
}
