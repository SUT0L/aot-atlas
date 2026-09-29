using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Atlas;

[Flags]
public enum TypeEvidence : uint {
    None = 0, TypeMap = 1, DerivedMap = 2, InvokeMap = 4, FieldMap = 8, GenericMap = 16,
    TypeLink = 32, GenericMethod = 64, NativeSignature = 128, VirtualMethod = 256, TypeTemplate = 512,
    StaticConstructor = 1024, GenericStatics = 2048, StaticAllocation = 4096, FrozenObject = 8192,
    GenericVirtualMethod = 16384, Marshalling = 32768, ExceptionHandling = 65536
}

public struct MethodTable {
    public ulong Address, RelatedType, TypeManager, WritableData, DispatchMap, Finalizer;
    public ulong SealedVtable, GenericDefinition, Composition, FinalizerCell;
    public uint Flags, BaseSize, Hash, ValuePadding, NullableOffset;
    public ushort VtableCount, InterfaceCount, GenericArity;
    public bool ByrefLike;
    public TypeEvidence Evidence;
    public IndexRange Vtable, Interfaces, Arguments, Variance;

    public int Kind => (int)((Flags >> 16) & 3);
    public int ElementType => (int)((Flags >> 26) & 31);
    public bool HasComponentSize => (Flags & 0x80000000) != 0;
    public int ComponentSize => HasComponentSize ? (int)(Flags & 0xFFFF) : 0;
    public bool IsGeneric => (Flags & 0x02000000) != 0;
    public bool IsValueType => Kind == 0 && ElementType is >= 1 and <= 0x12 and not 0x11;
    public uint ValueSize => IsValueType ? BaseSize - 16 - ValuePadding : 0;
}

public sealed class MethodTables {
    public readonly List<MethodTable> Types = new(65536);
    public readonly List<ulong> Pointers = new(262144);
    public readonly List<byte> Variances = new(4096);
    public readonly Dictionary<ulong, int> Index = new(65536);

    public int Add(ulong address, TypeEvidence evidence) {
        if (address == 0)
            throw new InvalidDataException("A runtime type reference is null.");

        ref int index = ref CollectionsMarshal.GetValueRefOrAddDefault(Index, address, out bool present);
        if (present) {
            CollectionsMarshal.AsSpan(Types)[index].Evidence |= evidence;
            return index;
        }

        index = Types.Count;
        Types.Add(new MethodTable { Address = address, Evidence = evidence });
        return index;
    }

    public void Read(PeImage image, ReadyToRun rtr, RuntimeMemory memory) {
        bool legacy = rtr.Major < 10;
        int cursor = 0, genericCursor = 0;
        var pendingGenerics = new List<int>(32768);

        while (cursor < Types.Count || genericCursor < pendingGenerics.Count) {
            while (cursor < Types.Count) {
                MethodTable type = Types[cursor];
                int regionIndex = memory.Find(type.Address);
                if (regionIndex < 0)
                    throw new InvalidDataException($"MethodTable 0x{type.Address:X} has no initialized storage.");

                ref readonly var region = ref memory.Regions[regionIndex];
                if (region.Writable && !region.Hydrated)
                    throw new InvalidDataException($"MethodTable 0x{type.Address:X} is in mutable, unhydrated storage.");

                var bytes = region.Data.Span[(int)(type.Address - region.Start)..];
                if (bytes.Length < 24)
                    throw new InvalidDataException($"Truncated MethodTable at 0x{type.Address:X}.");

                type.Flags = BinaryPrimitives.ReadUInt32LittleEndian(bytes);
                type.BaseSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes[4..]);
                type.RelatedType = BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]);
                type.VtableCount = BinaryPrimitives.ReadUInt16LittleEndian(bytes[16..]);
                type.InterfaceCount = BinaryPrimitives.ReadUInt16LittleEndian(bytes[18..]);
                type.Hash = BinaryPrimitives.ReadUInt32LittleEndian(bytes[20..]);

                if ((type.Evidence & TypeEvidence.GenericVirtualMethod) != 0 && type.Kind != 3 && (type.Kind != 0 || type.IsGeneric))
                    throw new InvalidDataException("GVM owner is not an open type definition.");

                if ((type.Flags & 0x00080000) != 0)
                    throw new InvalidDataException($"Static image references a dynamic MethodTable at 0x{type.Address:X}.");

                if (type.Kind == 0 && type.ElementType != 0x15 && !type.HasComponentSize
                    && (type.BaseSize < 24 || (type.BaseSize & 7) != 0))
                    throw new InvalidDataException($"Invalid allocation size at MethodTable 0x{type.Address:X}.");

                if (type.Kind == 2) {
                    bool array = type.ElementType is 0x17 or 0x18;
                    bool indirect = type.ElementType is 0x19 or 0x1A;
                    if ((!array && !indirect) || type.RelatedType == 0
                        || (array && (!type.HasComponentSize || type.BaseSize < 24))
                        || (indirect && (type.HasComponentSize || type.BaseSize != (type.ElementType == 0x19 ? 1 : 0))))
                        throw new InvalidDataException($"Invalid parameterized type shape at 0x{type.Address:X}.");

                    if ((type.ElementType == 0x18 && type.BaseSize != 24)
                        || (type.ElementType == 0x17 && (type.BaseSize is < 32 or > 280 || (type.BaseSize & 7) != 0)))
                        throw new InvalidDataException($"Invalid array rank at 0x{type.Address:X}.");
                }

                if (type.Kind == 1 && type.RelatedType == 0)
                    throw new InvalidDataException($"Function-pointer type has no return type at 0x{type.Address:X}.");

                if (type.Kind == 3) {
                    if (type.RelatedType != 0 || type.IsGeneric)
                        throw new InvalidDataException($"Invalid generic definition at 0x{type.Address:X}.");

                    type.GenericArity = checked((ushort)(legacy ? type.Flags & 0xFFFF : type.BaseSize));
                }

                if (type.RelatedType != 0)
                    Add(type.RelatedType, TypeEvidence.TypeLink);

                int offset = 24;
                int pointerCount = type.VtableCount + type.InterfaceCount;
                if (pointerCount > (bytes.Length - offset) / 8)
                    throw new InvalidDataException($"MethodTable pointer arrays exceed storage at 0x{type.Address:X}.");

                type.Vtable = new IndexRange(Pointers.Count, type.VtableCount);
                type.Interfaces = new IndexRange(Pointers.Count + type.VtableCount, type.InterfaceCount);
                Pointers.EnsureCapacity(checked(Pointers.Count + pointerCount));

                for (int i = 0; i < pointerCount; ++i, offset += 8) {
                    ulong pointer = BinaryPrimitives.ReadUInt64LittleEndian(bytes[offset..]);
                    Pointers.Add(pointer);

                    // Canonical templates reserve zero interface slots for runtime construction (EETypeNode.OutputInterfaceMap)
                    if (i >= type.VtableCount && pointer != 0)
                        Add(pointer, TypeEvidence.TypeLink);
                }

                // GetFieldOffset defines one ordered tail
                // Consume it once; each flag advances the same cursor used for the next field
                type.TypeManager = Relative(bytes, ref offset, type.Address);
                type.WritableData = Relative(bytes, ref offset, type.Address, allowNil: true);

                if ((type.Flags & 0x00040000) != 0)
                    type.DispatchMap = Relative(bytes, ref offset, type.Address);

                if ((type.Flags & 0x00100000) != 0) {
                    type.FinalizerCell = type.Address + (uint)offset;
                    type.Finalizer = Relative(bytes, ref offset, type.Address);
                    if (!image.IsExecutable(type.Finalizer))
                        throw new InvalidDataException($"Finalizer at MethodTable 0x{type.Address:X} is outside executable storage.");
                }

                uint extendedFlags = type.HasComponentSize ? 0 : type.Flags & 0xFFFF;
                type.ValuePadding = legacy ? 0 : (extendedFlags & 0xE0) >> 5;
                type.NullableOffset = legacy ? 1 : 1U << (int)((extendedFlags & 0x700) >> 8);
                type.ByrefLike = !legacy && (extendedFlags & 0x10) != 0;

                if (legacy && (type.Flags & 0x01000000) != 0) {
                    ulong fields = Relative(bytes, ref offset, type.Address);
                    int fieldRegion = memory.Find(fields);
                    if (fieldRegion < 0)
                        throw new InvalidDataException("MethodTable OptionalFields is outside initialized storage.");

                    ref readonly var source = ref memory.Regions[fieldRegion];
                    var reader = new NativeReader(source.Data.Span, checked((int)(fields - source.Start)));
                    byte tag;

                    do {
                        tag = reader.Take(1)[0];
                        uint value = reader.Unsigned();

                        switch (tag & 0x7F) {
                            case 0:
                                type.ByrefLike = (value & 0x8000) != 0;
                                break;
                            case 1:
                                type.ValuePadding = (value & 7) | ((value & 0xFFFFFF00) >> 5);
                                break;
                            case 2:
                                type.NullableOffset = checked(value + 1);
                                break;
                        }
                    } while ((tag & 0x80) == 0);
                }

                if (!type.IsValueType)
                    type.ValuePadding = 0;
                else if (type.ValuePadding >= type.BaseSize - 16)
                    throw new InvalidDataException("MethodTable value-type padding consumes the complete payload.");

                if (type.IsValueType && type.ElementType is >= 2 and <= 0x0F) {
                    uint size = type.ElementType switch {
                        2 or 4 or 5 => 1,
                        3 or 6 or 7 => 2,
                        8 or 9 or 14 => 4,
                        _ => 8
                    };
                    if (type.ValueSize != size)
                        throw new InvalidDataException("Primitive MethodTable size disagrees with its runtime element code.");
                }

                if (type.ElementType != 0x12)
                    type.NullableOffset = 0;

                if ((type.Flags & 0x00400000) != 0)
                    type.SealedVtable = Relative(bytes, ref offset, type.Address);

                if (type.IsGeneric) {
                    type.GenericDefinition = Relative(bytes, ref offset, type.Address);
                    Add(type.GenericDefinition, TypeEvidence.TypeLink);
                    pendingGenerics.Add(cursor);
                }

                if (type.IsGeneric || (type.Kind == 3 && (type.Flags & 0x00800000) != 0)) {
                    type.Composition = Relative(bytes, ref offset, type.Address);

                    if (type.Kind == 3) {
                        var variance = memory.Read(type.Composition, type.GenericArity);
                        type.Variance = new IndexRange(Variances.Count, variance.Length);
                        Variances.EnsureCapacity(checked(Variances.Count + variance.Length));

                        foreach (byte value in variance) {
                            if (value is not (0 or 1 or 2 or 0x20))
                                throw new InvalidDataException("Invalid generic variance value.");

                            Variances.Add(value);
                        }
                    }
                }

                if (type.Kind == 1) {
                    int count = checked((int)(type.BaseSize & 0x7FFFFFFF));
                    if (count > (bytes.Length - offset) / 4)
                        throw new InvalidDataException("Function-pointer parameters exceed MethodTable storage.");

                    type.Arguments = new IndexRange(Pointers.Count, count);
                    Pointers.EnsureCapacity(checked(Pointers.Count + count));

                    for (int i = 0; i < count; ++i) {
                        ulong argument = Relative(bytes, ref offset, type.Address);
                        Pointers.Add(argument);
                        Add(argument, TypeEvidence.TypeLink);
                    }
                }

                type.Evidence |= Types[cursor].Evidence;
                Types[cursor++] = type;
            }

            // Headers reach a fixed point before argument decoding
            // Every generic definitions arity is then available without reparsing
            while (genericCursor < pendingGenerics.Count) {
                int index = pendingGenerics[genericCursor++];
                MethodTable type = Types[index];
                MethodTable definition = Types[Index[type.GenericDefinition]];
                if (definition.Kind != 3 || definition.GenericArity == 0)
                    throw new InvalidDataException("Generic instance has no nonempty generic definition.");

                int count = definition.GenericArity;
                type.GenericArity = definition.GenericArity;
                type.Arguments = new IndexRange(Pointers.Count, count);
                Pointers.EnsureCapacity(checked(Pointers.Count + count));

                if (count == 1) {
                    Pointers.Add(type.Composition);
                    Add(type.Composition, TypeEvidence.TypeLink);
                } else {
                    var arguments = memory.Read(type.Composition, checked(count * 4));
                    int offset = 0;

                    for (int i = 0; i < count; ++i) {
                        ulong argument = Relative(arguments, ref offset, type.Composition);
                        Pointers.Add(argument);
                        Add(argument, TypeEvidence.TypeLink);
                    }
                }

                type.Evidence |= Types[index].Evidence;
                Types[index] = type;
            }
        }

        foreach (ref readonly var type in CollectionsMarshal.AsSpan(Types)) {
            for (int i = type.Interfaces.Start; i < type.Interfaces.End; ++i) {
                if (Pointers[i] != 0 && Types[Index[Pointers[i]]].ElementType != 0x15)
                    throw new InvalidDataException($"Interface map at 0x{type.Address:X} refers to a non-interface type.");
            }
        }
    }

    private static ulong Relative(ReadOnlySpan<byte> bytes, ref int offset, ulong address, bool allowNil = false) {
        if (offset > bytes.Length - 4)
            throw new InvalidDataException($"Truncated MethodTable tail at 0x{address:X}.");

        int delta = BinaryPrimitives.ReadInt32LittleEndian(bytes[offset..]);
        ulong target = allowNil && delta == 0 ? 0 : checked((ulong)((long)address + offset + delta));
        offset += 4;
        return target;
    }
}
