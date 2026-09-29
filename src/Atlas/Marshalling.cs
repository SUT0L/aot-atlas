using System.Runtime.InteropServices;
using System.Text;

namespace Atlas;

public enum NativeSizeSource : byte {
    Unknown, MarshallingMap, MethodTable, RuntimeCopy
}

public struct NativeStruct {
    public int Vertex, Length, TypeIndex;
    public uint Header, Hash, Size;
    public ulong ToNative, ToManaged, Cleanup;
    public IndexRange Fields;
    public NativeSizeSource SizeSource;
    public bool InvalidLayout => (Header & 2) != 0;
    public bool HasLayoutSize => SizeSource is NativeSizeSource.MarshallingMap or NativeSizeSource.MethodTable;
}

public readonly struct NativeField(IndexRange name, uint offset) {
    public readonly IndexRange Name = name;
    public readonly uint Offset = offset;
}

public struct NativeDelegate {
    public int Vertex, Length, TypeIndex;
    public uint Hash;
    public ulong Open, Closed, Create;
}

public sealed class Marshalling {
    public readonly List<NativeStruct> Structs = new(1024);
    public readonly List<NativeField> Fields = new(8192);
    public readonly List<NativeDelegate> Delegates = new(1024);
    public ReadOnlyMemory<byte> StructData;
    private uint structHashMask, delegateHashMask;

    public void Read(PeImage image, ReadyToRun rtr, ReadOnlySpan<ulong> fixups, MethodTables types) {
        var section = rtr.Find(316);
        StructData = section.Length == 0 ? default : image.FileMemory(section.Start, checked((int)section.Length));
        var data = StructData.Span;
        var utf8 = new UTF8Encoding(false, true);
        var table = new NativeTable(data);
        structHashMask = ((uint)table.BucketMask << 8) | 255;
        while (table.MoveNext()) {
            var reader = new NativeReader(data, table.Vertex);
            NativeStruct entry = new() {
                Vertex = table.Vertex,
                Hash = ((uint)table.Bucket << 8) | table.LowHash,
                TypeIndex = types.Add(Reference(ref reader, fixups), TypeEvidence.Marshalling),
                Header = reader.Unsigned()
            };

            if ((entry.Header & 1) != 0) {
                entry.Size = reader.Unsigned();
                entry.SizeSource = NativeSizeSource.MarshallingMap;
                entry.ToNative = Code(ref reader, fixups, image);
                entry.ToManaged = Code(ref reader, fixups, image);
                entry.Cleanup = Code(ref reader, fixups, image);
            }

            int count = checked((int)(entry.Header >> 2));
            if (count > reader.Remaining / 2)
                throw new InvalidDataException("Native field records exceed marshalling storage.");

            entry.Fields = new IndexRange(Fields.Count, entry.InvalidLayout ? 0 : count);
            Fields.EnsureCapacity(checked(Fields.Count + entry.Fields.Count));
            for (int i = 0; i < count; ++i) {
                int length = checked((int)reader.Unsigned());
                var name = new IndexRange(reader.Position, length);
                utf8.GetCharCount(reader.Take(length));
                uint offset = reader.Unsigned();
                if (!entry.InvalidLayout)
                    Fields.Add(new NativeField(name, offset));
            }

            // Older compilers retain payload after the invalid-layout flag
            // Consume those bytes, but they cant establish a usable layout
            if (entry.InvalidLayout) {
                entry.Size = 0;
                entry.SizeSource = NativeSizeSource.Unknown;
                entry.ToNative = entry.ToManaged = entry.Cleanup = 0;
            }

            entry.Length = reader.Position - entry.Vertex;
            Structs.Add(entry);
        }

        section = rtr.Find(317);
        data = section.Length == 0 ? default : image.FileSpan(section.Start, checked((int)section.Length));
        table = new NativeTable(data);
        delegateHashMask = ((uint)table.BucketMask << 8) | 255;
        while (table.MoveNext()) {
            var reader = new NativeReader(data, table.Vertex);
            NativeDelegate entry = new() {
                Vertex = table.Vertex,
                Hash = ((uint)table.Bucket << 8) | table.LowHash,
                TypeIndex = types.Add(Reference(ref reader, fixups), TypeEvidence.Marshalling),
                Open = Code(ref reader, fixups, image),
                Closed = Code(ref reader, fixups, image),
                Create = Code(ref reader, fixups, image)
            };
            entry.Length = reader.Position - entry.Vertex;
            Delegates.Add(entry);
        }
    }

    public void Bind(MethodTables tables, Metadata metadata, ReflectionMaps maps, bool legacyGc) {
        var types = CollectionsMarshal.AsSpan(tables.Types);
        var layouts = new Dictionary<ulong, uint>(Structs.Count);
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Structs)) {
            ref readonly var type = ref types[entry.TypeIndex];
            if (!entry.InvalidLayout && entry.SizeSource == NativeSizeSource.Unknown && type.IsValueType)
                layouts.TryAdd(type.IsGeneric ? type.GenericDefinition : type.Address, 0);
        }

        int bits = 32 - metadata.HandleBits;
        if (layouts.Count != 0) {
            foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Types)) {
                if (layouts.ContainsKey(entry.MethodTable) && entry.Handle >> bits == 0x3A
                    && metadata.TypeIndex.TryGetValue(entry.Handle & ((1U << bits) - 1), out int index))
                    layouts[entry.MethodTable] = metadata.Types[index].Flags & 0x18;
            }
        }

        foreach (ref var entry in CollectionsMarshal.AsSpan(Structs)) {
            ref readonly var type = ref types[entry.TypeIndex];
            if (entry.Hash != (type.Hash & structHashMask))
                throw new InvalidDataException("Struct marshalling hash does not match its runtime lookup bucket.");
            if (entry.InvalidLayout)
                continue;

            // GetStructUnsafeStructSize uses the managed payload for these records
            // .NET 8 also emits auto-layout offsets in a different layout domain; their copy size cant bound offsets or define a native structure
            if (entry.SizeSource == NativeSizeSource.Unknown && type.IsValueType) {
                uint pointerFlag = legacyGc ? 0x00200000U : 0x01000000U;
                if ((type.Flags & pointerFlag) == 0) {
                    entry.Size = type.ValueSize;
                    ulong definition = type.IsGeneric ? type.GenericDefinition : type.Address;
                    entry.SizeSource = layouts.TryGetValue(definition, out uint layout) && layout is 8 or 16
                        ? NativeSizeSource.MethodTable : NativeSizeSource.RuntimeCopy;
                }
            }

            for (int i = entry.Fields.Start; i < entry.Fields.End; ++i) {
                if (entry.HasLayoutSize && Fields[i].Offset > entry.Size)
                    throw new InvalidDataException("Native field offset exceeds its marshalled layout.");
            }
        }

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Delegates)) {
            if (entry.Hash != (types[entry.TypeIndex].Hash & delegateHashMask))
                throw new InvalidDataException("Delegate marshalling hash does not match its runtime lookup bucket.");
        }
    }

    private static ulong Reference(ref NativeReader reader, ReadOnlySpan<ulong> fixups) {
        uint index = reader.Unsigned();
        if (index >= fixups.Length || fixups[(int)index] == 0)
            throw new InvalidDataException("Marshalling map refers outside CommonFixups or to null.");

        return fixups[(int)index];
    }

    private static ulong Code(ref NativeReader reader, ReadOnlySpan<ulong> fixups, PeImage image) {
        ulong address = Reference(ref reader, fixups);
        if (!image.IsExecutable(address))
            throw new InvalidDataException("Marshalling stub is outside executable storage.");

        return address;
    }
}
