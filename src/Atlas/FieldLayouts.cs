using System.Runtime.InteropServices;

namespace Atlas;

public enum FieldStorageKind : byte {
    Unknown, Value, Reference, Pointer, ByReference
}

public enum FieldSizeSource : byte {
    Unknown, MethodTable, Signature, NullablePrimitive
}

public struct FieldType {
    public int MapIndex, Owner, Signature, Binding;
    public uint MetadataOffset, Size;
    public FieldStorageKind Storage;
    public FieldSizeSource Source;
}

public struct InstanceLayout {
    public uint Length;
    public int BaseType;
    public IndexRange Fields;
}

public struct InstanceField {
    public int FieldIndex;
    public uint Offset, Extent;
}

public sealed class FieldLayouts {
    public readonly TypeBindings Bindings;
    public readonly CanonicalTypes Canonical;
    public readonly List<FieldType> FieldTypes;
    public readonly InstanceLayout[] Layouts;
    public readonly InstanceField[] Fields;

    public FieldLayouts(Metadata metadata, ReflectionMaps maps, MethodTables tables) {
        FieldTypes = new List<FieldType>(maps.Fields.Count);
        CollectionsMarshal.SetCount(FieldTypes, maps.Fields.Count);
        Layouts = new InstanceLayout[tables.Types.Count];
        var signatures = metadata.Signatures;
        var owners = new Dictionary<ulong, uint>(maps.Types.Count);
        int bits = 32 - metadata.HandleBits;
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Types)) {
            if (entry.Handle >> bits == 0x3A)
                owners.Add(entry.MethodTable, entry.Handle & ((1U << bits) - 1));
        }

        var declared = new Dictionary<(uint Owner, string Name), int>(metadata.Fields.Count);
        foreach (ref readonly var type in CollectionsMarshal.AsSpan(metadata.Types)) {
            for (int i = type.Fields.Start; i < type.Fields.End; ++i) {
                uint offset = metadata.Handles[i];
                int binding = metadata.FieldIndex[offset] + 1;
                var field = metadata.Fields[binding - 1];
                ref int slot = ref CollectionsMarshal.GetValueRefOrAddDefault(declared, (type.Offset, field.Name), out _);
                slot = slot == 0 || slot == binding ? binding : -1;
            }
        }

        var canonical = Canonical = new CanonicalTypes(tables);
        var direct = new Dictionary<(int Owner, uint Metadata, string Name), int>(maps.Fields.Count);
        var groups = new Dictionary<(int Owner, uint Metadata, string Name), int>(maps.Fields.Count);
        var sources = new List<int>(maps.Fields.Count);
        for (int i = 0; i < maps.Fields.Count; ++i) {
            ref readonly var field = ref CollectionsMarshal.AsSpan(maps.Fields)[i];
            ref var resolved = ref CollectionsMarshal.AsSpan(FieldTypes)[i];
            resolved.MapIndex = i;
            resolved.Signature = field.Signature;
            resolved.MetadataOffset = field.MetadataOffset;
            int owner = tables.Index[field.DeclaringType];
            resolved.Owner = owner + 1;
            ref readonly var type = ref CollectionsMarshal.AsSpan(tables.Types)[owner];

            // Legacy maps carry names
            // The declaring types own metadata collection supplies identity; a global field-name search cant
            ulong definition = type.IsGeneric ? type.GenericDefinition : type.Address;
            if (resolved.Signature == 0 && owners.TryGetValue(definition, out uint typeOffset)
                && declared.TryGetValue((typeOffset, field.Name), out int member) && member > 0) {
                ref var record = ref CollectionsMarshal.AsSpan(metadata.Fields)[member - 1];
                if (record.Signature == 0) {
                    var reader = metadata.Reader(record.SignatureOffset);
                    record.Signature = metadata.TypeSignature(reader.Unsigned());
                }

                resolved.Signature = record.Signature;
                resolved.MetadataOffset = record.Offset;
            }

            if (field.Storage == 0 && field.Location == FieldLocation.Offset) {
                direct.Add((owner + 1, resolved.MetadataOffset, field.Name), i);
                var key = (canonical.Groups[owner], resolved.MetadataOffset, field.Name);
                if (groups.TryAdd(key, i)) {
                    sources.Add(i);
                } else {
                    ref readonly var existing = ref CollectionsMarshal.AsSpan(maps.Fields)[groups[key]];
                    if (existing.Value != field.Value)
                        throw new InvalidDataException("Canonically equivalent fields have different offsets.");
                }
            }
        }

        Bindings = new TypeBindings(tables, maps, signatures);
        sources.Sort((left, right) => {
            int a = canonical.Groups[FieldTypes[left].Owner - 1];
            int b = canonical.Groups[FieldTypes[right].Owner - 1];
            return a != b ? a.CompareTo(b) : left.CompareTo(right);
        });

        var ranges = new IndexRange[tables.Types.Count];
        for (int first = 0; first < sources.Count;) {
            int group = canonical.Groups[FieldTypes[sources[first]].Owner - 1];
            int end = first + 1;
            while (end < sources.Count && canonical.Groups[FieldTypes[sources[end]].Owner - 1] == group)
                ++end;

            ranges[group - 1] = new IndexRange(first, end - first);
            first = end;
        }

        int count = 0;
        for (int i = 0; i < tables.Types.Count; ++i) {
            ref readonly var type = ref CollectionsMarshal.AsSpan(tables.Types)[i];
            ref var layout = ref Layouts[i];
            if (type.Kind == 0 && type.ElementType != 0x15) {
                layout.Length = type.IsValueType ? type.ValueSize : type.BaseSize - 8;
                if (!type.IsValueType && type.RelatedType != 0)
                    layout.BaseType = tables.Index[type.RelatedType] + 1;
            }

            layout.Fields = new IndexRange(count, ranges[canonical.Groups[i] - 1].Count);
            count = layout.Fields.End;
        }

        var baseState = new byte[Layouts.Length];
        for (int root = 0; root < Layouts.Length; ++root) {
            int parent = root;
            while (parent >= 0 && baseState[parent] == 0) {
                baseState[parent] = 1;
                parent = Layouts[parent].BaseType - 1;
            }
            if (parent >= 0 && baseState[parent] == 1)
                throw new InvalidDataException($"Cyclic base type at MethodTable 0x{tables.Types[parent].Address:X}.");

            parent = root;
            while (parent >= 0 && baseState[parent] == 1) {
                baseState[parent] = 2;
                parent = Layouts[parent].BaseType - 1;
            }
        }

        Fields = new InstanceField[count];
        FieldTypes.EnsureCapacity(checked(FieldTypes.Count + count - direct.Count));
        for (int owner = 0; owner < tables.Types.Count; ++owner) {
            ref readonly var layout = ref Layouts[owner];
            var range = ranges[canonical.Groups[owner] - 1];
            for (int j = 0; j < range.Count; ++j) {
                int source = sources[range.Start + j];
                var fieldType = FieldTypes[source];
                ref readonly var field = ref CollectionsMarshal.AsSpan(maps.Fields)[source];
                if (!direct.TryGetValue((owner + 1, fieldType.MetadataOffset, field.Name), out int index)) {
                    fieldType.Owner = owner + 1;
                    index = FieldTypes.Count;
                    FieldTypes.Add(fieldType);
                }

                if (layout.Length == 0 || field.Value >= layout.Length)
                    throw new InvalidDataException($"Instance field {field.Name} exceeds MethodTable 0x{tables.Types[owner].Address:X}.");

                Fields[layout.Fields.Start + j] = new InstanceField { FieldIndex = index, Offset = field.Value };
            }
        }

        foreach (ref var field in CollectionsMarshal.AsSpan(FieldTypes)) {
            int context = maps.Fields[field.MapIndex].Location == FieldLocation.Ordinal ? 0 : field.Owner;
            field.Binding = Bindings.Resolve(field.Signature, context);
            ResolveStorage(ref field, context, signatures, tables);
        }

        foreach (ref readonly var layout in Layouts.AsSpan()) {
            var fields = Fields.AsSpan(layout.Fields.Start, layout.Fields.Count);
            fields.Sort(static (left, right) => left.Offset != right.Offset
                ? left.Offset.CompareTo(right.Offset) : left.FieldIndex.CompareTo(right.FieldIndex));

            uint boundary = layout.Length;
            for (int end = fields.Length; end > 0;) {
                int first = end - 1;
                uint offset = fields[first].Offset;
                while (first > 0 && fields[first - 1].Offset == offset)
                    --first;

                for (int i = first; i < end; ++i)
                    fields[i].Extent = Math.Min(FieldTypes[fields[i].FieldIndex].Size, boundary - offset);

                boundary = offset;
                end = first;
            }
        }
    }

    private void ResolveStorage(ref FieldType field, int owner, Signatures signatures, MethodTables tables) {
        if (field.Binding != 0) {
            ref readonly var type = ref CollectionsMarshal.AsSpan(tables.Types)[field.Binding - 1];
            if (type.IsValueType) {
                field.Storage = FieldStorageKind.Value;
                field.Size = type.ValueSize;
            } else if (type.Kind == 1 || type.ElementType == 0x1A) {
                field.Storage = FieldStorageKind.Pointer;
                field.Size = 8;
            } else if (type.ElementType == 0x19) {
                field.Storage = FieldStorageKind.ByReference;
                field.Size = 8;
            } else if (type.Kind != 3) {
                field.Storage = FieldStorageKind.Reference;
                field.Size = 8;
            }

            if (field.Size != 0)
                field.Source = FieldSizeSource.MethodTable;
            return;
        }

        int signature = field.Signature;
        while (signatures.Nodes[signature].Kind == SignatureKind.Modified)
            signature = signatures.Nodes[signature].Element;

        ref readonly var node = ref CollectionsMarshal.AsSpan(signatures.Nodes)[signature];
        field.Storage = node.Kind switch {
            SignatureKind.Array or SignatureKind.SzArray => FieldStorageKind.Reference,
            SignatureKind.Pointer or SignatureKind.FunctionPointer => FieldStorageKind.Pointer,
            SignatureKind.ByReference => FieldStorageKind.ByReference,
            _ => FieldStorageKind.Unknown
        };
        if (field.Storage != FieldStorageKind.Unknown) {
            field.Size = 8;
            field.Source = FieldSizeSource.Signature;
            return;
        }

        if (node.Kind != SignatureKind.Instantiation)
            return;

        int definition = Bindings.Resolve(node.Element, owner);
        if (definition == 0)
            return;

        ref readonly var generic = ref CollectionsMarshal.AsSpan(tables.Types)[definition - 1];
        if (generic.Kind != 3 || generic.GenericArity != node.Arguments.Count)
            throw new InvalidDataException("Field signature does not match its generic definition.");

        if (generic.ElementType is 0x14 or 0x15) {
            field.Storage = FieldStorageKind.Reference;
            field.Size = 8;
            field.Source = FieldSizeSource.Signature;
        } else if (generic.ElementType == 0x12 && node.Arguments.Count == 1) {
            int argument = Bindings.Resolve(signatures.Edges[node.Arguments.Start], owner);
            if (argument == 0)
                return;

            ref readonly var underlying = ref CollectionsMarshal.AsSpan(tables.Types)[argument - 1];
            // Primitive element codes establish alignment
            // A structs size alone cant establish where Nullable places its value
            if (underlying.ElementType is >= 2 and <= 0x0F && underlying.IsValueType) {
                field.Storage = FieldStorageKind.Value;
                field.Size = checked(2 * underlying.ValueSize);
                field.Source = FieldSizeSource.NullablePrimitive;
            }
        }
    }
}
