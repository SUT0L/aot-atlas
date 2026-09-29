using System.Runtime.InteropServices;

namespace Atlas;

public struct EnumDefinition {
    public int MetadataType, Signature, BaseSignature, ValueSignature;
    public byte Width;
    public bool Signed, Flags;
    public IndexRange Members;
}

public readonly struct EnumMember(int field, ulong bits) {
    public readonly int Field = field;
    public readonly ulong Bits = bits;
}

public sealed class Enumerations {
    public readonly List<EnumDefinition> Definitions;
    public readonly List<EnumMember> Members;
    public int[] RuntimeIndices = [];

    public Enumerations(Metadata metadata) {
        Definitions = new List<EnumDefinition>(metadata.Types.Count);
        Members = new List<EnumMember>(metadata.Fields.Count);
        var metadataIndices = new int[metadata.Types.Count];
        var names = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < metadata.Types.Count; ++i) {
            var type = metadata.Types[i];
            int parent = metadata.TypeSignature(type.BaseType);
            var baseType = metadata.Signatures.Nodes[parent];
            if (baseType.Kind != SignatureKind.Named || baseType.Name != "System.Enum")
                continue;

            EnumDefinition definition = new() {
                MetadataType = i,
                Signature = metadata.TypeSignature((type.Offset << metadata.HandleBits) | 0x3A),
                BaseSignature = parent
            };
            names.Clear();
            names.EnsureCapacity(type.Fields.Count);
            int start = Members.Count;
            for (int j = type.Fields.Start; j < type.Fields.End; ++j) {
                int fieldIndex = metadata.FieldIndex[metadata.Handles[j]];
                var field = metadata.Fields[fieldIndex];
                if ((field.Flags & 0x10) == 0) {
                    if (definition.ValueSignature != 0 || field.Name != "value__")
                        throw new InvalidDataException("An enum declares an unexpected instance field.");
                    definition.ValueSignature = field.Signature;
                    continue;
                }

                if ((field.Flags & 0x8050) != 0x8050 || !names.Add(field.Name))
                    throw new InvalidDataException("An enum member lacks a constant or has a duplicate name.");

                var signature = metadata.Signatures.Nodes[field.Signature];
                bool ownType = field.Signature == definition.Signature;
                if (signature.Kind == SignatureKind.Instantiation && signature.Element == definition.Signature
                    && signature.Arguments.Count == type.GenericParameters.Count) {
                    ownType = true;
                    for (int argument = 0; argument < signature.Arguments.Count; ++argument) {
                        var variable = metadata.Signatures.Nodes[metadata.Signatures.Edges[signature.Arguments.Start + argument]];
                        ownType &= variable.Kind == SignatureKind.TypeVariable && variable.Value == argument;
                    }
                }

                if (!ownType)
                    throw new InvalidDataException("An enum constant has a different declared type.");

                var value = ReadValue(metadata, field.DefaultValue);
                if (definition.Width != 0 && (definition.Width != value.Width || definition.Signed != value.Signed))
                    throw new InvalidDataException("An enum mixes different underlying constant types.");
                definition.Width = value.Width;
                definition.Signed = value.Signed;
                Members.Add(new EnumMember(fieldIndex, value.Bits));
            }

            definition.Members = new IndexRange(start, Members.Count - start);
            metadataIndices[i] = Definitions.Count + 1;
            Definitions.Add(definition);
        }

        foreach (ref readonly var attribute in CollectionsMarshal.AsSpan(metadata.Attributes)) {
            if (attribute.OwnerMethod != 0)
                continue;

            int index = metadataIndices[metadata.TypeIndex[attribute.OwnerType]];
            if (index != 0 && metadata.Signatures.Nodes[attribute.Type].Name == "System.FlagsAttribute")
                CollectionsMarshal.AsSpan(Definitions)[index - 1].Flags = true;
        }
    }

    private static (ulong Bits, byte Width, bool Signed) ReadValue(Metadata metadata, uint handle) {
        uint kind = handle & ((1U << metadata.HandleBits) - 1);
        if (metadata.LegacyConstants && kind == 7)
            kind = 6;
        var reader = metadata.Reader(handle >> metadata.HandleBits);
        return kind switch {
            0x16 => (reader.Take(1)[0], 1, true),
            0x06 => (reader.Take(1)[0], 1, false),
            0x0F => (unchecked((ushort)checked((short)reader.Signed())), 2, true),
            0x1C => (checked((ushort)reader.Unsigned()), 2, false),
            0x11 => (unchecked((uint)reader.Signed()), 4, true),
            0x1E => (reader.Unsigned(), 4, false),
            0x13 => (unchecked((ulong)reader.SignedLong()), 8, true),
            0x20 => (reader.UnsignedLong(), 8, false),
            _ => throw new InvalidDataException($"Enum constant has unsupported NativeFormat kind 0x{kind:X}.")
        };
    }

    public void Bind(ReflectionMaps maps, MethodTables tables, TypeBindings bindings) {
        RuntimeIndices = new int[tables.Types.Count];
        var definitions = new Dictionary<int, int>(Definitions.Count);
        for (int i = 0; i < Definitions.Count; ++i)
            definitions.Add(Definitions[i].Signature, i + 1);

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Types)) {
            if (definitions.TryGetValue(entry.Signature, out int index))
                RuntimeIndices[tables.Index[entry.MethodTable]] = index;
        }

        for (int i = 0; i < tables.Types.Count; ++i) {
            ref readonly var type = ref CollectionsMarshal.AsSpan(tables.Types)[i];
            if (type.IsGeneric)
                RuntimeIndices[i] = RuntimeIndices[tables.Index[type.GenericDefinition]];

            int index = RuntimeIndices[i];
            if (index == 0)
                continue;

            ref var definition = ref CollectionsMarshal.AsSpan(Definitions)[index - 1];
            if (type.ElementType is < 4 or > 11 || (!type.IsValueType && type.Kind != 3))
                throw new InvalidDataException("Enum metadata disagrees with the MethodTable's underlying type.");

            byte width = (byte)(1 << ((type.ElementType - 4) / 2));
            bool signed = (type.ElementType & 1) == 0;
            if (definition.Width != 0 && (definition.Width != width || definition.Signed != signed))
                throw new InvalidDataException("Enum constants disagree with the runtime width or signedness.");
            if (type.IsValueType && type.ValueSize != width)
                throw new InvalidDataException("The enum's runtime payload disagrees with its underlying type.");

            int parent = bindings.Resolve(definition.BaseSignature);
            if (parent != 0 && type.Kind != 3 && tables.Types[parent - 1].Address != type.RelatedType)
                throw new InvalidDataException("Enum metadata and MethodTable base identities differ.");

            int value = bindings.Resolve(definition.ValueSignature);
            if (value != 0 && tables.Types[value - 1].ElementType != type.ElementType)
                throw new InvalidDataException("The enum's value__ field has a different underlying type.");

            definition.Width = width;
            definition.Signed = signed;
        }
    }
}
