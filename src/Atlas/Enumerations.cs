using System.Runtime.InteropServices;

namespace Atlas;

public struct EnumDefinition {
    public int MetadataType;
    internal int Signature;
    internal int BaseSignature;
    internal int ValueSignature;

    public byte Width;
    public bool Signed;
    public bool Flags;

    public IndexRange Members;
    public MetadataFactStatus Status;
    public IndexRange Failures;
}

public readonly struct EnumMember(int field, ulong bits) {
    public readonly int Field = field;
    public readonly ulong Bits = bits;
}

public readonly record struct EnumFailure(int MetadataType, uint FieldOffset, MetadataFactStatus Status, string Error);

public sealed class Enumerations {
    internal readonly List<EnumDefinition> Definitions;
    internal readonly List<EnumMember> Members;
    internal int[] RuntimeIndices = [];
    private readonly List<EnumFailure> failures = new();

    public ReadOnlySpan<EnumDefinition> DefinitionEntries => CollectionsMarshal.AsSpan(Definitions);
    public ReadOnlySpan<EnumMember> MemberEntries => CollectionsMarshal.AsSpan(Members);
    public ReadOnlySpan<EnumFailure> Failures => CollectionsMarshal.AsSpan(failures);

    internal static void ReadSignatures(MetadataBuilder metadata, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        foreach (ref readonly var type in CollectionsMarshal.AsSpan(metadata.Types)) {
            cancellationToken.ThrowIfCancellationRequested();

            uint handle = type.BaseType;
            string projection = "enum base type";
            try {
                int parent = metadata.TypeSignature(handle);
                var baseType = metadata.SignatureBuilder.Nodes[parent];
                if (baseType.Kind == SignatureKind.Named && baseType.Name == "System.Enum") {
                    handle = (type.Offset << metadata.HandleBits) | (uint)MetadataRecordKind.TypeDefinition;
                    projection = "enum declaring type";
                    metadata.TypeSignature(handle);
                }
            } catch (Exception error) when (error is InvalidDataException or OverflowException or NotSupportedException) {
                metadata.RecordFailure(handle, projection, error);
            }
        }
    }

    public Enumerations(Metadata metadata, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        var signatures = metadata.PublishedSignatures;

        Definitions = new List<EnumDefinition>(metadata.Types.Length);
        Members = new List<EnumMember>(metadata.Fields.Length);

        var metadataIndices = new int[metadata.Types.Length];

        var names = new HashSet<string>(StringComparer.Ordinal);

        for (int i = 0; i < metadata.Types.Length; ++i) {
            cancellationToken.ThrowIfCancellationRequested();

            var type = metadata.Types[i];
            if (!metadata.TryReadTypeSignature(type.BaseType, out var parentType)) {
                continue;
            }
            var baseType = signatures.Nodes[parentType.Index];
            if (baseType.Kind != SignatureKind.Named || baseType.Name != "System.Enum") {
                continue;
            }
            uint ownerHandle = (type.Offset << metadata.HandleBits) | (uint)MetadataRecordKind.TypeDefinition;
            if (!metadata.TryReadTypeSignature(ownerHandle, out var ownerType)) {
                continue;
            }
            EnumDefinition definition = new() {
                MetadataType = i,
                Signature = ownerType.Index,
                BaseSignature = parentType.Index
            };
            var typeFacts = metadata.Facts.Type(new(type.Offset));
            var fields = typeFacts.Fields;

            names.Clear();
            names.EnsureCapacity(fields.Count);

            int start = Members.Count;
            int failureStart = failures.Count;
            bool widthConflict = false;

            if (fields.Status != MetadataFactStatus.Valid) {
                AddFailure(ref definition, 0, fields.Status,
                    $"Enum field collection is partial ({fields.Status}).");
            }
            for (int j = 0; j < fields.Count; ++j) {
                cancellationToken.ThrowIfCancellationRequested();
                var reference = fields[j];
                uint fieldOffset = reference.Value.Offset;
                if (!reference.IsAvailable || reference.Value.IsNil) {
                    var referenceStatus = reference.Status | MetadataFactStatus.InvalidHandle;
                    AddFailure(ref definition, fieldOffset, referenceStatus,
                        $"Enum field reference {j} is unavailable ({referenceStatus}).");
                    continue;
                }
                if (!metadata.FieldIndex.TryGetValue(fieldOffset, out int fieldIndex)) {
                    AddFailure(ref definition, fieldOffset, MetadataFactStatus.Unresolved,
                        "Enum field metadata is unavailable.");
                    continue;
                }
                var field = metadata.Fields[fieldIndex];
                var nameField = metadata.Facts.Field(new(MetadataRecordKind.Field, field.Offset), MetadataFieldName.Name);
                var nameReference = nameField.Reference;
                var name = metadata.Facts.Name(new(nameReference.Value.Offset)).Text;
                var nameStatus = nameField.Status | nameReference.Status | name.Status;
                if (nameStatus != MetadataFactStatus.Valid || name.Value.Length == 0) {
                    if (nameStatus == MetadataFactStatus.Valid) {
                        nameStatus = MetadataFactStatus.InvalidName;
                    }
                    AddFailure(ref definition, field.Offset, nameStatus,
                        $"Enum field name is unavailable ({nameStatus}).");
                    continue;
                }

                try {
                    if ((field.Flags & 0x10) == 0) {
                        if (definition.ValueSignature != 0 || field.Name != "value__") {
                            throw new InvalidDataException("An enum declares an unexpected instance field.");
                        }
                        definition.ValueSignature = field.Signature;
                        if (field.Signature == 0) {
                            AddFailure(ref definition, field.Offset, MetadataFactStatus.Unresolved,
                                "Enum value__ field signature is unavailable.");
                        }
                        continue;
                    }

                    if ((field.Flags & 0x8050) != 0x8050 || !names.Add(field.Name)) {
                        throw new InvalidDataException("An enum member lacks a constant or has a duplicate name.");
                    }
                    if (field.Signature == 0) {
                        AddFailure(ref definition, field.Offset, MetadataFactStatus.Unresolved,
                            "Enum member declared type is unavailable.");
                    } else {
                        var signature = signatures.Nodes[field.Signature];
                        bool ownType = field.Signature == definition.Signature;
                        if (signature.Kind == SignatureKind.Instantiation
                            && signature.Element == definition.Signature
                            && (ulong)signature.Arguments.Count == typeFacts.GenericParameters.DeclaredCount) {
                            ownType = true;
                            for (int argument = 0; argument < signature.Arguments.Count; ++argument) {
                                var variable = signatures.Nodes[
                                    signatures.Edges[signature.Arguments.Start + argument]];
                                ownType &= variable.Kind == SignatureKind.TypeVariable && variable.Value == argument;
                            }
                        }
                        if (!ownType) {
                            throw new InvalidDataException("An enum constant has a different declared type.");
                        }
                    }

                    var defaultValue = new MetadataFact<uint>(field.DefaultValue, field.DefaultValueStatus,
                        MetadataSourceRange.Unavailable);
                    if (!defaultValue.IsAvailable) {
                        AddFailure(ref definition, field.Offset, field.DefaultValueStatus,
                            $"Enum constant reference is unavailable ({field.DefaultValueStatus}).");
                        continue;
                    }
                    var value = ReadValue(metadata, field.DefaultValue);
                    if (definition.Width != 0
                        && (definition.Width != value.Width || definition.Signed != value.Signed)) {
                        widthConflict = true;
                        definition.Width = 0;
                        AddFailure(ref definition, field.Offset, MetadataFactStatus.InvalidNumeric,
                            "An enum mixes different underlying constant types.");
                    }
                    if (!widthConflict) {
                        definition.Width = value.Width;
                        definition.Signed = value.Signed;
                    }
                    Members.Add(new EnumMember(fieldIndex, value.Bits));
                } catch (Exception error) when (error is InvalidDataException or OverflowException or NotSupportedException) {
                    AddFailure(ref definition, field.Offset, MetadataFactStatus.Unresolved, error.Message);
                }
            }

            definition.Failures = new(failureStart, failures.Count - failureStart);
            definition.Members = new IndexRange(start, Members.Count - start);
            metadataIndices[i] = Definitions.Count + 1;
            Definitions.Add(definition);
        }

        foreach (ref readonly var attribute in metadata.AttributeDefinitions) {
            if (attribute.OwnerMethod != 0)
                continue;

            if (!metadata.TypeIndex.TryGetValue(attribute.OwnerType, out int ownerIndex)) {
                continue;
            }
            int index = metadataIndices[ownerIndex];
            if (index != 0 && signatures.Nodes[attribute.Type].Name == "System.FlagsAttribute")
                CollectionsMarshal.AsSpan(Definitions)[index - 1].Flags = true;
        }
    }

    private void AddFailure(ref EnumDefinition definition, uint fieldOffset, MetadataFactStatus status, string error) {
        status |= MetadataFactStatus.Incomplete;
        definition.Status |= status;
        failures.Add(new(definition.MetadataType, fieldOffset, status, error));
    }

    private static (ulong Bits, byte Width, bool Signed) ReadValue(Metadata metadata, uint handle) {
        var facts = metadata.Facts;
        uint kind = handle & ((1U << metadata.HandleBits) - 1);
        if (kind > 63) {
            throw new InvalidDataException($"Enum constant has unsupported NativeFormat kind 0x{kind:X}.");
        }
        var id = facts.Encoding.DecodeHandle(handle);
        (int width, bool signed) = id.Kind switch {
            MetadataRecordKind.ConstantSByteValue => (1, true),
            MetadataRecordKind.ConstantByteValue => (1, false),
            MetadataRecordKind.ConstantInt16Value => (2, true),
            MetadataRecordKind.ConstantUInt16Value => (2, false),
            MetadataRecordKind.ConstantInt32Value => (4, true),
            MetadataRecordKind.ConstantUInt32Value => (4, false),
            MetadataRecordKind.ConstantInt64Value => (8, true),
            MetadataRecordKind.ConstantUInt64Value => (8, false),
            _ => throw new InvalidDataException($"Enum constant has unsupported NativeFormat kind {id.Kind}.")
        };
        var value = facts.Field(id, MetadataFieldName.Value).UInt64;
        if (!value.IsAvailable) {
            throw new InvalidDataException($"Enum constant 0x{handle:X} is unavailable: {value.Status}.");
        }
        ulong bits = width == 8 ? value.Value : value.Value & ((1UL << (width * 8)) - 1);
        return (bits, (byte)width, signed);
    }

    internal void Bind(ReflectionMaps maps, MethodTables tables, TypeBindings bindings) {
        RuntimeIndices = new int[tables.Types.Count];

        var definitions = new Dictionary<int, int>(Definitions.Count);

        for (int i = 0; i < Definitions.Count; ++i)
            definitions.Add(Definitions[i].Signature, i + 1);

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Types)) {
            if (definitions.TryGetValue(entry.Signature, out int index))
                RuntimeIndices[tables.Index[entry.MethodTable]] = index;
        }

        int initialFailures = failures.Count;
        for (int i = 0; i < tables.Types.Count; ++i) {
            ref readonly var type = ref CollectionsMarshal.AsSpan(tables.Types)[i];
            if (type.IsGeneric)
                RuntimeIndices[i] = RuntimeIndices[tables.Index[type.GenericDefinition]];

            int index = RuntimeIndices[i];
            if (index == 0)
                continue;

            ref var definition = ref CollectionsMarshal.AsSpan(Definitions)[index - 1];
            try {
                if (type.ElementType is < 4 or > 11 || (!type.IsValueType && type.Kind != 3))
                    throw new InvalidDataException("Enum metadata disagrees with the MethodTable's underlying type.");

                byte width = (byte)(1 << ((type.ElementType - 4) / 2));
                bool signed = (type.ElementType & 1) == 0;

                if (definition.Width != 0
                    && (definition.Width != width || definition.Signed != signed))
                    throw new InvalidDataException("Enum constants disagree with the runtime width or signedness.");

                if (type.IsValueType && type.ValueSize != width)
                    throw new InvalidDataException("The enum's runtime payload disagrees with its underlying type.");

                int parent = bindings.Resolve(definition.BaseSignature);
                if (parent != 0
                    && type.Kind != 3
                    && tables.Types[parent - 1].Address != type.RelatedType)
                    throw new InvalidDataException("Enum metadata and MethodTable base identities differ.");

                int value = bindings.Resolve(definition.ValueSignature);
                if (value != 0 && tables.Types[value - 1].ElementType != type.ElementType)
                    throw new InvalidDataException("The enum's value__ field has a different underlying type.");

                if (definition.Width != 0 || (definition.Status & MetadataFactStatus.InvalidNumeric) == 0) {
                    definition.Width = width;
                    definition.Signed = signed;
                }
            } catch (Exception error) when (error is InvalidDataException or OverflowException or NotSupportedException) {
                definition.Width = 0;
                AddFailure(ref definition, 0, MetadataFactStatus.InvalidNumeric | MetadataFactStatus.Unresolved, error.Message);
            }
        }
        if (failures.Count != initialFailures) {
            ReindexFailures();
        }
    }

    private void ReindexFailures() {
        failures.Sort(static (left, right) => {
            int owner = left.MetadataType.CompareTo(right.MetadataType);
            if (owner != 0) {
                return owner;
            }
            int field = left.FieldOffset.CompareTo(right.FieldOffset);
            return field != 0 ? field : StringComparer.Ordinal.Compare(left.Error, right.Error);
        });
        int first = 0;
        foreach (ref var definition in CollectionsMarshal.AsSpan(Definitions)) {
            int start = first;
            while (first < failures.Count && failures[first].MetadataType == definition.MetadataType) {
                ++first;
            }
            definition.Failures = new(start, first - start);
        }
    }
}
