using System.Collections.Frozen;

namespace Atlas;

public struct MetadataProperty {
    public uint Offset;
    public uint Flags;

    public uint SignatureOffset;
    public uint CallingConvention;
    public uint DefaultValue;
    public MetadataFactStatus DefaultValueStatus;

    public string Name;
    internal int Type;

    public IndexRange Parameters;
    public IndexRange Accessors;
    public IndexRange Attributes;
}

public struct MetadataEvent {
    public uint Offset;
    public uint Flags;

    public string Name;
    internal int Type;

    public IndexRange Accessors;
    public IndexRange Attributes;
}

public struct MetadataParameter {
    public uint Offset;
    public uint Flags;
    public uint Sequence;

    public uint DefaultValue;
    public MetadataFactStatus DefaultValueStatus;
    public string Name;
    public IndexRange Attributes;
}

public struct MetadataGenericParameter {
    public uint Offset;
    public uint Number;
    public uint Flags;
    public uint Kind;

    public string Name;

    public IndexRange Constraints;
    public IndexRange Attributes;
}

public readonly struct MetadataAccessor(uint offset, uint semantics, uint method) {
    public readonly uint Offset = offset;
    public readonly uint Semantics = semantics;
    public readonly uint Method = method;
}

public sealed class MetadataMembers {
    private readonly Signatures signatures;
    internal readonly System.Collections.Frozen.FrozenDictionary<uint, MetadataProperty> Properties;
    internal readonly System.Collections.Frozen.FrozenDictionary<uint, MetadataEvent> Events;
    internal readonly System.Collections.Frozen.FrozenDictionary<uint, MetadataParameter> Parameters;
    internal readonly System.Collections.Frozen.FrozenDictionary<uint, MetadataGenericParameter> GenericParameters;
    private readonly uint[] handles;
    private readonly MetadataAccessor[] accessors;
    private readonly int[] handleSignatures;

    public IReadOnlyDictionary<uint, MetadataProperty> PropertyDefinitions => Properties;
    public IReadOnlyDictionary<uint, MetadataEvent> EventDefinitions => Events;
    public IReadOnlyDictionary<uint, MetadataParameter> ParameterDefinitions => Parameters;
    public IReadOnlyDictionary<uint, MetadataGenericParameter> GenericParameterDefinitions => GenericParameters;
    public ReadOnlySpan<uint> MemberHandles => handles;
    public ReadOnlySpan<MetadataAccessor> AccessorEntries => accessors;
    internal ReadOnlySpan<uint> Handles => handles;
    internal ReadOnlySpan<MetadataAccessor> Accessors => accessors;

    public SignatureType PropertyType(uint offset) => signatures.Types[Properties[offset].Type];
    public SignatureType EventType(uint offset) => signatures.Types[Events[offset].Type];
    public SignatureType PropertyParameterTypeAt(uint offset, int position) => CollectedTypeAt(Properties[offset].Parameters, position);
    public SignatureType GenericConstraintTypeAt(uint offset, int position) => CollectedTypeAt(GenericParameters[offset].Constraints, position);

    private SignatureType CollectedTypeAt(IndexRange range, int position) {
        if ((uint)position >= (uint)range.Count)
            throw new ArgumentOutOfRangeException(nameof(position));
        return signatures.Types[handleSignatures[range.Start + position]];
    }

    internal MetadataMembers(MetadataMembersBuilder source, Signatures publication) {
        signatures = publication;
        Properties = source.Properties.ToFrozenDictionary();
        Events = source.Events.ToFrozenDictionary();
        Parameters = source.Parameters.ToFrozenDictionary();
        GenericParameters = source.GenericParameters.ToFrozenDictionary();
        handles = source.Handles.ToArray();
        accessors = source.Accessors.ToArray();
        handleSignatures = source.HandleSignatures.ToArray();
    }
}

internal sealed class MetadataMembersBuilder(MetadataBuilder metadata) {
    internal readonly Dictionary<uint, MetadataProperty> Properties = new();
    internal readonly Dictionary<uint, MetadataEvent> Events = new();
    internal readonly Dictionary<uint, MetadataParameter> Parameters = new();
    internal readonly Dictionary<uint, MetadataGenericParameter> GenericParameters = new();
    internal readonly List<uint> Handles = new();
    internal readonly List<MetadataAccessor> Accessors = new();
    internal readonly List<int> HandleSignatures = new();
    private bool read;

    internal void ReadAll(CancellationToken cancellationToken) {
        if (read)
            return;
        foreach (var id in metadata.ReadRecordIds().ToArray()) {
            cancellationToken.ThrowIfCancellationRequested();
            switch (id.Kind) {
                case MetadataRecordKind.Property:
                    metadata.Recover(id, "property", () => ReadProperty(id));
                    break;
                case MetadataRecordKind.Event:
                    metadata.Recover(id, "event", () => ReadEvent(id));
                    break;
                case MetadataRecordKind.Parameter:
                    metadata.Recover(id, "parameter", () => ReadParameter(id));
                    break;
                case MetadataRecordKind.GenericParameter:
                    metadata.Recover(id, "generic parameter", () => ReadGeneric(id));
                    break;
            }
        }
        foreach (var type in metadata.Types)
            ValidateGenerics(type.GenericParameters, 0, new(MetadataRecordKind.TypeDefinition, type.Offset));
        foreach (var method in metadata.Methods)
            ValidateGenerics(method.GenericParameters, 1, new(MetadataRecordKind.Method, method.Offset));
        read = true;
    }

    private void ValidateGenerics(IndexRange range, uint expectedKind, MetadataRecordId owner) {
        for (int i = range.Start; i < range.End; i++) {
            if (GenericParameters.TryGetValue(metadata.Handles[i], out var parameter) && parameter.Kind != expectedKind)
                metadata.RecordFailure(metadata.Encoding.EncodeHandle(owner), "generic parameters",
                    new InvalidDataException("Generic parameter kind disagrees with its declaring member."));
        }
    }

    internal MetadataMembers Publish(Signatures signatures) => new(this, signatures);

    private void ReadProperty(MetadataRecordId id) {
        if (Properties.ContainsKey(id.Offset))
            return;
        uint defaultValue = metadata.AvailableHandle(id, MetadataFieldName.DefaultValue, out var defaultStatus);
        MetadataProperty property = new() {
            Offset = id.Offset,
            Flags = checked((ushort)metadata.UInt(id, MetadataFieldName.Flags)),
            Name = metadata.Name(id),
            SignatureOffset = metadata.AvailableOffset(id, MetadataFieldName.Signature),
            Accessors = ReadAccessors(id),
            DefaultValue = defaultValue,
            DefaultValueStatus = defaultStatus,
            Attributes = Collection(id, MetadataFieldName.CustomAttributes, false)
        };
        metadata.Recover(id, "property signature", () => {
            var signature = new MetadataRecordId(MetadataRecordKind.PropertySignature, property.SignatureOffset);
            property.CallingConvention = metadata.UInt(signature, MetadataFieldName.CallingConvention);
            property.Type = metadata.TypeSignature(metadata.Handle(signature, MetadataFieldName.Type));
            property.Parameters = Collection(signature, MetadataFieldName.Parameters, true);
        });
        Properties.Add(id.Offset, property);
    }

    private void ReadEvent(MetadataRecordId id) {
        if (Events.ContainsKey(id.Offset))
            return;
        MetadataEvent value = new() {
            Offset = id.Offset,
            Flags = checked((ushort)metadata.UInt(id, MetadataFieldName.Flags)),
            Name = metadata.Name(id),
            Accessors = ReadAccessors(id),
            Attributes = Collection(id, MetadataFieldName.CustomAttributes, false)
        };
        metadata.Recover(id, "event type", () => value.Type = metadata.TypeSignature(metadata.Handle(id, MetadataFieldName.Type)));
        Events.Add(id.Offset, value);
    }

    private void ReadParameter(MetadataRecordId id) {
        if (Parameters.ContainsKey(id.Offset))
            return;
        uint defaultValue = metadata.AvailableHandle(id, MetadataFieldName.DefaultValue, out var defaultStatus);
        Parameters.Add(id.Offset, new MetadataParameter {
            Offset = id.Offset,
            Flags = checked((ushort)metadata.UInt(id, MetadataFieldName.Flags)),
            Sequence = checked((ushort)metadata.UInt(id, MetadataFieldName.Sequence)),
            Name = metadata.Name(id),
            DefaultValue = defaultValue,
            DefaultValueStatus = defaultStatus,
            Attributes = Collection(id, MetadataFieldName.CustomAttributes, false)
        });
    }

    private void ReadGeneric(MetadataRecordId id) {
        if (GenericParameters.ContainsKey(id.Offset))
            return;
        GenericParameters.Add(id.Offset, new MetadataGenericParameter {
            Offset = id.Offset,
            Number = checked((ushort)metadata.UInt(id, MetadataFieldName.Number)),
            Flags = checked((ushort)metadata.UInt(id, MetadataFieldName.Flags)),
            Kind = metadata.UInt(id, MetadataFieldName.Kind),
            Name = metadata.Name(id),
            Constraints = Collection(id, MetadataFieldName.Constraints, true),
            Attributes = Collection(id, MetadataFieldName.CustomAttributes, false)
        });
    }

    private IndexRange ReadAccessors(MetadataRecordId id) {
        var items = metadata.RecordField(id, MetadataFieldName.MethodSemantics).Items;
        int start = Accessors.Count;
        for (int i = 0; i < items.Count; i++) {
            var item = items[i].Reference;
            if (!item.IsAvailable || item.Value.IsNil) {
                metadata.RecordFailure(metadata.Encoding.EncodeHandle(id), "accessor", new InvalidDataException($"Accessor is unavailable ({item.Status})."));
                continue;
            }
            var accessor = item.Value;
            metadata.Recover(accessor, "accessor", () => {
                uint semantics = metadata.UInt(accessor, MetadataFieldName.Attributes);
                uint method = metadata.Offset(accessor, MetadataFieldName.Method);
                if (semantics > ushort.MaxValue)
                    throw new InvalidDataException("Accessor semantics exceed the runtime field width.");
                if (!metadata.MethodIndex.ContainsKey(method))
                    throw new InvalidDataException("Accessor method projection is unavailable.");
                Accessors.Add(new(accessor.Offset, semantics, method));
            });
        }
        if (items.Status != MetadataFactStatus.Valid)
            metadata.RecordFailure(metadata.Encoding.EncodeHandle(id), "accessors", new InvalidDataException($"Accessor collection is partial ({items.Status})."));
        return new(start, Accessors.Count - start);
    }

    private IndexRange Collection(MetadataRecordId id, MetadataFieldName name, bool signatures) {
        var items = metadata.RecordField(id, name).Items;
        int start = Handles.Count;
        for (int i = 0; i < items.Count; i++) {
            var reference = items[i].Reference;
            if (!reference.IsAvailable || reference.Value.IsNil) {
                metadata.RecordFailure(metadata.Encoding.EncodeHandle(id), name.ToString(), new InvalidDataException($"Collection item is unavailable ({reference.Status})."));
                continue;
            }
            uint handle = signatures ? metadata.Encoding.EncodeHandle(reference.Value) : reference.Value.Offset;
            int signature = 0;
            if (signatures)
                metadata.Recover(reference.Value, "type signature", () => signature = metadata.TypeSignature(handle));
            Handles.Add(handle);
            HandleSignatures.Add(signature);
        }
        if (items.Status != MetadataFactStatus.Valid)
            metadata.RecordFailure(metadata.Encoding.EncodeHandle(id), name.ToString(), new InvalidDataException($"Member collection is partial ({items.Status})."));
        return new(start, Handles.Count - start);
    }
}
