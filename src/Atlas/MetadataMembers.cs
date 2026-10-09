using System.Runtime.InteropServices;

namespace Atlas;

public struct MetadataProperty {
    public uint Offset;
    public uint Flags;

    public uint SignatureOffset;
    public uint CallingConvention;
    public uint DefaultValue;

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
    private readonly SignatureBuilder signatureBuilder;
    private readonly ReadOnlyMemory<byte> sourceData;
    private Signatures? signatures;
    private Signatures SignaturePublication => signatures ??= signatureBuilder.Publish();
    internal readonly Dictionary<uint, MetadataProperty> Properties;
    internal readonly Dictionary<uint, MetadataEvent> Events;
    internal readonly Dictionary<uint, MetadataParameter> Parameters;
    internal readonly Dictionary<uint, MetadataGenericParameter> GenericParameters;

    internal readonly List<uint> Handles;
    internal readonly List<MetadataAccessor> Accessors;
    private readonly List<int> handleSignatures;

    private System.Collections.ObjectModel.ReadOnlyDictionary<uint, MetadataProperty>? propertyDefinitions;
    private System.Collections.ObjectModel.ReadOnlyDictionary<uint, MetadataEvent>? eventDefinitions;
    private System.Collections.ObjectModel.ReadOnlyDictionary<uint, MetadataParameter>? parameterDefinitions;
    private System.Collections.ObjectModel.ReadOnlyDictionary<uint, MetadataGenericParameter>? genericParameterDefinitions;

    public System.Collections.ObjectModel.ReadOnlyDictionary<uint, MetadataProperty> PropertyDefinitions =>
        propertyDefinitions ??= new(Properties);
    public System.Collections.ObjectModel.ReadOnlyDictionary<uint, MetadataEvent> EventDefinitions =>
        eventDefinitions ??= new(Events);
    public System.Collections.ObjectModel.ReadOnlyDictionary<uint, MetadataParameter> ParameterDefinitions =>
        parameterDefinitions ??= new(Parameters);
    public System.Collections.ObjectModel.ReadOnlyDictionary<uint, MetadataGenericParameter> GenericParameterDefinitions =>
        genericParameterDefinitions ??= new(GenericParameters);
    public ReadOnlySpan<uint> MemberHandles => CollectionsMarshal.AsSpan(Handles);
    public ReadOnlySpan<MetadataAccessor> AccessorEntries => CollectionsMarshal.AsSpan(Accessors);

    public SignatureType PropertyType(uint offset) => SignaturePublication.Types[Properties[offset].Type];
    public SignatureType EventType(uint offset) => SignaturePublication.Types[Events[offset].Type];
    public SignatureType PropertyParameterTypeAt(uint offset, int position) =>
        CollectedTypeAt(Properties[offset].Parameters, position);
    public SignatureType GenericConstraintTypeAt(uint offset, int position) =>
        CollectedTypeAt(GenericParameters[offset].Constraints, position);

    private SignatureType CollectedTypeAt(IndexRange range, int position) {
        if ((uint)position >= (uint)range.Count)
            throw new ArgumentOutOfRangeException(nameof(position));

        return SignaturePublication.Types[handleSignatures[range.Start + position]];
    }

    internal MetadataMembers RebindTo(Metadata metadata) {
        var destination = metadata.PublishedSignatures;

        if (!sourceData.Equals(metadata.Data)
            || !destination.HasSamePrefix(signatureBuilder.Nodes, signatureBuilder.Edges, signatureBuilder.Methods))
            throw new ArgumentException("Member definitions require the same metadata input and preserved signature prefix.", nameof(metadata));

        return new(this, metadata);
    }

    internal void ValidateOwner(Metadata metadata) {
        if (!sourceData.Equals(metadata.Data)
            || !ReferenceEquals(signatureBuilder.Origin, metadata.SignatureBuilder.Origin))
            throw new ArgumentException("Member definitions belong to different metadata.", nameof(metadata));
    }

    private MetadataMembers(MetadataMembers source, Metadata metadata) {
        signatureBuilder = metadata.SignatureBuilder;
        sourceData = metadata.Data;
        Properties = source.Properties;
        Events = source.Events;
        Parameters = source.Parameters;
        GenericParameters = source.GenericParameters;
        Handles = source.Handles;
        Accessors = source.Accessors;
        handleSignatures = source.handleSignatures;
    }

    public MetadataMembers(Metadata metadata, CancellationToken cancellationToken = default)
        : this(metadata, cancellationToken, ownsMetadataDraft: false) {
    }

    internal MetadataMembers(Metadata metadata, CancellationToken cancellationToken, bool ownsMetadataDraft) {
        cancellationToken.ThrowIfCancellationRequested();
        var sourceMetadata = metadata;

        if (!ownsMetadataDraft)
            metadata = metadata.WorkingCopy();

        sourceData = metadata.Data;
        Handles = new();
        Accessors = new();
        handleSignatures = new();
        int properties = 0;
        int events = 0;
        int parameters = 0;
        int generics = 0;

        foreach (ref readonly var type in CollectionsMarshal.AsSpan(metadata.Types)) {
            cancellationToken.ThrowIfCancellationRequested();

            properties = checked(properties + type.Properties.Count);
            events = checked(events + type.Events.Count);
            generics = checked(generics + type.GenericParameters.Count);
        }

        foreach (ref readonly var method in CollectionsMarshal.AsSpan(metadata.Methods)) {
            cancellationToken.ThrowIfCancellationRequested();

            parameters = checked(parameters + method.Parameters.Count);
            generics = checked(generics + method.GenericParameters.Count);
        }

        Properties = new(properties);
        Events = new(events);
        Parameters = new(parameters);
        GenericParameters = new(generics);

        foreach (ref readonly var type in CollectionsMarshal.AsSpan(metadata.Types)) {
            cancellationToken.ThrowIfCancellationRequested();

            for (int i = type.Properties.Start; i < type.Properties.End; ++i) {
                cancellationToken.ThrowIfCancellationRequested();

                uint offset = metadata.Handles[i];
                if (Properties.ContainsKey(offset))
                    continue;

                var reader = metadata.Reader(offset);

                MetadataProperty property = new() {
                    Offset = offset,
                    Flags = checked((ushort)reader.Unsigned())
                };

                property.Name = metadata.String(reader.Unsigned());
                property.SignatureOffset = reader.Unsigned();

                property.Accessors = ReadAccessors(metadata, ref reader);
                property.DefaultValue = reader.Unsigned();
                property.Attributes = Collection(ref reader);

                var signature = metadata.Reader(property.SignatureOffset);
                property.CallingConvention = signature.Unsigned();
                property.Type = metadata.TypeSignature(signature.Unsigned());
                property.Parameters = Collection(ref signature, metadata);

                Properties.Add(offset, property);
            }

            for (int i = type.Events.Start; i < type.Events.End; ++i) {
                cancellationToken.ThrowIfCancellationRequested();

                uint offset = metadata.Handles[i];
                if (Events.ContainsKey(offset))
                    continue;

                var reader = metadata.Reader(offset);

                MetadataEvent entry = new() {
                    Offset = offset,
                    Flags = checked((ushort)reader.Unsigned())
                };

                entry.Name = metadata.String(reader.Unsigned());
                entry.Type = metadata.TypeSignature(reader.Unsigned());

                entry.Accessors = ReadAccessors(metadata, ref reader);
                entry.Attributes = Collection(ref reader);

                Events.Add(offset, entry);
            }

            ReadGenerics(metadata, type.GenericParameters, 0, cancellationToken);
        }

        foreach (ref readonly var method in CollectionsMarshal.AsSpan(metadata.Methods)) {
            cancellationToken.ThrowIfCancellationRequested();

            for (int i = method.Parameters.Start; i < method.Parameters.End; ++i) {
                cancellationToken.ThrowIfCancellationRequested();

                uint offset = metadata.Handles[i];
                if (Parameters.ContainsKey(offset))
                    continue;

                var reader = metadata.Reader(offset);

                MetadataParameter parameter = new() {
                    Offset = offset,
                    Flags = checked((ushort)reader.Unsigned()),
                    Sequence = checked((ushort)reader.Unsigned()),
                    Name = metadata.String(reader.Unsigned()),
                    DefaultValue = reader.Unsigned()
                };

                parameter.Attributes = Collection(ref reader);

                Parameters.Add(offset, parameter);
            }

            ReadGenerics(metadata, method.GenericParameters, 1, cancellationToken);
        }

        cancellationToken.ThrowIfCancellationRequested();
        signatureBuilder = metadata.SignatureBuilder;

        if (!ownsMetadataDraft)
            sourceMetadata.Adopt(metadata);
    }

    private void ReadGenerics(Metadata metadata, IndexRange range, uint kind, CancellationToken cancellationToken) {
        for (int i = range.Start; i < range.End; ++i) {
            cancellationToken.ThrowIfCancellationRequested();

            uint offset = metadata.Handles[i];
            if (!GenericParameters.TryGetValue(offset, out var parameter)) {
                var reader = metadata.Reader(offset);

                parameter = new MetadataGenericParameter {
                    Offset = offset,
                    Number = checked((ushort)reader.Unsigned()),
                    Flags = checked((ushort)reader.Unsigned()),
                    Kind = reader.Unsigned(),
                    Name = metadata.String(reader.Unsigned())
                };

                parameter.Constraints = Collection(ref reader, metadata);
                parameter.Attributes = Collection(ref reader);

                GenericParameters.Add(offset, parameter);
            }

            if (parameter.Kind != kind)
                throw new InvalidDataException("Generic parameter kind disagrees with its declaring member.");
        }
    }

    private IndexRange ReadAccessors(Metadata metadata, ref NativeReader reader) {
        int count = checked((int)reader.Unsigned());

        if (count > reader.Remaining)
            throw new InvalidDataException("Accessor collection exceeds the metadata blob.");

        int start = Accessors.Count;
        Accessors.EnsureCapacity(checked(start + count));

        for (int i = 0; i < count; ++i) {
            uint offset = reader.Unsigned();
            var record = metadata.Reader(offset);

            uint semantics = checked((ushort)record.Unsigned());
            uint method = record.Unsigned();

            if (!metadata.MethodIndex.ContainsKey(method))
                throw new InvalidDataException("A property or event accessor does not identify a retained method.");

            Accessors.Add(new MetadataAccessor(offset, semantics, method));
        }

        return new IndexRange(start, count);
    }

    private IndexRange Collection(ref NativeReader reader, Metadata? signatures = null) {
        int count = checked((int)reader.Unsigned());

        if (count > reader.Remaining)
            throw new InvalidDataException("Member collection exceeds the metadata blob.");

        int start = Handles.Count;
        Handles.EnsureCapacity(checked(start + count));
        handleSignatures.EnsureCapacity(checked(start + count));

        for (int i = 0; i < count; ++i) {
            uint handle = reader.Unsigned();
            int signature = signatures?.TypeSignature(handle) ?? 0;

            Handles.Add(handle);
            handleSignatures.Add(signature);
        }

        return new IndexRange(start, count);
    }
}
