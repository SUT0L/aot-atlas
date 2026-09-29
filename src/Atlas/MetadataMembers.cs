using System.Runtime.InteropServices;

namespace Atlas;

public struct MetadataProperty {
    public uint Offset, Flags, SignatureOffset, CallingConvention, DefaultValue;
    public string Name;
    public int Type;
    public IndexRange Parameters, Accessors, Attributes;
}

public struct MetadataEvent {
    public uint Offset, Flags;
    public string Name;
    public int Type;
    public IndexRange Accessors, Attributes;
}

public struct MetadataParameter {
    public uint Offset, Flags, Sequence, DefaultValue;
    public string Name;
    public IndexRange Attributes;
}

public struct MetadataGenericParameter {
    public uint Offset, Number, Flags, Kind;
    public string Name;
    public IndexRange Constraints, Attributes;
}

public readonly struct MetadataAccessor(uint offset, uint semantics, uint method) {
    public readonly uint Offset = offset, Semantics = semantics, Method = method;
}

public sealed class MetadataMembers {
    public readonly Dictionary<uint, MetadataProperty> Properties;
    public readonly Dictionary<uint, MetadataEvent> Events;
    public readonly Dictionary<uint, MetadataParameter> Parameters;
    public readonly Dictionary<uint, MetadataGenericParameter> GenericParameters;
    public readonly List<uint> Handles = new();
    public readonly List<MetadataAccessor> Accessors = new();

    public MetadataMembers(Metadata metadata) {
        int properties = 0, events = 0, parameters = 0, generics = 0;
        foreach (ref readonly var type in CollectionsMarshal.AsSpan(metadata.Types)) {
            properties = checked(properties + type.Properties.Count);
            events = checked(events + type.Events.Count);
            generics = checked(generics + type.GenericParameters.Count);
        }
        foreach (ref readonly var method in CollectionsMarshal.AsSpan(metadata.Methods)) {
            parameters = checked(parameters + method.Parameters.Count);
            generics = checked(generics + method.GenericParameters.Count);
        }
        Properties = new(properties);
        Events = new(events);
        Parameters = new(parameters);
        GenericParameters = new(generics);

        foreach (ref readonly var type in CollectionsMarshal.AsSpan(metadata.Types)) {
            for (int i = type.Properties.Start; i < type.Properties.End; ++i) {
                uint offset = metadata.Handles[i];
                if (Properties.ContainsKey(offset))
                    continue;

                var reader = metadata.Reader(offset);
                MetadataProperty property = new() { Offset = offset, Flags = checked((ushort)reader.Unsigned()) };
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
                uint offset = metadata.Handles[i];
                if (Events.ContainsKey(offset))
                    continue;

                var reader = metadata.Reader(offset);
                MetadataEvent entry = new() { Offset = offset, Flags = checked((ushort)reader.Unsigned()) };
                entry.Name = metadata.String(reader.Unsigned());
                entry.Type = metadata.TypeSignature(reader.Unsigned());
                entry.Accessors = ReadAccessors(metadata, ref reader);
                entry.Attributes = Collection(ref reader);
                Events.Add(offset, entry);
            }

            ReadGenerics(metadata, type.GenericParameters, 0);
        }

        foreach (ref readonly var method in CollectionsMarshal.AsSpan(metadata.Methods)) {
            for (int i = method.Parameters.Start; i < method.Parameters.End; ++i) {
                uint offset = metadata.Handles[i];
                if (Parameters.ContainsKey(offset))
                    continue;

                var reader = metadata.Reader(offset);
                MetadataParameter parameter = new() {
                    Offset = offset, Flags = checked((ushort)reader.Unsigned()), Sequence = checked((ushort)reader.Unsigned()),
                    Name = metadata.String(reader.Unsigned()), DefaultValue = reader.Unsigned()
                };
                parameter.Attributes = Collection(ref reader);
                Parameters.Add(offset, parameter);
            }

            ReadGenerics(metadata, method.GenericParameters, 1);
        }
    }

    private void ReadGenerics(Metadata metadata, IndexRange range, uint kind) {
        for (int i = range.Start; i < range.End; ++i) {
            uint offset = metadata.Handles[i];
            if (!GenericParameters.TryGetValue(offset, out var parameter)) {
                var reader = metadata.Reader(offset);
                parameter = new MetadataGenericParameter {
                    Offset = offset, Number = checked((ushort)reader.Unsigned()), Flags = checked((ushort)reader.Unsigned()),
                    Kind = reader.Unsigned(), Name = metadata.String(reader.Unsigned())
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
        for (int i = 0; i < count; ++i) {
            uint handle = reader.Unsigned();
            if (signatures != null)
                signatures.TypeSignature(handle);
            Handles.Add(handle);
        }
        return new IndexRange(start, count);
    }
}
