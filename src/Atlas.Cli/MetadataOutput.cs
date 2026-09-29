using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class MetadataOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Metadata metadata, MetadataMembers members, PeImage image, ReadyToRun rtr, double seconds) {
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("metadata_bytes", metadata.Data.Length);
        json.WriteNumber("metadata_seconds", seconds);
        json.WriteNumber("signature_nodes", metadata.Signatures.Nodes.Count - 1);
        json.WriteNumber("signature_edges", metadata.Signatures.Edges.Count);
        json.WriteStartArray("scopes");
        foreach (ref readonly var scope in CollectionsMarshal.AsSpan(metadata.Scopes)) {
            json.WriteStartArray();
            json.WriteNumberValue(scope.Offset);
            json.WriteStringValue(scope.Name);
            json.WriteEndArray();
        }
        json.WriteEndArray();

        json.WriteStartObject("types");
        foreach (ref readonly var type in CollectionsMarshal.AsSpan(metadata.Types)) {
            json.WriteStartObject(type.Offset.ToString());
            json.WriteString("name", type.Name);
            json.WriteNumber("scope", type.Scope);
            json.WriteNumber("flags", type.Flags);
            json.WriteNumber("base_type", type.BaseType);
            json.WriteNumber("enclosing_type", type.EnclosingType);
            json.WriteNumber("size", type.Size);
            json.WriteNumber("packing", type.Packing);
            json.WriteStartArray("methods");
            for (int i = type.Methods.Start; i < type.Methods.End; ++i)
                json.WriteNumberValue(metadata.Handles[i]);
            json.WriteEndArray();

            json.WriteStartArray("fields");
            for (int i = type.Fields.Start; i < type.Fields.End; ++i)
                json.WriteNumberValue(metadata.Handles[i]);
            json.WriteEndArray();
            Collection(json, "properties", metadata.Handles, type.Properties);
            Collection(json, "events", metadata.Handles, type.Events);
            Collection(json, "generic_parameters", metadata.Handles, type.GenericParameters);
            json.WriteEndObject();
        }
        json.WriteEndObject();

        json.WriteStartObject("methods");
        foreach (ref readonly var method in CollectionsMarshal.AsSpan(metadata.Methods)) {
            json.WriteStartObject(method.Offset.ToString());
            json.WriteString("name", method.Name);
            json.WriteNumber("flags", method.Flags);
            json.WriteNumber("implementation_flags", method.ImplementationFlags);
            json.WriteNumber("signature_offset", method.SignatureOffset);
            json.WriteNumber("unique_owner", method.Shared ? 0 : method.UniqueOwner);
            json.WriteString("signature", metadata.Signatures.RenderMethod(method.Name, method.Signature));
            Collection(json, "parameters", metadata.Handles, method.Parameters);
            Collection(json, "generic_parameters", metadata.Handles, method.GenericParameters);
            json.WriteEndObject();
        }
        json.WriteEndObject();

        json.WriteStartObject("fields");
        foreach (ref readonly var field in CollectionsMarshal.AsSpan(metadata.Fields)) {
            json.WriteStartObject(field.Offset.ToString());
            json.WriteString("name", field.Name);
            json.WriteNumber("flags", field.Flags);
            json.WriteNumber("signature_offset", field.SignatureOffset);
            json.WriteNumber("default_value", field.DefaultValue);
            json.WriteNumber("explicit_offset", field.ExplicitOffset);
            json.WriteString("signature", metadata.Signatures.RenderType(field.Signature));
            json.WriteEndObject();
        }
        json.WriteEndObject();

        json.WriteStartArray("forwarders");
        foreach (ref readonly var forwarder in CollectionsMarshal.AsSpan(metadata.Forwarders)) {
            json.WriteStartArray();
            json.WriteNumberValue(forwarder.Offset);
            json.WriteNumberValue(forwarder.SourceScope);
            json.WriteStringValue(forwarder.Name);
            json.WriteStringValue(forwarder.Assembly);
            json.WriteEndArray();
        }
        json.WriteEndArray();

        json.WriteStartArray("attributes");
        foreach (ref readonly var attribute in CollectionsMarshal.AsSpan(metadata.Attributes)) {
            json.WriteStartArray();
            json.WriteNumberValue(attribute.OwnerType);
            json.WriteNumberValue(attribute.OwnerMethod);
            json.WriteNumberValue(attribute.Offset);
            json.WriteNumberValue(attribute.Constructor);
            json.WriteStringValue(metadata.Signatures.RenderType(attribute.Type));
            json.WriteEndArray();
        }
        json.WriteEndArray();
        Members(json, metadata, members);
        json.WriteEndObject();
    }

    private static void Collection(Utf8JsonWriter json, string name, List<uint> handles, IndexRange range) {
        json.WriteStartArray(name);
        foreach (uint handle in CollectionsMarshal.AsSpan(handles).Slice(range.Start, range.Count))
            json.WriteNumberValue(handle);
        json.WriteEndArray();
    }

    private static void Accessors(Utf8JsonWriter json, MetadataMembers members, IndexRange range) {
        json.WriteStartArray("accessors");
        foreach (ref readonly var accessor in CollectionsMarshal.AsSpan(members.Accessors).Slice(range.Start, range.Count)) {
            json.WriteStartObject();
            json.WriteNumber("offset", accessor.Offset);
            json.WriteNumber("semantics", accessor.Semantics);
            json.WriteNumber("method", accessor.Method);
            json.WriteEndObject();
        }
        json.WriteEndArray();
    }

    private static void Members(Utf8JsonWriter json, Metadata metadata, MetadataMembers members) {
        json.WriteStartObject("properties");
        foreach (var property in members.Properties.Values) {
            json.WriteStartObject(property.Offset.ToString());
            json.WriteString("name", property.Name);
            json.WriteNumber("flags", property.Flags);
            json.WriteNumber("signature_offset", property.SignatureOffset);
            json.WriteNumber("calling_convention", property.CallingConvention);
            json.WriteString("type", metadata.Signatures.RenderType(property.Type));
            json.WriteNumber("default_value", property.DefaultValue);
            json.WriteStartArray("parameters");
            foreach (uint handle in CollectionsMarshal.AsSpan(members.Handles).Slice(property.Parameters.Start, property.Parameters.Count))
                json.WriteStringValue(metadata.Signatures.RenderType(metadata.TypeSignature(handle)));
            json.WriteEndArray();
            Accessors(json, members, property.Accessors);
            Collection(json, "attributes", members.Handles, property.Attributes);
            json.WriteEndObject();
        }
        json.WriteEndObject();

        json.WriteStartObject("events");
        foreach (var entry in members.Events.Values) {
            json.WriteStartObject(entry.Offset.ToString());
            json.WriteString("name", entry.Name);
            json.WriteNumber("flags", entry.Flags);
            json.WriteString("type", metadata.Signatures.RenderType(entry.Type));
            Accessors(json, members, entry.Accessors);
            Collection(json, "attributes", members.Handles, entry.Attributes);
            json.WriteEndObject();
        }
        json.WriteEndObject();

        json.WriteStartObject("parameters");
        foreach (var parameter in members.Parameters.Values) {
            json.WriteStartObject(parameter.Offset.ToString());
            json.WriteNumber("flags", parameter.Flags);
            json.WriteNumber("sequence", parameter.Sequence);
            json.WriteString("name", parameter.Name);
            json.WriteNumber("default_value", parameter.DefaultValue);
            Collection(json, "attributes", members.Handles, parameter.Attributes);
            json.WriteEndObject();
        }
        json.WriteEndObject();

        json.WriteStartObject("generic_parameters");
        foreach (var parameter in members.GenericParameters.Values) {
            json.WriteStartObject(parameter.Offset.ToString());
            json.WriteNumber("number", parameter.Number);
            json.WriteNumber("flags", parameter.Flags);
            json.WriteString("kind", parameter.Kind == 0 ? "type" : "method");
            json.WriteString("name", parameter.Name);
            json.WriteStartArray("constraints");
            foreach (uint handle in CollectionsMarshal.AsSpan(members.Handles).Slice(parameter.Constraints.Start, parameter.Constraints.Count))
                json.WriteStringValue(metadata.Signatures.RenderType(metadata.TypeSignature(handle)));
            json.WriteEndArray();
            Collection(json, "attributes", members.Handles, parameter.Attributes);
            json.WriteEndObject();
        }
        json.WriteEndObject();
    }
}
