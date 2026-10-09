using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class MetadataOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Metadata metadata,
        MetadataMembers members, PeImage image, ReadyToRun rtr, double seconds,
        bool includeSignatureGraph = true, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("metadata_bytes", metadata.Data.Length);
        json.WriteNumber("metadata_seconds", seconds);

        json.WriteStartArray("scopes");

        foreach (ref readonly var scope in CollectionsMarshal.AsSpan(metadata.Scopes)) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartArray();
            json.WriteNumberValue(scope.Offset);
            JsonOutput.WriteStringValue(json, scope.Name);
            json.WriteEndArray();
        }

        json.WriteEndArray();

        json.WriteStartObject("scope_attributes");

        foreach (ref readonly var scope in CollectionsMarshal.AsSpan(metadata.Scopes)) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject(scope.Offset.ToString());
            json.WriteStartArray("assembly");

            foreach (var attribute in metadata.ScopeAttributePayloads(scope.Offset, cancellationToken: cancellationToken))
                Attribute(json, attribute, cancellationToken: cancellationToken);

            json.WriteEndArray();

            json.WriteStartArray("module");

            foreach (var attribute in metadata.ScopeAttributePayloads(
                scope.Offset, module: true, cancellationToken: cancellationToken))
                Attribute(json, attribute, cancellationToken: cancellationToken);

            json.WriteEndArray();
            json.WriteEndObject();
        }

        json.WriteEndObject();

        json.WriteStartObject("types");

        foreach (ref readonly var type in CollectionsMarshal.AsSpan(metadata.Types)) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject(type.Offset.ToString());
            JsonOutput.WriteString(json, "name", type.Name);
            json.WriteNumber("scope", type.Scope);
            json.WriteNumber("flags", type.Flags);
            json.WriteNumber("base_type", type.BaseType);
            json.WriteNumber("base_type_signature_id", metadata.TypeSignature(type.BaseType));
            json.WriteNumber("enclosing_type", type.EnclosingType);
            json.WriteNumber("size", type.Size);
            json.WriteNumber("packing", type.Packing);

            json.WriteStartArray("interfaces");

            for (int i = type.Interfaces.Start; i < type.Interfaces.End; ++i) {
                cancellationToken.ThrowIfCancellationRequested();
                uint handle = metadata.Handles[i];

                json.WriteStartObject();
                json.WriteNumber("handle", handle);
                json.WriteNumber("signature_id", metadata.TypeSignature(handle));
                json.WriteEndObject();
            }

            json.WriteEndArray();

            json.WriteStartArray("methods");

            for (int i = type.Methods.Start; i < type.Methods.End; ++i) {
                cancellationToken.ThrowIfCancellationRequested();
                json.WriteNumberValue(metadata.Handles[i]);
            }

            json.WriteEndArray();

            json.WriteStartArray("fields");

            for (int i = type.Fields.Start; i < type.Fields.End; ++i) {
                cancellationToken.ThrowIfCancellationRequested();
                json.WriteNumberValue(metadata.Handles[i]);
            }

            json.WriteEndArray();

            Collection(json, "properties", metadata.Handles, type.Properties, cancellationToken);
            Collection(json, "events", metadata.Handles, type.Events, cancellationToken);
            Collection(json, "generic_parameters", metadata.Handles, type.GenericParameters, cancellationToken);
            json.WriteEndObject();
        }

        json.WriteEndObject();

        json.WriteStartObject("methods");

        foreach (ref readonly var method in CollectionsMarshal.AsSpan(metadata.Methods)) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject(method.Offset.ToString());
            JsonOutput.WriteString(json, "name", method.Name);
            json.WriteNumber("flags", method.Flags);
            json.WriteNumber("implementation_flags", method.ImplementationFlags);
            json.WriteNumber("signature_offset", method.SignatureOffset);
            json.WriteNumber("signature_id", method.Signature);
            json.WriteNumber("unique_owner", method.Shared ? 0 : method.UniqueOwner);
            JsonOutput.WriteString(json, "signature", metadata.SignatureBuilder.RenderMethod(method.Name, method.Signature));

            Collection(json, "parameters", metadata.Handles, method.Parameters, cancellationToken);
            Collection(json, "generic_parameters", metadata.Handles, method.GenericParameters, cancellationToken);
            json.WriteEndObject();
        }

        json.WriteEndObject();

        json.WriteStartObject("fields");

        foreach (ref readonly var field in CollectionsMarshal.AsSpan(metadata.Fields)) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject(field.Offset.ToString());
            JsonOutput.WriteString(json, "name", field.Name);
            json.WriteNumber("flags", field.Flags);
            json.WriteNumber("signature_offset", field.SignatureOffset);
            json.WriteNumber("type_signature_id", field.Signature);
            json.WriteNumber("default_value", field.DefaultValue);
            if (field.DefaultValue != 0) {
                json.WritePropertyName("constant");
                Value(json, metadata.Constant(field.DefaultValue, cancellationToken),
                    includeHandle: false, cancellationToken: cancellationToken);
            }

            json.WriteNumber("explicit_offset", field.ExplicitOffset);
            JsonOutput.WriteString(json, "signature", metadata.SignatureBuilder.RenderType(field.Signature));
            AttributePayloads(json, metadata, metadata.Handles, field.Attributes, cancellationToken);
            json.WriteEndObject();
        }

        json.WriteEndObject();

        json.WriteStartArray("forwarders");

        foreach (ref readonly var forwarder in CollectionsMarshal.AsSpan(metadata.Forwarders)) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartArray();
            json.WriteNumberValue(forwarder.Offset);
            json.WriteNumberValue(forwarder.SourceScope);
            JsonOutput.WriteStringValue(json, forwarder.Name);
            JsonOutput.WriteStringValue(json, forwarder.Assembly);
            json.WriteEndArray();
        }

        json.WriteEndArray();

        json.WriteStartArray("attributes");

        foreach (ref readonly var attribute in CollectionsMarshal.AsSpan(metadata.Attributes)) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartArray();
            json.WriteNumberValue(attribute.OwnerType);
            json.WriteNumberValue(attribute.OwnerMethod);
            json.WriteNumberValue(attribute.Offset);
            json.WriteNumberValue(attribute.Constructor);
            JsonOutput.WriteStringValue(json, metadata.SignatureBuilder.RenderType(attribute.Type));
            Attribute(json, metadata.AttributePayload(attribute.Offset, cancellationToken),
                includeIdentity: false, cancellationToken: cancellationToken);
            json.WriteEndArray();
        }

        json.WriteEndArray();

        Members(json, metadata, members, cancellationToken);

        // Payload decoding and member signatures can append roots during serialization.
        json.WriteNumber("signature_nodes", metadata.SignatureBuilder.Nodes.Length - 1);
        json.WriteNumber("signature_edges", metadata.SignatureBuilder.Edges.Length);

        if (includeSignatureGraph)
            MetadataIdentityOutput.Write(json, metadata, cancellationToken);

        cancellationToken.ThrowIfCancellationRequested();
        json.WriteEndObject();
    }

    private static void Collection(Utf8JsonWriter json, string name, List<uint> handles, IndexRange range,
        CancellationToken cancellationToken) {
        json.WriteStartArray(name);

        foreach (uint handle in CollectionsMarshal.AsSpan(handles).Slice(range.Start, range.Count)) {
            cancellationToken.ThrowIfCancellationRequested();
            json.WriteNumberValue(handle);
        }

        json.WriteEndArray();
    }

    private static void Accessors(Utf8JsonWriter json, MetadataMembers members, IndexRange range,
        CancellationToken cancellationToken) {
        json.WriteStartArray("accessors");

        foreach (ref readonly var accessor in CollectionsMarshal.AsSpan(members.Accessors)
            .Slice(range.Start, range.Count)) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject();
            json.WriteNumber("offset", accessor.Offset);
            json.WriteNumber("semantics", accessor.Semantics);
            json.WriteNumber("method", accessor.Method);
            json.WriteEndObject();
        }

        json.WriteEndArray();
    }

    private static void Members(Utf8JsonWriter json, Metadata metadata, MetadataMembers members,
        CancellationToken cancellationToken) {
        json.WriteStartObject("properties");

        foreach (var property in members.Properties.Values) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject(property.Offset.ToString());
            JsonOutput.WriteString(json, "name", property.Name);
            json.WriteNumber("flags", property.Flags);
            json.WriteNumber("signature_offset", property.SignatureOffset);
            json.WriteNumber("type_signature_id", property.Type);
            json.WriteNumber("calling_convention", property.CallingConvention);
            JsonOutput.WriteString(json, "type", metadata.SignatureBuilder.RenderType(property.Type));
            json.WriteNumber("default_value", property.DefaultValue);

            if (property.DefaultValue != 0) {
                json.WritePropertyName("constant");
                Value(json, metadata.Constant(property.DefaultValue, cancellationToken),
                    includeHandle: false, cancellationToken: cancellationToken);
            }

            json.WriteStartArray("parameters");

            foreach (uint handle in CollectionsMarshal.AsSpan(members.Handles)
                .Slice(property.Parameters.Start, property.Parameters.Count)) {
                cancellationToken.ThrowIfCancellationRequested();
                JsonOutput.WriteStringValue(json, metadata.SignatureBuilder.RenderType(metadata.TypeSignature(handle)));
            }

            json.WriteEndArray();

            Accessors(json, members, property.Accessors, cancellationToken);
            Collection(json, "attributes", members.Handles, property.Attributes, cancellationToken);
            AttributePayloads(json, metadata, members.Handles, property.Attributes, cancellationToken);
            json.WriteEndObject();
        }

        json.WriteEndObject();

        json.WriteStartObject("events");

        foreach (var entry in members.Events.Values) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject(entry.Offset.ToString());
            JsonOutput.WriteString(json, "name", entry.Name);
            json.WriteNumber("flags", entry.Flags);
            JsonOutput.WriteString(json, "type", metadata.SignatureBuilder.RenderType(entry.Type));
            json.WriteNumber("type_signature_id", entry.Type);

            Accessors(json, members, entry.Accessors, cancellationToken);
            Collection(json, "attributes", members.Handles, entry.Attributes, cancellationToken);
            AttributePayloads(json, metadata, members.Handles, entry.Attributes, cancellationToken);
            json.WriteEndObject();
        }

        json.WriteEndObject();

        json.WriteStartObject("parameters");

        foreach (var parameter in members.Parameters.Values) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject(parameter.Offset.ToString());
            json.WriteNumber("flags", parameter.Flags);
            json.WriteNumber("sequence", parameter.Sequence);
            JsonOutput.WriteString(json, "name", parameter.Name);
            json.WriteNumber("default_value", parameter.DefaultValue);

            if (parameter.DefaultValue != 0) {
                json.WritePropertyName("constant");
                Value(json, metadata.Constant(parameter.DefaultValue, cancellationToken),
                    includeHandle: false, cancellationToken: cancellationToken);
            }

            Collection(json, "attributes", members.Handles, parameter.Attributes, cancellationToken);
            AttributePayloads(json, metadata, members.Handles, parameter.Attributes, cancellationToken);
            json.WriteEndObject();
        }

        json.WriteEndObject();

        json.WriteStartObject("generic_parameters");

        foreach (var parameter in members.GenericParameters.Values) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject(parameter.Offset.ToString());
            json.WriteNumber("number", parameter.Number);
            json.WriteNumber("flags", parameter.Flags);
            json.WriteString("kind", parameter.Kind == 0 ? "type" : "method");
            JsonOutput.WriteString(json, "name", parameter.Name);

            json.WriteStartArray("constraints");

            foreach (uint handle in CollectionsMarshal.AsSpan(members.Handles)
                .Slice(parameter.Constraints.Start, parameter.Constraints.Count)) {
                cancellationToken.ThrowIfCancellationRequested();
                JsonOutput.WriteStringValue(json, metadata.SignatureBuilder.RenderType(metadata.TypeSignature(handle)));
            }

            json.WriteEndArray();

            Collection(json, "attributes", members.Handles, parameter.Attributes, cancellationToken);
            AttributePayloads(json, metadata, members.Handles, parameter.Attributes, cancellationToken);
            json.WriteEndObject();
        }

        json.WriteEndObject();
    }

    private static void Attribute(Utf8JsonWriter json, MetadataAttributePayload payload,
        bool includeIdentity = true, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        json.WriteStartObject();
        if (includeIdentity) {
            json.WriteNumber("offset", payload.Offset);
            json.WriteNumber("constructor", payload.Constructor);
            JsonOutput.WriteString(json, "type", payload.Type);
        }

        json.WriteStartArray("fixed_arguments");

        foreach (var value in payload.FixedArguments)
            Value(json, value, cancellationToken: cancellationToken);

        json.WriteEndArray();

        json.WriteStartArray("named_arguments");

        foreach (var argument in payload.NamedArguments) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject();
            json.WriteNumber("flags", argument.Flags);
            JsonOutput.WriteString(json, "name", argument.Name);
            JsonOutput.WriteString(json, "type", argument.Type);
            json.WritePropertyName("value");
            Value(json, argument.Value, cancellationToken: cancellationToken);
            json.WriteEndObject();
        }

        json.WriteEndArray();
        json.WriteEndObject();
    }

    private static void Value(Utf8JsonWriter json, MetadataValue value,
        bool includeHandle = true, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        json.WriteStartObject();
        if (includeHandle)
            json.WriteNumber("handle", value.Handle);

        json.WriteString("kind", value.Kind);
        if (value.Type is not null)
            JsonOutput.WriteString(json, "type", value.Type);

        json.WritePropertyName("value");
        RawValue(json, value.Value, cancellationToken);
        json.WriteEndObject();
    }

    private static void RawValue(Utf8JsonWriter json, object? value, CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();
        switch (value) {
            case null:
                json.WriteNullValue();
                break;
            case string text:
                JsonOutput.WriteStringValue(json, text);
                break;
            case bool boolean:
                json.WriteBooleanValue(boolean);
                break;
            case byte number:
                json.WriteNumberValue(number);
                break;
            case sbyte number:
                json.WriteNumberValue(number);
                break;
            case short number:
                json.WriteNumberValue(number);
                break;
            case ushort number:
                json.WriteNumberValue(number);
                break;
            case int number:
                json.WriteNumberValue(number);
                break;
            case uint number:
                json.WriteNumberValue(number);
                break;
            case long number:
                json.WriteNumberValue(number);
                break;
            case ulong number:
                json.WriteNumberValue(number);
                break;
            case float number:
                if (float.IsFinite(number))
                    json.WriteNumberValue(number);
                else
                    json.WriteStringValue(number.ToString(System.Globalization.CultureInfo.InvariantCulture));
                break;
            case double number:
                if (double.IsFinite(number))
                    json.WriteNumberValue(number);
                else
                    json.WriteStringValue(number.ToString(System.Globalization.CultureInfo.InvariantCulture));
                break;
            case MetadataValue nested:
                Value(json, nested, cancellationToken: cancellationToken);
                break;
            case System.Collections.ObjectModel.ReadOnlyCollection<MetadataValue> array:
                json.WriteStartArray();

                foreach (var item in array)
                    Value(json, item, cancellationToken: cancellationToken);

                json.WriteEndArray();
                break;
            case System.Collections.ObjectModel.ReadOnlyCollection<object> array:
                json.WriteStartArray();

                foreach (var item in array)
                    RawValue(json, item, cancellationToken);

                json.WriteEndArray();
                break;
            default:
                throw new InvalidOperationException("Unexpected metadata value representation.");
        }
    }

    private static void AttributePayloads(Utf8JsonWriter json, Metadata metadata, List<uint> handles, IndexRange range,
        CancellationToken cancellationToken) {
        json.WriteStartArray("attribute_payloads");

        foreach (uint offset in CollectionsMarshal.AsSpan(handles).Slice(range.Start, range.Count)) {
            cancellationToken.ThrowIfCancellationRequested();
            Attribute(json, metadata.AttributePayload(offset, cancellationToken), cancellationToken: cancellationToken);
        }

        json.WriteEndArray();
    }
}
