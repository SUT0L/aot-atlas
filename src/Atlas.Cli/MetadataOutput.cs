using System.Collections.ObjectModel;
using System.Text.Json;
using Atlas;

internal static class MetadataOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Metadata metadata, double seconds,
        bool includeSignatureGraph = true, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        JsonOutput.StartDocument(json, "metadata");
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("metadata_bytes", metadata.Data.Length);
        json.WriteNumber("metadata_seconds", seconds);

        json.WriteStartArray("scopes");

        foreach (ref readonly var scope in metadata.ScopeDefinitions) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartArray();
            json.WriteNumberValue(scope.Offset);
            var name = metadata.Facts.Scope(new(MetadataRecordKind.ScopeDefinition, scope.Offset)).Name;
            NameText(json, metadata.Facts, name, scope.Name);
            json.WriteEndArray();
        }

        json.WriteEndArray();

        json.WriteStartObject("scope_attributes");

        foreach (ref readonly var scope in metadata.ScopeDefinitions) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject(scope.Offset.ToString());
            ScopeAttributes(json, "assembly", metadata, scope.Offset, module: false, cancellationToken);
            ScopeAttributes(json, "module", metadata, scope.Offset, module: true, cancellationToken);
            json.WriteEndObject();
        }

        json.WriteEndObject();

        json.WriteStartObject("types");

        foreach (ref readonly var type in metadata.TypeDefinitions) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject(type.Offset.ToString());
            json.WritePropertyName("name");
            var name = metadata.Facts.Type(new(type.Offset)).Name;
            NameText(json, metadata.Facts, name, type.Name);
            json.WriteNumber("scope", type.Scope);
            json.WriteNumber("flags", type.Flags);
            json.WriteNumber("base_type", type.BaseType);
            TypeSignatureId(json, "base_type_signature_id", metadata, type.BaseType);
            json.WriteNumber("enclosing_type", type.EnclosingType);
            json.WriteNumber("size", type.Size);
            json.WriteNumber("packing", type.Packing);

            json.WriteStartArray("interfaces");

            for (int i = type.Interfaces.Start; i < type.Interfaces.End; ++i) {
                cancellationToken.ThrowIfCancellationRequested();
                uint handle = metadata.DefinitionHandles[i];

                json.WriteStartObject();
                json.WriteNumber("handle", handle);
                TypeSignatureId(json, "signature_id", metadata, handle);
                json.WriteEndObject();
            }

            json.WriteEndArray();

            json.WriteStartArray("methods");

            for (int i = type.Methods.Start; i < type.Methods.End; ++i) {
                cancellationToken.ThrowIfCancellationRequested();
                json.WriteNumberValue(metadata.DefinitionHandles[i]);
            }

            json.WriteEndArray();

            json.WriteStartArray("fields");

            for (int i = type.Fields.Start; i < type.Fields.End; ++i) {
                cancellationToken.ThrowIfCancellationRequested();
                json.WriteNumberValue(metadata.DefinitionHandles[i]);
            }

            json.WriteEndArray();

            Collection(json, "properties", metadata.DefinitionHandles, type.Properties, cancellationToken);
            Collection(json, "events", metadata.DefinitionHandles, type.Events, cancellationToken);
            Collection(json, "generic_parameters", metadata.DefinitionHandles, type.GenericParameters, cancellationToken);
            json.WriteEndObject();
        }

        json.WriteEndObject();

        json.WriteStartObject("methods");

        foreach (ref readonly var method in metadata.MethodDefinitions) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject(method.Offset.ToString());
            var methodFacts = metadata.Facts.Method(new(method.Offset));
            json.WritePropertyName("name");
            NameText(json, metadata.Facts, methodFacts.Name, method.Name);
            json.WriteNumber("flags", method.Flags);
            json.WriteNumber("implementation_flags", method.ImplementationFlags);
            json.WriteNumber("signature_offset", method.SignatureOffset);
            json.WriteNumber("signature_id", method.Signature);
            json.WriteNumber("unique_owner", method.Shared ? 0 : method.UniqueOwner);
            if (methodFacts.Signature.IsAvailable
                && metadata.TryReadMethodSignature(method.SignatureOffset, out var signature)
                && !signature.IsEmpty)
                JsonOutput.WriteString(json, "signature", signature.Render(method.Name));
            else
                json.WriteNull("signature");

            Collection(json, "parameters", metadata.DefinitionHandles, method.Parameters, cancellationToken);
            Collection(json, "generic_parameters", metadata.DefinitionHandles, method.GenericParameters, cancellationToken);
            json.WriteEndObject();
        }

        json.WriteEndObject();

        json.WriteStartObject("fields");

        foreach (ref readonly var field in metadata.FieldDefinitions) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject(field.Offset.ToString());
            json.WritePropertyName("name");
            var fieldFacts = metadata.Facts.FieldDefinition(new(MetadataRecordKind.Field, field.Offset));
            NameText(json, metadata.Facts, fieldFacts.Name, field.Name);
            StatusNumber(json, "flags", fieldFacts.Flags.Value, field.FlagsStatus);
            json.WriteNumber("signature_offset", field.SignatureOffset);
            json.WriteNumber("type_signature_id", field.Signature);
            DefaultValue(json, metadata, field.DefaultValue, field.DefaultValueStatus, cancellationToken);
            StatusNumber(json, "explicit_offset", fieldFacts.ExplicitOffset.Value, field.ExplicitOffsetStatus);
            if (field.Signature != 0)
                JsonOutput.WriteString(json, "signature", metadata.PublishedSignatures.RenderType(field.Signature));
            else
                json.WriteNull("signature");
            AttributePayloads(json, metadata, metadata.DefinitionHandles, field.Attributes, cancellationToken);
            json.WriteEndObject();
        }

        json.WriteEndObject();

        json.WriteStartArray("forwarders");

        foreach (ref readonly var forwarder in metadata.TypeForwarders) {
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

        foreach (ref readonly var attribute in metadata.AttributeDefinitions) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartArray();
            json.WriteNumberValue(attribute.OwnerType);
            json.WriteNumberValue(attribute.OwnerMethod);
            json.WriteNumberValue(attribute.Offset);
            json.WriteNumberValue(attribute.Constructor);
            JsonOutput.WriteStringValue(json, metadata.PublishedSignatures.RenderType(attribute.Type));
            if (metadata.TryAttributePayload(attribute.Offset, out var payload))
                Attribute(json, payload, includeIdentity: false, cancellationToken: cancellationToken);
            else
                json.WriteNullValue();
            json.WriteEndArray();
        }

        json.WriteEndArray();

        Members(json, metadata, metadata.Members, cancellationToken);

        if (metadata.ProjectionDiagnostics.Count != 0) {
            json.WriteStartArray("diagnostics");

            foreach (var diagnostic in metadata.ProjectionDiagnostics) {
                cancellationToken.ThrowIfCancellationRequested();
                json.WriteStartObject();
                json.WriteNumber("handle", diagnostic.Handle);
                json.WriteString("projection", diagnostic.Projection);
                JsonOutput.WriteString(json, "error", diagnostic.Error);
                json.WriteEndObject();
            }

            json.WriteEndArray();
        }

        if (!metadata.IsComplete)
            PartialRecords(json, metadata, cancellationToken);

        json.WriteNumber("signature_nodes", metadata.PublishedSignatures.Nodes.Length - 1);
        json.WriteNumber("signature_edges", metadata.PublishedSignatures.Edges.Length);

        if (includeSignatureGraph)
            MetadataIdentityOutput.Write(json, metadata, cancellationToken);

        cancellationToken.ThrowIfCancellationRequested();
        json.WriteEndObject();
    }

    private static void PartialRecords(Utf8JsonWriter json, Metadata metadata,
        CancellationToken cancellationToken) {
        var facts = metadata.Facts;
        var affected = new HashSet<MetadataRecordId>();
        foreach (var diagnostic in metadata.ProjectionDiagnostics)
            affected.Add(facts.Encoding.DecodeHandle(diagnostic.Handle));

        json.WriteStartArray("partial_records");
        foreach (var id in facts.Records) {
            cancellationToken.ThrowIfCancellationRequested();
            var record = facts.Record(id);
            bool include = record.Status != MetadataFactStatus.Valid || affected.Contains(id);

            if (id.Kind == MetadataRecordKind.Method) {
                var method = facts.Method(new(id.Offset));
                include |= !metadata.MethodIndex.ContainsKey(id.Offset)
                    || !method.Name.IsAvailable
                    || !facts.Name(method.Name.Value).Text.IsAvailable
                    || ReferenceAffected(facts, method.Signature, affected)
                    || !facts.GenericArity(method.Id).IsAvailable;
            } else if (id.Kind == MetadataRecordKind.TypeDefinition) {
                var type = facts.Type(new(id.Offset));
                include |= !metadata.TypeIndex.ContainsKey(id.Offset)
                    || !type.Name.IsAvailable
                    || !facts.Name(type.Name.Value).Text.IsAvailable
                    || ReferenceAffected(facts, type.BaseType, affected)
                    || ReferenceAffected(facts, type.Owner, affected);
            }

            if (!include)
                continue;

            json.WriteStartObject();
            json.WriteNumber("handle", facts.RawHandle(id));
            json.WriteString("kind", id.Kind.ToString());
            FactState(json, record.Status, record.Source);
            var source = record.Source;
            if (source.IsAvailable)
                JsonOutput.WriteHexString(json, "bytes", facts.Bytes.Slice(source.Offset, source.Length));
            else
                json.WriteNull("bytes");

            if (id.Kind == MetadataRecordKind.Method) {
                var method = facts.Method(new(id.Offset));
                NameFact(json, facts, method.Name);
                UnsignedFact(json, "flags", method.Flags);
                UnsignedFact(json, "implementation_flags", method.ImplementationFlags);
                ReferenceFact(json, "signature", facts, method.Signature);
                var arity = facts.GenericArity(method.Id);
                json.WriteStartObject("generic_arity");
                json.WriteNumber("value", arity.Value);
                FactState(json, arity.Status, arity.Source);
                json.WriteEndObject();
            } else if (id.Kind == MetadataRecordKind.TypeDefinition) {
                var type = facts.Type(new(id.Offset));
                NameFact(json, facts, type.Name);
                UnsignedFact(json, "flags", type.Flags);
                UnsignedFact(json, "size", type.Size);
                UnsignedFact(json, "packing", type.PackingSize);
                ReferenceFact(json, "base_type", facts, type.BaseType);
                ReferenceFact(json, "owner", facts, type.Owner);
            }

            RawFields(json, facts, id, cancellationToken);
            json.WriteEndObject();
        }
        json.WriteEndArray();
    }

    private static void RawFields(Utf8JsonWriter json, MetadataFacts facts, MetadataRecordId id,
        CancellationToken cancellationToken) {
        json.WriteStartObject("fields");
        foreach (var field in facts.Fields(id)) {
            cancellationToken.ThrowIfCancellationRequested();
            json.WriteStartObject(field.Name.ToString());
            RawField(json, facts, field);
            if (field.Items.Count != 0) {
                json.WriteStartArray("items");
                foreach (var item in field.Items) {
                    cancellationToken.ThrowIfCancellationRequested();
                    json.WriteStartObject();
                    RawField(json, facts, item);
                    json.WriteEndObject();
                }
                json.WriteEndArray();
            }
            json.WriteEndObject();
        }
        json.WriteEndObject();
    }

    private static void RawField(Utf8JsonWriter json, MetadataFacts facts, MetadataFieldValue field) {
        json.WriteNumber("bits", field.Bits);
        FactState(json, field.Status, field.Source);
        var reference = field.Reference;
        if (reference.Value.Value != 0)
            json.WriteNumber("reference_handle", facts.RawHandle(reference.Value));
        if (field.PayloadSource.IsAvailable && field.PayloadSource.Length != 0)
            JsonOutput.WriteHexString(json, "payload", field.Payload);
    }

    private static bool ReferenceAffected(MetadataFacts facts, MetadataFact<MetadataRecordId> reference,
        HashSet<MetadataRecordId> affected) => !reference.IsAvailable
            || (!reference.Value.IsNil && (affected.Contains(reference.Value)
                || facts.Record(reference.Value).Status != MetadataFactStatus.Valid));

    private static void NameText(Utf8JsonWriter json, MetadataFacts facts,
        MetadataFact<MetadataNameId> reference, string display) {
        if (reference.IsAvailable && facts.Name(reference.Value).Text.IsAvailable)
            JsonOutput.WriteStringValue(json, display);
        else
            json.WriteNullValue();
    }

    private static void NameFact(Utf8JsonWriter json, MetadataFacts facts, MetadataFact<MetadataNameId> reference) {
        var name = facts.Name(reference.Value);
        json.WriteStartObject("name");
        json.WriteNumber("offset", reference.Value.Offset);
        json.WriteString("reference_status", reference.Status.ToString());
        if (reference.IsAvailable && name.Text.IsAvailable)
            JsonOutput.WriteString(json, "value", name.Text.Value);
        else
            json.WriteNull("value");
        FactState(json, name.Text.Status, name.Source);
        JsonOutput.WriteHexString(json, "bytes", name.Bytes);
        json.WriteEndObject();
    }

    private static void UnsignedFact(Utf8JsonWriter json, string name, MetadataFact<uint> fact) {
        json.WriteStartObject(name);
        json.WriteNumber("value", fact.Value);
        FactState(json, fact.Status, fact.Source);
        json.WriteEndObject();
    }

    private static void ReferenceFact(Utf8JsonWriter json, string name, MetadataFacts facts,
        MetadataFact<MetadataRecordId> fact) {
        json.WriteStartObject(name);
        json.WriteNumber("handle", facts.RawHandle(fact.Value));
        FactState(json, fact.Status, fact.Source);
        json.WriteEndObject();
    }

    private static void FactState(Utf8JsonWriter json, MetadataFactStatus status, MetadataSourceRange source) {
        json.WriteString("status", status.ToString());
        json.WriteNumber("source_offset", source.Offset);
        json.WriteNumber("source_length", source.Length);
    }

    private static void Collection(Utf8JsonWriter json, string name, ReadOnlySpan<uint> handles, IndexRange range,
        CancellationToken cancellationToken) {
        json.WriteStartArray(name);

        foreach (uint handle in handles.Slice(range.Start, range.Count)) {
            cancellationToken.ThrowIfCancellationRequested();
            json.WriteNumberValue(handle);
        }

        json.WriteEndArray();
    }

    private static void Accessors(Utf8JsonWriter json, MetadataMembers members, IndexRange range,
        CancellationToken cancellationToken) {
        json.WriteStartArray("accessors");

        foreach (ref readonly var accessor in members.AccessorEntries
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
            if (property.Type != 0)
                JsonOutput.WriteString(json, "type", metadata.PublishedSignatures.RenderType(property.Type));
            else
                json.WriteNull("type");
            DefaultValue(json, metadata, property.DefaultValue, property.DefaultValueStatus, cancellationToken);

            json.WriteStartArray("parameters");

            foreach (uint handle in members.MemberHandles
                .Slice(property.Parameters.Start, property.Parameters.Count)) {
                cancellationToken.ThrowIfCancellationRequested();
                TypeSignatureText(json, metadata, handle);
            }

            json.WriteEndArray();

            Accessors(json, members, property.Accessors, cancellationToken);
            Collection(json, "attributes", members.MemberHandles, property.Attributes, cancellationToken);
            AttributePayloads(json, metadata, members.MemberHandles, property.Attributes, cancellationToken);
            json.WriteEndObject();
        }

        json.WriteEndObject();

        json.WriteStartObject("events");

        foreach (var entry in members.Events.Values) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject(entry.Offset.ToString());
            JsonOutput.WriteString(json, "name", entry.Name);
            json.WriteNumber("flags", entry.Flags);
            if (entry.Type != 0)
                JsonOutput.WriteString(json, "type", metadata.PublishedSignatures.RenderType(entry.Type));
            else
                json.WriteNull("type");
            json.WriteNumber("type_signature_id", entry.Type);

            Accessors(json, members, entry.Accessors, cancellationToken);
            Collection(json, "attributes", members.MemberHandles, entry.Attributes, cancellationToken);
            AttributePayloads(json, metadata, members.MemberHandles, entry.Attributes, cancellationToken);
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
            DefaultValue(json, metadata, parameter.DefaultValue, parameter.DefaultValueStatus, cancellationToken);

            Collection(json, "attributes", members.MemberHandles, parameter.Attributes, cancellationToken);
            AttributePayloads(json, metadata, members.MemberHandles, parameter.Attributes, cancellationToken);
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

            foreach (uint handle in members.MemberHandles
                .Slice(parameter.Constraints.Start, parameter.Constraints.Count)) {
                cancellationToken.ThrowIfCancellationRequested();
                TypeSignatureText(json, metadata, handle);
            }

            json.WriteEndArray();

            Collection(json, "attributes", members.MemberHandles, parameter.Attributes, cancellationToken);
            AttributePayloads(json, metadata, members.MemberHandles, parameter.Attributes, cancellationToken);
            json.WriteEndObject();
        }

        json.WriteEndObject();
    }

    private static void TypeSignatureId(Utf8JsonWriter json, string name, Metadata metadata, uint handle) {
        if (metadata.TryReadTypeSignature(handle, out var signature))
            json.WriteNumber(name, signature.Index);
        else
            json.WriteNull(name);
    }

    private static void TypeSignatureText(Utf8JsonWriter json, Metadata metadata, uint handle) {
        if (metadata.TryReadTypeSignature(handle, out var signature))
            JsonOutput.WriteStringValue(json, signature.Render());
        else
            json.WriteNullValue();
    }

    private const MetadataFactStatus UnknownEncoding = MetadataFactStatus.Truncated
        | MetadataFactStatus.InvalidEncoding | MetadataFactStatus.LimitExceeded
        | MetadataFactStatus.Absent | MetadataFactStatus.InvalidHeader;

    private static bool HasEncodedValue(MetadataFactStatus status) =>
        (status & UnknownEncoding) == 0 && status != MetadataFactStatus.Unresolved;

    private static void StatusNumber(Utf8JsonWriter json, string name, uint value, MetadataFactStatus status) {
        if (HasEncodedValue(status))
            json.WriteNumber(name, value);
        else
            json.WriteNull(name);
        if (status != MetadataFactStatus.Valid)
            json.WriteString(name + "_status", status.ToString());
    }

    private static void DefaultValue(Utf8JsonWriter json, Metadata metadata, uint value,
        MetadataFactStatus status, CancellationToken cancellationToken) {
        StatusNumber(json, "default_value", value, status);
        if (value == 0 && status == MetadataFactStatus.Valid)
            return;
        json.WritePropertyName("constant");
        if (HasEncodedValue(status) && value != 0)
            Constant(json, metadata, value, cancellationToken);
        else
            json.WriteNullValue();
    }

    private static void Constant(Utf8JsonWriter json, Metadata metadata, uint handle,
        CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();
        if (metadata.TryConstant(handle, out var value))
            Value(json, value, includeHandle: false, cancellationToken: cancellationToken);
        else
            json.WriteNullValue();
    }

    private static void ScopeAttributes(Utf8JsonWriter json, string name, Metadata metadata,
        uint offset, bool module, CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();
        var scope = metadata.Facts.Scope(new(MetadataRecordKind.ScopeDefinition, offset));
        var attributes = module ? scope.ModuleCustomAttributes : scope.CustomAttributes;
        json.WritePropertyName(name);
        if (attributes.Count == 0 && attributes.Status != MetadataFactStatus.Valid) {
            json.WriteNullValue();
            return;
        }

        json.WriteStartArray();
        foreach (var reference in attributes) {
            cancellationToken.ThrowIfCancellationRequested();
            if (reference.IsAvailable && metadata.TryAttributePayload(reference.Value.Offset, out var attribute))
                Attribute(json, attribute, cancellationToken: cancellationToken);
            else
                json.WriteNullValue();
        }
        json.WriteEndArray();
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
                FloatingPoint(json, number);
                break;
            case double number:
                FloatingPoint(json, number);
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
            case ReadOnlyCollection<bool> array:
                PrimitiveArray(json, array, static (writer, item) => writer.WriteBooleanValue(item), cancellationToken);
                break;
            case ReadOnlyCollection<byte> array:
                PrimitiveArray(json, array, static (writer, item) => writer.WriteNumberValue(item), cancellationToken);
                break;
            case ReadOnlyCollection<sbyte> array:
                PrimitiveArray(json, array, static (writer, item) => writer.WriteNumberValue(item), cancellationToken);
                break;
            case ReadOnlyCollection<short> array:
                PrimitiveArray(json, array, static (writer, item) => writer.WriteNumberValue(item), cancellationToken);
                break;
            case ReadOnlyCollection<ushort> array:
                PrimitiveArray(json, array, static (writer, item) => writer.WriteNumberValue(item), cancellationToken);
                break;
            case ReadOnlyCollection<int> array:
                PrimitiveArray(json, array, static (writer, item) => writer.WriteNumberValue(item), cancellationToken);
                break;
            case ReadOnlyCollection<uint> array:
                PrimitiveArray(json, array, static (writer, item) => writer.WriteNumberValue(item), cancellationToken);
                break;
            case ReadOnlyCollection<long> array:
                PrimitiveArray(json, array, static (writer, item) => writer.WriteNumberValue(item), cancellationToken);
                break;
            case ReadOnlyCollection<ulong> array:
                PrimitiveArray(json, array, static (writer, item) => writer.WriteNumberValue(item), cancellationToken);
                break;
            case ReadOnlyCollection<float> array:
                PrimitiveArray(json, array, static (writer, item) => FloatingPoint(writer, item), cancellationToken);
                break;
            case ReadOnlyCollection<double> array:
                PrimitiveArray(json, array, static (writer, item) => FloatingPoint(writer, item), cancellationToken);
                break;
            default:
                throw new InvalidOperationException("Unexpected metadata value representation.");
        }
    }

    private static void PrimitiveArray<T>(Utf8JsonWriter json, ReadOnlyCollection<T> values,
        Action<Utf8JsonWriter, T> write, CancellationToken cancellationToken) where T : struct {
        json.WriteStartArray();
        for (int i = 0; i < values.Count; ++i) {
            if ((i & 1023) == 0)
                cancellationToken.ThrowIfCancellationRequested();
            write(json, values[i]);
        }
        json.WriteEndArray();
    }

    private static void FloatingPoint(Utf8JsonWriter json, float value) {
        if (float.IsFinite(value))
            json.WriteNumberValue(value);
        else
            json.WriteStringValue(float.IsNaN(value) ? "NaN" : value > 0 ? "Infinity" : "-Infinity");
    }

    private static void FloatingPoint(Utf8JsonWriter json, double value) {
        if (double.IsFinite(value))
            json.WriteNumberValue(value);
        else
            json.WriteStringValue(double.IsNaN(value) ? "NaN" : value > 0 ? "Infinity" : "-Infinity");
    }

    private static void AttributePayloads(Utf8JsonWriter json, Metadata metadata, ReadOnlySpan<uint> handles, IndexRange range,
        CancellationToken cancellationToken) {
        json.WriteStartArray("attribute_payloads");

        foreach (uint offset in handles.Slice(range.Start, range.Count)) {
            cancellationToken.ThrowIfCancellationRequested();
            if (metadata.TryAttributePayload(offset, out var payload))
                Attribute(json, payload, cancellationToken: cancellationToken);
            else
                json.WriteNullValue();
        }

        json.WriteEndArray();
    }
}
