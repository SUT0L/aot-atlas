using System.Text.Json;
using Atlas;

internal static class MetadataIdentityOutput {
    internal static void WriteContext(
        Utf8JsonWriter json,
        int signature,
        bool method,
        scoped SignatureContext context) {
        json.WriteStartObject("signature_context");
        json.WriteNumber(method ? "method_signature_id" : "type_signature_id", signature);
        Arguments(json, "type_arguments", context.TypeArguments);
        Arguments(json, "method_arguments", context.MethodArguments);
        json.WriteEndObject();
    }

    private static void Arguments(Utf8JsonWriter json, string name, ReadOnlySpan<SignatureArgument> arguments) {
        json.WriteStartArray(name);

        foreach (var argument in arguments) {
            json.WriteStartObject();
            json.WriteString("kind", argument.Kind.ToString());

            switch (argument.Kind) {
                case SignatureArgumentKind.RuntimeType:
                    json.WriteNumber("type_address", argument.TypeAddress);
                    break;
                case SignatureArgumentKind.TypeSignature:
                    json.WriteNumber("type_signature_id", argument.Signature);
                    json.WriteString("substitutions", "none");
                    break;
                case SignatureArgumentKind.ParameterName:
                    JsonOutput.WriteString(json, "name", argument.Display);
                    break;
                case SignatureArgumentKind.Unresolved:
                    if (!string.IsNullOrEmpty(argument.Display))
                        JsonOutput.WriteString(json, "display", argument.Display);
                    break;
            }
            json.WriteEndObject();
        }

        json.WriteEndArray();
    }

    internal static void EndObject(Utf8JsonWriter json, Metadata metadata, Signatures signatures,
        CancellationToken cancellationToken = default, bool includeSignatureGraph = false) {
        cancellationToken.ThrowIfCancellationRequested();
        if (json.CurrentDepth == 1 && (includeSignatureGraph || signatures.HasAbbreviatedReferences))
            Write(json, metadata, signatures, cancellationToken);

        json.WriteEndObject();
    }

    internal static void EndObject(Utf8JsonWriter json, Metadata metadata,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        // Nested extract outputs share the graph written once at the outer boundary.
        if (json.CurrentDepth == 1 && metadata.PublishedSignatures.HasAbbreviatedReferences)
            Write(json, metadata, cancellationToken);

        json.WriteEndObject();
    }

    internal static void Write(Utf8JsonWriter json, Metadata metadata,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        Write(json, metadata, metadata.PublishedSignatures, cancellationToken);
    }

    internal static void Write(Utf8JsonWriter json, Metadata metadata, Signatures signatures,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        if (!ReferenceEquals(metadata.PublishedSignatures, signatures))
            throw new ArgumentException("The published signature graph belongs to different metadata.", nameof(signatures));

        json.WriteStartObject("signature_graph");
        json.WriteStartArray("scope_definitions");

        foreach (var scope in metadata.ScopeDefinitions) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject();
            json.WriteNumber("handle", checked(scope.Offset << metadata.HandleBits) | 0x38);
            JsonOutput.WriteString(json, "name", scope.Name);
            Version(json, scope.Major, scope.Minor, scope.Build, scope.Revision);
            json.WriteNumber("flags", scope.Flags);
            JsonOutput.WriteHexString(json, "public_key", scope.PublicKey.Span);
            JsonOutput.WriteString(json, "culture", scope.Culture);
            json.WriteEndObject();
        }

        json.WriteEndArray();

        json.WriteStartArray("scope_references");

        foreach (var scope in metadata.ReferencedScopes) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject();
            json.WriteNumber("handle", checked(scope.Offset << metadata.HandleBits) | 0x39);
            JsonOutput.WriteString(json, "name", scope.Name);
            Version(json, scope.Major, scope.Minor, scope.Build, scope.Revision);
            json.WriteNumber("flags", scope.Flags);
            JsonOutput.WriteHexString(json, "public_key_or_token", scope.PublicKeyOrToken.Span);
            JsonOutput.WriteString(json, "culture", scope.Culture);
            json.WriteEndObject();
        }

        json.WriteEndArray();

        json.WriteStartObject("handles");

        foreach (var signature in metadata.TypeSignatureHandles) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteNumber(signature.Key.ToString(), signature.Value);
        }

        json.WriteEndObject();

        json.WriteStartArray("types");

        for (int i = 1; i < signatures.Nodes.Length; ++i) {
            cancellationToken.ThrowIfCancellationRequested();
            var node = signatures.Nodes[i];

            json.WriteStartObject();
            json.WriteNumber("id", i);
            json.WriteString("kind", node.Kind.ToString());
            if (node.MetadataScope != 0)
                json.WriteNumber("scope", node.MetadataScope);
            if (node.Name is not null)
                JsonOutput.WriteString(json, "name", node.Name);
            if (node.TypeAddress != 0)
                json.WriteNumber("type_address", node.TypeAddress);

            json.WriteNumber("element", node.Element);
            json.WriteNumber("value", node.Value);
            json.WriteBoolean("optional", node.Optional);
            json.WriteBoolean("native_convention", node.NativeConvention);
            Edges(json, "arguments", signatures, node.Arguments, cancellationToken);
            Edges(json, "varargs", signatures, node.Varargs, cancellationToken);
            Edges(json, "sizes", signatures, node.Sizes, cancellationToken);
            Edges(json, "lower_bounds", signatures, node.LowerBounds, cancellationToken);
            json.WriteEndObject();
        }

        json.WriteEndArray();

        json.WriteStartArray("methods");

        for (int i = 1; i < signatures.Methods.Length; ++i) {
            cancellationToken.ThrowIfCancellationRequested();
            var method = signatures.Methods[i];

            json.WriteStartObject();
            json.WriteNumber("id", i);
            json.WriteNumber("offset", method.Offset);
            json.WriteNumber("calling_convention", method.CallingConvention);
            json.WriteNumber("generic_parameter_count", method.GenericParameterCount);
            json.WriteNumber("return_type", method.ReturnType);
            json.WriteBoolean("native_convention", method.NativeConvention);
            Edges(json, "parameters", signatures, method.Parameters, cancellationToken);
            Edges(json, "varargs", signatures, method.Varargs, cancellationToken);
            json.WriteEndObject();
        }

        cancellationToken.ThrowIfCancellationRequested();
        json.WriteEndArray();
        json.WriteEndObject();
    }

    private static void Version(Utf8JsonWriter json, ushort major, ushort minor, ushort build, ushort revision) {
        json.WriteStartArray("version");
        json.WriteNumberValue(major);
        json.WriteNumberValue(minor);
        json.WriteNumberValue(build);
        json.WriteNumberValue(revision);
        json.WriteEndArray();
    }

    private static void Edges(Utf8JsonWriter json, string name, Signatures signatures, IndexRange range,
        CancellationToken cancellationToken) {
        json.WriteStartArray(name);

        for (int i = range.Start; i < range.End; ++i) {
            cancellationToken.ThrowIfCancellationRequested();
            json.WriteNumberValue(signatures.Edges[i]);
        }

        json.WriteEndArray();
    }
}
