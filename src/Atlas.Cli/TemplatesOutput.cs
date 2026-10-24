using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class TemplatesOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        JsonOutput.StartDocument(json, "templates");
        json.WriteString("input_sha256", inputSha256);
        ExtractionStatusOutput.Write(json, extraction);

        var renderer = new MethodText(extraction);
        bool hasTypeSignatures = Write(json, extraction, renderer, cancellationToken);
        MetadataIdentityOutput.EndObject(json, extraction.Metadata, extraction.Signatures,
            cancellationToken, includeSignatureGraph: hasTypeSignatures || renderer.HasAbbreviatedReferences);
    }

    internal static bool Write(Utf8JsonWriter json, Extraction extraction, MethodText renderer,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        var templates = extraction.Templates;
        var signatures = extraction.Signatures;
        var tables = extraction.Types;
        var names = extraction.Names;
        bool hasTypeSignatures = false;

        json.WriteStartArray("type_templates");

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(templates.Types)) {
            cancellationToken.ThrowIfCancellationRequested();
            var facts = entry.Facts;

            json.WriteStartObject();
            json.WriteNumber("vertex", entry.Vertex);
            json.WriteNumber("method_table", entry.MethodTable);
            json.WriteNumber("layout_offset", entry.LayoutOffset);
            json.WriteNumber("non_gc_static_bytes", facts.NonGcStaticBytes);
            json.WriteNumber("gc_static_bytes", facts.GcStaticBytes);
            json.WriteNumber("thread_static_bytes", facts.ThreadStaticBytes);
            json.WriteNumber("gc_static_descriptor", facts.GcDescriptor);
            json.WriteNumber("thread_static_descriptor", facts.ThreadDescriptor);
            json.WriteNumber("class_constructor", facts.ClassConstructor);
            JsonOutput.WriteString(json, "name", names.Values[tables.Index[entry.MethodTable]]);

            json.WritePropertyName("base_type");
            if (entry.BaseType.Signature == 0) {
                json.WriteNullValue();
            } else {
                WriteType(json, signatures, entry.BaseType);
                hasTypeSignatures = true;
            }

            json.WriteStartArray("interfaces");

            for (int index = entry.Interfaces.Start; index < entry.Interfaces.End; ++index) {
                cancellationToken.ThrowIfCancellationRequested();
                WriteType(json, signatures, templates.Interfaces[index]);
                hasTypeSignatures = true;
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }

        json.WriteEndArray();

        json.WriteStartArray("method_templates");

        for (int index = 0; index < templates.Methods.Count; ++index) {
            cancellationToken.ThrowIfCancellationRequested();
            ref readonly var template = ref CollectionsMarshal.AsSpan(templates.Methods)[index];
            ref readonly var entry = ref template.Method;
            ref readonly var owner = ref signatures.Nodes[entry.DeclaringType];
            var text = renderer.Render(template);

            json.WriteStartObject();
            json.WriteNumber("vertex", template.Vertex);
            json.WriteNumber("layout_offset", template.LayoutOffset);
            json.WriteNumber("method_offset", entry.Offset);
            json.WriteNumber("token", entry.Token);
            json.WriteNumber("metadata_offset", entry.Identity.MetadataOffset);
            json.WriteNumber("native_offset", entry.Identity.NativeOffset);
            json.WriteNumber("flags", entry.Flags);
            json.WriteNumber("entrypoint", entry.Entrypoint);
            json.WriteNumber("jump_target", extraction.Shared.JumpTargets[index]);

            json.WriteNumber("declaring_type_address", owner.TypeAddress);
            JsonOutput.WriteString(json, "declaring_type", renderer.Owner);
            JsonOutput.WriteString(json, "method_name", entry.Identity.Name);
            JsonOutput.WriteString(json, "name", text[..renderer.NameLength]);
            JsonOutput.WriteString(json, "declared_signature", text);

            if (!renderer.SignatureComplete)
                MetadataIdentityOutput.WriteContext(json, renderer.SignatureIndex, method: true, renderer.Context);

            json.WriteBoolean("has_unboxing_flag", (entry.Flags & 2) != 0);
            json.WriteBoolean("is_universal_canonical", template.UniversalCanonical);
            json.WriteBoolean("is_async_variant", template.AsyncVariant);
            json.WriteBoolean("is_return_dropping_async_thunk", template.ReturnDroppingAsyncThunk);

            json.WriteStartArray("arguments");

            foreach (string argument in renderer.Arguments) {
                cancellationToken.ThrowIfCancellationRequested();
                JsonOutput.WriteStringValue(json, argument);
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }

        json.WriteEndArray();

        return hasTypeSignatures;
    }

    private static void WriteType(Utf8JsonWriter json, Signatures signatures, TemplateTypeSignature type) {
        json.WriteStartObject();
        json.WriteNumber("native_offset", type.Offset);
        json.WriteNumber("signature_id", type.Signature);
        JsonOutput.WriteString(json, "signature", signatures.Types[type.Signature].Render());
        json.WriteEndObject();
    }
}
