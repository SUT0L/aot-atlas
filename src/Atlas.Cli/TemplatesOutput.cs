using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class TemplatesOutput {
    internal static void Write(Utf8JsonWriter json, Extraction extraction, MethodText renderer) {
        var templates = extraction.Templates;
        var signatures = extraction.Metadata.Signatures;
        var tables = extraction.Types;
        var names = extraction.Names;
        json.WriteStartArray("type_templates");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(templates.Types)) {
            json.WriteStartObject();
            json.WriteNumber("vertex", entry.Vertex);
            json.WriteNumber("method_table", entry.MethodTable);
            json.WriteNumber("layout_offset", entry.LayoutOffset);
            json.WriteString("name", names.Values[tables.Index[entry.MethodTable]]);
            json.WriteEndObject();
        }
        json.WriteEndArray();

        json.WriteStartArray("method_templates");
        for (int index = 0; index < templates.Methods.Count; ++index) {
            ref readonly var template = ref CollectionsMarshal.AsSpan(templates.Methods)[index];
            ref readonly var entry = ref template.Method;
            ref readonly var owner = ref CollectionsMarshal.AsSpan(signatures.Nodes)[entry.DeclaringType];
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
            json.WriteString("declaring_type", renderer.Owner);
            json.WriteString("method_name", entry.Identity.Name);
            json.WriteString("name", text[..renderer.NameLength]);
            json.WriteString("declared_signature", text);
            json.WriteBoolean("has_unboxing_flag", (entry.Flags & 2) != 0);
            json.WriteBoolean("is_universal_canonical", template.UniversalCanonical);
            json.WriteBoolean("is_async_variant", template.AsyncVariant);
            json.WriteStartArray("arguments");
            foreach (string argument in renderer.Arguments)
                json.WriteStringValue(argument);
            json.WriteEndArray();
            json.WriteEndObject();
        }

        json.WriteEndArray();
    }
}
