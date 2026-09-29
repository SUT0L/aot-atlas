using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class MapsOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, ReflectionMaps maps, PeImage image, Metadata metadata, double seconds) {
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteString("map_format", maps.Format == MapFormat.Legacy ? "legacy" : "metadata");
        json.WriteNumber("maps_seconds", seconds);
        json.WriteStartArray("types");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Types)) {
            json.WriteStartArray();
            json.WriteNumberValue(entry.Vertex);
            json.WriteNumberValue(entry.MethodTable);
            json.WriteNumberValue(entry.Handle);
            json.WriteStringValue(entry.Name);
            json.WriteEndArray();
        }
        json.WriteEndArray();

        json.WriteStartArray("derived_types");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.DerivedTypes)) {
            json.WriteStartArray();
            json.WriteNumberValue(entry.Section);
            json.WriteNumberValue(entry.Vertex);
            json.WriteNumberValue(entry.MethodTable);
            json.WriteEndArray();
        }
        json.WriteEndArray();

        json.WriteStartArray("methods");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Methods)) {
            json.WriteStartObject();
            json.WriteNumber("entrypoint", entry.Entrypoint);
            json.WriteString("method_name", entry.Name);
            json.WriteNumber("declaring_type", entry.DeclaringType);
            json.WriteNumber("flags", entry.Flags);
            json.WriteBoolean("is_generic", (entry.Flags & 2) != 0);
            json.WriteBoolean("is_default_ctor", (entry.Flags & 8) != 0);
            json.WriteNumber("metadata_handle", entry.MetadataOffset);
            json.WriteNumber("native_signature_offset", entry.NativeSignatureOffset);
            json.WriteStartArray("generic_argument_types");
            for (int i = entry.GenericArguments.Start; i < entry.GenericArguments.End; ++i)
                json.WriteNumberValue(maps.GenericArguments[i]);
            json.WriteEndArray();
            json.WriteNumber("invoke_stub_va", entry.InvokeStub);
            json.WriteNumber("map_entry_offset", entry.Vertex);
            if (entry.Signature != 0)
                json.WriteString("signature", metadata.Signatures.RenderMethod(entry.Name, entry.Signature));
            json.WriteEndObject();
        }
        json.WriteEndArray();

        json.WriteStartArray("fields");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Fields)) {
            json.WriteStartObject();
            json.WriteNumber("map_entry_offset", entry.Vertex);
            json.WriteNumber("declaring_type", entry.DeclaringType);
            json.WriteNumber("metadata_handle", entry.MetadataOffset);
            json.WriteNumber("storage", entry.Storage);
            json.WriteNumber("flags", entry.Flags);
            json.WriteBoolean("is_init_only", (entry.Flags & 0x80) != 0);
            json.WriteString("field_name", entry.Name);
            json.WriteString("location", entry.Location.ToString());
            json.WriteNumber("value", entry.Value);
            json.WriteNumber("static_base", entry.StaticBase);
            if (entry.Location is FieldLocation.StaticAddress or FieldLocation.StaticBlock)
                json.WriteNumber("statics_base_index", entry.StaticBaseIndex);
            if (entry.Signature != 0)
                json.WriteString("signature", metadata.Signatures.RenderType(entry.Signature));
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }
}
