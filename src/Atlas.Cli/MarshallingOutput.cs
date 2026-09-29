using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class MarshallingOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction) {
        var marshalling = extraction.Marshalling;
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("struct_table", extraction.Header.Find(316).Start);
        json.WriteNumber("delegate_table", extraction.Header.Find(317).Start);
        json.WriteStartArray("structs");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(marshalling.Structs)) {
            string name = extraction.Names.Values[entry.TypeIndex];
            json.WriteStartObject();
            json.WriteNumber("vertex", entry.Vertex);
            json.WriteNumber("length", entry.Length);
            json.WriteNumber("type", extraction.Types.Types[entry.TypeIndex].Address);
            json.WriteString("type_name", name);
            json.WriteString("name", $"native::{name}");
            json.WriteNumber("header", entry.Header);
            json.WriteBoolean("invalid_layout", entry.InvalidLayout);
            json.WriteNumber("size", entry.Size);
            json.WriteString("size_source", entry.SizeSource.ToString());
            json.WriteNumber("to_native", entry.ToNative);
            json.WriteNumber("to_managed", entry.ToManaged);
            json.WriteNumber("cleanup", entry.Cleanup);
            json.WriteStartArray("fields");
            for (int i = entry.Fields.Start; i < entry.Fields.End; ++i) {
                ref readonly var field = ref CollectionsMarshal.AsSpan(marshalling.Fields)[i];
                json.WriteStartObject();
                json.WriteString("name", marshalling.StructData.Span.Slice(field.Name.Start, field.Name.Count));
                json.WriteNumber("offset", field.Offset);
                json.WriteEndObject();
            }
            json.WriteEndArray();
            json.WriteEndObject();
        }
        json.WriteEndArray();

        json.WriteStartArray("delegates");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(marshalling.Delegates)) {
            string name = extraction.Names.Values[entry.TypeIndex];
            json.WriteStartObject();
            json.WriteNumber("vertex", entry.Vertex);
            json.WriteNumber("length", entry.Length);
            json.WriteNumber("type", extraction.Types.Types[entry.TypeIndex].Address);
            json.WriteString("type_name", name);
            json.WriteString("name", $"delegate_marshalling::{name}");
            json.WriteNumber("open", entry.Open);
            json.WriteNumber("closed", entry.Closed);
            json.WriteNumber("create", entry.Create);
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }
}
