using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class ResourcesOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, PeImage image, ResourceMap resources, double? seconds) {
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("index_start", resources.IndexStart);
        json.WriteNumber("index_length", resources.IndexData.Length);
        json.WriteNumber("data_start", resources.DataStart);
        json.WriteNumber("data_length", resources.Data.Length);
        if (seconds.HasValue)
            json.WriteNumber("resource_seconds", seconds.Value);
        json.WriteStartArray("resources");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(resources.Entries)) {
            json.WriteStartObject();
            json.WriteString("assembly", resources.IndexData.Span.Slice(entry.Assembly.Start, entry.Assembly.Count));
            json.WriteString("name", resources.IndexData.Span.Slice(entry.Name.Start, entry.Name.Count));
            json.WriteNumber("index_address", resources.IndexStart + (uint)entry.IndexOffset);
            json.WriteNumber("address", resources.DataStart + (uint)entry.Data.Start);
            json.WriteNumber("offset", entry.Data.Start);
            json.WriteNumber("length", entry.Data.Count);
            json.WriteBase64String("data", resources.Data.Span.Slice(entry.Data.Start, entry.Data.Count));
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }
}
