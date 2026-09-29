using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Atlas;

internal static class StringsOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, PeImage image, NativeStrings strings, double seconds, long allocated) {
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("scan_seconds", seconds);
        json.WriteNumber("allocated_bytes", allocated);
        json.WriteNumber("scanned_bytes", strings.ScannedBytes);
        json.WriteStartArray("strings");
        foreach (ref readonly var item in CollectionsMarshal.AsSpan(strings.Items)) {
            json.WriteStartObject();
            json.WriteNumber("address", image.ImageBase + item.Rva);
            json.WriteNumber("byte_length", item.Data.Count);
            json.WriteString("encoding", item.Wide ? "utf-16le" : "ascii");
            json.WriteString("evidence", "nul_terminated_printable_bytes");
            var bytes = image.FileData.AsSpan(item.Data.Start, item.Data.Count);
            json.WriteString("text", item.Wide ? Encoding.Unicode.GetString(bytes) : Encoding.ASCII.GetString(bytes));
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }
}
