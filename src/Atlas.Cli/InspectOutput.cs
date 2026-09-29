using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Atlas;

internal static class InspectOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, PeImage image, ReadyToRun rtr,
        HydratedRegion hydration, ReadOnlySpan<RuntimeFunction> functions, ulong[] commonFixups,
        ulong[] nativeReferences, ulong[] nativeStatics, ReadOnlySpan<double> seconds) {
        Begin(json, inputSha256, image, rtr, hydration, new PeDebug(image));
        json.WriteStartArray("runtime_functions");
        foreach (ref readonly var function in functions) {
            json.WriteStartArray();
            json.WriteNumberValue(function.Begin);
            json.WriteNumberValue(function.End);
            json.WriteNumberValue(function.Unwind);
            json.WriteEndArray();
        }
        json.WriteEndArray();
        End(json, image, rtr, commonFixups, nativeReferences, nativeStatics, seconds);
    }

    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction) {
        Begin(json, inputSha256, extraction.Image, extraction.Header, extraction.Hydrated, extraction.Debug);
        json.WriteStartArray("runtime_functions");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(extraction.Unwind.Entries)[..extraction.Unwind.DirectoryCount]) {
            json.WriteStartArray();
            json.WriteNumberValue(entry.Function.Begin);
            json.WriteNumberValue(entry.Function.End);
            json.WriteNumberValue(entry.Function.Unwind);
            json.WriteEndArray();
        }
        json.WriteEndArray();
        End(json, extraction.Image, extraction.Header, extraction.CommonFixups, extraction.NativeReferences,
            extraction.NativeStatics, []);
    }

    private static void Begin(Utf8JsonWriter json, string inputSha256, PeImage image, ReadyToRun rtr, HydratedRegion hydration,
        PeDebug debug) {
        json.WriteStartObject();
        json.WriteString("operation", "inspect");
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("input_bytes", image.FileData.Length);
        json.WriteNumber("image_base", image.ImageBase);

        json.WriteStartArray("codeview");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(debug.CodeViews)) {
            json.WriteStartObject();
            json.WriteNumber("directory_file_offset", entry.RecordFileOffset);
            json.WriteNumber("data_rva", entry.Rva);
            json.WriteNumber("data_file_offset", entry.Data.Start);
            var data = image.FileData.AsSpan(entry.Data.Start, entry.Data.Count);
            json.WriteBase64String("data_base64", data);
            json.WriteString("format", entry.Rsds ? "RSDS" : "unparsed");
            if (entry.Rsds) {
                json.WriteString("guid", entry.Guid);
                json.WriteNumber("age", entry.Age);
                var path = image.FileData.AsSpan(entry.Path.Start, entry.Path.Count);
                json.WriteBase64String("path_bytes_base64", path);
                json.WriteBoolean("path_utf8_valid", entry.PathUtf8Valid);
                if (entry.PathUtf8Valid)
                    json.WriteString("path", path);
            }
            json.WriteEndObject();
        }
        json.WriteEndArray();

        json.WriteStartObject("rtr");
        json.WriteNumber("file_offset", rtr.FileOffset);
        json.WriteNumber("major", rtr.Major);
        json.WriteNumber("minor", rtr.Minor);
        json.WriteNumber("flags", rtr.Flags);
        json.WriteNumber("entry_size", rtr.EntrySize);
        json.WriteNumber("entry_type", rtr.EntryType);
        json.WriteStartArray("sections");
        foreach (ref readonly var section in rtr.Sections.AsSpan()) {
            json.WriteStartArray();
            json.WriteNumberValue(section.Id);
            json.WriteNumberValue(section.Start);
            json.WriteNumberValue(section.Start + section.Length);
            json.WriteEndArray();
        }
        json.WriteEndArray();
        json.WriteEndObject();

        json.WriteStartObject("hydration");
        json.WriteNumber("start", hydration.Start);
        json.WriteNumber("length", hydration.Length);
        json.WriteString("sha256", Convert.ToHexStringLower(SHA256.HashData(hydration.Bytes)));
        json.WriteEndObject();
    }

    private static void End(Utf8JsonWriter json, PeImage image, ReadyToRun rtr, ulong[] commonFixups,
        ulong[] nativeReferences, ulong[] nativeStatics, ReadOnlySpan<double> seconds) {
        foreach (var (id, entries) in new[] { (308, commonFixups), (331, nativeReferences), (333, nativeStatics) }) {
            json.WriteStartArray($"fixups_{id}");
            foreach (ulong va in entries)
                json.WriteNumberValue(va);
            json.WriteEndArray();
        }

        json.WriteStartObject("native_hashtables");
        foreach (int id in new[] { 301, 306, 307, 309, 332, 335, 336 }) {
            var section = rtr.Find(id);
            json.WriteStartArray(id.ToString());
            if (section.Length != 0) {
                var table = new NativeTable(image.FileSpan(section.Start, checked((int)section.Length)));
                while (table.MoveNext()) {
                    json.WriteStartArray();
                    json.WriteNumberValue(table.Bucket);
                    json.WriteNumberValue(table.LowHash);
                    json.WriteNumberValue(table.Vertex);
                    json.WriteEndArray();
                }
            }
            json.WriteEndArray();
        }
        json.WriteEndObject();

        if (!seconds.IsEmpty) {
            string[] names = ["load", "rtr", "hydration", "tables", "total_before_serialization"];
            json.WriteStartObject("seconds");
            for (int i = 0; i < names.Length; ++i)
                json.WriteNumber(names[i], seconds[i]);
            json.WriteEndObject();
        }
        json.WriteEndObject();
    }
}
