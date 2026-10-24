using System.Text.Json;
using Atlas;

internal static class TypeMapsOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction,
        CancellationToken cancellationToken = default) {
        JsonOutput.StartDocument(json, "typemaps");
        json.WriteString("input_sha256", inputSha256);
        ExtractionStatusOutput.Write(json, extraction);
        WriteMap(json, "external", extraction.TypeMaps.External, extraction, cancellationToken);
        WriteMap(json, "proxy", extraction.TypeMaps.Proxy, extraction, cancellationToken);
        json.WriteEndObject();
    }

    private static void WriteMap(Utf8JsonWriter json, string name, InteropTypeMap map,
        Extraction extraction, CancellationToken cancellationToken) {
        json.WriteStartObject(name);
        json.WriteNumber("section", (int)map.Section);
        json.WriteString("status", map.Present ? "decoded" : "absent");
        json.WriteNumber("address", map.Address);
        json.WriteNumber("length", map.Bytes.Length);
        json.WriteNumber("hash_mask", map.HashMask);
        json.WriteNumber("group_count", map.Groups.Length);
        json.WriteNumber("mapping_count", map.Entries.Length);
        json.WriteStartArray("groups");

        foreach (var group in map.Groups) {
            cancellationToken.ThrowIfCancellationRequested();
            json.WriteStartObject();
            json.WriteNumber("vertex", group.Vertex);
            json.WriteNumber("length", group.Length);
            json.WriteNumber("hash", group.Hash);
            json.WriteNumber("group_fixup", group.GroupFixup);
            WriteType(json, "group_type", group.GroupType, extraction);
            json.WriteNumber("state", group.State);
            json.WriteBoolean("valid", group.IsValid);

            if (group.IsValid) {
                json.WriteNumber("table_offset", group.TableOffset);
                json.WriteNumber("hash_mask", group.HashMask);
            } else {
                json.WriteNumber("throwing_stub_fixup", group.ThrowingStubFixup);
                json.WriteNumber("throwing_stub", group.ThrowingStub);
            }

            json.WriteStartArray("entries");
            foreach (var entry in map.Entries.Slice(group.Entries.Start, group.Entries.Count)) {
                cancellationToken.ThrowIfCancellationRequested();
                json.WriteStartObject();
                json.WriteNumber("vertex", entry.Vertex);
                json.WriteNumber("length", entry.Length);
                json.WriteNumber("hash", entry.Hash);
                if (map.Kind == InteropTypeMapKind.External) {
                    JsonOutput.WriteString(json, "name", entry.Name!);
                    json.WriteNumber("name_offset", entry.NameBytes.Start);
                    json.WriteNumber("name_length", entry.NameBytes.Count);
                    JsonOutput.WriteBase64String(json, "name_bytes_base64",
                        map.Bytes.Slice(entry.NameBytes.Start, entry.NameBytes.Count));
                } else {
                    json.WriteNumber("source_fixup", entry.SourceFixup);
                    WriteType(json, "source_type", entry.SourceType, extraction);
                }

                json.WriteNumber("target_fixup", entry.TargetFixup);
                WriteType(json, "target_type", entry.TargetType, extraction);
                json.WriteEndObject();
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }

        json.WriteEndArray();
        json.WriteEndObject();
    }

    private static void WriteType(Utf8JsonWriter json, string name, ulong address, Extraction extraction) {
        int index = extraction.Types.Index[address];
        json.WriteNumber(name, address);
        JsonOutput.WriteString(json, name + "_name", extraction.Names.Values[index]);
        json.WriteBoolean(name + "_name_complete", extraction.Names.Complete[index]);
    }
}
