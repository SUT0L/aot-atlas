using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class EnumsOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction) {
        var enums = extraction.Enums;
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("image_base", extraction.Image.ImageBase);
        json.WriteStartArray("definitions");
        foreach (ref readonly var definition in CollectionsMarshal.AsSpan(enums.Definitions)) {
            var type = extraction.Metadata.Types[definition.MetadataType];
            json.WriteStartObject();
            json.WriteNumber("metadata_type", type.Offset);
            json.WriteString("name", type.Name);
            json.WriteNumber("width", definition.Width);
            json.WriteBoolean("signed", definition.Signed);
            json.WriteBoolean("flags", definition.Flags);
            json.WriteStartArray("members");
            for (int i = definition.Members.Start; i < definition.Members.End; ++i) {
                var member = enums.Members[i];
                var field = extraction.Metadata.Fields[member.Field];
                json.WriteStartObject();
                json.WriteNumber("metadata_field", field.Offset);
                json.WriteNumber("constant", field.DefaultValue);
                json.WriteString("name", field.Name);
                json.WriteNumber("bits", member.Bits);
                json.WriteEndObject();
            }
            json.WriteEndArray();
            json.WriteEndObject();
        }
        json.WriteEndArray();

        json.WriteStartArray("runtime_types");
        for (int i = 0; i < enums.RuntimeIndices.Length; ++i) {
            int index = enums.RuntimeIndices[i];
            if (index == 0)
                continue;

            json.WriteStartObject();
            json.WriteNumber("address", extraction.Types.Types[i].Address);
            json.WriteNumber("metadata_type", extraction.Metadata.Types[enums.Definitions[index - 1].MetadataType].Offset);
            json.WriteString("name", extraction.Names.Values[i]);
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }
}
