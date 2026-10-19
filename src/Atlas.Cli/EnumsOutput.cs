using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class EnumsOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction) {
        var enums = extraction.Enums;

        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        ExtractionStatusOutput.Write(json, extraction);
        json.WriteNumber("image_base", extraction.Image.ImageBase);

        json.WriteStartArray("definitions");

        foreach (ref readonly var definition in CollectionsMarshal.AsSpan(enums.Definitions)) {
            var type = extraction.Metadata.Types[definition.MetadataType];

            json.WriteStartObject();
            json.WriteNumber("metadata_type", type.Offset);
            JsonOutput.WriteString(json, "name", type.Name);
            if (definition.Width != 0) {
                json.WriteNumber("width", definition.Width);
                json.WriteBoolean("signed", definition.Signed);
            } else {
                json.WriteNull("width");
                json.WriteNull("signed");
            }
            json.WriteBoolean("flags", definition.Flags);
            if (definition.Status != MetadataFactStatus.Valid)
                json.WriteString("status", definition.Status.ToString());

            json.WriteStartArray("members");

            for (int i = definition.Members.Start; i < definition.Members.End; ++i) {
                var member = enums.Members[i];
                var field = extraction.Metadata.Fields[member.Field];

                json.WriteStartObject();
                json.WriteNumber("metadata_field", field.Offset);
                json.WriteNumber("constant", field.DefaultValue);
                JsonOutput.WriteString(json, "name", field.Name);
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
            json.WriteNumber("metadata_type",
                extraction.Metadata.Types[enums.Definitions[index - 1].MetadataType].Offset);
            JsonOutput.WriteString(json, "name", extraction.Names.Values[i]);
            json.WriteEndObject();
        }

        json.WriteEndArray();

        if (!enums.Failures.IsEmpty) {
            json.WriteStartArray("failures");
            foreach (var failure in enums.Failures) {
                json.WriteStartObject();
                json.WriteNumber("metadata_type", extraction.Metadata.Types[failure.MetadataType].Offset);
                if (failure.FieldOffset != 0)
                    json.WriteNumber("metadata_field", failure.FieldOffset);
                json.WriteString("status", failure.Status.ToString());
                JsonOutput.WriteString(json, "error", failure.Error);
                json.WriteEndObject();
            }
            json.WriteEndArray();
        }
        json.WriteEndObject();
    }
}
