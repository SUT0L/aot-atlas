using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class FieldsOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction) {
        var layouts = extraction.Fields;
        var tables = extraction.Types;
        var names = extraction.Names;

        JsonOutput.StartDocument(json, "fields");
        json.WriteString("input_sha256", inputSha256);
        ExtractionStatusOutput.Write(json, extraction);

        json.WriteStartArray("layouts");

        int maximumArguments = 0;

        for (int i = 0; i < layouts.Layouts.Length; ++i) {
            ref readonly var layout = ref layouts.Layouts[i];
            ref readonly var type = ref CollectionsMarshal.AsSpan(tables.Types)[i];

            maximumArguments = Math.Max(maximumArguments, type.Arguments.Count);

            if (layout.Length == 0)
                continue;

            json.WriteStartObject();
            json.WriteNumber("type", type.Address);
            JsonOutput.WriteString(json, "name", names.Values[i]);
            json.WriteString("origin", type.IsValueType ? "payload" : "object");
            json.WriteNumber("length", layout.Length);
            json.WriteNumber("component_size", type.ComponentSize);
            json.WriteNumber("base_type", layout.BaseType == 0
                ? 0
                : tables.Types[layout.BaseType - 1].Address);

            json.WriteStartArray("fields");

            for (int j = layout.Fields.Start; j < layout.Fields.End; ++j) {
                ref readonly var field = ref layouts.Fields[j];

                json.WriteStartArray();
                json.WriteNumberValue(field.FieldIndex);
                json.WriteNumberValue(field.Offset);
                json.WriteNumberValue(field.Extent);
                json.WriteEndArray();
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }

        json.WriteEndArray();

        json.WriteStartArray("fields");

        var arguments = new string[maximumArguments];
        SignatureArgument[]? bindings = null;
        var builder = new System.Text.StringBuilder(256);
        bool hasAbbreviatedReferences = false;

        foreach (ref readonly var field in CollectionsMarshal.AsSpan(layouts.FieldTypes)) {
            ref readonly var entry = ref CollectionsMarshal.AsSpan(extraction.Maps.Fields)[field.MapIndex];
            int owner = field.Owner - 1;
            var args = entry.Location == FieldLocation.Ordinal ? default : tables.Types[owner].Arguments;
            var typeAddresses = CollectionsMarshal.AsSpan(tables.Pointers).Slice(args.Start, args.Count);

            for (int j = 0; j < args.Count; ++j)
                arguments[j] = names.Values[tables.Index[typeAddresses[j]]];

            builder.Clear();
            bool complete = extraction.Signatures.AppendTypeWithStatus(
                builder, field.Signature, arguments.AsSpan(0, args.Count));

            json.WriteStartObject();
            json.WriteNumber("field_map_vertex", entry.Vertex);
            json.WriteNumber("declaring_type", tables.Types[owner].Address);
            json.WriteNumber("map_declaring_type", entry.DeclaringType);
            JsonOutput.WriteString(json, "field_name", entry.Name);
            JsonOutput.WriteString(json, "name", $"{names.Values[owner]}::{entry.Name}");
            json.WriteNumber("metadata_offset", field.MetadataOffset);
            JsonOutput.WriteString(json, "signature", builder.ToString());

            if (!complete) {
                hasAbbreviatedReferences = true;
                bindings ??= new SignatureArgument[maximumArguments];

                for (int i = 0; i < args.Count; ++i)
                    bindings[i] = SignatureArgument.RuntimeType(typeAddresses[i], arguments[i]);

                MetadataIdentityOutput.WriteContext(
                    json, field.Signature, method: false, new(bindings.AsSpan(0, args.Count)));
            }

            json.WriteNumber("field_type", field.Binding == 0 ? 0 : tables.Types[field.Binding - 1].Address);
            json.WriteString("storage", field.Storage.ToString());
            json.WriteNumber("size", field.Size);
            json.WriteString("size_source", field.Source.ToString());
            json.WriteString("location", entry.Location.ToString());
            json.WriteNumber(entry.Location == FieldLocation.Ordinal ? "ordinal" : "offset", entry.Value);
            json.WriteEndObject();
        }

        json.WriteEndArray();
        MetadataIdentityOutput.EndObject(json, extraction.Metadata, extraction.Signatures,
            includeSignatureGraph: hasAbbreviatedReferences);
    }
}
