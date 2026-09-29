using System.Text.Json;
using Atlas;

internal static class PropertyOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction, PropertyProjections properties) {
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("property_definitions", properties.Members.Properties.Count);
        json.WriteNumber("legacy_identities", properties.LegacyIdentities);
        json.WriteNumber("legacy_matches", properties.LegacyMatches);
        json.WriteNumber("unjoined_dispatch", properties.UnjoinedDispatch);
        json.WriteStartObject("rejected");
        for (int i = 0; i < properties.Rejected.Length; ++i) {
            if (properties.Rejected[i] != 0) {
                json.WriteNumber(((PropertyRejection)i).ToString(), properties.Rejected[i]);
            }
        }
        json.WriteEndObject();
        json.WriteStartArray("projections");
        foreach (var projection in properties.Projections) {
            var property = properties.Members.Properties[projection.Property];
            string owner = extraction.Names.Values[projection.Owner];
            string contract = extraction.Names.Values[projection.Contract];
            string prefix = projection.Origin switch {
                PropertyOrigin.Interface => "interface_property", PropertyOrigin.Base => "base_property",
                PropertyOrigin.Canonical => "canonical_property", _ => "property"
            };
            if (projection.Getter == 0) {
                prefix += "_store";
            }
            json.WriteStartObject();
            json.WriteString("name", projection.Owner == projection.Contract ? $"{prefix}::{owner}::{property.Name}"
                : $"{prefix}::{owner}::{contract}::{property.Name}");
            json.WriteString("origin", projection.Origin.ToString());
            json.WriteNumber("owner", extraction.Types.Types[projection.Owner].Address);
            json.WriteString("owner_name", owner);
            json.WriteNumber("contract", extraction.Types.Types[projection.Contract].Address);
            json.WriteString("contract_name", contract);
            json.WriteNumber("source_owner", extraction.Types.Types[projection.SourceOwner].Address);
            json.WriteNumber("property", projection.Property);
            json.WriteString("property_name", property.Name);
            json.WriteString("declared_type", extraction.Metadata.Signatures.RenderType(property.Type));
            json.WriteNumber("storage_type", projection.Storage.Binding == 0 ? 0 : extraction.Types.Types[projection.Storage.Binding - 1].Address);
            json.WriteString("storage_name", projection.Storage.Binding == 0 ? extraction.Metadata.Signatures.RenderType(projection.Signature)
                : extraction.Names.Values[projection.Storage.Binding - 1]);
            json.WriteString("storage_kind", projection.Storage.Kind.ToString());
            json.WriteNumber("offset", projection.Offset);
            json.WriteNumber("size", projection.Size);
            json.WriteBoolean("returns_by_reference", projection.ByReference);
            json.WriteString("access", projection.Getter == 0 ? "store" : projection.Setter == 0 ? "load" : "load_store");
            json.WriteNumber("getter", projection.Getter);
            json.WriteNumber("setter", projection.Setter);
            json.WriteNumber("getter_metadata", projection.GetterMethod);
            json.WriteNumber("setter_metadata", projection.SetterMethod);
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteStartArray("accessor_functions");
        foreach (var function in properties.Functions) {
            json.WriteStartObject();
            json.WriteNumber("address", function.Address);
            json.WriteNumber("projection", function.Projection);
            json.WriteBoolean("setter", function.Setter);
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }
}
