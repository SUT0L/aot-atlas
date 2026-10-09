using System.Text.Json;
using Atlas;

internal static class ExtractionStatusOutput {
    internal static void Write(
        Utf8JsonWriter json,
        ExtractionStage stages,
        ReadOnlySpan<DictionarySignatureGap> dictionarySignatureGaps) {
        if (json.CurrentDepth != 1)
            return;

        json.WriteStartObject("extraction_stages");
        Stage("runtime_types", ExtractionStage.RuntimeTypes);
        Stage("member_layouts", ExtractionStage.MemberLayouts);
        Stage("dispatch", ExtractionStage.Dispatch);
        Stage("method_tracing", ExtractionStage.MethodTracing);
        Stage("dictionary_bindings", ExtractionStage.DictionaryBindings);
        Stage("resources", ExtractionStage.Resources);
        Stage("linkage", ExtractionStage.Linkage);
        Stage("pinvoke_fixups", ExtractionStage.PInvokes);
        Stage("enums", ExtractionStage.Enums);

        bool closureComplete = dictionarySignatureGaps.IsEmpty;
        json.WriteString("dictionary_signatures", (stages & ExtractionStage.RuntimeTypes) == 0 ? "not_requested"
            : closureComplete ? "complete" : "partial");
        json.WriteString("signature_graph_closure", (stages & ExtractionStage.RuntimeTypes) == 0 ? "not_requested"
            : closureComplete ? "requested_stages" : "partial_dictionary_signatures");

        if (!closureComplete) {
            json.WriteStartArray("dictionary_signature_gaps");

            foreach (var gap in dictionarySignatureGaps) {
                json.WriteStartObject();
                json.WriteNumber("layout_offset", gap.LayoutOffset);
                json.WriteNumber("recipe_offset", gap.RecipeOffset);
                json.WriteNumber("kind", gap.Kind);
                json.WriteNumber("remaining_slots", gap.RemainingSlots);
                json.WriteEndObject();
            }

            json.WriteEndArray();
        }

        json.WriteEndObject();

        void Stage(string name, ExtractionStage stage) =>
            json.WriteString(name, (stages & stage) != 0 ? "available" : "not_requested");
    }
}
