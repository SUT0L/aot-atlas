using System.Text.Json;
using Atlas;

internal static class ExtractionStatusOutput {
    internal static void Write(Utf8JsonWriter json, Extraction extraction) {
        if (json.CurrentDepth != 1)
            return;

        var stages = extraction.Stages;
        var metadata = extraction.Metadata;
        var dictionarySignatureGaps = extraction.DictionarySignatureGaps;
        int dispatchMetadataFailures = (stages & ExtractionStage.RuntimeTypes) != 0
            ? extraction.DispatchCellMetadata.Failures.Length
            : 0;
        int enumFailures = (stages & ExtractionStage.Enums) != 0 ? extraction.Enums.Failures.Length : 0;

        json.WriteStartObject("extraction_stages");
        Stage("runtime_types", ExtractionStage.RuntimeTypes);
        Stage("member_layouts", ExtractionStage.MemberLayouts);
        Stage("dispatch", ExtractionStage.Dispatch);
        Stage("method_tracing", ExtractionStage.MethodTracing);
        Stage("dictionary_bindings", ExtractionStage.DictionaryBindings);
        Stage("resources", ExtractionStage.Resources);
        Stage("linkage", ExtractionStage.Linkage);
        Stage("pinvoke_fixups", ExtractionStage.PInvokes);
        json.WriteString("enums", (stages & ExtractionStage.Enums) == 0 ? "not_requested"
            : enumFailures == 0 ? "available" : "partial");

        bool metadataComplete = metadata.IsComplete;
        bool closureComplete = dictionarySignatureGaps.IsEmpty && metadataComplete && dispatchMetadataFailures == 0;
        json.WriteString("dictionary_signatures", (stages & ExtractionStage.RuntimeTypes) == 0 ? "not_requested"
            : dictionarySignatureGaps.IsEmpty ? "complete" : "partial");
        json.WriteString("signature_graph_closure", (stages & ExtractionStage.RuntimeTypes) == 0 ? "not_requested"
            : closureComplete ? "requested_stages"
            : !metadataComplete ? "partial_metadata"
            : dispatchMetadataFailures != 0 ? "partial_dispatch_metadata" : "partial_dictionary_signatures");

        json.WriteString("metadata", metadata.Bytes.IsEmpty ? "absent" : metadataComplete ? "complete" : "partial");
        json.WriteNumber("metadata_projection_failures", metadata.ProjectionDiagnostics.Count);
        if (metadata.Facts.Status != MetadataFactStatus.Valid)
            json.WriteString("metadata_decode_status", metadata.Facts.Status.ToString());

        if (enumFailures != 0)
            json.WriteNumber("enum_failures", enumFailures);

        if (dispatchMetadataFailures != 0)
            json.WriteNumber("dispatch_metadata_failures", dispatchMetadataFailures);

        if (!dictionarySignatureGaps.IsEmpty) {
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
