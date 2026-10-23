using System.Text.Json;
using Atlas;

internal static class AnalysisOutput {
    internal static string PhaseName(UnwindPhase phase) => phase switch {
        UnwindPhase.Unwind => "unwind",
        UnwindPhase.PeDebug => "pe_debug",
        _ => "managed_unwind"
    };

    internal static void Write(Utf8JsonWriter json, AnalysisProducts products) {
        var extraction = products.Extraction;
        var gcInfo = products.GcInfo;
        var analysis = extraction.UnwindAnalysis;
        int enumFailures = (extraction.Stages & ExtractionStage.Enums) != 0 ? extraction.Enums.Failures.Length : 0;
        int unprovenDispatchUses = products.Code is { } code ? code.UnprovenDispatchCellUseEntries.Length : 0;
        bool gcFailed = gcInfo is not null && gcInfo.Methods.Any(method => method.Error is not null);
        bool regionUnknown = analysis.Managed?.RegionSource == ManagedRegionSource.Unknown;
        string delegateStatus = extraction.Traces.Methods.Count == 0 ? "unavailable" : "complete";
        bool pointerComplete = products.FunctionPointers is { } pointers
            && pointers.ConstructorMapStatus != "partial"
            && FatFunctionPointersOutput.DescriptorUsesStatus(analysis, gcInfo, pointers, delegateStatus) == "complete"
            && FatFunctionPointersOutput.DictionaryConsumersStatus(pointers) == "complete";
        bool helpersComplete = products.Helpers?.Status == RuntimeHelperStatus.Complete;
        bool sourcesComplete = extraction.Metadata.IsComplete
            && extraction.DictionarySignatureGaps.IsEmpty
            && extraction.DispatchCellMetadata.Failures.IsEmpty
            && enumFailures == 0
            && unprovenDispatchUses == 0;

        json.WriteStartObject("analysis_status");
        json.WriteString("status", sourcesComplete && analysis.Failures.Length == 0 && !gcFailed && !regionUnknown
            && pointerComplete && helpersComplete
            ? "complete" : "partial");
        json.WriteString("metadata", extraction.Metadata.Bytes.IsEmpty ? "absent"
            : extraction.Metadata.IsComplete ? "complete" : "partial");
        if (extraction.Metadata.Facts.Status != MetadataFactStatus.Valid)
            json.WriteString("metadata_decode_status", extraction.Metadata.Facts.Status.ToString());
        if (enumFailures != 0)
            json.WriteNumber("enum_failures", enumFailures);
        if (unprovenDispatchUses != 0)
            json.WriteNumber("unproven_dispatch_cell_uses", unprovenDispatchUses);
        if (gcInfo is not null) {
            json.WriteString("gcinfo", gcFailed ? "partial"
                : regionUnknown ? "unknown_region" : "available");
        }

        json.WriteString("unwind", analysis.Unwind is null ? "unavailable" : "available");
        json.WriteString("pe_debug", analysis.Debug is null ? "unavailable" : "available");
        json.WriteString("managed_unwind", analysis.Managed is null ? "unavailable" : "available");
        if (analysis.Managed is { } managed)
            json.WriteString("managed_region_source", managed.RegionSource.ToString());
        if (analysis.Startup is { } startup)
            json.WriteString("startup", startup.Status.ToString());

        json.WriteStartArray("failures");

        foreach (var failure in analysis.Failures) {
            json.WriteStartObject();
            json.WriteString("phase", PhaseName(failure.Phase));
            json.WriteString("error", failure.Error);
            json.WriteEndObject();
        }

        foreach (var failure in extraction.Metadata.ProjectionDiagnostics) {
            json.WriteStartObject();
            json.WriteString("phase", "metadata");
            json.WriteNumber("handle", failure.Handle);
            json.WriteString("projection", failure.Projection);
            json.WriteString("error", failure.Error);
            json.WriteEndObject();
        }

        foreach (var failure in extraction.DispatchCellMetadata.Failures) {
            json.WriteStartObject();
            json.WriteString("phase", "dispatch_metadata");
            json.WriteNumber("section", (int)failure.Section);
            json.WriteNumber("vertex", failure.Vertex);
            json.WriteNumber("cell_index", failure.CellIndex);
            JsonOutput.WriteString(json, "error", failure.Error);
            json.WriteEndObject();
        }

        if (enumFailures != 0) {
            foreach (var failure in extraction.Enums.Failures) {
                json.WriteStartObject();
                json.WriteString("phase", "enums");
                json.WriteNumber("metadata_type", extraction.Metadata.Types[failure.MetadataType].Offset);
                if (failure.FieldOffset != 0)
                    json.WriteNumber("metadata_field", failure.FieldOffset);
                json.WriteString("status", failure.Status.ToString());
                JsonOutput.WriteString(json, "error", failure.Error);
                json.WriteEndObject();
            }
        }

        json.WriteEndArray();

        if (analysis.Managed is null)
            json.WriteString("type_evidence", "exception-only types unavailable");

        json.WriteStartArray("unavailable_outputs");
        if (analysis.Unwind is null)
            json.WriteStringValue("unwind");
        if (analysis.Unwind is null || analysis.Debug is null)
            json.WriteStringValue("inspect");
        if (analysis.Managed is null) {
            foreach (string output in new[] {
                "exceptions", "gcinfo", "generic_context", "code", "dispatch_cells", "methods", "properties"
            }) {
                json.WriteStringValue(output);
            }

            if (analysis.Startup is null)
                json.WriteStringValue("runtime_helpers");
        }

        json.WriteEndArray();
        json.WriteEndObject();
    }
}
