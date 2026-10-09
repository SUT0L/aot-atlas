using System.Text.Json;
using Atlas;

internal static class AnalysisOutput {
    internal static string PhaseName(UnwindPhase phase) => phase switch {
        UnwindPhase.Unwind => "unwind",
        UnwindPhase.PeDebug => "pe_debug",
        _ => "managed_unwind"
    };

    internal static void Write(Utf8JsonWriter json, UnwindAnalysis analysis, MethodGcMap? gcInfo = null) {
        bool gcFailed = gcInfo is not null && gcInfo.Methods.Any(method => method.Error is not null);
        bool regionUnknown = analysis.Managed?.RegionSource == ManagedRegionSource.Unknown;

        json.WriteStartObject("analysis_status");
        json.WriteString("status", analysis.Failures.Length == 0 && !gcFailed && !regionUnknown ? "complete" : "partial");
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
