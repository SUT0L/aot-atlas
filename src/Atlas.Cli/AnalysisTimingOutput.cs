using System.Text.Json;
using Atlas;

internal static class AnalysisTimingOutput {
    internal static void Write(Utf8JsonWriter json, AnalysisProducts products,
        double metadataSeconds, double mapsSeconds) {
        json.WriteStartObject("analysis_measurements");
        json.WriteNumber("metadata_definitions_and_members_seconds", metadataSeconds);
        json.WriteNumber("reflection_maps_seconds", mapsSeconds);
        Write(json, "analysis_total", products.TotalMeasurement);
        Write(json, "extraction_total", products.ExtractionMeasurement);

        json.WriteStartArray("extraction_phases");

        foreach (var phase in products.Extraction.PhaseMeasurements) {
            json.WriteStartObject();
            json.WriteString("phase", phase.Phase);
            json.WriteNumber("elapsed_seconds", phase.Seconds);
            json.WriteNumber("allocated_bytes", phase.AllocatedBytes);
            json.WriteEndObject();
        }

        json.WriteEndArray();
        Write(json, "members", products.MetadataMemberMeasurement);
        Write(json, "abi", products.AbiMeasurement);
        Write(json, "properties", products.PropertyMeasurement);
        Write(json, "code", products.CodeMeasurement);
        Write(json, "dispatch_cells", products.DispatchCellMeasurement);
        Write(json, "helpers", products.HelperMeasurement);
        Write(json, "gcinfo", products.GcInfoMeasurement);
        Write(json, "generic_contexts", products.GenericContextMeasurement);
        Write(json, "function_pointers", products.FunctionPointerMeasurement);
        Write(json, "strings", products.StringMeasurement);
        Write(json, "string_references", products.StringReferenceMeasurement);
        json.WriteEndObject();
    }

    private static void Write(Utf8JsonWriter json, string name, AnalysisMeasurement measurement) {
        json.WriteStartObject(name);
        json.WriteNumber("elapsed_seconds", measurement.Seconds);
        json.WriteNumber("allocated_bytes", measurement.AllocatedBytes);
        json.WriteEndObject();
    }
}
