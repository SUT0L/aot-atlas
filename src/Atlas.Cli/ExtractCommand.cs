using System.Diagnostics;
using System.Text.Json;
using Atlas;

internal static class ExtractCommand {
    internal static void Write(Utf8JsonWriter json, string inputSha256, PeImage image,
        ReadyToRun rtr, MapFormat format, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        json.WriteStartObject();
        json.WriteString("operation", "extract");
        json.WriteNumber("schema_version", 1);
        json.WriteString("input_sha256", inputSha256);

        long start = Stopwatch.GetTimestamp();
        var metadata = Metadata.FromImage(image, rtr);

        metadata.ReadDefinitions(cancellationToken);
        var members = new MetadataMembers(metadata, cancellationToken);

        double metadataSeconds = Stopwatch.GetElapsedTime(start).TotalSeconds;

        json.WritePropertyName("metadata");
        MetadataOutput.Write(
            json, inputSha256, metadata, members, image, rtr, metadataSeconds,
            includeSignatureGraph: false, cancellationToken: cancellationToken);

        start = Stopwatch.GetTimestamp();

        var fixups = RuntimeTables.Fixups(image, rtr.Find(RtrSectionId.CommonFixupsTable));
        var maps = new ReflectionMaps();

        maps.Read(image, rtr, metadata, fixups, format, cancellationToken);

        double mapsSeconds = Stopwatch.GetElapsedTime(start).TotalSeconds;

        json.WritePropertyName("maps");
        MapsOutput.Write(json, inputSha256, maps, image, metadata, mapsSeconds, cancellationToken);

        var products = new AnalysisProducts(image, rtr, metadata, maps, fixups,
            requested: AnalysisProduct.All & ~AnalysisProduct.StringReferences,
            members: members, cancellationToken: cancellationToken);
        var extraction = products.Extraction;
        metadata = extraction.Metadata;
        maps = extraction.Maps;
        var analysis = extraction.UnwindAnalysis;
        var gcInfo = products.GcInfo;
        var fatPointers = products.FunctionPointers!;

        ExtractionStatusOutput.Write(json, extraction.Stages, extraction.DictionarySignatureGaps);
        AnalysisOutput.Write(json, analysis, gcInfo);

        json.WritePropertyName("dictionaries");
        DictionariesOutput.Write(json, inputSha256, extraction);

        if (analysis.Unwind is not null && analysis.Debug is not null) {
            json.WritePropertyName("inspect");
            InspectOutput.Write(json, inputSha256, extraction);
        }

        json.WritePropertyName("types");
        TypesOutput.Write(json, inputSha256,
            extraction.Types, extraction.Gc, extraction.Names, image, extraction.TypesSeconds,
            extraction.Stages, extraction.DictionarySignatureGaps);

        json.WritePropertyName("fields");
        FieldsOutput.Write(json, inputSha256, extraction);

        json.WritePropertyName("dispatch");
        DispatchOutput.Write(json, inputSha256, image, extraction.Types, extraction.Names, extraction.Dispatch,
            extraction.Virtuals, extraction.DispatchSeconds, extraction.Stages, extraction.DictionarySignatureGaps);

        json.WritePropertyName("statics");
        StaticsOutput.Write(json, inputSha256, extraction);

        json.WritePropertyName("frozen");
        FrozenOutput.Write(json, inputSha256, extraction);

        json.WritePropertyName("enums");
        EnumsOutput.Write(json, inputSha256, extraction);

        json.WritePropertyName("gvm");
        GvmOutput.Write(json, inputSha256, extraction);

        json.WritePropertyName("marshalling");
        MarshallingOutput.Write(json, inputSha256, extraction);

        json.WritePropertyName("typemaps");
        TypeMapsOutput.Write(json, inputSha256, extraction, cancellationToken);

        json.WritePropertyName("pinvoke");
        PInvokeOutput.Write(json, inputSha256, extraction);

        json.WritePropertyName("resources");
        ResourcesOutput.Write(json, inputSha256, image, extraction.Resources, null);

        json.WritePropertyName("linkage");
        LinkageOutput.Write(json, inputSha256, image, extraction.Linkage);

        if (analysis.Unwind is not null) {
            json.WritePropertyName("unwind");
            UnwindOutput.Write(json, inputSha256, image, analysis.Unwind);
        }

        if (analysis.Managed is not null) {
            json.WritePropertyName("exceptions");
            ExceptionsOutput.Write(json, inputSha256, image, extraction.Unwind, analysis.Managed);

            json.WritePropertyName("gcinfo");
            GcInfoOutput.Write(json, inputSha256, image, analysis.Managed, gcInfo!, cancellationToken);

            json.WritePropertyName("generic_context");
            GenericContextOutput.Write(json, inputSha256, image, analysis.Managed, gcInfo!,
                products.GenericContexts!, products.DictionaryConsumers!,
                extraction.Traces.Methods.Count == 0 ? "unavailable" : "complete");

            var abi = products.Abi!;
            var code = products.Code!;

            json.WritePropertyName("code");
            CodeOutput.Write(json, inputSha256, extraction, code,
                products.CodeMeasurement.Seconds, products.CodeMeasurement.AllocatedBytes);

            json.WritePropertyName("dispatch_cells");
            DispatchCellsOutput.Write(json, inputSha256, extraction, products.DispatchCells!,
                products.DispatchCellMeasurement.Seconds);

            json.WritePropertyName("runtime_helpers");
            RuntimeHelpersOutput.Write(json, inputSha256,
                products.Helpers!);

            json.WritePropertyName("methods");
            MethodsOutput.Write(json, inputSha256, extraction, abi, products.AbiMeasurement.Seconds, cancellationToken);

            json.WritePropertyName("properties");
            PropertyOutput.Write(json, inputSha256, extraction, products.Properties!);
        } else {
            json.WritePropertyName("templates");
            TemplatesOutput.Write(json, inputSha256, extraction, cancellationToken);

            if (analysis.Startup is { } startup) {
                json.WritePropertyName("runtime_helpers");
                RuntimeHelpersOutput.Write(json, inputSha256, startup);
            }
        }

        json.WritePropertyName("fat_function_pointers");
        FatFunctionPointersOutput.Write(json, inputSha256, image, analysis, gcInfo, fatPointers,
            extraction.Traces.Methods.Count == 0 ? "unavailable" : "complete", null);

        json.WritePropertyName("strings");
        StringsOutput.Write(json, inputSha256, image, products.Strings!,
            products.StringMeasurement.Seconds, products.StringMeasurement.AllocatedBytes, cancellationToken);

        json.WritePropertyName("sections");
        SectionsOutput.Write(json, inputSha256, image, rtr);

        MetadataIdentityOutput.Write(json, metadata, cancellationToken: cancellationToken);
        AnalysisTimingOutput.Write(json, products, metadataSeconds, mapsSeconds);
        cancellationToken.ThrowIfCancellationRequested();
        json.WriteEndObject();
    }
}
