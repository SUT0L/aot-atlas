using System.Diagnostics;
using System.Security.Cryptography;
using Atlas;

internal static class AnalysisMeasurementChecks {
    internal static void Run(string operation, string path) {
        AnalysisProduct requested = operation switch {
            "full" => AnalysisProduct.All & ~AnalysisProduct.StringReferences,
            "code" => AnalysisProduct.Code,
            "types" => AnalysisProduct.None,
            _ => throw new ArgumentException("Expected full, code or types.", nameof(operation))
        };
        ExtractionStage stages = operation == "full" ? ExtractionStage.All
            : operation == "types" ? ExtractionStage.RuntimeTypes
            : AnalysisProducts.RequiredExtractionStages(requested);

        // Warm code paths, then release their products. The retained measurement
        // holds precisely the next result across a collection, not discarded work.
        Prepare(path, requested, stages);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        long retainedBefore = GC.GetTotalMemory(forceFullCollection: true);
        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        long start = Stopwatch.GetTimestamp();

        var result = Prepare(path, requested, stages);
        double seconds = Stopwatch.GetElapsedTime(start).TotalSeconds;
        long allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
        long retained = GC.GetTotalMemory(forceFullCollection: true) - retainedBefore;
        using var process = Process.GetCurrentProcess();
        long peakWorkingSet = process.PeakWorkingSet64;
        GC.KeepAlive(result);

        var extraction = result.Extraction;
        double phaseSeconds = 0;
        long phaseAllocated = 0;
        var phaseNames = new HashSet<string>(StringComparer.Ordinal);

        foreach (var phase in extraction.PhaseMeasurements) {
            Check(phase.Seconds >= 0 && phase.AllocatedBytes >= 0 && phaseNames.Add(phase.Phase));
            phaseSeconds += phase.Seconds;
            phaseAllocated += phase.AllocatedBytes;
        }

        Check(phaseSeconds <= extraction.TotalSeconds
            && phaseAllocated <= extraction.TotalAllocatedBytes
            && extraction.TotalSeconds <= result.ExtractionMeasurement.Seconds
            && result.ExtractionMeasurement.Seconds <= result.TotalMeasurement.Seconds
            && result.TotalMeasurement.Seconds <= seconds);
        Check(result.TotalMeasurement.AllocatedBytes <= allocated);

        double productSeconds = result.ExtractionMeasurement.Seconds
            + result.AbiMeasurement.Seconds + result.PropertyMeasurement.Seconds + result.CodeMeasurement.Seconds
            + result.DispatchCellMeasurement.Seconds + result.HelperMeasurement.Seconds
            + result.GcInfoMeasurement.Seconds + result.GenericContextMeasurement.Seconds
            + result.FunctionPointerMeasurement.Seconds + result.StringMeasurement.Seconds
            + result.StringReferenceMeasurement.Seconds;
        Check(productSeconds <= result.TotalMeasurement.Seconds);

        if (operation != "full")
            Check(result.Members is null && result.Properties is null && result.FunctionPointers is null
                && result.Strings is null && result.StringReferences.IsEmpty);

        Console.WriteLine($"Core {operation}: {seconds * 1000:F3} ms, allocated {allocated:N0} B, "
            + $"retained managed delta {retained:N0} B, process peak working set {peakWorkingSet:N0} B; "
            + $"{extraction.Types.Types.Count} types, {result.Code?.InstructionCount ?? 0} instructions.");
    }

    private static AnalysisProducts Prepare(string path, AnalysisProduct requested, ExtractionStage stages) {
        var image = PeImage.ReadFile(path);
        SHA256.HashData(image.FileData);
        var header = ReadyToRun.Read(image);
        var metadata = MetadataBuilder.FromImage(image, header);
        metadata.ReadDefinitions();
        var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        var maps = ReflectionMaps.Decode(image, header, metadata, fixups);

        return new AnalysisProducts(image, header, metadata, maps, fixups, requested, stages);
    }

    private static void Check(bool value) {
        if (!value)
            throw new Exception("Complete-operation measurement or selective workload invariant failed.");
    }
}
