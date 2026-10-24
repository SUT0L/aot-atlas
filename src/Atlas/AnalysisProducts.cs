using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Atlas;

[Flags]
public enum AnalysisProduct : ushort {
    None = 0,
    MetadataMembers = 1,
    Abi = 2,
    Properties = 4,
    Code = 8,
    DispatchCells = 16,
    Helpers = 32,
    GcInfo = 64,
    GenericContexts = 128,
    FunctionPointers = 256,
    Strings = 512,
    StringReferences = 1024,
    All = MetadataMembers | Abi | Properties | Code | DispatchCells | Helpers
        | GcInfo | GenericContexts | FunctionPointers | Strings | StringReferences
}

// Managed allocations on the synchronous caller thread; native allocations are separate.
public readonly record struct AnalysisMeasurement(double Seconds, long AllocatedBytes) {
    internal static AnalysisMeasurement Since(long start, long allocated) => new(
        Stopwatch.GetElapsedTime(start).TotalSeconds,
        GC.GetAllocatedBytesForCurrentThread() - allocated);
}

public sealed class AnalysisProducts {
    private const ExtractionStage CodeStages = ExtractionStage.MemberLayouts
        | ExtractionStage.MethodTracing | ExtractionStage.Dispatch | ExtractionStage.Linkage;

    public Extraction Extraction { get; }
    public MetadataMembers? Members { get; }
    public ManagedAbi? Abi { get; }
    public PropertyProjections? Properties { get; }
    public CodeFlow? Code { get; }
    public DispatchCells? DispatchCells { get; }
    public RuntimeHelpers? Helpers { get; }
    public MethodGcMap? GcInfo { get; }
    public GenericContextReferences? GenericContexts { get; }
    public DictionarySlotConsumers? DictionaryConsumers { get; }
    public FatFunctionPointers? FunctionPointers { get; }
    public NativeStrings? Strings { get; }
    private readonly List<CodeEdge>? stringReferences;
    public ReadOnlySpan<CodeEdge> StringReferences => stringReferences is null
        ? [] : CollectionsMarshal.AsSpan(stringReferences);

    public AnalysisMeasurement ExtractionMeasurement { get; }
    public AnalysisMeasurement TotalMeasurement { get; }
    public AnalysisMeasurement AbiMeasurement { get; }
    public AnalysisMeasurement PropertyMeasurement { get; }
    public AnalysisMeasurement CodeMeasurement { get; }
    public AnalysisMeasurement DispatchCellMeasurement { get; }
    public AnalysisMeasurement HelperMeasurement { get; }
    public AnalysisMeasurement GcInfoMeasurement { get; }
    public AnalysisMeasurement GenericContextMeasurement { get; }
    public AnalysisMeasurement FunctionPointerMeasurement { get; }
    public AnalysisMeasurement StringMeasurement { get; }
    public AnalysisMeasurement StringReferenceMeasurement { get; }

    public static AnalysisProducts Read(
        PeImage image,
        AnalysisProduct requested = AnalysisProduct.All,
        ExtractionStage? stages = null,
        MapFormat mapFormat = MapFormat.Auto,
        CancellationToken cancellationToken = default) {
        var required = RequiredExtractionStages(requested);
        var selected = stages ?? (requested == AnalysisProduct.All ? ExtractionStage.All : required);
        if ((ExtractionPlan.Required(selected) & required) != required)
            throw new ArgumentException("The extraction stages do not provide the requested analysis products.", nameof(stages));

        var input = Extraction.ReadInputs(image, mapFormat, cancellationToken);
        return new(image, input.Header, input.Metadata, input.Maps, input.Fixups, requested, selected,
            cancellationToken, allowStageExpansion: stages is null);
    }

    internal AnalysisProducts(
        PeImage image,
        ReadyToRun header,
        MetadataBuilder metadata,
        ReflectionMaps maps,
        ulong[] fixups,
        AnalysisProduct requested = AnalysisProduct.All,
        ExtractionStage stages = ExtractionStage.All,
        CancellationToken cancellationToken = default,
        bool allowStageExpansion = false) {
        long operationAllocated = GC.GetAllocatedBytesForCurrentThread();
        long operationStart = Stopwatch.GetTimestamp();
        cancellationToken.ThrowIfCancellationRequested();
        requested = RequiredProducts(requested);
        var requiredStages = RequiredExtractionStages(requested);

        if ((ExtractionPlan.Required(stages) & requiredStages) != requiredStages)
            throw new ArgumentException("The extraction stages do not provide the requested analysis products.", nameof(stages));

        RuntimeHelpers? startupHelpers = null;
        AnalysisMeasurement helperMeasurement = default;
        long allocated = GC.GetAllocatedBytesForCurrentThread();
        long start = Stopwatch.GetTimestamp();

        if ((requested & AnalysisProduct.Helpers) != 0
            && (ExtractionPlan.Required(stages) & CodeStages) != CodeStages) {
            try {
                var hydrated = Hydration.Read(image, header, cancellationToken);
                var memory = new RuntimeMemory(image, hydrated);
                var unwind = new UnwindTables(image, cancellationToken);
                startupHelpers = new RuntimeHelpers(image, header, memory, unwind, cancellationToken);
            } catch (Exception error) when (error is InvalidDataException or NotSupportedException or OverflowException) {
                startupHelpers = null;
            }

            helperMeasurement = AnalysisMeasurement.Since(start, allocated);

            if (startupHelpers?.Status != RuntimeHelperStatus.Complete) {
                if (!allowStageExpansion)
                    throw new ArgumentException("The extraction stages do not provide the helper code fallback.", nameof(stages));
                stages |= CodeStages;
            }
        }

        allocated = GC.GetAllocatedBytesForCurrentThread();
        start = Stopwatch.GetTimestamp();
        Extraction = new Extraction(image, header, metadata, maps, fixups, stages, cancellationToken);
        ExtractionMeasurement = AnalysisMeasurement.Since(start, allocated);
        var extraction = Extraction;
        var analysis = extraction.UnwindAnalysis;
        if (startupHelpers?.Status != RuntimeHelperStatus.Complete)
            startupHelpers = analysis.Startup;

        if ((requested & AnalysisProduct.MetadataMembers) != 0) {
            cancellationToken.ThrowIfCancellationRequested();
            Members = extraction.Metadata.Members;
        }

        if (analysis.Managed is not null) {
            if ((requested & AnalysisProduct.GcInfo) != 0) {
                cancellationToken.ThrowIfCancellationRequested();
                allocated = GC.GetAllocatedBytesForCurrentThread();
                start = Stopwatch.GetTimestamp();
                GcInfo = new MethodGcMap(image, header, analysis.RequireUnwind(), analysis.Managed, cancellationToken);
                GcInfoMeasurement = AnalysisMeasurement.Since(start, allocated);
            }

            if ((requested & AnalysisProduct.Helpers) != 0
                && startupHelpers?.Status != RuntimeHelperStatus.Complete)
                requested |= AnalysisProduct.Code | AnalysisProduct.Abi;

            if ((requested & AnalysisProduct.Abi) != 0) {
                cancellationToken.ThrowIfCancellationRequested();
                allocated = GC.GetAllocatedBytesForCurrentThread();
                start = Stopwatch.GetTimestamp();
                Abi = new ManagedAbi(extraction, cancellationToken);
                AbiMeasurement = AnalysisMeasurement.Since(start, allocated);
            }

            if ((requested & AnalysisProduct.Properties) != 0) {
                cancellationToken.ThrowIfCancellationRequested();
                allocated = GC.GetAllocatedBytesForCurrentThread();
                start = Stopwatch.GetTimestamp();
                Properties = new PropertyProjections(extraction, Abi!, cancellationToken);
                PropertyMeasurement = AnalysisMeasurement.Since(start, allocated);
            }

            if ((requested & AnalysisProduct.Code) != 0) {
                cancellationToken.ThrowIfCancellationRequested();
                allocated = GC.GetAllocatedBytesForCurrentThread();
                start = Stopwatch.GetTimestamp();
                Code = new CodeFlow(extraction, Abi!, cancellationToken);
                CodeMeasurement = AnalysisMeasurement.Since(start, allocated);
            }

            if ((requested & AnalysisProduct.DispatchCells) != 0) {
                cancellationToken.ThrowIfCancellationRequested();
                allocated = GC.GetAllocatedBytesForCurrentThread();
                start = Stopwatch.GetTimestamp();
                DispatchCells = new DispatchCells(extraction, Code!, cancellationToken);
                DispatchCellMeasurement = AnalysisMeasurement.Since(start, allocated);
            }
        }

        if ((requested & AnalysisProduct.Helpers) != 0) {
            cancellationToken.ThrowIfCancellationRequested();
            allocated = GC.GetAllocatedBytesForCurrentThread();
            start = Stopwatch.GetTimestamp();
            Helpers = startupHelpers?.Status == RuntimeHelperStatus.Complete
                ? startupHelpers
                : Code is null ? startupHelpers : new RuntimeHelpers(extraction, Code, cancellationToken);
            var fallbackMeasurement = AnalysisMeasurement.Since(start, allocated);
            HelperMeasurement = new(
                helperMeasurement.Seconds + fallbackMeasurement.Seconds,
                helperMeasurement.AllocatedBytes + fallbackMeasurement.AllocatedBytes);
        }

        if ((requested & AnalysisProduct.FunctionPointers) != 0) {
            cancellationToken.ThrowIfCancellationRequested();
            allocated = GC.GetAllocatedBytesForCurrentThread();
            start = Stopwatch.GetTimestamp();
            var consumers = ManagedFunctionPointerConsumers.Read(
                extraction.Metadata, extraction.Traces, extraction.Signatures, cancellationToken);
            FunctionPointers = new FatFunctionPointers(
                image, header, extraction.Memory, analysis.Unwind, GcInfo, consumers, cancellationToken);
            DictionaryConsumers = FunctionPointers.DictionaryConsumers;
            FunctionPointerMeasurement = AnalysisMeasurement.Since(start, allocated);
        }

        if ((requested & AnalysisProduct.GenericContexts) != 0 && GcInfo is not null) {
            cancellationToken.ThrowIfCancellationRequested();

            if (DictionaryConsumers is null) {
                allocated = GC.GetAllocatedBytesForCurrentThread();
                start = Stopwatch.GetTimestamp();
                var consumers = ManagedFunctionPointerConsumers.Read(
                    extraction.Metadata, extraction.Traces, extraction.Signatures, cancellationToken);
                DictionaryConsumers = new DictionarySlotConsumers(
                    image, extraction.Memory, analysis.RequireUnwind(), GcInfo, consumers, cancellationToken);
                GenericContextMeasurement = AnalysisMeasurement.Since(start, allocated);
            }

            GenericContexts = DictionaryConsumers.ContextReferences;
        }

        if ((requested & AnalysisProduct.Strings) != 0) {
            cancellationToken.ThrowIfCancellationRequested();
            allocated = GC.GetAllocatedBytesForCurrentThread();
            start = Stopwatch.GetTimestamp();
            Strings = new NativeStrings(image, header.Sections, cancellationToken);
            StringMeasurement = AnalysisMeasurement.Since(start, allocated);
        }

        if ((requested & AnalysisProduct.StringReferences) != 0 && Code is not null) {
            cancellationToken.ThrowIfCancellationRequested();
            allocated = GC.GetAllocatedBytesForCurrentThread();
            start = Stopwatch.GetTimestamp();
            stringReferences = new List<CodeEdge>();
            Strings!.AppendReferences(image.ImageBase, Code.AddressEdges, stringReferences, cancellationToken);
            StringReferenceMeasurement = AnalysisMeasurement.Since(start, allocated);
        }

        cancellationToken.ThrowIfCancellationRequested();
        TotalMeasurement = AnalysisMeasurement.Since(operationStart, operationAllocated);
    }

    private static AnalysisProduct RequiredProducts(AnalysisProduct requested) {
        if ((requested & ~AnalysisProduct.All) != 0)
            throw new ArgumentOutOfRangeException(nameof(requested));

        if ((requested & AnalysisProduct.StringReferences) != 0)
            requested |= AnalysisProduct.Strings | AnalysisProduct.Code;

        if ((requested & AnalysisProduct.DispatchCells) != 0)
            requested |= AnalysisProduct.Code;

        if ((requested & AnalysisProduct.Properties) != 0)
            requested |= AnalysisProduct.MetadataMembers | AnalysisProduct.Abi;

        if ((requested & AnalysisProduct.Code) != 0)
            requested |= AnalysisProduct.Abi;

        if ((requested & (AnalysisProduct.FunctionPointers | AnalysisProduct.GenericContexts)) != 0)
            requested |= AnalysisProduct.GcInfo;

        return requested;
    }

    public static ExtractionStage RequiredExtractionStages(AnalysisProduct requested) {
        requested = RequiredProducts(requested);
        var stages = ExtractionStage.RuntimeTypes;

        if ((requested & AnalysisProduct.Abi) != 0)
            stages |= ExtractionStage.MemberLayouts | ExtractionStage.MethodTracing;

        if ((requested & AnalysisProduct.Properties) != 0)
            stages |= ExtractionStage.Dispatch;

        if ((requested & AnalysisProduct.Code) != 0)
            stages |= CodeStages;

        if ((requested & AnalysisProduct.DispatchCells) != 0)
            stages |= ExtractionStage.DictionaryBindings;

        if ((requested & (AnalysisProduct.FunctionPointers | AnalysisProduct.GenericContexts)) != 0)
            stages |= ExtractionStage.MethodTracing;

        return stages;
    }
}
