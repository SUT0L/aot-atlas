using System.Diagnostics;
using System.Numerics;
using System.Runtime.InteropServices;

namespace Atlas;

public readonly record struct ExtractionPhaseMeasurement(string Phase, double Seconds, long AllocatedBytes);

public sealed partial class Extraction {
    public readonly PeImage Image;
    public readonly ReadyToRun Header;
    public readonly Metadata Metadata;
    public readonly ReflectionMaps Maps;
    internal readonly ulong[] CommonFixups;
    public ReadOnlySpan<ulong> Fixups => CommonFixups;
    public readonly ExtractionStage Stages;

    private readonly ulong[]? nativeReferences;
    private readonly ulong[]? nativeStatics;
    private readonly HydratedRegion? hydrated;
    private readonly RuntimeMemory? memory;

    private readonly NativeLayout? layout;
    private readonly GenericMaps? generics;
    private readonly GvmTables? gvms;
    private readonly Marshalling? marshalling;
    private readonly TypeMaps? typeMaps;
    private readonly DispatchCellMetadata? dispatchCellMetadata;
    private readonly VirtualMap? virtuals;
    private readonly TemplateMaps? templates;
    private readonly GenericDictionaries? dictionaries;
    private readonly TraceMaps? traces;

    private readonly StaticStorage? statics;
    private readonly FrozenObjects? frozen;
    private readonly ResourceMap? resources;
    private readonly PeLinkage? linkage;
    private readonly PInvokeFixups? pInvokes;
    private readonly Enumerations? enums;
    private readonly UnwindAnalysis? unwindAnalysis;

    private readonly MethodTables? types;
    private readonly GcLayouts? gc;
    private readonly RuntimeNames? names;
    private readonly Signatures? signatures;
    private readonly TypeBindings? bindings;
    private RuntimeTypeIndex? runtimeTypeIndex;
    private readonly FieldLayouts? fields;
    private readonly SharedMethods? shared;
    private readonly Dispatch? dispatch;

    internal ulong[] NativeReferences => Require(nativeReferences, ExtractionStage.RuntimeTypes);
    internal ulong[] NativeStatics => Require(nativeStatics, ExtractionStage.RuntimeTypes);
    public ReadOnlySpan<ulong> NativeReferenceAddresses => NativeReferences;
    public ReadOnlySpan<ulong> NativeStaticAddresses => NativeStatics;

    public HydratedRegion Hydrated {
        get {
            if ((Stages & ExtractionStage.RuntimeTypes) == 0)
                throw new InvalidOperationException("RuntimeTypes was not requested.");

            return hydrated ?? throw new InvalidOperationException("Extraction phase did not initialize runtime memory.");
        }
    }

    public RuntimeMemory Memory => Require(memory, ExtractionStage.RuntimeTypes);
    private NativeLayout Layout => Require(layout, ExtractionStage.RuntimeTypes);
    public GenericMaps Generics => Require(generics, ExtractionStage.RuntimeTypes);
    public GvmTables Gvms => Require(gvms, ExtractionStage.RuntimeTypes);
    public Marshalling Marshalling => Require(marshalling, ExtractionStage.RuntimeTypes);
    public TypeMaps TypeMaps => Require(typeMaps, ExtractionStage.RuntimeTypes);
    public DispatchCellMetadata DispatchCellMetadata => Require(dispatchCellMetadata, ExtractionStage.RuntimeTypes);
    public VirtualMap Virtuals => Require(virtuals, ExtractionStage.Dispatch);
    public TemplateMaps Templates => Require(templates, ExtractionStage.RuntimeTypes);
    public GenericDictionaries Dictionaries => Require(dictionaries, ExtractionStage.DictionaryBindings);
    public ReadOnlySpan<DictionarySignatureGap> DictionarySignatureGaps =>
        dictionaries is null ? [] : dictionaries.SignatureGaps;
    public TraceMaps Traces => Require(traces, ExtractionStage.MethodTracing);
    public string? TraceError { get; private set; }

    public StaticStorage Statics => Require(statics, ExtractionStage.RuntimeTypes);
    public FrozenObjects Frozen => Require(frozen, ExtractionStage.RuntimeTypes);
    public ResourceMap Resources => Require(resources, ExtractionStage.Resources);
    public PeLinkage Linkage => Require(linkage, ExtractionStage.Linkage);
    public PInvokeFixups PInvokes => Require(pInvokes, ExtractionStage.PInvokes);
    public Enumerations Enums => Require(enums, ExtractionStage.Enums);

    public UnwindAnalysis UnwindAnalysis => Require(unwindAnalysis, ExtractionStage.RuntimeTypes);
    public UnwindTables Unwind => UnwindAnalysis.RequireUnwind();
    public PeDebug Debug => UnwindAnalysis.RequireDebug();
    public ManagedUnwind Managed => UnwindAnalysis.RequireManaged();

    public MethodTables Types => Require(types, ExtractionStage.RuntimeTypes);
    public GcLayouts Gc => Require(gc, ExtractionStage.RuntimeTypes);
    public RuntimeNames Names => Require(names, ExtractionStage.RuntimeTypes);
    public Signatures Signatures => Require(signatures, ExtractionStage.RuntimeTypes);
    public TypeBindings Bindings =>
        bindings ?? throw new InvalidOperationException("Runtime signature bindings are unavailable.");
    public FieldLayouts Fields => Require(fields, ExtractionStage.MemberLayouts);
    public SharedMethods Shared => Require(shared, ExtractionStage.MemberLayouts);
    public Dispatch Dispatch => Require(dispatch, ExtractionStage.Dispatch);

    // References share one owner even when concurrent readers first request them.
    private RuntimeTypeIndex RuntimeIndex => Volatile.Read(ref runtimeTypeIndex) ?? CreateRuntimeIndex();

    private RuntimeTypeIndex CreateRuntimeIndex() {
        var runtime = new RuntimeTypeIndex(Types);
        return Interlocked.CompareExchange(ref runtimeTypeIndex, runtime, null) ?? runtime;
    }

    public readonly double TypesSeconds;
    public readonly double DispatchSeconds;
    public readonly double FrozenSeconds;
    public readonly double TotalSeconds;
    public readonly long TotalAllocatedBytes;

    private readonly ExtractionPhaseMeasurement[] phaseMeasurements;
    public ReadOnlySpan<ExtractionPhaseMeasurement> PhaseMeasurements => phaseMeasurements;

    private T Require<T>(T? value, ExtractionStage stage) where T : class {
        if ((Stages & stage) == 0)
            throw new InvalidOperationException($"{stage} was not requested.");

        return value ?? throw new InvalidOperationException($"Extraction phase did not initialize {stage}.");
    }

    public static Extraction Read(
        PeImage image,
        ExtractionStage requested = ExtractionStage.All,
        MapFormat mapFormat = MapFormat.Auto,
        CancellationToken cancellationToken = default) {
        var required = ExtractionPlan.Required(requested);
        cancellationToken.ThrowIfCancellationRequested();
        if ((required & ExtractionStage.RuntimeTypes) == 0) {
            var header = ReadyToRun.Read(image);
            var encoding = new MetadataEncoding(header.MetadataHandleBits, header.Format.LegacyMetadataConstants,
                header.Format.CombinedMetadataTypeOwnership);
            var metadata = new MetadataBuilder(ReadOnlyMemory<byte>.Empty, encoding, cancellationToken);
            return new(image, header, metadata, new ReflectionMaps(), [], requested, cancellationToken);
        }
        var input = ReadInputs(image, mapFormat, cancellationToken);
        return new(image, input.Header, input.Metadata, input.Maps, input.Fixups, requested, cancellationToken);
    }

    internal static (ReadyToRun Header, MetadataBuilder Metadata, ReflectionMaps Maps, ulong[] Fixups) ReadInputs(
        PeImage image,
        MapFormat mapFormat,
        CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();
        var header = ReadyToRun.Read(image);
        var metadata = MetadataBuilder.FromImage(image, header, cancellationToken);
        metadata.ReadDefinitions(cancellationToken);
        var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable), cancellationToken);
        var maps = ReflectionMaps.Decode(image, header, metadata, fixups, mapFormat, cancellationToken);
        return (header, metadata, maps, fixups);
    }

    internal Extraction(
        PeImage image,
        ReadyToRun rtr,
        MetadataBuilder metadata,
        ReflectionMaps maps,
        ulong[] commonFixups,
        ExtractionStage requested = ExtractionStage.All,
        CancellationToken cancellationToken = default) {
        long operationStart = Stopwatch.GetTimestamp();
        long operationAllocated = GC.GetAllocatedBytesForCurrentThread();
        cancellationToken.ThrowIfCancellationRequested();

        rtr = rtr.ValidateSource(image);

        var schedule = ExtractionPlan.Schedule(requested);

        if ((schedule.Stages & ExtractionStage.RuntimeTypes) != 0)
            maps.ValidateSignatureOrigin(metadata.SignatureBuilder.Origin);

        Image = image;
        Header = rtr;
        Maps = maps;
        CommonFixups = (ulong[])commonFixups.Clone();
        commonFixups = CommonFixups;
        Stages = schedule.Stages;

        phaseMeasurements = new ExtractionPhaseMeasurement[schedule.Phases.Length];
        int measurementIndex = 0;
        double typesSeconds = 0;
        List<FieldType>? memberSignatures = null;

        foreach (var phase in schedule.Phases) {
            cancellationToken.ThrowIfCancellationRequested();

            long phaseAllocated = GC.GetAllocatedBytesForCurrentThread();
            long phaseStart = Stopwatch.GetTimestamp();

            switch (phase) {
                case ExtractionPhase.MetadataSignatures:
                    Enumerations.ReadSignatures(metadata, cancellationToken);
                    break;

                case ExtractionPhase.EnumDefinitions:
                    System.Diagnostics.Debug.Assert(Metadata is not null);
                    enums = new Enumerations(Metadata, cancellationToken);
                    break;

                case ExtractionPhase.RuntimeSources:
                    hydrated = Hydration.Read(image, rtr, cancellationToken);
                    memory = new RuntimeMemory(image, Hydrated);
                    unwindAnalysis = new UnwindAnalysis(image, rtr, Memory, cancellationToken);

                    nativeReferences = RuntimeTables.Fixups(image, rtr.Find(RtrSectionId.NativeReferences), cancellationToken);
                    nativeStatics = RuntimeTables.Fixups(image, rtr.Find(RtrSectionId.NativeStatics), cancellationToken);
                    var section = rtr.Find(RtrSectionId.NativeLayoutInfo);
                    layout = new NativeLayout(
                        section.Length == 0
                            ? default
                            : image.FileMemory(section.Start, checked((int)section.Length)),
                        NativeReferences,
                        metadata.SignatureBuilder,
                        takeOwnership: true,
                        methodFlags: rtr.Format.ReturnDroppingAsyncThunks ? 31U : 15U);

                    gc = new GcLayouts();
                    generics = new GenericMaps();
                    gvms = new GvmTables();
                    marshalling = new Marshalling();
                    virtuals = new VirtualMap();
                    templates = new TemplateMaps();
                    dictionaries = new GenericDictionaries();
                    break;

                case ExtractionPhase.NativeSignatures:
                    Generics.Read(image, rtr, metadata, Layout, NativeReferences, maps.Format, cancellationToken);

                    int typeRoots = checked(maps.Types.Count + maps.DerivedTypes.Count + Generics.Types.Count);
                    int typeCapacity = checked((int)BitOperations.RoundUpToPowerOf2((uint)Math.Max(256, typeRoots)));
                    types = new MethodTables(typeCapacity);

                    Gvms.Read(image, rtr, metadata, Layout, commonFixups, maps.Format, Types, cancellationToken);
                    Marshalling.Read(image, rtr, commonFixups, Types, cancellationToken);
                    typeMaps = new TypeMaps(image, rtr, commonFixups, Types, cancellationToken);
                    dispatchCellMetadata = new DispatchCellMetadata(
                        image, rtr, Memory, NativeReferences, metadata, Layout, maps.Format, Types, cancellationToken);
                    virtuals!.Read(image, rtr, metadata, Layout, commonFixups, maps.Format, cancellationToken);
                    Templates.Read(image, rtr, metadata, Layout, commonFixups, NativeStatics, maps.Format, cancellationToken);

                    if ((Stages & ExtractionStage.DictionaryBindings) != 0)
                        dictionaries!.Read(image, rtr, metadata, Layout, Templates, maps.Format, cancellationToken);
                    else
                        dictionaries!.ReadSignatures(image, rtr, metadata, Layout, Templates, maps.Format, cancellationToken);

                    break;

                case ExtractionPhase.TraceSignatures:
                    try {
                        traces = new TraceMaps(image, rtr, metadata, commonFixups, cancellationToken);
                    } catch (Exception error) when (error is InvalidDataException or NotSupportedException or OverflowException) {
                        TraceError = error.Message;
                        traces = TraceMaps.Unavailable(metadata, cancellationToken);
                    }
                    break;

                case ExtractionPhase.StaticSources:
                    statics = new StaticStorage(image, rtr, Memory, commonFixups, NativeReferences, NativeStatics, cancellationToken);

                    foreach (ref var entry in CollectionsMarshal.AsSpan(maps.Methods)) {
                        cancellationToken.ThrowIfCancellationRequested();

                        if (entry.MetadataOffset == 0)
                            entry.Signature = Layout.Method(entry.NativeSignatureOffset).Signature;
                    }

                    break;

                case ExtractionPhase.RuntimeRoots:
                    var roots = Types;

                    foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Types))
                        roots.Add(entry.MethodTable, TypeEvidence.TypeMap);

                    foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.DerivedTypes))
                        roots.Add(entry.MethodTable, TypeEvidence.DerivedMap);

                    foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Methods))
                        roots.Add(entry.DeclaringType, TypeEvidence.InvokeMap);

                    foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Fields))
                        roots.Add(entry.DeclaringType, TypeEvidence.FieldMap);

                    foreach (ulong argument in CollectionsMarshal.AsSpan(maps.GenericArguments))
                        roots.Add(argument, TypeEvidence.InvokeMap);

                    foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Generics.Types))
                        roots.Add(entry.MethodTable, TypeEvidence.GenericMap);

                    foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Generics.Methods))
                        roots.Add(entry.DeclaringType, TypeEvidence.GenericMethod);

                    foreach (ulong argument in CollectionsMarshal.AsSpan(Generics.Arguments))
                        roots.Add(argument, TypeEvidence.GenericMethod);

                    foreach (ref readonly var entry in CollectionsMarshal.AsSpan(virtuals!.Entries))
                        roots.Add(entry.DeclaringType, TypeEvidence.VirtualMethod);

                    foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Templates.Types))
                        roots.Add(entry.MethodTable, TypeEvidence.TypeTemplate);

                    foreach (ulong address in Layout.ExternalTypes.Keys)
                        roots.Add(address, TypeEvidence.NativeSignature);

                    foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Statics.Constructors))
                        roots.Add(entry.Type, TypeEvidence.StaticConstructor);

                    foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Statics.Generics))
                        roots.Add(entry.Type, TypeEvidence.GenericStatics);

                    foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Statics.Allocations))
                        roots.Add(entry.RelatedType, TypeEvidence.StaticAllocation);

                    if (UnwindAnalysis.Managed is { } managed) {
                        foreach (ref readonly var clause in managed.Clauses.AsSpan()) {
                            if (clause.Kind == ExceptionClauseKind.Typed && !clause.TypeUnavailable)
                                roots.Add(image.ImageBase + clause.Type, TypeEvidence.ExceptionHandling);
                        }
                    }

                    long frozenStart = Stopwatch.GetTimestamp();
                    frozen = new FrozenObjects(rtr.Find(RtrSectionId.FrozenObjectRegion), Memory, Types, cancellationToken);
                    FrozenSeconds = Stopwatch.GetElapsedTime(frozenStart).TotalSeconds;
                    break;

                case ExtractionPhase.RuntimeTypes:
                    Types.Read(image, rtr, Memory, cancellationToken);
                    Frozen.ReadRuntimeTypes(image, rtr, Memory, Types, cancellationToken);
                    break;

                case ExtractionPhase.MemberSignatures:
                    memberSignatures = FieldLayouts.ReadSignatures(metadata, maps, Types, cancellationToken);
                    break;

                case ExtractionPhase.TemplateSignatures:
                    // Keep the established signature and runtime-type prefixes. New
                    // leaves resume the append-only reader before GC/name publication.
                    int signaturePrefix = metadata.SignatureBuilder.Nodes.Length;
                    Templates.ReadSignatures(image, rtr, Layout, cancellationToken);

                    foreach (var entry in Layout.ExternalTypes) {
                        if (entry.Value >= signaturePrefix)
                            Types.Add(entry.Key, TypeEvidence.NativeSignature);
                    }

                    Types.Read(image, rtr, Memory, cancellationToken);
                    Templates.ValidateRelations(Types, metadata.SignatureBuilder, cancellationToken);
                    break;

                case ExtractionPhase.RuntimePublication:
                    Gc.Read(Types, Memory, rtr.Format.LegacyTypeLayout, cancellationToken);

                    long bindStart = Stopwatch.GetTimestamp();
                    Frozen.Bind(Types, Gc, cancellationToken);
                    FrozenSeconds += Stopwatch.GetElapsedTime(bindStart).TotalSeconds;

                    names = new RuntimeNames(Types, maps);
                    Layout.BindTypes(Types, Names);
                    Gvms.Bind(Types, metadata.SignatureBuilder, cancellationToken);
                    Marshalling.Bind(Types, metadata, maps, rtr.Format.LegacyTypeLayout, cancellationToken);
                    TypeMaps.ValidateHashes(Types, cancellationToken);
                    DispatchCellMetadata.ValidateTypes(Types, cancellationToken);
                    Statics.BindFields(image, Memory, maps, Types);
                    break;

                case ExtractionPhase.SignaturePublication:
                    Metadata = metadata.Publish(cancellationToken);
                    signatures = Metadata.PublishedSignatures;
                    maps.SetSignatureOrigin(signatures);
                    break;

                case ExtractionPhase.BindingIndex:
                    bindings = new TypeBindings(RuntimeIndex, maps, Signatures);
                    break;

                case ExtractionPhase.MemberLayouts:
                    fields = new FieldLayouts(maps, Types, memberSignatures!, Bindings, cancellationToken);
                    shared = new SharedMethods(this);
                    break;

                case ExtractionPhase.MethodTracing:
                    traces!.Publish(Signatures, cancellationToken);
                    break;

                case ExtractionPhase.DictionaryBindings:
                    Dictionaries.Bind(this, cancellationToken);
                    break;

                case ExtractionPhase.Dispatch:
                    long dispatchStart = Stopwatch.GetTimestamp();
                    dispatch = new Dispatch(image, Memory, Types, cancellationToken);
                    virtuals!.Bind(image, Memory, Types, Dispatch, cancellationToken);
                    DispatchSeconds = Stopwatch.GetElapsedTime(dispatchStart).TotalSeconds;
                    break;

                case ExtractionPhase.Enums:
                    Enums.Bind(maps, Types, Bindings);
                    break;

                case ExtractionPhase.Resources:
                    resources = new ResourceMap(image, rtr, cancellationToken);
                    break;

                case ExtractionPhase.Linkage:
                    linkage = new PeLinkage(image, cancellationToken);
                    break;

                case ExtractionPhase.PInvokes:
                    pInvokes = new PInvokeFixups(image, Types, maps);
                    break;

                default:
                    throw new InvalidOperationException($"No extraction operation for phase {phase}.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            double seconds = Stopwatch.GetElapsedTime(phaseStart).TotalSeconds;
            long allocated = GC.GetAllocatedBytesForCurrentThread() - phaseAllocated;
            phaseMeasurements[measurementIndex++] = new(phase.ToString(), seconds, allocated);

            // The type aggregate excludes independent products. The individual
            // phase measurements are disjoint; FrozenSeconds is a nested detail.
            if (phase is not (ExtractionPhase.EnumDefinitions or ExtractionPhase.Enums
                or ExtractionPhase.Dispatch or ExtractionPhase.Resources
                or ExtractionPhase.Linkage or ExtractionPhase.PInvokes))
                typesSeconds += seconds;
        }

        Metadata ??= metadata.Publish(cancellationToken);
        // Source readers and their mutable signature buffers belong to construction.
        // Consumers retain the published graph and resolved IDs on their own rows.
        layout = null;
        TypesSeconds = typesSeconds;
        TotalSeconds = Stopwatch.GetElapsedTime(operationStart).TotalSeconds;
        TotalAllocatedBytes = GC.GetAllocatedBytesForCurrentThread() - operationAllocated;
    }
}
