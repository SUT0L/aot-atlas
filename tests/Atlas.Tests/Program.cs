using Atlas;

if (args.Length == 1 && args[0] == "--registered-cli-commands") {
    foreach (string command in CommandPlan.Commands.Order(StringComparer.Ordinal))
        Console.WriteLine(command);
    return;
}

if (args.Length == 1 && args[0] == "--typemaps") {
    TypeMapsChecks.Run();
    return;
}

if (args.Length == 2 && args[0] == "--typemaps-producer") {
    TypeMapsProducerChecks.Run(args[1]);
    return;
}

if (args.Length == 1 && args[0] == "--json-output") {
    JsonOutputChecks.Run();
    return;
}

if (args.Length is 1 or 2 && args[0] == "--rtr32") {
    Rtr32Checks.Run();
    if (args.Length == 2)
        Rtr32Checks.Producer(args[1]);
    return;
}

if (args.Length == 1 && args[0] == "--metadata-facts") {
    MetadataFactsChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--metadata-payloads") {
    MetadataPayloadChecks.Run();
    return;
}

if (args.Length > 1 && args[0] == "--analysis-products") {
    AnalysisProductChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length > 1 && args[0] == "--metadata-transactions") {
    MetadataDefinitionRecoveryChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 1 && args[0] == "--owned-references") {
    OwnedReferenceChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--owned-collections") {
    OwnedCollectionChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--short-tailcalls") {
    ShortTailcallChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--signature-comparison") {
    SignatureComparisonChecks.Run();
    return;
}

if (args.Length > 1 && args[0] == "--prepared-analysis") {
    PreparedAnalysisChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length > 1 && args[0] == "--metadata-producers") {
    MetadataProducerChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 1 && args[0] == "--iterative-bindings") {
    IterativeBindingChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--runtime-type-index") {
    RuntimeTypeIndexChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--method-control-flow") {
    MethodControlFlowChecks.Run();
    return;
}

if (args.Length > 1 && args[0] == "--dictionary-stages") {
    DictionaryStageChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 1 && args[0] == "--template-relations") {
    TemplateRelationChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--write-extents") {
    FatWriteExtentChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--native-layout-state") {
    NativeLayoutChecks.Run();
    NativeLayoutStateChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--native-reader-source") {
    NativeReaderSourceChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--signature-rendering") {
    SignatureRenderChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--signature-contexts") {
    SignatureContextChecks.Run();
    return;
}

if (args.Length > 0 && args[0] == "--signature-parser-state") {
    if (args.Length == 1)
        SignatureParserStateChecks.Run();
    else
        SignatureParserStateChecks.Binaries(args.AsSpan(1));
    return;
}

if (args.Length == 1 && args[0] == "--bounded-names") {
    RuntimeNameChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--metadata-identities") {
    MetadataIdentityChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--shared-bindings") {
    TypeBindingChecks.Run();
    SharedBindingChecks.Run();
    SignatureComparisonChecks.Run();
    return;
}

if (args.Length is 1 or 2 && args[0] == "--type-graphs") {
    TypeGraphChecks.Run(args.Length == 2 ? args[1] : null);
    return;
}

if (args.Length > 1 && args[0] == "--trace-stages") {
    TraceStageChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length > 1 && args[0] == "--extraction-stages") {
    ExtractionStageChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 1 && args[0] == "--hydration") {
    HydrationChecks.Run();
    HydrationBoundaryChecks.Run();
    return;
}

if (args.Length > 1 && args[0] == "--cancellation") {
    CancellationChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 1 && args[0] == "--timed-cancellation") {
    CancellationChecks.RunFixups();
    return;
}

if (args.Length == 1 && args[0] == "--method-gc") {
    MethodGcChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--managed-unwind") {
    ManagedUnwindChecks.Run();
    return;
}

if (args.Length > 1 && args[0] == "--extraction-availability") {
    ExtractionAvailabilityChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 1 && args[0] == "--metadata-values") {
    MetadataValueChecks.Run();
    TemplateFactChecks.Run();
    return;
}

if (args.Length == 2 && args[0] == "--trace-abi") {
    TraceAbiChecks.Run(args[1]);
    return;
}

if (args.Length == 2 && args[0] == "--trace-abi-folded") {
    TraceAbiChecks.Run(args[1], folded: true);
    return;
}

if (args.Length > 1 && args[0] == "--dictionary-relationships") {
    DictionarySlotChecks.Relationships(args.AsSpan(1));
    return;
}

if (args.Length > 1 && args[0] == "--dispatch-resolution") {
    DispatchResolutionChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length > 1 && args[0] == "--properties") {
    PropertyChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 1 && args[0] == "--strings") {
    NativeStringChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--rtr-source") {
    RtrSourceChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--code-flow") {
    CodeFlowChecks.Run();
    return;
}

if (args.Length > 1 && args[0] == "--shared-methods") {
    SharedMethodChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length > 1 && args[0] == "--marshalling-sizes") {
    MarshallingChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 3 && args[0] == "--marshalling-positive") {
    MarshallingProducerChecks.Run(args[1], args[2]);
    return;
}

if (args.Length > 1 && args[0] == "--methodtables-producer") {
    MethodTableProducerChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length != 0)
    throw new ArgumentException($"Unknown test invocation: {string.Join(' ', args)}");

var checks = new DefaultSuiteTests();
checks.RtrEmptySections();
checks.RtrSourceOwnership();
checks.TemplateRelations();
checks.MethodControlFlow();
checks.ShortTailcalls();
checks.Rtr32();
checks.JsonOutput();
checks.MetadataFacts();
checks.MetadataSignatures();
checks.MetadataValues();
checks.MetadataPayloads();
checks.OwnedReferences();
checks.OwnedCollections();
checks.TemplateFacts();
checks.NativeLayout();
checks.NativeLayoutState();
checks.NativeReaderSource();
checks.SignatureRendering();
checks.SignatureContexts();
checks.SignatureParserState();
checks.RuntimeNames();
checks.MetadataIdentity();
checks.TypeGraphs();
checks.TypeBinding();
checks.SharedBindings();
checks.SignatureComparison();
checks.IterativeBinding();
checks.RuntimeTypeIndex();
checks.ImageWriteExtents();
checks.FrozenObjects();
checks.Unwind();
checks.ManagedUnwind();
checks.MethodGc();
checks.TypeMaps();
checks.CodeFlow();
checks.PropertyAccess();
checks.NativeStrings();
checks.Hydration();
checks.HydrationBoundaries();
