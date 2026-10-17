using Atlas;

internal sealed record CommandPlan(
    ExtractionStage? RequestedStages = null,
    AnalysisProduct Products = AnalysisProduct.None,
    int PositionalCount = 3,
    bool AllowMapFormat = false,
    bool Maps = false,
    bool Metadata = false) {
    internal ExtractionStage? Stages => Products == AnalysisProduct.None ? RequestedStages
        : AnalysisProducts.RequiredExtractionStages(Products) | RequestedStages.GetValueOrDefault();
    internal bool NeedsMaps => Maps || Stages.HasValue;
    internal bool NeedsMetadata => Metadata || NeedsMaps;
    internal bool AcceptsMapFormat => AllowMapFormat || NeedsMaps;

    internal static CommandPlan? For(string command) => command switch {
        "metadata" => new(Metadata: true),
        "maps" => new(Maps: true),
        "types" or "frozen" or "gvm" or "marshalling" or "typemaps" or "statics" => new(RequestedStages: ExtractionStage.RuntimeTypes),
        "templates" or "fields" or "header" => new(RequestedStages: ExtractionStage.MemberLayouts),
        "enums" => new(RequestedStages: ExtractionStage.Enums),
        "pinvoke" => new(RequestedStages: ExtractionStage.PInvokes),
        "dictionaries" => new(RequestedStages: ExtractionStage.DictionaryBindings),
        "methods" => new(Products: AnalysisProduct.Abi),
        "dispatch" => new(RequestedStages: ExtractionStage.Dispatch),
        "resolve-dispatch" => new(RequestedStages: ExtractionStage.Dispatch, PositionalCount: 6),
        "code" => new(Products: AnalysisProduct.Code),
        "properties" => new(Products: AnalysisProduct.Properties),
        "dispatch-cells" => new(Products: AnalysisProduct.DispatchCells),
        "search" => new(Products: AnalysisProduct.Code | AnalysisProduct.Strings, PositionalCount: 4),
        "extract" or "runtime-helpers" => new(AllowMapFormat: true),
        "inspect" or "sections" or "strings" or "resources" or "linkage" or "unwind" or "exceptions"
            or "gcinfo" or "generic-context" or "fat-function-pointers" => new(),
        _ => null
    };
}
