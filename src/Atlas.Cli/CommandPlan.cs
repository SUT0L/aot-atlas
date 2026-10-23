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

    private static readonly Dictionary<string, CommandPlan> Registered = RegisterCommands();

    internal static IEnumerable<string> Commands => Registered.Keys;

    internal static CommandPlan? For(string command) => Registered.GetValueOrDefault(command);

    private static Dictionary<string, CommandPlan> RegisterCommands() {
        var commands = new Dictionary<string, CommandPlan>(StringComparer.Ordinal);

        void Add(CommandPlan plan, params string[] names) {
            foreach (string name in names)
                commands.Add(name, plan);
        }

        Add(new(Metadata: true), "metadata");
        Add(new(Maps: true), "maps");
        Add(new(RequestedStages: ExtractionStage.RuntimeTypes),
            "types", "frozen", "gvm", "marshalling", "typemaps", "statics");
        Add(new(RequestedStages: ExtractionStage.MemberLayouts), "templates", "fields", "header");
        Add(new(RequestedStages: ExtractionStage.Enums), "enums");
        Add(new(RequestedStages: ExtractionStage.PInvokes), "pinvoke");
        Add(new(RequestedStages: ExtractionStage.DictionaryBindings), "dictionaries");
        Add(new(Products: AnalysisProduct.Abi), "methods");
        Add(new(RequestedStages: ExtractionStage.Dispatch), "dispatch");
        Add(new(RequestedStages: ExtractionStage.Dispatch, PositionalCount: 6), "resolve-dispatch");
        Add(new(Products: AnalysisProduct.Code), "code");
        Add(new(Products: AnalysisProduct.Properties), "properties");
        Add(new(Products: AnalysisProduct.DispatchCells), "dispatch-cells");
        Add(new(Products: AnalysisProduct.Code | AnalysisProduct.Strings, PositionalCount: 4), "search");
        Add(new(AllowMapFormat: true), "extract", "runtime-helpers");
        Add(new(), "inspect", "sections", "strings", "resources", "linkage", "unwind",
            "exceptions", "gcinfo", "generic-context", "fat-function-pointers");

        return commands;
    }
}
