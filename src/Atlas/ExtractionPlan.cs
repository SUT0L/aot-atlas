namespace Atlas;

[Flags]
public enum ExtractionStage : ushort {
    None = 0,
    RuntimeTypes = 1,
    MemberLayouts = 2,
    Dispatch = 4,
    MethodTracing = 8,
    DictionaryBindings = 16,
    Resources = 32,
    Linkage = 64,
    PInvokes = 128,
    Enums = 256,

    All = RuntimeTypes | MemberLayouts | Dispatch | MethodTracing | DictionaryBindings
        | Resources | Linkage | PInvokes | Enums
}

[Flags]
internal enum ExtractionPhase : uint {
    MetadataSignatures = 1 << 0,
    RuntimeSources = 1 << 1,
    NativeSignatures = 1 << 2,
    TraceSignatures = 1 << 3,
    StaticSources = 1 << 4,
    RuntimeRoots = 1 << 5,
    RuntimeTypes = 1 << 6,
    MemberSignatures = 1 << 7,
    SignaturePublication = 1 << 8,
    MemberLayouts = 1 << 9,
    MethodTracing = 1 << 10,
    DictionaryBindings = 1 << 11,
    Dispatch = 1 << 12,
    Resources = 1 << 13,
    Linkage = 1 << 14,
    PInvokes = 1 << 15,
    BindingIndex = 1 << 16,
    Enums = 1 << 17,
    EnumDefinitions = 1 << 18,
    TemplateSignatures = 1 << 19,
    RuntimePublication = 1 << 20
}

internal readonly record struct ExtractionSchedule(ExtractionStage Stages, ExtractionPhase[] Phases);

public static class ExtractionPlan {
    private readonly record struct Phase(
        ExtractionPhase Id,
        ExtractionPhase Requires = 0,
        ExtractionPhase AfterSelected = 0,
        ExtractionStage Provides = 0);

    // The order preserves append-only signature/type IDs when several sources are requested.
    // AfterSelected is a barrier for optional discovery, without making that source mandatory.
    private static readonly Phase[] phases = [
        new(ExtractionPhase.Linkage, Provides: ExtractionStage.Linkage),
        new(ExtractionPhase.Resources, Provides: ExtractionStage.Resources),
        new(ExtractionPhase.MetadataSignatures),
        new(ExtractionPhase.RuntimeSources, ExtractionPhase.MetadataSignatures),
        new(ExtractionPhase.NativeSignatures, ExtractionPhase.RuntimeSources),
        new(ExtractionPhase.TraceSignatures, ExtractionPhase.NativeSignatures),
        new(ExtractionPhase.StaticSources, ExtractionPhase.NativeSignatures, ExtractionPhase.TraceSignatures),
        new(ExtractionPhase.RuntimeRoots, ExtractionPhase.StaticSources),
        new(ExtractionPhase.RuntimeTypes, ExtractionPhase.RuntimeRoots),
        new(ExtractionPhase.MemberSignatures, ExtractionPhase.RuntimeTypes),
        new(ExtractionPhase.TemplateSignatures, ExtractionPhase.RuntimeTypes,
            ExtractionPhase.MemberSignatures),
        new(ExtractionPhase.RuntimePublication, ExtractionPhase.TemplateSignatures),
        new(ExtractionPhase.SignaturePublication, ExtractionPhase.RuntimePublication,
            Provides: ExtractionStage.RuntimeTypes),
        new(ExtractionPhase.EnumDefinitions, ExtractionPhase.SignaturePublication),
        new(ExtractionPhase.BindingIndex, ExtractionPhase.SignaturePublication),
        new(ExtractionPhase.MemberLayouts, ExtractionPhase.BindingIndex | ExtractionPhase.MemberSignatures,
            Provides: ExtractionStage.MemberLayouts),
        new(ExtractionPhase.MethodTracing, ExtractionPhase.SignaturePublication | ExtractionPhase.TraceSignatures,
            Provides: ExtractionStage.MethodTracing),
        new(ExtractionPhase.DictionaryBindings, ExtractionPhase.MemberLayouts,
            Provides: ExtractionStage.DictionaryBindings),
        new(ExtractionPhase.Dispatch, ExtractionPhase.SignaturePublication, Provides: ExtractionStage.Dispatch),
        new(ExtractionPhase.PInvokes, ExtractionPhase.SignaturePublication, Provides: ExtractionStage.PInvokes),
        new(ExtractionPhase.Enums, ExtractionPhase.BindingIndex | ExtractionPhase.EnumDefinitions,
            Provides: ExtractionStage.Enums)
    ];

    public static ExtractionStage Prerequisites(ExtractionStage stage) {
        if (stage == ExtractionStage.None || ((ushort)stage & ((ushort)stage - 1)) != 0)
            throw new ArgumentOutOfRangeException(nameof(stage));

        return Required(stage) & ~stage;
    }

    public static ExtractionStage Required(ExtractionStage requested) => Schedule(requested).Stages;

    internal static ExtractionSchedule Schedule(ExtractionStage requested) {
        if (requested == ExtractionStage.None || (requested & ~ExtractionStage.All) != 0)
            throw new ArgumentOutOfRangeException(nameof(requested));

        ExtractionPhase selected = 0;

        foreach (var phase in phases) {
            if ((phase.Provides & requested) != 0)
                selected |= phase.Id;
        }

        while (true) {
            var previous = selected;

            foreach (var phase in phases) {
                if ((selected & phase.Id) != 0)
                    selected |= phase.Requires;
            }

            if (previous == selected)
                break;
        }

        var order = new ExtractionPhase[System.Numerics.BitOperations.PopCount((uint)selected)];

        ExtractionPhase completed = 0;
        ExtractionStage stages = 0;
        int count = 0;

        while (completed != selected) {
            int previous = count;

            foreach (var phase in phases) {
                if ((selected & phase.Id) == 0 || (completed & phase.Id) != 0)
                    continue;

                var required = phase.Requires | (phase.AfterSelected & selected);

                if ((required & completed) != required)
                    continue;

                order[count++] = phase.Id;
                completed |= phase.Id;
                stages |= phase.Provides;
            }

            if (count == previous)
                throw new InvalidOperationException("Extraction phase prerequisites contain a cycle or missing phase.");
        }

        return new ExtractionSchedule(stages, order);
    }
}
