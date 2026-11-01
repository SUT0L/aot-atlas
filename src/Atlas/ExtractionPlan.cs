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

public static class ExtractionPlan {
    public static ExtractionStage Prerequisites(ExtractionStage stage) {
        if (stage == ExtractionStage.None || ((ushort)stage & ((ushort)stage - 1)) != 0)
            throw new ArgumentOutOfRangeException(nameof(stage));

        return Required(stage) & ~stage;
    }

    public static ExtractionStage Required(ExtractionStage requested) {
        if (requested == ExtractionStage.None || (requested & ~ExtractionStage.All) != 0)
            throw new ArgumentOutOfRangeException(nameof(requested));

        if ((requested & ExtractionStage.DictionaryBindings) != 0) {
            requested |= ExtractionStage.MemberLayouts;
        }

        if ((requested & ~(ExtractionStage.Resources | ExtractionStage.Linkage)) != 0) {
            requested |= ExtractionStage.RuntimeTypes;
        }

        return requested;
    }
}
