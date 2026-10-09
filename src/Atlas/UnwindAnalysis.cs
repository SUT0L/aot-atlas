namespace Atlas;

public enum UnwindPhase : byte {
    Unwind,
    PeDebug,
    ManagedUnwind
}

public readonly record struct UnwindFailure(UnwindPhase Phase, string Error);

// PE debug records and unwind tables are independent evidence. A rejected phase must
// not discard runtime maps, or stop reconstruction from other validated evidence.
public sealed class UnwindAnalysis {
    public readonly UnwindTables? Unwind;
    public readonly PeDebug? Debug;
    public readonly ManagedUnwind? Managed;
    public readonly RuntimeHelpers? Startup;

    internal readonly UnwindFailure[] Failures;
    public ReadOnlySpan<UnwindFailure> FailureEntries => Failures;

    public UnwindAnalysis(PeImage image, ReadyToRun header, RuntimeMemory memory, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        header = header.ValidateSource(image);

        var failures = new List<UnwindFailure>();

        try {
            Unwind = new UnwindTables(image, cancellationToken);
        } catch (Exception error) when (IsInputError(error)) {
            failures.Add(new(UnwindPhase.Unwind, error.Message));
        }

        try {
            cancellationToken.ThrowIfCancellationRequested();
            Debug = new PeDebug(image);
        } catch (Exception error) when (IsInputError(error)) {
            failures.Add(new(UnwindPhase.PeDebug, error.Message));
        }

        if (Unwind is not null) {
            try {
                var managed = new ManagedUnwind(image, Unwind, Debug, cancellationToken: cancellationToken);

                if (managed.RegionSource == ManagedRegionSource.Unknown) {
                    Startup = new RuntimeHelpers(image, header, memory, Unwind, cancellationToken);
                    managed = new ManagedUnwind(image, Unwind, Debug, Startup, cancellationToken);
                }

                ValidateExceptionTypes(image, header, memory, managed);

                Managed = managed;
            } catch (Exception error) when (IsInputError(error)) {
                failures.Add(new(UnwindPhase.ManagedUnwind, error.Message));
            }
        }

        Failures = failures.ToArray();
        cancellationToken.ThrowIfCancellationRequested();
    }

    private static void ValidateExceptionTypes(
        PeImage image,
        ReadyToRun header,
        RuntimeMemory memory,
        ManagedUnwind managed) {
        int typedCount = 0;

        foreach (ref readonly var clause in managed.Clauses.AsSpan()) {
            if (clause.Kind == ExceptionClauseKind.Typed)
                ++typedCount;
        }

        if (typedCount == 0)
            return;

        // Optional EH roots must establish their complete EEType/GC closure before they can enter the core type set.
        var candidates = new MethodTables(typedCount);

        foreach (ref readonly var clause in managed.Clauses.AsSpan()) {
            if (clause.Kind == ExceptionClauseKind.Typed)
                candidates.Add(image.ImageBase + clause.Type, TypeEvidence.ExceptionHandling);
        }

        candidates.Read(image, header, memory);
        new GcLayouts(candidates.Types.Count).Read(candidates, memory, header.Format.LegacyTypeLayout);
    }

    public UnwindTables RequireUnwind() => Unwind ?? throw Unavailable(UnwindPhase.Unwind);
    public PeDebug RequireDebug() => Debug ?? throw Unavailable(UnwindPhase.PeDebug);
    public ManagedUnwind RequireManaged() => Managed ?? throw Unavailable(UnwindPhase.ManagedUnwind);

    private InvalidDataException Unavailable(UnwindPhase phase) {
        foreach (var failure in Failures) {
            if (failure.Phase == phase
                || (phase == UnwindPhase.ManagedUnwind && failure.Phase == UnwindPhase.Unwind))
                return new InvalidDataException($"{phase} analysis unavailable: {failure.Error}");
        }

        return new InvalidDataException($"{phase} analysis unavailable.");
    }

    private static bool IsInputError(Exception error) =>
        error is InvalidDataException or NotSupportedException or OverflowException;
}
