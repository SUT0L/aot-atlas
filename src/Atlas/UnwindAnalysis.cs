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

                ValidateExceptionTypes(image, header, memory, managed, failures);

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
        ManagedUnwind managed,
        List<UnwindFailure> failures) {
        var roots = new HashSet<uint>();

        foreach (ref var clause in managed.Clauses.AsSpan()) {
            if (clause.Kind != ExceptionClauseKind.Typed)
                continue;

            if (clause.TypeUnavailable) {
                failures.Add(new(UnwindPhase.ManagedUnwind,
                    $"Exception catch type at RVA 0x{clause.Address:X} is outside mapped storage."));
            } else {
                roots.Add(clause.Type);
            }
        }

        if (roots.Count == 0)
            return;

        try {
            ValidateRoots(image, header, memory, roots);
            return;
        } catch (Exception error) when (IsInputError(error)) {
            // A failed batch does not identify the bad clause. Check each independent closure.
        }

        var rejected = new Dictionary<uint, string>();

        foreach (uint root in roots) {
            try {
                ValidateRoots(image, header, memory, [root]);
            } catch (Exception error) when (IsInputError(error)) {
                rejected.Add(root, error.Message);
            }
        }

        var survivors = roots.Where(root => !rejected.ContainsKey(root)).ToArray();

        if (survivors.Length != 0) {
            try {
                ValidateRoots(image, header, memory, survivors);
            } catch (Exception error) when (IsInputError(error)) {
                foreach (uint root in survivors)
                    rejected.Add(root, error.Message);
            }
        }

        foreach (ref var clause in managed.Clauses.AsSpan()) {
            if (clause.Kind != ExceptionClauseKind.Typed
                || !rejected.TryGetValue(clause.Type, out string? error))
                continue;

            clause.TypeUnavailable = true;
            failures.Add(new(UnwindPhase.ManagedUnwind,
                $"Exception catch type at RVA 0x{clause.Address:X}: {error}"));
        }
    }

    private static void ValidateRoots(PeImage image, ReadyToRun header, RuntimeMemory memory,
        IEnumerable<uint> roots) {
        var candidates = new MethodTables();

        foreach (uint root in roots)
            candidates.Add(image.ImageBase + root, TypeEvidence.ExceptionHandling);

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
