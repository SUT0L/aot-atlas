using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace Atlas.Binja;

[StructLayout(LayoutKind.Sequential)]
public unsafe struct ApplyStats {
    public ulong InputBytes;
    public ulong ImageBase;

    public uint MethodTables;
    public uint DataVariables;
    public uint Symbols;
    public uint DataReferences;

    public double ExtractSeconds;
    public double ApplySeconds;

    public fixed byte InputSha256[32];
}

public static unsafe class Plugin {
    private enum Operation : byte {
        Metadata,
        FieldReferences,
        RestoreAnnotations,
        RestoreEnums,
        Complete
    }

    private static readonly Lock ActiveLock = new();
    private static readonly Dictionary<nint, TaskCompletionSource> ActiveFiles = [];

    [UnmanagedCallersOnly(EntryPoint = "CorePluginABIVersion", CallConvs = [typeof(CallConvCdecl)])]
    public static uint AbiVersion() => 187;

    [UnmanagedCallersOnly(EntryPoint = "CorePluginInit", CallConvs = [typeof(CallConvCdecl)])]
    public static byte Initialize() {
        if (Core.BNGetCurrentCoreABIVersion() != 187)
            return 0;

        fixed (byte* name = "AOT Atlas\\Apply metadata\0"u8)
        fixed (byte* description = "\0"u8)
            Core.BNRegisterPluginCommand(name, description, &Start, &Valid, 0);

        // The finalization event runs before saved types and metadata are loaded
        Core.BNRegisterBinaryViewEvent(1, &RestoreAnnotations, 0);

        return 1;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void RestoreAnnotations(nint context, nint view) {
        nint retainedView = Core.BNNewViewReference(view);

        try {
            // A host callback may hold the global lock. Leave that callback
            // before waiting for the publication barrier on a worker thread.
            ThreadPool.QueueUserWorkItem(static state => {
                try {
                    Run(state, MapFormat.Auto, 0, Operation.RestoreAnnotations, out _);
                } finally {
                    Core.BNFreeBinaryView(state);
                }
            }, retainedView, preferLocal: false);
        } catch (Exception error) {
            Core.BNFreeBinaryView(retainedView);
            Log(3, error.ToString());
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static byte Valid(nint context, nint view) {
        if (view == 0)
            return 0;

        byte* kind = Core.BNGetViewType(view);
        byte result = kind[0] == 'P' && kind[1] == 'E' && kind[2] == 0 ? (byte)1 : (byte)0;

        Core.BNFreeString(kind);

        return result;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void Start(nint context, nint view) {
        long invocationStart = Stopwatch.GetTimestamp();
        long invocationAllocated = GC.GetTotalAllocatedBytes(precise: true);
        nint ownedView = Core.BNNewViewReference(view);

        try {
            // Analysis waits are prohibited on Binary Ninjas own worker threads
            ThreadPool.QueueUserWorkItem(static state => Work(state.View, state.Start, state.Allocated),
                (View: ownedView, Start: invocationStart, Allocated: invocationAllocated), preferLocal: false);
        } catch (Exception error) {
            Core.BNFreeBinaryView(ownedView);

            Log(3, error.ToString());
        }
    }

    private static void Work(nint view, long invocationStart, long invocationAllocated) {
        nint task;
        int status;

        fixed (byte* text = "AOT Atlas: extracting\0"u8)
            task = Core.BNBeginBackgroundTask(text, 1);

        try {
            status = Run(view, MapFormat.Auto, task, Operation.Complete, out _);
        } finally {
            Core.BNFreeBinaryView(view);
            Core.BNFinishBackgroundTask(task);
            Core.BNFreeBackgroundTask(task);
        }

        LogTotal("Complete operation", invocationStart, invocationAllocated, status);
    }

    [UnmanagedCallersOnly(EntryPoint = "AtlasApplyMetadata", CallConvs = [typeof(CallConvCdecl)])]
    // Synchronous exports wait for a host notification barrier. Call them outside
    // notifications that hold the host's global lock; the command queues a worker.
    public static int Apply(nint view, byte format, ApplyStats* output) {
        long invocationStart = Stopwatch.GetTimestamp();
        long invocationAllocated = GC.GetTotalAllocatedBytes(precise: true);
        int status = Run(view, (MapFormat)format, 0, Operation.Metadata, out var stats);

        if (output != null)
            *output = stats;

        LogTotal("Metadata operation", invocationStart, invocationAllocated, status);
        return status;
    }

    [UnmanagedCallersOnly(EntryPoint = "AtlasApplyFieldReferences", CallConvs = [typeof(CallConvCdecl)])]
    public static int ApplyFieldReferences(nint view) => Run(view, MapFormat.Auto, 0, Operation.FieldReferences, out _);

    [UnmanagedCallersOnly(EntryPoint = "AtlasRestoreEnumTypes", CallConvs = [typeof(CallConvCdecl)])]
    public static int RestoreEnumTypes(nint view) => Run(view, MapFormat.Auto, 0, Operation.RestoreEnums, out _);

    private static int Run(nint view, MapFormat format, nint task, Operation operation, out ApplyStats stats) {
        long operationAllocated = GC.GetAllocatedBytesForCurrentThread();
        stats = default;

        TaskCompletionSource? completed = null;
        nint activeFile = 0;

        try {
            using var cancellation = new BackgroundCancellation(task);
            CancellationToken cancellationToken = cancellation.Token;
            cancellationToken.ThrowIfCancellationRequested();

            if (view == 0 || format is < MapFormat.Auto or > MapFormat.Metadata)
                throw new ArgumentException("A valid view and map format are required.");

            if (Core.BNGetCurrentCoreABIVersion() != 187)
                throw new NotSupportedException("AOT Atlas requires Binary Ninja core ABI 187.");

            activeFile = Core.BNGetFileForView(view);
            while (true) {
                TaskCompletionSource pending;
                lock (ActiveLock) {
                    if (!ActiveFiles.TryGetValue(activeFile, out pending!)) {
                        completed = new(TaskCreationOptions.RunContinuationsAsynchronously);
                        ActiveFiles.Add(activeFile, completed);
                        break;
                    }
                }

                if (operation == Operation.RestoreAnnotations)
                    return 0;

                pending.Task.Wait(cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
            }

            using var currentView = new AnnotationView(view);
            AnnotationArtifacts? artifacts = null;

            if (operation is Operation.RestoreEnums or Operation.RestoreAnnotations) {
                int enums;
                if (!EnumTypes.TryRestoreSignedTypes(currentView, out enums, out var originalFormat, cancellationToken)) {
                    NativeApply.Run(currentView, originalFormat, task, out _, out var fresh, cancellationToken);
                    artifacts = fresh;
                }

                if (enums != 0)
                    Log(1, $"Restored {enums} signed enum types.");

                if (operation == Operation.RestoreEnums)
                    return 0;
            }

            if (operation is Operation.FieldReferences or Operation.RestoreAnnotations) {
                int references;
                if (artifacts.HasValue)
                    AnalysisWait.Run(currentView, cancellationToken);

                while (!FieldAnnotations.TryApply(currentView, required: operation == Operation.FieldReferences,
                    out references, out var originalFormat, cancellationToken, artifacts)) {
                    NativeApply.Run(currentView, originalFormat, task, out _, out var fresh, cancellationToken);
                    artifacts = fresh;
                    AnalysisWait.Run(currentView, cancellationToken);
                }

                if (references != 0)
                    Log(1, $"Applied {references} field references.");

                return 0;
            }

            currentView.Refresh();
            if (operation == Operation.Complete && Core.BNGetAnalysisState(currentView.Handle) == 1)
                throw new InvalidOperationException("Release the Binary Ninja analysis hold before running the Atlas command.");

            NativeApplyMeasurement measurement = default;
            double waitSeconds = 0;
            double fieldSeconds = 0;

            while (true) {
                stats = NativeApply.Run(currentView, format, task, out var attempt, out var fresh, cancellationToken);
                measurement = measurement.Add(attempt);

                if (operation != Operation.Complete)
                    break;

                fixed (byte* text = "AOT Atlas: analyzing functions\0"u8)
                    Core.BNSetBackgroundTaskProgressText(task, text);

                long waitStart = Stopwatch.GetTimestamp();
                AnalysisWait.Run(currentView, cancellationToken);
                waitSeconds += Stopwatch.GetElapsedTime(waitStart).TotalSeconds;

                long fieldStart = Stopwatch.GetTimestamp();
                bool current = FieldAnnotations.TryApply(currentView, required: true, out int references,
                    out format, cancellationToken, fresh);
                fieldSeconds += Stopwatch.GetElapsedTime(fieldStart).TotalSeconds;

                if (!current)
                    continue;

                Log(1, $"Applied {references} field references.");
                break;
            }

            Log(1,
                $"Applied {stats.MethodTables} MethodTables, {stats.DataVariables} data variables and {stats.DataReferences} references; "
                + $"operation-thread allocation {GC.GetAllocatedBytesForCurrentThread() - operationAllocated:N0} B; "
                + $"validation/ownership {measurement.ValidationAndOwnership.Seconds * 1000:F1} ms, "
                + $"read/copy {measurement.Read.Seconds * 1000:F1} ms, hash {measurement.Hash.Seconds * 1000:F1} ms, "
                + $"preparation {measurement.Preparation.Seconds * 1000:F1} ms, evidence {measurement.Evidence.Seconds * 1000:F1} ms, "
                + $"preparation attempts {measurement.PreparationAttempts}, input revalidation {measurement.InputRevalidation.Seconds * 1000:F1} ms, "
                + $"input settling {measurement.InputSettling.Seconds * 1000:F1} ms, "
                + $"publication wait {measurement.PublicationWait.Seconds * 1000:F1} ms, "
                + $"application {measurement.Application.Seconds * 1000:F1} ms, ownership cleanup {measurement.OwnershipCleanup.Seconds * 1000:F1} ms, "
                + $"host wait {waitSeconds * 1000:F1} ms, "
                + $"field references {fieldSeconds * 1000:F1} ms.");

            return 0;
        } catch (OperationCanceledException) {
            Log(1, "AOT Atlas cancelled.");

            return 2;
        } catch (Exception error) {
            // Exceptions must end here; unwinding through the hosts C stack is invalid
            Log(3, error.ToString());

            return 1;
        } finally {
            if (completed != null) {
                lock (ActiveLock) {
                    ActiveFiles.Remove(activeFile);
                    completed.SetResult();
                }
            }

            if (activeFile != 0)
                Core.BNFreeFileMetadata(activeFile);
        }
    }

    private static void LogTotal(string operation, long start, long allocated, int status) =>
        Log(1, $"{operation}: status {status}, total {Stopwatch.GetElapsedTime(start).TotalMilliseconds:F1} ms, "
            + $"process managed allocation delta {GC.GetTotalAllocatedBytes(precise: true) - allocated:N0} B.");

    internal static void Log(byte level, string message) {
        byte[] text = Encoding.UTF8.GetBytes(message + '\0');

        fixed (byte* logger = "AOT Atlas\0"u8)
        fixed (byte* pointer = text)
            Core.BNLogString(0, level, logger, 0, pointer);
    }
}
