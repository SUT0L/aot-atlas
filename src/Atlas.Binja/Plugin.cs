using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace Atlas.Binja;

[StructLayout(LayoutKind.Sequential)]
public unsafe struct ApplyStats {
    public ulong InputBytes, ImageBase;
    public uint MethodTables, DataVariables, Symbols, DataReferences;
    public double ExtractSeconds, ApplySeconds;
    public fixed byte InputSha256[32];
}

public static unsafe class Plugin {
    private enum Operation : byte { Metadata, FieldReferences, RestoreAnnotations, RestoreEnums, Complete }
    private static readonly Lock ActiveLock = new();
    private static readonly HashSet<nint> ActiveViews = [];

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
    private static void RestoreAnnotations(nint context, nint view) =>
        Run(view, MapFormat.Auto, 0, Operation.RestoreAnnotations, out _);

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
        nint ownedView = Core.BNNewViewReference(view);
        try {
            // Analysis waits are prohibited on Binary Ninjas own worker threads
            ThreadPool.QueueUserWorkItem(static owned => Work(owned), ownedView, preferLocal: false);
        } catch (Exception error) {
            Core.BNFreeBinaryView(ownedView);
            Log(3, error.ToString());
        }
    }

    private static void Work(nint view) {
        nint task;
        fixed (byte* text = "AOT Atlas: extracting\0"u8)
            task = Core.BNBeginBackgroundTask(text, 1);

        try {
            Run(view, MapFormat.Auto, task, Operation.Complete, out _);
        } finally {
            Core.BNFreeBinaryView(view);
            Core.BNFinishBackgroundTask(task);
            Core.BNFreeBackgroundTask(task);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "AtlasApplyMetadata", CallConvs = [typeof(CallConvCdecl)])]
    public static int Apply(nint view, byte format, ApplyStats* output) {
        int status = Run(view, (MapFormat)format, 0, Operation.Metadata, out var stats);
        if (output != null)
            *output = stats;

        return status;
    }

    [UnmanagedCallersOnly(EntryPoint = "AtlasApplyFieldReferences", CallConvs = [typeof(CallConvCdecl)])]
    public static int ApplyFieldReferences(nint view) => Run(view, MapFormat.Auto, 0, Operation.FieldReferences, out _);

    [UnmanagedCallersOnly(EntryPoint = "AtlasRestoreEnumTypes", CallConvs = [typeof(CallConvCdecl)])]
    public static int RestoreEnumTypes(nint view) => Run(view, MapFormat.Auto, 0, Operation.RestoreEnums, out _);

    private static int Run(nint view, MapFormat format, nint task, Operation operation, out ApplyStats stats) {
        stats = default;
        bool entered = false;
        try {
            if (view == 0 || format is < MapFormat.Auto or > MapFormat.Metadata)
                throw new ArgumentException("A valid view and map format are required.");
            if (Core.BNGetCurrentCoreABIVersion() != 187)
                throw new NotSupportedException("AOT Atlas requires Binary Ninja core ABI 187.");

            lock (ActiveLock)
                entered = ActiveViews.Add(view);

            if (!entered) {
                if (operation == Operation.RestoreAnnotations)
                    return 0;
                throw new InvalidOperationException("AOT Atlas is already applying metadata to this view.");
            }

            if (operation is Operation.RestoreEnums or Operation.RestoreAnnotations) {
                int enums = EnumTypes.RestoreSignedTypes(view);
                if (enums != 0)
                    Log(1, $"Restored {enums} signed enum types.");
                if (operation == Operation.RestoreEnums)
                    return 0;
            }
            if (operation is Operation.FieldReferences or Operation.RestoreAnnotations) {
                int references = FieldAnnotations.Apply(view, required: operation == Operation.FieldReferences);
                if (references != 0)
                    Log(1, $"Applied {references} field references.");
                return 0;
            }
            if (operation == Operation.Complete && Core.BNGetAnalysisState(view) == 1)
                throw new InvalidOperationException("Release the Binary Ninja analysis hold before running the Atlas command.");

            stats = NativeApply.Run(view, format, task);
            if (operation == Operation.Complete) {
                fixed (byte* text = "AOT Atlas: analyzing functions\0"u8)
                    Core.BNSetBackgroundTaskProgressText(task, text);
                Core.BNUpdateAnalysisAndWait(view);
                if (Core.BNIsBackgroundTaskCancelled(task) != 0)
                    throw new OperationCanceledException();
                int references = FieldAnnotations.Apply(view, required: true);
                Log(1, $"Applied {references} field references.");
            }
            Log(1, $"Applied {stats.MethodTables} MethodTables, {stats.DataVariables} data variables and {stats.DataReferences} references; extraction {stats.ExtractSeconds * 1000:F1} ms, application {stats.ApplySeconds * 1000:F1} ms.");
            return 0;
        } catch (OperationCanceledException) {
            Log(1, "AOT Atlas cancelled.");
            return 2;
        } catch (Exception error) {
            // Exceptions must end here; unwinding through the hosts C stack is invalid
            Log(3, error.ToString());
            return 1;
        } finally {
            if (entered) {
                lock (ActiveLock)
                    ActiveViews.Remove(view);
            }
        }
    }

    private static void Log(byte level, string message) {
        byte[] text = Encoding.UTF8.GetBytes(message + '\0');
        fixed (byte* logger = "AOT Atlas\0"u8)
        fixed (byte* pointer = text)
            Core.BNLogString(0, level, logger, 0, pointer);
    }
}
