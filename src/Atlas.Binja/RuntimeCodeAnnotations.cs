using System.Runtime.InteropServices;
using System.Text;
using System.Text.Unicode;

namespace Atlas.Binja;

internal static unsafe class RuntimeCodeAnnotations {
    internal static void Apply(Symbols symbols, nint view, Extraction extraction, RuntimeCode runtime, ref ApplyStats stats, nint task) {
        if (runtime.Functions.Length == 0)
            return;

        nint platform = Core.BNGetDefaultPlatform(view);
        if (platform == 0)
            throw new NotSupportedException("The Binary Ninja view has no platform for runtime functions.");

        char[] text = new char[runtime.NameCapacity];
        byte[] utf8 = new byte[checked(Encoding.UTF8.GetMaxByteCount(text.Length) + 1)];
        var roles = CollectionsMarshal.AsSpan(runtime.Roles);
        ulong baseAddress = extraction.Image.ImageBase;
        try {
            fixed (byte* name = utf8) {
                int processed = 0;
                foreach (var group in runtime.Functions) {
                    if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();

                    ref readonly var first = ref roles[group.Start];
                    ulong address = stats.ImageBase + (first.Target - baseAddress);
                    nint function = Core.BNGetAnalysisFunction(view, platform, address);
                    if (function == 0)
                        function = Core.BNAddFunctionForAnalysis(view, platform, address, 0, 0);
                    if (function == 0)
                        throw new InvalidOperationException($"Binary Ninja rejected runtime function 0x{address:X}.");
                    Core.BNFreeFunction(function);

                    if (group.Count == 1) {
                        int length = RuntimeCode.WriteName(extraction, first, text);
                        int bytes = Encoding.UTF8.GetBytes(text.AsSpan(0, length), utf8);
                        utf8[bytes] = 0;
                    } else {
                        Utf8.TryWrite(utf8, $"runtime_roles::shared::{first.Target - baseAddress:X8}\0", out _);
                    }
                    symbols.Define(address, 0, name);
                    ++stats.Symbols;

                    // Vtable and dispatch stages already link their pointer cells
                    // Finalizers and initializer lists need the same navigation
                    foreach (ref readonly var role in roles.Slice(group.Start, group.Count)) {
                        if (role.Kind is RuntimeCodeKind.Vtable or RuntimeCodeKind.SealedVtable)
                            continue;
                        Core.BNAddUserDataReference(view, stats.ImageBase + (role.Witness - baseAddress), address);
                        ++stats.DataReferences;
                    }
                }
            }
        } finally {
            Core.BNFreePlatform(platform);
        }
    }
}
