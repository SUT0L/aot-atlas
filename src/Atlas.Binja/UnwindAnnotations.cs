using System.Runtime.InteropServices;
using System.Text.Unicode;

namespace Atlas.Binja;

internal static unsafe class UnwindAnnotations {
    internal static void Apply(Symbols symbols, TagOwnership ownership, DataVariables variables, nint view, Extraction extraction, ref ApplyStats stats, nint task) {
        var unwind = extraction.Unwind;
        if (unwind.DirectoryCount == 0)
            return;

        ownership.Reserve(unwind.Entries.Count);

        nint platform = Core.BNGetDefaultPlatform(view);
        if (platform == 0)
            throw new NotSupportedException("The Binary Ninja view has no platform for runtime functions.");

        byte empty = 0;
        BoolConfidence unsigned = new() { Confidence = 255 };
        nint u8 = Core.BNCreateIntegerType(1, &unsigned, &empty);
        nint u16 = Core.BNCreateIntegerType(2, &unsigned, &empty);
        nint u32 = Core.BNCreateIntegerType(4, &unsigned, &empty);
        nint entryType = UnwindTypes.Entry(u32);
        nint[] types = new nint[768];
        nint tagType = 0;
        Span<byte> text = stackalloc byte[192];
        Span<byte> identifier = stackalloc byte[64];
        var embedded = new bool[unwind.Entries.Count];
        var functions = new HashSet<uint>(unwind.DirectoryCount);
        try {
            fixed (byte* name = "AOT Atlas unwind\0"u8)
            fixed (byte* icon = "🧵\0"u8) {
                tagType = Core.BNGetTagType(view, name);
                if (tagType == 0) {
                    tagType = Core.BNCreateTagType(view);
                    Core.BNTagTypeSetName(tagType, name);
                    Core.BNTagTypeSetIcon(tagType, icon);
                    Core.BNAddTagType(view, tagType);
                }
            }

            fixed (byte* name = text)
            fixed (byte* id = identifier)
            fixed (byte* atlas = "atlas\0"u8)
            fixed (byte* category = "pe\0"u8)
            fixed (byte* join = "::\0"u8) {
                byte** parts = stackalloc byte*[3] { atlas, category, name };
                QualifiedName qualified = new() { Names = parts, Join = join, Count = 3 };
                "runtime_function\0"u8.CopyTo(text);
                "aot-atlas:runtime-function:v1\0"u8.CopyTo(identifier);
                var actual = Core.BNDefineAnalysisType(view, id, &qualified, entryType);
                nint reference = Core.BNCreateNamedTypeReferenceFromTypeAndId(id, &actual, entryType);
                Core.BNFreeQualifiedName(&actual);
                var element = new TypeConfidence(reference);
                nint array = Core.BNCreateArrayType(&element, (uint)unwind.DirectoryCount);
                Core.BNFreeType(reference);
                "pe::runtime_functions\0"u8.CopyTo(text);
                symbols.DefineData(variables, stats.ImageBase + extraction.Image.ExceptionRva, array, name, ref stats);
                Core.BNFreeType(array);

                int processed = 0;
                foreach (ref readonly var info in CollectionsMarshal.AsSpan(unwind.Infos)) {
                    if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();

                    int tail = (info.Flags & 4) != 0 ? 2 : (info.Flags & 3) != 0 ? 1 : 0;
                    int key = tail * 256 + info.SlotCount;
                    if (types[key] == 0) {
                        nint type = UnwindTypes.Info(info, u8, u16, u32, entryType);
                        Utf8.TryWrite(identifier, $"aot-atlas:unwind-info:v1:{key:X3}\0", out _);
                        Utf8.TryWrite(text, $"unwind_info_{key:X3}\0", out _);
                        actual = Core.BNDefineAnalysisType(view, id, &qualified, type);
                        types[key] = Core.BNCreateNamedTypeReferenceFromTypeAndId(id, &actual, type);
                        Core.BNFreeQualifiedName(&actual);
                        Core.BNFreeType(type);
                    }

                    Utf8.TryWrite(text, $"pe::unwind_info::{info.Address:X8}\0", out _);
                    symbols.DefineData(variables, stats.ImageBase + info.Address, types[key], name, ref stats);
                    if (info.ChainedEntry != 0)
                        embedded[info.ChainedEntry - 1] = true;
                    if (info.Handler != 0) {
                        Core.BNAddUserDataReference(view, stats.ImageBase + info.Address + (uint)info.TailOffset, stats.ImageBase + info.Handler);
                        ++stats.DataReferences;
                        functions.Add(info.Handler);
                    }
                }

                for (int i = 0; i < unwind.Entries.Count; ++i) {
                    if (task != 0 && (i & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();

                    var entry = unwind.Entries[i];
                    var root = unwind.Entries[entry.Root - 1];
                    ulong address = stats.ImageBase + entry.Address;
                    if (i >= unwind.DirectoryCount && !embedded[i]) {
                        Utf8.TryWrite(text, $"pe::runtime_function::{entry.Address:X8}\0", out _);
                        symbols.DefineData(variables, address, entryType, name, ref stats);
                    }

                    Core.BNAddUserDataReference(view, address, stats.ImageBase + entry.Function.Begin);
                    Core.BNAddUserDataReference(view, address + 8, stats.ImageBase + (entry.Function.Unwind & ~1U));
                    stats.DataReferences += 2;
                    if (entry.Parent != 0 && root.Function.Begin != entry.Function.Begin) {
                        Core.BNAddUserDataReference(view, address, stats.ImageBase + root.Function.Begin);
                        ++stats.DataReferences;
                    }
                    Utf8.TryWrite(text, $"pe::unwind_range::{entry.Function.Begin:X8}-{entry.Function.End:X8} record={entry.Address:X8} unwind={entry.Function.Unwind:X8} root={root.Address:X8}\0", out int length);
                    DataTags.Set(ownership, view, tagType, address, text[..length]);

                    if (entry.Parent == 0)
                        functions.Add(entry.Function.Begin);
                }

                foreach (ref readonly var frame in extraction.Managed.Frames.AsSpan()) {
                    if (frame.UnboxingTarget != 0)
                        functions.Add(frame.UnboxingTarget);
                }

                processed = 0;
                foreach (uint rva in functions) {
                    if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();

                    ulong begin = stats.ImageBase + rva;
                    nint function = Core.BNGetAnalysisFunction(view, platform, begin);
                    if (function == 0)
                        function = Core.BNAddFunctionForAnalysis(view, platform, begin, 0, 0);
                    if (function == 0)
                        throw new InvalidDataException($"Binary Ninja rejected the runtime function at 0x{begin:X}.");
                    Core.BNFreeFunction(function);
                }
            }
        } finally {
            Core.BNFreePlatform(platform);
            if (tagType != 0)
                Core.BNFreeTagType(tagType);
            foreach (nint type in types) {
                if (type != 0)
                    Core.BNFreeType(type);
            }
            Core.BNFreeType(entryType);
            Core.BNFreeType(u32);
            Core.BNFreeType(u16);
            Core.BNFreeType(u8);
        }
    }
}
