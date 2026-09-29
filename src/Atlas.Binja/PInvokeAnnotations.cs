using System.Runtime.InteropServices;
using System.Text.Unicode;

namespace Atlas.Binja;

internal static unsafe class PInvokeAnnotations {
    internal static void Apply(Symbols symbols, DataVariables variables, nint view, Extraction extraction, nint pointer, nint headerPointer, ref ApplyStats stats, nint task) {
        var fixups = extraction.PInvokes;
        if (fixups.Methods.Count == 0)
            return;

        int maxModule = 0, maxMethod = 0;
        foreach (ref readonly var module in CollectionsMarshal.AsSpan(fixups.Modules))
            maxModule = Math.Max(maxModule, module.Name.Count);
        foreach (ref readonly var method in CollectionsMarshal.AsSpan(fixups.Methods))
            maxMethod = Math.Max(maxMethod, method.Name.Count);

        byte[] text = new byte[checked(maxModule + maxMethod + 64)];
        Span<byte> identifier = stackalloc byte[64];
        byte empty = 0;
        BoolConfidence unsigned = new() { Confidence = 255 }, qualifier = default;
        nint u32 = Core.BNCreateIntegerType(4, &unsigned, &empty);
        nint u64 = Core.BNCreateIntegerType(8, &unsigned, &empty);
        nint character = Core.BNCreateIntegerType(1, &unsigned, &empty);
        var target = new TypeConfidence(character);
        nint namePointer = Core.BNCreatePointerTypeOfWidth(8, &target, &qualifier, &qualifier, 0);
        nint modulePointer = 0;
        nint[] types = new nint[3];
        try {
            fixed (byte* name = text)
            fixed (byte* id = identifier)
            fixed (byte* atlas = "atlas\0"u8)
            fixed (byte* category = "pinvoke\0"u8)
            fixed (byte* join = "::\0"u8) {
                byte** parts = stackalloc byte*[3] { atlas, category, name };
                QualifiedName qualified = new() { Names = parts, Join = join, Count = 3 };
                for (int i = 0; i < types.Length; ++i) {
                    string kind = i == 0 ? "module" : i == 1 ? "named_method" : "ordinal_method";
                    nint type = PInvokeTypes.Cell(i == 0, pointer, i == 2 ? u64 : namePointer,
                        i == 0 ? headerPointer : modulePointer, u32);
                    Utf8.TryWrite(identifier, $"aot-atlas:pinvoke:v1:{kind}\0", out _);
                    Utf8.TryWrite(text, $"{kind}_fixup\0", out _);
                    var actual = Core.BNDefineAnalysisType(view, id, &qualified, type);
                    types[i] = Core.BNCreateNamedTypeReferenceFromTypeAndId(id, &actual, type);
                    Core.BNFreeQualifiedName(&actual);
                    Core.BNFreeType(type);
                    if (i == 0) {
                        target = new TypeConfidence(types[0]);
                        modulePointer = Core.BNCreatePointerTypeOfWidth(8, &target, &qualifier, &qualifier, 0);
                    }
                }

                int processed = 0;
                foreach (ref readonly var module in CollectionsMarshal.AsSpan(fixups.Modules)) {
                    if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();

                    ReadOnlySpan<byte> prefix = "nativeaot::pinvoke_module::"u8;
                    prefix.CopyTo(text);
                    extraction.Image.FileData.AsSpan(module.Name.Start, module.Name.Count).CopyTo(text.AsSpan(prefix.Length));
                    ulong rva = module.Address - extraction.Image.ImageBase;
                    Utf8.TryWrite(text.AsSpan(prefix.Length + module.Name.Count), $"::{rva:X8}\0", out _);
                    ulong address = stats.ImageBase + rva;
                    symbols.DefineData(variables, address, types[0], name, ref stats);
                    Core.BNAddUserDataReference(view, address + 8, stats.ImageBase + (module.NameAddress - extraction.Image.ImageBase));
                    Core.BNAddUserDataReference(view, address + 16, stats.ImageBase + (module.CallingAssemblyType - extraction.Image.ImageBase));
                    stats.DataReferences += 2;
                }

                processed = 0;
                foreach (ref readonly var method in CollectionsMarshal.AsSpan(fixups.Methods)) {
                    if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();

                    ref readonly var module = ref CollectionsMarshal.AsSpan(fixups.Modules)[method.Module];
                    ReadOnlySpan<byte> prefix = "nativeaot::pinvoke::"u8;
                    prefix.CopyTo(text);
                    extraction.Image.FileData.AsSpan(module.Name.Start, module.Name.Count).CopyTo(text.AsSpan(prefix.Length));
                    int position = prefix.Length + module.Name.Count;
                    "::"u8.CopyTo(text.AsSpan(position));
                    position += 2;
                    if (method.ByOrdinal) {
                        Utf8.TryWrite(text.AsSpan(position), $"#{method.EntryPoint}", out int written);
                        position += written;
                    } else {
                        extraction.Image.FileData.AsSpan(method.Name.Start, method.Name.Count).CopyTo(text.AsSpan(position));
                        position += method.Name.Count;
                    }
                    ulong rva = method.Address - extraction.Image.ImageBase;
                    Utf8.TryWrite(text.AsSpan(position), $"::{rva:X8}\0", out _);
                    ulong address = stats.ImageBase + rva;
                    symbols.DefineData(variables, address, types[method.ByOrdinal ? 2 : 1], name, ref stats);
                    Core.BNAddUserDataReference(view, address + 16, stats.ImageBase + (module.Address - extraction.Image.ImageBase));
                    ++stats.DataReferences;
                    if (!method.ByOrdinal) {
                        Core.BNAddUserDataReference(view, address + 8, stats.ImageBase + (method.EntryPoint - extraction.Image.ImageBase));
                        ++stats.DataReferences;
                    }
                }
            }
        } finally {
            foreach (nint type in types) {
                if (type != 0)
                    Core.BNFreeType(type);
            }
            if (modulePointer != 0)
                Core.BNFreeType(modulePointer);
            Core.BNFreeType(namePointer);
            Core.BNFreeType(character);
            Core.BNFreeType(u64);
            Core.BNFreeType(u32);
        }
    }
}
