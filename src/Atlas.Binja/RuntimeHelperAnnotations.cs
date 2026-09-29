using System.Text;

namespace Atlas.Binja;

internal static unsafe class RuntimeHelperAnnotations {
    internal static void Apply(Symbols symbols, DataVariables variables, nint view, Extraction extraction,
        RuntimeHelpers helpers, nint pointer, ref ApplyStats stats) {
        if (helpers.Status != RuntimeHelperStatus.Complete)
            return;

        ulong original = extraction.Image.ImageBase;
        var confidence = new TypeConfidence(pointer);
        nint builder = Core.BNCreateStructureBuilder();
        nint table;
        byte[] buffer = new byte[192];
        try {
            int helperIndex = 0;
            for (int slot = 0; slot < helpers.TableCount; ++slot) {
                bool present = helperIndex < helpers.Helpers.Length && helpers.Helpers[helperIndex].Cell == helpers.Table + (uint)slot * 8UL;
                string member = present ? helpers.Helpers[helperIndex++].Role : $"reserved_{slot}";
                int length = Encoding.UTF8.GetBytes(member, buffer);
                buffer[length] = 0;
                fixed (byte* name = buffer)
                    Core.BNAddStructureBuilderMemberAtOffset(builder, &confidence, name, (uint)slot * 8UL, 0, 0, 0, 0, 0);
            }
            Core.BNSetStructureBuilderWidth(builder, (uint)helpers.TableCount * 8UL);
            nint structure = Core.BNFinalizeStructureBuilder(builder);
            table = Core.BNCreateStructureType(structure);
            Core.BNFreeStructure(structure);
        } finally {
            Core.BNFreeStructureBuilder(builder);
        }
        nint platform = Core.BNGetDefaultPlatform(view);
        if (platform == 0) {
            Core.BNFreeType(table);
            throw new NotSupportedException("The Binary Ninja view has no platform for runtime helpers.");
        }

        try {
            fixed (byte* name = "runtime::classlib_functions\0"u8)
                symbols.DefineData(variables, stats.ImageBase + helpers.Table - original, table, name, ref stats);

            foreach (var helper in helpers.Helpers) {
                ulong address = stats.ImageBase + helper.Address - original;
                nint function = Core.BNGetAnalysisFunction(view, platform, address);
                if (function == 0)
                    function = Core.BNAddFunctionForAnalysis(view, platform, address, 0, 0);
                if (function == 0)
                    throw new InvalidOperationException($"Binary Ninja rejected runtime helper 0x{address:X}.");
                Core.BNFreeFunction(function);

                ReadOnlySpan<byte> prefix = "runtime::classlib::"u8;
                prefix.CopyTo(buffer);
                int length = Encoding.UTF8.GetBytes(helper.Role, buffer.AsSpan(prefix.Length));
                buffer[prefix.Length + length] = 0;
                fixed (byte* name = buffer)
                    symbols.Define(address, 0, name);
                ++stats.Symbols;
                Core.BNAddUserDataReference(view, stats.ImageBase + helper.Cell - original, address);
                ++stats.DataReferences;
            }
            Core.BNAddUserDataReference(view, stats.ImageBase + helpers.Registration - original, stats.ImageBase + helpers.Table - original);
            Core.BNAddUserDataReference(view, stats.ImageBase + helpers.Registration - original, stats.ImageBase + helpers.ModuleArray - original);
            stats.DataReferences += 2;
        } finally {
            Core.BNFreePlatform(platform);
            Core.BNFreeType(table);
        }
    }
}
