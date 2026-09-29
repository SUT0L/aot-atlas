namespace Atlas.Binja;

internal static unsafe class DispatchTypes {
    internal static nint Entry(nint u16, bool isStatic) {
        nint builder = Core.BNCreateStructureBuilder();
        Core.BNSetStructureBuilderPacked(builder, 1);
        var member = new TypeConfidence(u16);
        fixed (byte* names = "interface_index\0interface_slot\0implementation_slot\0context_source\0"u8) {
            Core.BNAddStructureBuilderMemberAtOffset(builder, &member, names, 0, 0, 0, 0, 0, 0);
            Core.BNAddStructureBuilderMemberAtOffset(builder, &member, names + 16, 2, 0, 0, 0, 0, 0);
            Core.BNAddStructureBuilderMemberAtOffset(builder, &member, names + 31, 4, 0, 0, 0, 0, 0);
            if (isStatic)
                Core.BNAddStructureBuilderMemberAtOffset(builder, &member, names + 51, 6, 0, 0, 0, 0, 0);
        }
        nint structure = Core.BNFinalizeStructureBuilder(builder);
        nint type = Core.BNCreateStructureType(structure);
        Core.BNFreeStructure(structure);
        Core.BNFreeStructureBuilder(builder);
        return type;
    }

    internal static nint Map(in DispatchMap map, nint u16, nint instance, nint statics) {
        nint builder = Core.BNCreateStructureBuilder();
        Core.BNSetStructureBuilderPacked(builder, 1);
        var integer = new TypeConfidence(u16);
        fixed (byte* names = "standard_count\0default_count\0static_count\0static_default_count\0standard_entries\0default_entries\0static_entries\0static_default_entries\0"u8) {
            Span<int> counts = stackalloc int[4] { map.StandardCount, map.DefaultCount, map.StaticCount, map.StaticDefaultCount };
            Span<int> countNames = stackalloc int[4] { 0, 15, 29, 42 };
            Span<int> arrayNames = stackalloc int[4] { 63, 80, 96, 111 };
            uint offset = 8;
            for (int i = 0; i < 4; ++i) {
                Core.BNAddStructureBuilderMemberAtOffset(builder, &integer, names + countNames[i], (uint)i * 2, 0, 0, 0, 0, 0);
                if (counts[i] == 0)
                    continue;
                var entry = new TypeConfidence(i < 2 ? instance : statics);
                nint array = Core.BNCreateArrayType(&entry, (uint)counts[i]);
                var member = new TypeConfidence(array);
                Core.BNAddStructureBuilderMemberAtOffset(builder, &member, names + arrayNames[i], offset, 0, 0, 0, 0, 0);
                offset += (uint)counts[i] * (i < 2 ? 6U : 8U);
                Core.BNFreeType(array);
            }
        }
        nint structure = Core.BNFinalizeStructureBuilder(builder);
        nint type = Core.BNCreateStructureType(structure);
        Core.BNFreeStructure(structure);
        Core.BNFreeStructureBuilder(builder);
        return type;
    }
}
