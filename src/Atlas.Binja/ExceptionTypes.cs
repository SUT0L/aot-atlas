namespace Atlas.Binja;

internal static unsafe class ExceptionTypes {
    internal static nint Header(int key, nint u8, nint u32, nint i32) {
        nint builder = Core.BNCreateStructureBuilder();
        Core.BNSetStructureBuilderPacked(builder, 1);
        var flag = new TypeConfidence(u8);
        var rva = new TypeConfidence(u32);
        var signedRva = new TypeConfidence(i32);
        fixed (byte* names = "flags\0associated_data_rva\0eh_info_rva\0"u8) {
            Core.BNAddStructureBuilderMemberAtOffset(builder, &flag, names, 0, 0, 0, 0, 0, 0);
            if ((key & 2) != 0)
                Core.BNAddStructureBuilderMemberAtOffset(builder, &rva, names + 6, 1, 0, 0, 0, 0, 0);
            if ((key & 1) != 0)
                Core.BNAddStructureBuilderMemberAtOffset(builder, &signedRva, names + 26, (key & 2) == 0 ? 1U : 5U, 0, 0, 0, 0, 0);
        }
        nint structure = Core.BNFinalizeStructureBuilder(builder);
        nint type = Core.BNCreateStructureType(structure);
        Core.BNFreeStructure(structure);
        Core.BNFreeStructureBuilder(builder);
        return type;
    }

    internal static nint Associated(int key, nint u8, nint i32) {
        nint builder = Core.BNCreateStructureBuilder();
        Core.BNSetStructureBuilderPacked(builder, 1);
        var flag = new TypeConfidence(u8);
        var target = new TypeConfidence(i32);
        fixed (byte* names = "flags\0unboxing_target_rel32\0"u8) {
            Core.BNAddStructureBuilderMemberAtOffset(builder, &flag, names, 0, 0, 0, 0, 0, 0);
            if ((key & 1) != 0)
                Core.BNAddStructureBuilderMemberAtOffset(builder, &target, names + 6, 1, 0, 0, 0, 0, 0);
        }
        nint structure = Core.BNFinalizeStructureBuilder(builder);
        nint type = Core.BNCreateStructureType(structure);
        Core.BNFreeStructure(structure);
        Core.BNFreeStructureBuilder(builder);
        return type;
    }
}
