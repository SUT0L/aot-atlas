namespace Atlas.Binja;

internal static unsafe class UnwindTypes {
    internal static nint Entry(nint u32) {
        nint builder = Core.BNCreateStructureBuilder();
        Core.BNSetStructureBuilderPacked(builder, 1);
        var integer = new TypeConfidence(u32);
        fixed (byte* names = "begin_rva\0end_rva\0unwind_data\0"u8) {
            Core.BNAddStructureBuilderMemberAtOffset(builder, &integer, names, 0, 0, 0, 0, 0, 0);
            Core.BNAddStructureBuilderMemberAtOffset(builder, &integer, names + 10, 4, 0, 0, 0, 0, 0);
            Core.BNAddStructureBuilderMemberAtOffset(builder, &integer, names + 18, 8, 0, 0, 0, 0, 0);
        }
        nint structure = Core.BNFinalizeStructureBuilder(builder);
        nint type = Core.BNCreateStructureType(structure);
        Core.BNFreeStructure(structure);
        Core.BNFreeStructureBuilder(builder);
        return type;
    }

    internal static nint Info(in UnwindInfo info, nint u8, nint u16, nint u32, nint entry) {
        nint builder = Core.BNCreateStructureBuilder();
        Core.BNSetStructureBuilderPacked(builder, 1);
        Core.BNSetStructureBuilderWidth(builder, info.Length);
        var small = new TypeConfidence(u8);
        var word = new TypeConfidence(u16);
        var integer = new TypeConfidence(u32);
        var function = new TypeConfidence(entry);
        fixed (byte* names = "version_flags\0prolog_size\0slot_count\0frame_register_offset\0codes\0handler_rva\0chained_function\0"u8) {
            Core.BNAddStructureBuilderMemberAtOffset(builder, &small, names, 0, 0, 0, 0, 0, 0);
            Core.BNAddStructureBuilderMemberAtOffset(builder, &small, names + 14, 1, 0, 0, 0, 0, 0);
            Core.BNAddStructureBuilderMemberAtOffset(builder, &small, names + 26, 2, 0, 0, 0, 0, 0);
            Core.BNAddStructureBuilderMemberAtOffset(builder, &small, names + 37, 3, 0, 0, 0, 0, 0);
            if (info.SlotCount != 0) {
                nint array = Core.BNCreateArrayType(&word, info.SlotCount);
                var codes = new TypeConfidence(array);
                Core.BNAddStructureBuilderMemberAtOffset(builder, &codes, names + 59, 4, 0, 0, 0, 0, 0);
                Core.BNFreeType(array);
            }

            if ((info.Flags & 4) != 0)
                Core.BNAddStructureBuilderMemberAtOffset(builder, &function, names + 77, (uint)info.TailOffset, 0, 0, 0, 0, 0);
            else if ((info.Flags & 3) != 0)
                Core.BNAddStructureBuilderMemberAtOffset(builder, &integer, names + 65, (uint)info.TailOffset, 0, 0, 0, 0, 0);
        }
        nint structure = Core.BNFinalizeStructureBuilder(builder);
        nint type = Core.BNCreateStructureType(structure);
        Core.BNFreeStructure(structure);
        Core.BNFreeStructureBuilder(builder);
        return type;
    }
}
