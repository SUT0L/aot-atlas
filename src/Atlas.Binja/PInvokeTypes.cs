namespace Atlas.Binja;

internal static unsafe class PInvokeTypes {
    internal static nint Cell(bool module, nint pointer, nint nameOrOrdinal, nint owner, nint u32) {
        nint builder = Core.BNCreateStructureBuilder();
        Core.BNSetStructureBuilderPacked(builder, 1);
        ReadOnlySpan<byte> names = module
            ? "module_handle\0module_name\0calling_assembly_type\0search_path\0"u8
            : "target\0entry_point\0module\0flags\0"u8;
        ReadOnlySpan<nint> members = [pointer, nameOrOrdinal, owner, u32];
        fixed (byte* text = names) {
            int position = 0;
            for (int i = 0; i < members.Length; ++i) {
                var member = new TypeConfidence(members[i]);
                Core.BNAddStructureBuilderMemberAtOffset(builder, &member, text + position, (uint)i * 8, 0, 0, 0, 0, 0);
                position += names[position..].IndexOf((byte)0) + 1;
            }
        }

        // The PE emitter writes 28 bytes; the runtimes sizeof includes tail padding
        nint structure = Core.BNFinalizeStructureBuilder(builder);
        nint type = Core.BNCreateStructureType(structure);
        Core.BNFreeStructure(structure);
        Core.BNFreeStructureBuilder(builder);
        return type;
    }
}
