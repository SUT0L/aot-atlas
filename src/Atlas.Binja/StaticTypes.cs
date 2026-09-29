using System.Text.Unicode;

namespace Atlas.Binja;

internal static unsafe class StaticTypes {
    internal static nint Callable(nint pointer, bool descriptor) {
        nint builder = Core.BNCreateStructureBuilder();
        Core.BNSetStructureBuilderPacked(builder, 1);
        var value = new TypeConfidence(pointer);
        fixed (byte* method = descriptor ? "method\0"u8 : "tagged_method\0"u8)
        fixed (byte* context = "generic_context\0"u8) {
            Core.BNAddStructureBuilderMemberAtOffset(builder, &value, method, 0, 0, 0, 0, 0, 0);
            if (descriptor)
                Core.BNAddStructureBuilderMemberAtOffset(builder, &value, context, 8, 0, 0, 0, 0, 0);
        }
        return Finish(builder);
    }

    internal static nint Header(nint u32, nint pointer) {
        nint builder = Core.BNCreateStructureBuilder();
        Core.BNSetStructureBuilderPacked(builder, 1);
        var integer = new TypeConfidence(u32);
        var related = new TypeConfidence(pointer);
        fixed (byte* names = "flags\0base_size\0related_type\0"u8) {
            Core.BNAddStructureBuilderMemberAtOffset(builder, &integer, names, 0, 0, 0, 0, 0, 0);
            Core.BNAddStructureBuilderMemberAtOffset(builder, &integer, names + 6, 4, 0, 0, 0, 0, 0);
            Core.BNAddStructureBuilderMemberAtOffset(builder, &related, names + 16, 8, 0, 0, 0, 0, 0);
        }
        return Finish(builder);
    }

    internal static nint Cell(nint i32, bool preinitialized) {
        nint builder = Core.BNCreateStructureBuilder();
        Core.BNSetStructureBuilderPacked(builder, 1);
        Core.BNSetStructureBuilderWidth(builder, 8);
        var relative = new TypeConfidence(i32);
        fixed (byte* names = "tagged_descriptor_rel32\0preinit_rel32\0"u8) {
            Core.BNAddStructureBuilderMemberAtOffset(builder, &relative, names, 0, 0, 0, 0, 0, 0);
            if (preinitialized)
                Core.BNAddStructureBuilderMemberAtOffset(builder, &relative, names + 24, 4, 0, 0, 0, 0, 0);
        }
        return Finish(builder);
    }

    internal static nint ThreadIndex(nint pointer, nint i64) {
        nint builder = Core.BNCreateStructureBuilder();
        Core.BNSetStructureBuilderPacked(builder, 1);
        var module = new TypeConfidence(pointer);
        var index = new TypeConfidence(i64);
        fixed (byte* names = "type_manager\0index\0"u8) {
            Core.BNAddStructureBuilderMemberAtOffset(builder, &module, names, 0, 0, 0, 0, 0, 0);
            Core.BNAddStructureBuilderMemberAtOffset(builder, &index, names + 13, 8, 0, 0, 0, 0, 0);
        }
        return Finish(builder);
    }

    internal static nint GcDesc(int count, nint i64) {
        nint pair = Core.BNCreateStructureBuilder();
        Core.BNSetStructureBuilderPacked(pair, 1);
        var integer = new TypeConfidence(i64);
        fixed (byte* names = "encoded_size\0offset\0"u8) {
            Core.BNAddStructureBuilderMemberAtOffset(pair, &integer, names, 0, 0, 0, 0, 0, 0);
            Core.BNAddStructureBuilderMemberAtOffset(pair, &integer, names + 13, 8, 0, 0, 0, 0, 0);
        }
        nint entry = Finish(pair);
        var item = new TypeConfidence(entry);
        nint array = Core.BNCreateArrayType(&item, (uint)count);
        var series = new TypeConfidence(array);
        nint builder = Core.BNCreateStructureBuilder();
        Core.BNSetStructureBuilderPacked(builder, 1);
        fixed (byte* names = "series\0count\0"u8) {
            Core.BNAddStructureBuilderMemberAtOffset(builder, &series, names, 0, 0, 0, 0, 0, 0);
            Core.BNAddStructureBuilderMemberAtOffset(builder, &integer, names + 7, (uint)count * 16UL, 0, 0, 0, 0, 0);
        }
        Core.BNFreeType(array);
        Core.BNFreeType(entry);
        return Finish(builder);
    }

    internal static nint Storage(in StaticAllocation allocation, ReadOnlySpan<GcRun> runs,
        nint descriptorPointer, nint referencePointer, bool payload) {
        nint builder = Core.BNCreateStructureBuilder();
        Core.BNSetStructureBuilderPacked(builder, 1);
        Core.BNSetStructureBuilderWidth(builder, allocation.BaseSize - (payload ? 16U : 8U));
        if (!payload) {
            var header = new TypeConfidence(descriptorPointer);
            fixed (byte* name = "__allocation_descriptor\0"u8)
                Core.BNAddStructureBuilderMemberAtOffset(builder, &header, name, 0, 0, 0, 0, 0, 0);
        }
        var reference = new TypeConfidence(referencePointer);
        Span<byte> text = stackalloc byte[16];
        fixed (byte* name = text) {
            for (int i = allocation.Runs.Start; i < allocation.Runs.End; ++i) {
                ref readonly var run = ref runs[i];
                for (uint j = 0; j < run.Count; ++j) {
                    uint offset = checked(run.Offset + j * 8 - (payload ? 8U : 0U));
                    Utf8.TryWrite(text, $"_ref_{offset:X2}", out int length);
                    text[length] = 0;
                    Core.BNAddStructureBuilderMemberAtOffset(builder, &reference, name, offset, 0, 0, 0, 0, 0);
                }
            }
        }
        return Finish(builder);
    }

    private static nint Finish(nint builder) {
        nint structure = Core.BNFinalizeStructureBuilder(builder);
        nint type = Core.BNCreateStructureType(structure);
        Core.BNFreeStructure(structure);
        Core.BNFreeStructureBuilder(builder);
        return type;
    }
}
