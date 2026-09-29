using System.Buffers;
using System.Buffers.Text;

namespace Atlas.Binja;

internal static unsafe class ObjectTypes {
    internal static nint Box(uint width, nint payload, nint headerPointer) {
        nint builder = Core.BNCreateStructureBuilder();
        Core.BNSetStructureBuilderPacked(builder, 1);
        Core.BNSetStructureBuilderWidth(builder, width);
        var header = new TypeConfidence(headerPointer);
        var value = new TypeConfidence(payload);
        fixed (byte* name = "method_table\0payload\0"u8) {
            Core.BNAddStructureBuilderMemberAtOffset(builder, &header, name, 0, 0, 0, 0, 0, 0);
            Core.BNAddStructureBuilderMemberAtOffset(builder, &value, name + 13, 8, 0, 0, 0, 0, 0);
        }

        nint structure = Core.BNFinalizeStructureBuilder(builder);
        nint result = Core.BNCreateStructureType(structure);
        Core.BNFreeStructure(structure);
        Core.BNFreeStructureBuilder(builder);
        return result;
    }

    internal static nint DefineBox(nint view, uint rva, uint width, nint payload, nint headerPointer) {
        Span<byte> identifier = stackalloc byte[40];
        ReadOnlySpan<byte> prefix = "aot-atlas:boxed-type:v1:"u8;
        prefix.CopyTo(identifier);
        Utf8Formatter.TryFormat(rva, identifier[prefix.Length..], out _, new StandardFormat('X', 8));
        identifier[prefix.Length + 8] = 0;
        nint type = Box(width, payload, headerPointer);
        try {
            fixed (byte* id = identifier)
            fixed (byte* atlas = "atlas\0"u8)
            fixed (byte* boxed = "boxed\0"u8)
            fixed (byte* join = "::\0"u8) {
                byte** parts = stackalloc byte*[3] { atlas, boxed, id + prefix.Length };
                QualifiedName name = new() { Names = parts, Join = join, Count = 3 };
                var actual = Core.BNDefineAnalysisType(view, id, &name, type);
                nint reference = Core.BNCreateNamedTypeReferenceFromTypeAndId(id, &actual, type);
                Core.BNFreeQualifiedName(&actual);
                return reference;
            }
        } finally {
            Core.BNFreeType(type);
        }
    }

    internal static nint Sequence(in FrozenObject entry, in MethodTable table, nint element, nint headerPointer, nint integer) {
        bool text = entry.Kind == FrozenKind.String;
        var component = new TypeConfidence(element);
        nint array = Core.BNCreateArrayType(&component, (uint)entry.Count + (text ? 1U : 0));
        nint dimensions = 0;
        nint builder = Core.BNCreateStructureBuilder();
        try {
            Core.BNSetStructureBuilderPacked(builder, 1);
            Core.BNSetStructureBuilderWidth(builder, (uint)entry.AllocationSize - 8);
            var header = new TypeConfidence(headerPointer);
            var length = new TypeConfidence(integer);
            var elements = new TypeConfidence(array);
            fixed (byte* names = "method_table\0length\0elements\0chars\0dimensions\0lower_bounds\0"u8) {
                Core.BNAddStructureBuilderMemberAtOffset(builder, &header, names, 0, 0, 0, 0, 0, 0);
                Core.BNAddStructureBuilderMemberAtOffset(builder, &length, names + 13, 8, 0, 0, 0, 0, 0);
                Core.BNAddStructureBuilderMemberAtOffset(builder, &elements, names + (text ? 29 : 20),
                    (uint)(entry.Data.Start - entry.Offset), 0, 0, 0, 0, 0);

                if (!text && table.ElementType == 0x17) {
                    uint rank = (table.BaseSize - 24) / 8;
                    dimensions = Core.BNCreateArrayType(&length, rank);
                    var dimensionType = new TypeConfidence(dimensions);
                    Core.BNAddStructureBuilderMemberAtOffset(builder, &dimensionType, names + 35, 16, 0, 0, 0, 0, 0);
                    Core.BNAddStructureBuilderMemberAtOffset(builder, &dimensionType, names + 46, 16 + rank * 4, 0, 0, 0, 0, 0);
                }
            }

            nint structure = Core.BNFinalizeStructureBuilder(builder);
            nint result = Core.BNCreateStructureType(structure);
            Core.BNFreeStructure(structure);
            return result;
        } finally {
            Core.BNFreeStructureBuilder(builder);
            if (dimensions != 0)
                Core.BNFreeType(dimensions);
            Core.BNFreeType(array);
        }
    }
}
