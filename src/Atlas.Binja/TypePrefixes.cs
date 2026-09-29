using System.Buffers;
using System.Buffers.Text;

namespace Atlas.Binja;

internal struct TypePrefix {
    internal int TypeIndex;
    internal uint Width;
    internal nint Reference;
    internal QualifiedName Name;
}

internal sealed unsafe class TypePrefixes(nint view) {
    internal readonly List<TypePrefix> Jobs = [];
    private readonly Dictionary<(nint Source, uint Width), int> index = [];

    internal nint Add(nint source, int typeIndex, uint width) {
        if (index.TryGetValue((source, width), out int existing))
            return Jobs[existing].Reference;

        nint sourceReference = Core.BNGetTypeNamedTypeReference(source);
        byte* sourceId = Core.BNGetTypeReferenceId(sourceReference);
        var sourceName = Core.BNGetTypeReferenceName(sourceReference);
        Core.BNFreeNamedTypeReference(sourceReference);
        try {
            int sourceLength = 0;
            while (sourceId[sourceLength] != 0)
                ++sourceLength;

            Span<byte> id = stackalloc byte[128];
            ReadOnlySpan<byte> prefix = "aot-atlas:prefix:v1:"u8;
            prefix.CopyTo(id);
            new ReadOnlySpan<byte>(sourceId, sourceLength).CopyTo(id[prefix.Length..]);
            int suffix = prefix.Length + sourceLength;
            id[suffix++] = (byte)':';
            Utf8Formatter.TryFormat(width, id[suffix..], out _, new StandardFormat('X', 8));
            id[suffix + 8] = 0;

            fixed (byte* identifier = id)
            fixed (byte* prefixName = "prefix\0"u8) {
                byte** parts = stackalloc byte*[5] {
                    sourceName.Names[0], prefixName, sourceName.Names[1], sourceName.Names[2], identifier + suffix
                };
                QualifiedName name = new() { Names = parts, Join = sourceName.Join, Count = 5 };
                nint builder = Core.BNCreateStructureBuilder();
                Core.BNSetStructureBuilderPacked(builder, 1);
                Core.BNSetStructureBuilderWidth(builder, width);
                nint structure = Core.BNFinalizeStructureBuilder(builder);
                nint type = Core.BNCreateStructureType(structure);
                Core.BNFreeStructure(structure);
                Core.BNFreeStructureBuilder(builder);

                // A distinct identity keeps source-type updates from expanding this storage range to the sources complete width
                var actual = Core.BNDefineAnalysisType(view, identifier, &name, type);
                nint reference = Core.BNCreateNamedTypeReferenceFromTypeAndId(identifier, &actual, type);
                Core.BNFreeType(type);
                index.Add((source, width), Jobs.Count);
                Jobs.Add(new TypePrefix { TypeIndex = typeIndex, Width = width, Reference = reference, Name = actual });
                return reference;
            }
        } finally {
            Core.BNFreeString(sourceId);
            Core.BNFreeQualifiedName(&sourceName);
        }
    }

    internal void Free() {
        foreach (var job in Jobs) {
            Core.BNFreeType(job.Reference);
            var name = job.Name;
            Core.BNFreeQualifiedName(&name);
        }
    }
}
