using System.Buffers;
using System.Buffers.Binary;
using System.Buffers.Text;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Unicode;

namespace Atlas.Binja;

internal static unsafe class EnumTypes {
    internal static void Create(Metadata metadata, Enumerations enums, Span<nint> types) {
        int maxName = 0;
        foreach (ref readonly var member in CollectionsMarshal.AsSpan(enums.Members)) {
            string name = metadata.Fields[member.Field].Name;
            if (name.Contains('\0'))
                throw new InvalidDataException("An enum member contains a NUL and cant be represented by a native type.");
            maxName = Math.Max(maxName, name.Length);
        }

        byte[] text = new byte[Encoding.UTF8.GetMaxByteCount(maxName) + 1];
        fixed (byte* name = text) {
            for (int i = 0; i < enums.Definitions.Count; ++i) {
                var definition = enums.Definitions[i];
                if (definition.Width == 0)
                    continue;

                nint builder = Core.BNCreateEnumerationBuilder();
                try {
                    int shift = 64 - definition.Width * 8;
                    for (int j = definition.Members.Start; j < definition.Members.End; ++j) {
                        var member = enums.Members[j];
                        int length = Encoding.UTF8.GetBytes(metadata.Fields[member.Field].Name, text);
                        text[length] = 0;
                        // The core takes uint64_t even for signed enums
                        // Extend the sign so its member values retain the signed meaning
                        ulong value = definition.Signed ? unchecked((ulong)((long)(member.Bits << shift) >> shift)) : member.Bits;
                        Core.BNAddEnumerationBuilderMemberWithValue(builder, name, value);
                    }

                    nint enumeration = Core.BNFinalizeEnumerationBuilder(builder);
                    BoolConfidence signed = new() { Value = (byte)(definition.Signed ? 1 : 0), Confidence = 255 };
                    types[i] = Core.BNCreateEnumerationTypeOfWidth(enumeration, definition.Width, &signed);
                    Core.BNFreeEnumeration(enumeration);
                } finally {
                    Core.BNFreeEnumerationBuilder(builder);
                }
            }
        }
    }

    internal static void Apply(nint view, Metadata metadata, Enumerations enums, ReadOnlySpan<nint> types) {
        int maxName = 0;
        foreach (ref readonly var definition in CollectionsMarshal.AsSpan(enums.Definitions)) {
            string name = metadata.Types[definition.MetadataType].Name;
            if (name.Contains('\0'))
                throw new InvalidDataException("An enum name contains a NUL and cant be represented by a native type.");
            maxName = Math.Max(maxName, name.Length);
        }

        byte[] buffer = new byte[Encoding.UTF8.GetMaxByteCount(maxName) + 1];
        Span<byte> id = stackalloc byte[40];
        ReadOnlySpan<byte> prefix = "aot-atlas:enum:v1:"u8;
        prefix.CopyTo(id);
        id[prefix.Length + 8] = 0;
        fixed (byte* text = buffer)
        fixed (byte* identifier = id)
        fixed (byte* atlas = "atlas\0"u8)
        fixed (byte* kind = "enum\0"u8)
        fixed (byte* join = "::\0"u8) {
            byte** parts = stackalloc byte*[3] { atlas, kind, text };
            QualifiedName name = new() { Names = parts, Join = join, Count = 3 };
            for (int i = 0; i < types.Length; ++i) {
                if (types[i] == 0)
                    continue;

                var definition = metadata.Types[enums.Definitions[i].MetadataType];
                int length = Encoding.UTF8.GetBytes(definition.Name, buffer);
                buffer[length] = 0;
                Utf8Formatter.TryFormat(definition.Offset, id[prefix.Length..], out _, new StandardFormat('X', 8));
                var actual = Core.BNDefineAnalysisType(view, identifier, &name, types[i]);
                Core.BNFreeQualifiedName(&actual);
            }
        }
    }

    internal static void StoreSignedTypes(nint view, Extraction extraction) {
        var definitions = CollectionsMarshal.AsSpan(extraction.Enums.Definitions);
        var runtime = extraction.Enums.RuntimeIndices.AsSpan();
        byte[] bytes = new byte[checked(8 + 8 * (definitions.Length + runtime.Length))];
        "ATENUM01"u8.CopyTo(bytes);
        int position = 8;
        for (int i = 0; i < definitions.Length + runtime.Length; ++i) {
            bool isRuntime = i >= definitions.Length;
            int index = isRuntime ? runtime[i - definitions.Length] - 1 : i;
            if (index < 0)
                continue;

            ref readonly var definition = ref definitions[index];
            if (!definition.Signed || definition.Width == 0)
                continue;

            uint offset = isRuntime
                ? checked((uint)(extraction.Types.Types[i - definitions.Length].Address - extraction.Image.ImageBase))
                : extraction.Metadata.Types[definition.MetadataType].Offset;
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(position), offset);
            bytes[position + 4] = (byte)(isRuntime ? 1 : 0);
            bytes[position + 5] = definition.Width;
            position += 8;
        }

        fixed (byte* key = "aot-atlas:signed-enums\0"u8)
        fixed (byte* data = bytes) {
            nint record = Core.BNCreateMetadataRawData(data, (nuint)position);
            Core.BNBinaryViewStoreMetadata(view, key, record, 3);
            Core.BNFreeMetadata(record);
        }
    }

    internal static int RestoreSignedTypes(nint view) {
        nint record;
        fixed (byte* key = "aot-atlas:signed-enums\0"u8)
            record = Core.BNBinaryViewQueryMetadata(view, key);
        if (record == 0)
            return 0;

        byte* data = null;
        try {
            if (Core.BNMetadataIsRaw(record) == 0)
                throw new InvalidDataException("The Atlas signed-enum record is not raw metadata.");
            nuint length = 0;
            data = Core.BNMetadataGetRaw(record, &length);
            var bytes = new ReadOnlySpan<byte>(data, checked((int)length));
            if (bytes.Length < 8 || (bytes.Length - 8) % 8 != 0 || !bytes[..8].SequenceEqual("ATENUM01"u8))
                throw new InvalidDataException("The Atlas signed-enum record has an invalid format.");

            for (int position = 8; position < bytes.Length; position += 8) {
                var entry = bytes.Slice(position, 8);
                if (entry[4] > 1 || entry[5] is not (1 or 2 or 4 or 8) || entry[6] != 0 || entry[7] != 0)
                    throw new InvalidDataException("The Atlas signed-enum record has an invalid type entry.");
            }

            // BNDB reload in core 187 drops enum signedness
            // Keep the missing bit with the stable type identity, and repair only automatic types
            // User overrides and current names belong to the analyst
            Span<byte> identifier = stackalloc byte[64];
            BoolConfidence signed = new() { Value = 1, Confidence = 255 };
            int restored = 0;
            fixed (byte* id = identifier) {
                for (int position = 8; position < bytes.Length; position += 8) {
                    var entry = bytes.Slice(position, 8);
                    uint offset = BinaryPrimitives.ReadUInt32LittleEndian(entry);
                    if (entry[4] == 0)
                        Utf8.TryWrite(identifier, $"aot-atlas:enum:v1:{offset:X8}\0", out _);
                    else
                        Utf8.TryWrite(identifier, $"aot-atlas:runtime-type:v1:{offset:X8}\0", out _);

                    nint type = Core.BNGetAnalysisTypeById(view, id);
                    if (type == 0)
                        continue;
                    var name = Core.BNGetAnalysisTypeNameById(view, id);
                    try {
                        if (Core.BNIsAnalysisTypeAutoDefined(view, &name) == 0)
                            continue;
                        if (Core.BNGetTypeClass(type) != 5 || Core.BNGetTypeWidth(type) != entry[5])
                            throw new InvalidDataException($"Atlas enum type {offset:X8} no longer matches its saved layout.");
                        if (Core.BNIsTypeSigned(type).Value != 0)
                            continue;

                        nint builder = Core.BNCreateTypeBuilderFromType(type);
                        nint replacement;
                        try {
                            Core.BNTypeBuilderSetSigned(builder, &signed);
                            replacement = Core.BNFinalizeTypeBuilder(builder);
                        } finally {
                            Core.BNFreeTypeBuilder(builder);
                        }

                        try {
                            var actual = Core.BNDefineAnalysisType(view, id, &name, replacement);
                            Core.BNFreeQualifiedName(&actual);
                        } finally {
                            Core.BNFreeType(replacement);
                        }
                        ++restored;
                    } finally {
                        Core.BNFreeQualifiedName(&name);
                        Core.BNFreeType(type);
                    }
                }
            }
            return restored;
        } finally {
            if (data != null)
                Core.BNFreeMetadataRaw(data);
            Core.BNFreeMetadata(record);
        }
    }
}
