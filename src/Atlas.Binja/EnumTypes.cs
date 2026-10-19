using System.Buffers;
using System.Buffers.Binary;
using System.Buffers.Text;
using System.Runtime.InteropServices;
using System.Text;

namespace Atlas.Binja;

internal static unsafe class EnumTypes {
    internal static void Create(Metadata metadata, Enumerations enums, Span<nint> types) {
        int maxName = 0;

        foreach (ref readonly var member in CollectionsMarshal.AsSpan(enums.Members)) {
            string name = metadata.FieldDefinitions[member.Field].Name;
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
                        int length = Encoding.UTF8.GetBytes(metadata.FieldDefinitions[member.Field].Name, text);
                        text[length] = 0;

                        // The core takes uint64_t even for signed enums
                        // Extend the sign so its member values retain the signed meaning
                        ulong value = definition.Signed
                            ? unchecked((ulong)((long)(member.Bits << shift) >> shift))
                            : member.Bits;

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
            string name = metadata.TypeDefinitions[definition.MetadataType].Name;
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

                var definition = metadata.TypeDefinitions[enums.Definitions[i].MetadataType];
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
                : extraction.Metadata.TypeDefinitions[definition.MetadataType].Offset;

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

    internal static bool TryRestoreSignedTypes(AnnotationView currentView, out int count, out MapFormat format,
        CancellationToken cancellationToken = default) {
        int restored = 0;
        bool inputCurrent = true;
        MapFormat originalFormat = MapFormat.Auto;
        AnnotationPublication.Run(currentView.Handle, view => {
            currentView.Update(view);
            using var reconciliation = new AnnotationReconciliation(view, cancellationToken: cancellationToken);
            if (!reconciliation.TryInputFormat(out originalFormat)) {
                nint record;
                fixed (byte* key = "aot-atlas:signed-enums\0"u8)
                    record = Core.BNBinaryViewQueryMetadata(view, key);
                if (record == 0)
                    return;
                Core.BNFreeMetadata(record);
                throw new InvalidOperationException("The original Atlas map format is unavailable. Apply metadata with its map format before restoring annotations.");
            }
            inputCurrent = reconciliation.MetadataTrusted("aot-atlas:apply-input")
                && NativeApply.InputCurrent(view, out _, cancellationToken)
                && reconciliation.MetadataTrusted("aot-atlas:signed-enums");
            if (!inputCurrent)
                return;
            restored = reconciliation.NormalizeSignedEnums();
            if (restored != 0)
                reconciliation.CompleteRepairs();
        }, cancellationToken);
        count = restored;
        format = originalFormat;
        return inputCurrent;
    }

    internal static nint SignedCopy(nint type) {
        nint builder = Core.BNCreateTypeBuilderFromType(type);
        if (builder == 0)
            throw new IOException("Binary Ninja could not copy an Atlas enum type.");
        try {
            BoolConfidence signed = new() { Value = 1, Confidence = 255 };
            Core.BNTypeBuilderSetSigned(builder, &signed);
            nint replacement = Core.BNFinalizeTypeBuilder(builder);
            if (replacement == 0)
                throw new IOException("Binary Ninja could not restore Atlas enum signedness.");
            return replacement;
        } finally {
            Core.BNFreeTypeBuilder(builder);
        }
    }
}
