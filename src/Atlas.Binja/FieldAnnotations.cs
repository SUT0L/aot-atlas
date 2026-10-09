using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text.Unicode;

namespace Atlas.Binja;

internal static unsafe class FieldAnnotations {
    internal static byte[] Store(nint view, PeImage image, CodeFlow code, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        byte[] bytes = new byte[checked(8 + 20 * code.FieldReferences.Count)];
        "ATFLD001"u8.CopyTo(bytes);
        int position = 8;

        foreach (ref readonly var reference in CollectionsMarshal.AsSpan(code.FieldReferences)) {
            cancellationToken.ThrowIfCancellationRequested();

            ref readonly var access = ref CollectionsMarshal.AsSpan(code.ReceiverAccesses)[reference.AccessIndex];
            var record = bytes.AsSpan(position, 20);

            BinaryPrimitives.WriteUInt32LittleEndian(record, checked((uint)(access.Type - image.ImageBase)));
            BinaryPrimitives.WriteUInt32LittleEndian(record[4..], access.Offset);
            BinaryPrimitives.WriteUInt32LittleEndian(record[8..], checked((uint)(access.Function - image.ImageBase)));
            BinaryPrimitives.WriteUInt32LittleEndian(record[12..], checked((uint)(access.Instruction - image.ImageBase)));
            BinaryPrimitives.WriteUInt32LittleEndian(record[16..], access.Size);
            position += 20;
        }

        fixed (byte* key = "aot-atlas:field-references\0"u8)
        fixed (byte* data = bytes) {
            nint metadata = Core.BNCreateMetadataRawData(data, (nuint)bytes.Length);

            try {
                Core.BNBinaryViewStoreMetadata(view, key, metadata, 3);
            } finally {
                Core.BNFreeMetadata(metadata);
            }
        }

        return bytes;
    }

    internal static bool TryApply(AnnotationView currentView, bool required, out int count, out MapFormat format,
        CancellationToken cancellationToken = default, AnnotationArtifacts? artifacts = null) {
        int applied = 0;
        bool inputCurrent = true;
        MapFormat originalFormat = MapFormat.Auto;
        nint analyzedView = currentView.Handle;

        AnnotationPublication.Run(currentView.Handle, current => {
            currentView.Update(current);

            applied = ApplyLocked(current, required, current != analyzedView, out inputCurrent, out originalFormat,
                cancellationToken, artifacts);
        }, cancellationToken);

        count = applied;
        format = originalFormat;
        return inputCurrent;
    }

    private static int ApplyLocked(nint view, bool required, bool viewChanged, out bool inputCurrent, out MapFormat format,
        CancellationToken cancellationToken, AnnotationArtifacts? artifacts) {
        inputCurrent = true;
        format = MapFormat.Auto;
        cancellationToken.ThrowIfCancellationRequested();

        nint metadata = 0;

        if (!artifacts.HasValue) {
            fixed (byte* key = "aot-atlas:field-references\0"u8)
                metadata = Core.BNBinaryViewQueryMetadata(view, key);
        }

        if (metadata == 0 && !artifacts.HasValue) {
            nint receipt;
            fixed (byte* key = "aot-atlas:owned-annotations\0"u8)
                receipt = Core.BNBinaryViewQueryMetadata(view, key);
            if (receipt == 0) {
                if (!required)
                    return 0;

                throw new InvalidOperationException("Apply Atlas metadata before applying field references.");
            }
            Core.BNFreeMetadata(receipt);
        }

        byte* data = null;

        nint platform = 0;
        nint function = 0;

        var names = new Dictionary<uint, QualifiedName>();

        try {
            using var reconciliation = new AnnotationReconciliation(view, fieldsOnly: true, cancellationToken);
            if (artifacts is { } fresh) {
                format = fresh.Format;
                inputCurrent = NativeApply.InputMatches(view, fresh.Input, cancellationToken);
            } else {
                if (!reconciliation.TryInputFormat(out format))
                    throw new InvalidOperationException("The original Atlas map format is unavailable. Apply metadata with its map format before restoring annotations.");

                inputCurrent = reconciliation.MetadataTrusted("aot-atlas:apply-input")
                    && NativeApply.InputCurrent(view, out _, cancellationToken);
            }
            if (!inputCurrent || viewChanged) {
                inputCurrent = false;
                return 0;
            }

            ReadOnlySpan<byte> bytes;
            if (artifacts is { } prepared) {
                bytes = prepared.Fields;
            } else {
                if (metadata == 0 || Core.BNMetadataIsRaw(metadata) == 0) {
                    inputCurrent = false;
                    return 0;
                }

                nuint length = 0;
                data = Core.BNMetadataGetRaw(metadata, &length);
                bytes = new ReadOnlySpan<byte>(data, checked((int)length));
                if (!reconciliation.MetadataTrusted("aot-atlas:field-references", bytes)) {
                    inputCurrent = false;
                    return 0;
                }
            }

            if (bytes.Length < 8
                || (bytes.Length - 8) % 20 != 0
                || !bytes[..8].SequenceEqual("ATFLD001"u8))
                throw new InvalidDataException("The Atlas field-reference record has an invalid format.");

            int count = (bytes.Length - 8) / 20;
            int applied = 0;
            names.EnsureCapacity(count);

            ulong imageBase = Core.BNGetImageBase(view);
            platform = Core.BNGetDefaultPlatform(view);
            if (platform == 0)
                throw new NotSupportedException("The Binary Ninja view has no default platform.");

            nint architecture = Core.BNGetPlatformArchitecture(platform);

            uint previousFunction = 0;

            Span<byte> identifier = stackalloc byte[64];

            fixed (byte* id = identifier) {
                for (int position = 8; position < bytes.Length; position += 20) {
                    cancellationToken.ThrowIfCancellationRequested();

                    var record = bytes.Slice(position, 20);
                    uint type = BinaryPrimitives.ReadUInt32LittleEndian(record);
                    uint offset = BinaryPrimitives.ReadUInt32LittleEndian(record[4..]);
                    uint entrypoint = BinaryPrimitives.ReadUInt32LittleEndian(record[8..]);
                    ulong instruction = checked(imageBase + BinaryPrimitives.ReadUInt32LittleEndian(record[12..]));
                    ulong functionAddress = checked(imageBase + entrypoint);
                    ulong typeAddress = checked(imageBase + type);
                    uint size = BinaryPrimitives.ReadUInt32LittleEndian(record[16..]);

                    if (!names.TryGetValue(type, out var name)) {
                        Utf8.TryWrite(identifier, $"aot-atlas:runtime-type:v1:{type:X8}\0", out _);
                        name = Core.BNGetAnalysisTypeNameById(view, id);
                        if (name.Count == 0) {
                            Core.BNFreeQualifiedName(&name);
                            // A BNDB can omit an unresolved receiver type identity.
                            // Rebuild saved field evidence from the original input.
                            if (!artifacts.HasValue) {
                                inputCurrent = false;
                                return 0;
                            }
                            throw new InvalidOperationException($"Atlas runtime type 0x{typeAddress:X} is missing.");
                        }

                        names.Add(type, name);
                    }

                    if (function == 0 || entrypoint != previousFunction) {
                        if (function != 0)
                            Core.BNFreeFunction(function);

                        function = Core.BNGetAnalysisFunction(view, platform, functionAddress);
                        previousFunction = entrypoint;

                        if (function == 0)
                            throw new InvalidOperationException($"Atlas field-reference function 0x{functionAddress:X} is missing.");
                    }

                    // The core silently discards references outside analyzed blocks
                    // Expose that boundary instead of reporting a successful apply
                    nint block = Core.BNGetFunctionBasicBlockAtAddress(function, architecture, instruction);
                    if (block == 0)
                        throw new InvalidOperationException($"Analyze function 0x{functionAddress:X} before applying its field reference at 0x{instruction:X}.");

                    Core.BNFreeBasicBlock(block);

                    if (reconciliation.AddFieldReference(function, architecture, instruction, &name, offset, size))
                        ++applied;
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
            reconciliation.Complete();
            if (reconciliation.LegacyOwnershipMissing)
                Plugin.Log(2, "Atlas ownership record missing; preexisting user annotations retained.");
            if (reconciliation.LegacyTagIdentityMissing)
                Plugin.Log(2, "Legacy Atlas tag category unavailable; tag deletion identity cannot be recovered.");
            return applied;
        } finally {
            if (function != 0)
                Core.BNFreeFunction(function);

            if (platform != 0)
                Core.BNFreePlatform(platform);

            foreach (var entry in names.Values) {
                var name = entry;
                Core.BNFreeQualifiedName(&name);
            }

            if (data != null)
                Core.BNFreeMetadataRaw(data);

            if (metadata != 0)
                Core.BNFreeMetadata(metadata);
        }
    }
}
