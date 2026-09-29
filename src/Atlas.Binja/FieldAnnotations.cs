using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text.Unicode;

namespace Atlas.Binja;

internal static unsafe class FieldAnnotations {
    internal static void Store(nint view, PeImage image, CodeFlow code) {
        byte[] bytes = new byte[checked(8 + 20 * code.FieldReferences.Count)];
        "ATFLD001"u8.CopyTo(bytes);
        int position = 8;
        foreach (ref readonly var reference in CollectionsMarshal.AsSpan(code.FieldReferences)) {
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
            Core.BNBinaryViewStoreMetadata(view, key, metadata, 3);
            Core.BNFreeMetadata(metadata);
        }
    }

    internal static int Apply(nint view, bool required) {
        nint metadata;
        fixed (byte* key = "aot-atlas:field-references\0"u8)
            metadata = Core.BNBinaryViewQueryMetadata(view, key);
        if (metadata == 0) {
            if (!required)
                return 0;
            throw new InvalidOperationException("Apply Atlas metadata before applying field references.");
        }

        byte* data = null;
        nint platform = 0, function = 0;
        var names = new Dictionary<uint, QualifiedName>();
        try {
            if (Core.BNMetadataIsRaw(metadata) == 0)
                throw new InvalidDataException("The Atlas field-reference record is not raw metadata.");
            nuint length = 0;
            data = Core.BNMetadataGetRaw(metadata, &length);
            var bytes = new ReadOnlySpan<byte>(data, checked((int)length));
            if (bytes.Length < 8 || (bytes.Length - 8) % 20 != 0 || !bytes[..8].SequenceEqual("ATFLD001"u8))
                throw new InvalidDataException("The Atlas field-reference record has an invalid format.");

            int count = (bytes.Length - 8) / 20;
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
                    var record = bytes.Slice(position, 20);
                    uint type = BinaryPrimitives.ReadUInt32LittleEndian(record);
                    uint offset = BinaryPrimitives.ReadUInt32LittleEndian(record[4..]);
                    uint entrypoint = BinaryPrimitives.ReadUInt32LittleEndian(record[8..]);
                    ulong instruction = imageBase + BinaryPrimitives.ReadUInt32LittleEndian(record[12..]);
                    uint size = BinaryPrimitives.ReadUInt32LittleEndian(record[16..]);

                    if (!names.TryGetValue(type, out var name)) {
                        Utf8.TryWrite(identifier, $"aot-atlas:runtime-type:v1:{type:X8}\0", out _);
                        name = Core.BNGetAnalysisTypeNameById(view, id);
                        if (name.Count == 0)
                            throw new InvalidOperationException($"Atlas runtime type 0x{imageBase + type:X} is missing.");
                        names.Add(type, name);
                    }

                    if (function == 0 || entrypoint != previousFunction) {
                        if (function != 0)
                            Core.BNFreeFunction(function);
                        function = Core.BNGetAnalysisFunction(view, platform, imageBase + entrypoint);
                        previousFunction = entrypoint;
                        if (function == 0)
                            throw new InvalidOperationException($"Atlas field-reference function 0x{imageBase + entrypoint:X} is missing.");
                    }

                    // The core silently discards references outside analyzed blocks
                    // Expose that boundary instead of reporting a successful apply
                    nint block = Core.BNGetFunctionBasicBlockAtAddress(function, architecture, instruction);
                    if (block == 0)
                        throw new InvalidOperationException($"Analyze function 0x{imageBase + entrypoint:X} before applying its field reference at 0x{instruction:X}.");
                    Core.BNFreeBasicBlock(block);
                    Core.BNAddUserTypeFieldReference(function, architecture, instruction, &name, offset, size);
                }
            }
            return count;
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
            Core.BNFreeMetadata(metadata);
        }
    }
}
