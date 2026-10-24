using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Unicode;

namespace Atlas.Binja;

internal static unsafe class FieldAnnotations {
    private readonly record struct FieldRecord(uint Type, uint Offset, uint Function, uint Instruction, uint Size);
    private readonly record struct SavedName(bool Opaque, string Leaf);
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static byte[] Store(nint view, Extraction extraction, CodeFlow code, ReadOnlySpan<byte> scopes,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        PeImage image = extraction.Image;
        var entries = CollectionsMarshal.AsSpan(extraction.Types.Types);
        if (entries.Length != scopes.Length)
            throw new ArgumentException("Runtime type scopes do not match the type table.", nameof(scopes));

        var types = new SortedSet<uint>();
        using var output = new MemoryStream();
        using var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
        writer.Write("ATFLD002"u8);
        writer.Write(code.FieldReferences.Count);

        foreach (ref readonly var reference in CollectionsMarshal.AsSpan(code.FieldReferences)) {
            cancellationToken.ThrowIfCancellationRequested();

            ref readonly var access = ref CollectionsMarshal.AsSpan(code.ReceiverAccesses)[reference.AccessIndex];
            uint type = checked((uint)(access.Type - image.ImageBase));
            types.Add(type);
            writer.Write(type);
            writer.Write(access.Offset);
            writer.Write(checked((uint)(access.Function - image.ImageBase)));
            writer.Write(checked((uint)(access.Instruction - image.ImageBase)));
            writer.Write(access.Size);
        }

        writer.Write(types.Count);
        var indices = new Dictionary<uint, int>(types.Count);
        for (int i = 0; i < entries.Length; ++i) {
            uint type = checked((uint)(entries[i].Address - image.ImageBase));
            if (types.Contains(type))
                indices.Add(type, i);
        }
        Span<byte> identifier = stackalloc byte[64];
        fixed (byte* id = identifier) {
            foreach (uint type in types) {
                cancellationToken.ThrowIfCancellationRequested();
                ulong address = image.ImageBase + type;
                if (!indices.TryGetValue(type, out int index) || scopes[index] > 1)
                    throw new InvalidDataException($"Field receiver type 0x{address:X} has no runtime name.");
                var saved = new SavedName(scopes[index] == 1, extraction.Names.Values[index]);
                if (string.IsNullOrEmpty(saved.Leaf) || saved.Leaf.Contains('\0'))
                    throw new InvalidDataException($"Field receiver type 0x{address:X} has an invalid name.");

                identifier.Clear();
                if (!Utf8.TryWrite(identifier, $"aot-atlas:runtime-type:v1:{type:X8}\0", out _))
                    throw new InvalidDataException("A runtime type identifier does not fit the field record.");

                QualifiedName name = Core.BNGetAnalysisTypeNameById(view, id);
                try {
                    if (name.Count != 0 && !Matches(name, saved))
                        throw new InvalidDataException($"Field receiver type 0x{address:X} changed its name.");

                    byte[] text = StrictUtf8.GetBytes(saved.Leaf);
                    writer.Write(type);
                    writer.Write((byte)(saved.Opaque ? 1 : 0));
                    writer.Write(text.Length);
                    writer.Write(text);
                } finally {
                    Core.BNFreeQualifiedName(&name);
                }
            }
        }

        writer.Flush();
        byte[] bytes = output.ToArray();

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

    private static FieldRecord[] ReadRecords(ReadOnlySpan<byte> bytes, out Dictionary<uint, SavedName> savedNames) {
        savedNames = [];
        if (bytes.Length < 8)
            throw new InvalidDataException("The Atlas field-reference record is truncated.");

        if (bytes[..8].SequenceEqual("ATFLD001"u8)) {
            if ((bytes.Length - 8) % 20 != 0)
                throw new InvalidDataException("The Atlas field-reference record has an invalid length.");
            var legacy = new FieldRecord[(bytes.Length - 8) / 20];
            for (int i = 0, position = 8; i < legacy.Length; ++i, position += 20)
                legacy[i] = ReadRecord(bytes.Slice(position, 20));
            return legacy;
        }

        if (!bytes[..8].SequenceEqual("ATFLD002"u8) || bytes.Length < 16)
            throw new InvalidDataException("The Atlas field-reference record has an invalid format.");

        using var input = new MemoryStream(bytes.ToArray(), writable: false);
        using var reader = new BinaryReader(input, Encoding.UTF8);
        input.Position = 8;
        int count = reader.ReadInt32();
        if (count < 0 || count > (bytes.Length - 16) / 20)
            throw new InvalidDataException("The Atlas field-reference count is invalid.");

        var records = new FieldRecord[count];
        for (int i = 0; i < count; ++i)
            records[i] = new FieldRecord(reader.ReadUInt32(), reader.ReadUInt32(), reader.ReadUInt32(),
                reader.ReadUInt32(), reader.ReadUInt32());

        int nameCount = reader.ReadInt32();
        if (nameCount < 0 || nameCount > count)
            throw new InvalidDataException("The Atlas field receiver name count is invalid.");
        savedNames.EnsureCapacity(nameCount);
        for (int i = 0; i < nameCount; ++i) {
            if (input.Length - input.Position < 9)
                throw new InvalidDataException("The Atlas field receiver name is truncated.");
            uint type = reader.ReadUInt32();
            byte scope = reader.ReadByte();
            int length = reader.ReadInt32();
            if (scope > 1 || length <= 0 || length > input.Length - input.Position)
                throw new InvalidDataException("The Atlas field receiver name is invalid.");
            string leaf = StrictUtf8.GetString(reader.ReadBytes(length));
            if (leaf.Contains('\0') || !savedNames.TryAdd(type, new SavedName(scope == 1, leaf)))
                throw new InvalidDataException("The Atlas field receiver name is repeated or contains a NUL.");
        }

        if (input.Position != input.Length)
            throw new InvalidDataException("The Atlas field receiver names do not cover the field references.");
        foreach (FieldRecord record in records) {
            if (!savedNames.ContainsKey(record.Type))
                throw new InvalidDataException("The Atlas field receiver names do not cover the field references.");
        }
        return records;
    }

    private static FieldRecord ReadRecord(ReadOnlySpan<byte> record) => new(
        BinaryPrimitives.ReadUInt32LittleEndian(record),
        BinaryPrimitives.ReadUInt32LittleEndian(record[4..]),
        BinaryPrimitives.ReadUInt32LittleEndian(record[8..]),
        BinaryPrimitives.ReadUInt32LittleEndian(record[12..]),
        BinaryPrimitives.ReadUInt32LittleEndian(record[16..]));

    private static QualifiedName NativeName(SavedName saved) {
        byte[] leaf = StrictUtf8.GetBytes(saved.Leaf + '\0');
        fixed (byte* text = leaf)
        fixed (byte* atlas = "atlas\0"u8)
        fixed (byte* runtime = "runtime\0"u8)
        fixed (byte* opaque = "opaque\0"u8)
        fixed (byte* join = "::\0"u8) {
            byte** parts = stackalloc byte*[3] { atlas, saved.Opaque ? opaque : runtime, text };
            QualifiedName name = new() {
                Names = Core.BNAllocStringList(parts, 3),
                Join = Core.BNAllocString(join),
                Count = 3
            };
            if (name.Names == null || name.Join == null) {
                Core.BNFreeQualifiedName(&name);
                throw new OutOfMemoryException("Binary Ninja could not allocate a field receiver name.");
            }
            return name;
        }
    }

    private static bool Matches(QualifiedName name, SavedName saved) => name.Count == 3
        && Marshal.PtrToStringUTF8((nint)name.Names[0]) == "atlas"
        && Marshal.PtrToStringUTF8((nint)name.Names[1]) == (saved.Opaque ? "opaque" : "runtime")
        && Marshal.PtrToStringUTF8((nint)name.Names[2]) == saved.Leaf
        && Marshal.PtrToStringUTF8((nint)name.Join) == "::";

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

            FieldRecord[] records = ReadRecords(bytes, out var savedNames);
            int applied = 0;
            names.EnsureCapacity(savedNames.Count);

            ulong imageBase = Core.BNGetImageBase(view);
            platform = Core.BNGetDefaultPlatform(view);
            if (platform == 0)
                throw new NotSupportedException("The Binary Ninja view has no default platform.");

            nint architecture = Core.BNGetPlatformArchitecture(platform);

            uint previousFunction = 0;

            Span<byte> identifier = stackalloc byte[64];

            fixed (byte* id = identifier) {
                foreach (FieldRecord record in records) {
                    cancellationToken.ThrowIfCancellationRequested();

                    uint type = record.Type;
                    uint offset = record.Offset;
                    uint entrypoint = record.Function;
                    ulong instruction = checked(imageBase + record.Instruction);
                    ulong functionAddress = checked(imageBase + entrypoint);
                    ulong typeAddress = checked(imageBase + type);
                    uint size = record.Size;

                    if (!names.TryGetValue(type, out var name)) {
                        Utf8.TryWrite(identifier, $"aot-atlas:runtime-type:v1:{type:X8}\0", out _);
                        name = Core.BNGetAnalysisTypeNameById(view, id);
                        if (name.Count == 0) {
                            Core.BNFreeQualifiedName(&name);
                            if (savedNames.TryGetValue(type, out SavedName saved))
                                name = NativeName(saved);
                            else if (!artifacts.HasValue) {
                                // Legacy field records need a fresh extraction to recover a missing name.
                                inputCurrent = false;
                                return 0;
                            } else {
                                throw new InvalidOperationException($"Atlas runtime type 0x{typeAddress:X} is missing.");
                            }
                        }

                        if (savedNames.TryGetValue(type, out SavedName expected) && !Matches(name, expected)) {
                            Core.BNFreeQualifiedName(&name);
                            throw new InvalidDataException($"Field receiver type 0x{typeAddress:X} changed its name.");
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
