using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Atlas.Binja;

internal static unsafe class NativeApply {
    private static readonly Guid ApplicationBuild = typeof(NativeApply).Module.ModuleVersionId;
    private static readonly Guid ExtractionBuild = typeof(Extraction).Module.ModuleVersionId;
    private static readonly Guid PreviousPresentation = new("86b2bc9e-1726-433d-9def-2fbc1325f8ea");
    private static readonly Guid PreviousExtraction = new("e9486e1f-0e88-4f51-aca3-c0f14ab37bc8");

    internal static ApplyStats Run(nint view, MapFormat format, nint task) {
        byte* viewKind = Core.BNGetViewType(view);
        bool pe = viewKind[0] == 'P' && viewKind[1] == 'E' && viewKind[2] == 0;
        Core.BNFreeString(viewKind);
        if (!pe)
            throw new NotSupportedException("AOT Atlas requires a PE view.");

        byte[] data;
        nint file = Core.BNGetFileForView(view);
        nint raw;
        fixed (byte* name = "Raw\0"u8)
            raw = Core.BNGetFileViewOfType(file, name);

        Core.BNFreeFileMetadata(file);
        if (raw == 0)
            throw new InvalidDataException("The Binary Ninja file has no raw view.");

        try {
            ulong length = Core.BNGetViewLength(raw);
            int count = checked((int)length);
            nint buffer = Core.BNReadViewBuffer(raw, 0, length);
            if (buffer == 0)
                throw new IOException("Binary Ninja could not read the raw view.");

            try {
                if (Core.BNGetDataBufferLength(buffer) != length)
                    throw new IOException("Binary Ninja returned an incomplete raw view.");

                data = new ReadOnlySpan<byte>(Core.BNGetDataBufferContents(buffer), count).ToArray();
            } finally {
                Core.BNFreeDataBuffer(buffer);
            }
        } finally {
            Core.BNFreeBinaryView(raw);
        }

        long start = Stopwatch.GetTimestamp();
        var image = new PeImage(data);
        var header = ReadyToRun.Read(image);
        var section = header.Find(313);
        var metadata = new Metadata(section.Length == 0 ? default : image.FileMemory(section.Start, checked((int)section.Length)),
            header.MetadataHandleBits, header.Major < 10);
        metadata.ReadDefinitions();
        var fixups = RuntimeTables.Fixups(image, header.Find(308));
        var maps = new ReflectionMaps();
        maps.Read(image, header, metadata, fixups, format);
        var extraction = new Extraction(image, header, metadata, maps, fixups);
        var managedAbi = new ManagedAbi(extraction);
        var properties = new PropertyProjections(extraction, managedAbi);
        var code = new CodeFlow(extraction, managedAbi);
        var dispatchCells = new DispatchCells(extraction, code);
        var helpers = new RuntimeHelpers(extraction, code);
        if (code.Context.Origins.Text.Span.Contains('\0'))
            throw new InvalidDataException("A contextual function name contains a NUL and cant be represented by a native symbol.");
        var strings = new NativeStrings(image, header.Sections);
        var stringReferences = strings.FindReferences(image.ImageBase, CollectionsMarshal.AsSpan(code.Addresses));
        ApplyStats stats = new() {
            InputBytes = (ulong)data.Length,
            ImageBase = Core.BNGetImageBase(view),
            MethodTables = (uint)extraction.Types.Types.Count,
            ExtractSeconds = Stopwatch.GetElapsedTime(start).TotalSeconds
        };
        SHA256.HashData(data, new Span<byte>(stats.InputSha256, 32));
        if (stats.ImageBase > ulong.MaxValue - image.ImageSize)
            throw new InvalidDataException("The rebased image exceeds the address space.");

        if (task != 0) {
            if (Core.BNIsBackgroundTaskCancelled(task) != 0)
                throw new OperationCanceledException();

            fixed (byte* text = "AOT Atlas: applying metadata\0"u8)
                Core.BNSetBackgroundTaskProgressText(task, text);
        }

        long applyStart = Stopwatch.GetTimestamp();

        // Retraction must cover every annotation, including functions that have disappeared from the metadata
        // Until then, bind the view to one input and implementation so a partial or repeated apply cant mix claims
        // @Incomplete: Reconcile owned annotations before accepting changed inputs
        Span<byte> stamp = stackalloc byte[73];
        "ATINPUT1"u8.CopyTo(stamp);
        new ReadOnlySpan<byte>(stats.InputSha256, 32).CopyTo(stamp[8..]);
        ApplicationBuild.TryWriteBytes(stamp[40..]);
        ExtractionBuild.TryWriteBytes(stamp[56..]);
        stamp[72] = (byte)format;

        fixed (byte* key = "aot-atlas:apply-input\0"u8) {
            nint previous = Core.BNBinaryViewQueryMetadata(view, key);
            if (previous != 0) {
                try {
                    if (Core.BNMetadataIsRaw(previous) == 0)
                        throw new InvalidDataException("The stored Atlas input record is not raw metadata. Reopen the original binary in a fresh view.");

                    nuint length = 0;
                    byte* bytes = Core.BNMetadataGetRaw(previous, &length);
                    bool matches, presentationUpgrade;
                    try {
                        var stored = new ReadOnlySpan<byte>(bytes, checked((int)length));
                        matches = stored.SequenceEqual(stamp);
                        // This predecessor has identical extraction and annotation identities; its extractor MVID differs because it embeds the earlier git revision
                        // Symbols.Define reconciles only unchanged display names; the new constructor ABI is additive and respects explicit user types
                        presentationUpgrade = stored.Length == stamp.Length
                            && stored[..40].SequenceEqual(stamp[..40]) && stored[72] == stamp[72]
                            && new Guid(stored.Slice(40, 16)) == PreviousPresentation
                            && new Guid(stored.Slice(56, 16)) == PreviousExtraction;
                    } finally {
                        Core.BNFreeMetadataRaw(bytes);
                    }

                    if (!matches && !presentationUpgrade)
                        throw new NotSupportedException("Atlas input, map format, or implementation changed. Reopen the binary in a fresh view before applying metadata.");
                    if (presentationUpgrade) {
                        fixed (byte* current = stamp) {
                            nint record = Core.BNCreateMetadataRawData(current, (nuint)stamp.Length);
                            Core.BNBinaryViewStoreMetadata(view, key, record, 3);
                            Core.BNFreeMetadata(record);
                        }
                    }
                } finally {
                    Core.BNFreeMetadata(previous);
                }
            } else {
                nint existingHeader;
                fixed (byte* id = "aot-atlas:methodtable-header:v1\0"u8)
                    existingHeader = Core.BNGetAnalysisTypeById(view, id);

                if (existingHeader != 0) {
                    Core.BNFreeType(existingHeader);
                    throw new NotSupportedException("This view has Atlas annotations without an input record. Reopen the original binary in a fresh view before applying metadata.");
                }

                fixed (byte* bytes = stamp) {
                    nint record = Core.BNCreateMetadataRawData(bytes, (nuint)stamp.Length);
                    Core.BNBinaryViewStoreMetadata(view, key, record, 3);
                    Core.BNFreeMetadata(record);
                }
            }
        }

        var ownership = new TagOwnership(view);
        var variables = new DataVariables(view);
        bool complete = false;
        var types = CollectionsMarshal.AsSpan(extraction.Types.Types);
        var pointers = CollectionsMarshal.AsSpan(extraction.Types.Pointers);
        byte[] arrayKinds = new byte[ushort.MaxValue + 1];
        int maxName = 0, maxArray = 0;
        for (int i = 0; i < types.Length; ++i) {
            string name = extraction.Names.Values[i];
            if (name.Contains('\0'))
                throw new InvalidDataException("A MethodTable name contains a NUL and cant be represented by a native symbol.");

            maxName = Math.Max(maxName, name.Length);
            ref readonly var entry = ref types[i];
            arrayKinds[entry.Vtable.Count] |= 1;
            arrayKinds[entry.Interfaces.Count] |= 2;
            maxArray = Math.Max(maxArray, Math.Max(entry.Vtable.Count, entry.Interfaces.Count));
        }

        byte[] nameBuffer = new byte[checked(Encoding.UTF8.GetMaxByteCount(maxName) + 14)];
        nint[] arrayTypes = new nint[2 * (maxArray + 1)];
        nint[] runtimeTypes = new nint[types.Length];
        nint[] propertyTypes = new nint[types.Length];
        nint[] staticFields = new nint[maps.Fields.Count];
        BoolConfidence qualifier = default;
        nint voidType = Core.BNCreateVoidType();
        var pointerTarget = new TypeConfidence(voidType);
        nint pointer = Core.BNCreatePointerTypeOfWidth(8, &pointerTarget, &qualifier, &qualifier, 0);
        nint headerType = HeaderType(view, pointer);
        var headerConfidence = new TypeConfidence(headerType);
        nint interfacePointer = Core.BNCreatePointerTypeOfWidth(8, &headerConfidence, &qualifier, &qualifier, 0);
        try {
            InstanceTypes.Apply(view, extraction, headerType, pointer, runtimeTypes, staticFields, task);
            var propertyStats = PropertyTypes.Apply(ownership, view, extraction, properties, runtimeTypes, pointer, propertyTypes, task);
            stats.DataReferences += (uint)propertyStats.References;
            nint[] displayTypes = new nint[runtimeTypes.Length];
            for (int i = 0; i < displayTypes.Length; ++i)
                displayTypes[i] = propertyTypes[i] != 0 ? propertyTypes[i] : runtimeTypes[i];
            EnumTypes.StoreSignedTypes(view, extraction);

            var pointerConfidence = new TypeConfidence(pointer);
            var interfaceConfidence = new TypeConfidence(interfacePointer);
            for (int count = 1; count <= maxArray; ++count) {
                if ((arrayKinds[count] & 1) != 0)
                    arrayTypes[2 * count] = Core.BNCreateArrayType(&pointerConfidence, (uint)count);
                if ((arrayKinds[count] & 2) != 0)
                    arrayTypes[2 * count + 1] = Core.BNCreateArrayType(&interfaceConfidence, (uint)count);
            }

            var symbols = new Symbols(view, stats.ImageBase, checked(types.Length * 8 + code.Context.Functions.Length * 4));
            Core.BNBeginBulkModifySymbols(view);
            try {
                fixed (byte* symbolName = nameBuffer) {
                    for (int i = 0; i < types.Length; ++i) {
                        if (task != 0 && (i & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                            throw new OperationCanceledException();

                        ref readonly var entry = ref types[i];
                        string name = extraction.Names.Values[i];
                        int bytes = Encoding.UTF8.GetBytes(name, nameBuffer.AsSpan(13));
                        nameBuffer[13 + bytes] = 0;
                        "methodtable::"u8.CopyTo(nameBuffer);
                        ulong address = stats.ImageBase + (entry.Address - image.ImageBase);
                        symbols.Define(address, 3, symbolName);
                        variables.Define(address, headerType);
                        ++stats.Symbols;
                        ++stats.DataVariables;

                        if (entry.RelatedType != 0) {
                            Core.BNAddUserDataReference(view, address + 8, stats.ImageBase + (entry.RelatedType - image.ImageBase));
                            ++stats.DataReferences;
                        }

                        for (int kind = 0; kind < 2; ++kind) {
                            var slots = kind == 0 ? entry.Vtable : entry.Interfaces;
                            if (slots.Count == 0)
                                continue;

                            ulong arrayAddress = address + 24 + (kind == 0 ? 0 : (uint)entry.Vtable.Count * 8UL);
                            int prefix = kind == 0 ? 5 : 1;
                            if (kind == 0)
                                "vtable::"u8.CopyTo(nameBuffer.AsSpan(prefix));
                            else
                                "interfaces::"u8.CopyTo(nameBuffer.AsSpan(prefix));

                            byte* arrayName = symbolName + prefix;
                            symbols.Define(arrayAddress, 3, arrayName);
                            variables.Define(arrayAddress, arrayTypes[2 * slots.Count + kind]);
                            ++stats.Symbols;
                            ++stats.DataVariables;

                            for (int slot = 0; slot < slots.Count; ++slot) {
                                ulong target = pointers[slots.Start + slot];
                                if (target == 0 || (kind == 0 && !image.IsMapped(target, 1)))
                                    continue;

                                Core.BNAddUserDataReference(view, arrayAddress + (uint)slot * 8UL, stats.ImageBase + (target - image.ImageBase));
                                ++stats.DataReferences;
                            }
                        }
                    }
                }

                MethodAnnotations.Apply(symbols, ownership, view, extraction, managedAbi, displayTypes, headerType, voidType, pointer, ref stats, task);
                PropertyFunctionAnnotations.Apply(symbols, view, extraction, properties, displayTypes, voidType, ref stats, task);
                FrozenAnnotations.Apply(symbols, ownership, variables, view, extraction, displayTypes, interfacePointer, ref stats, task);
                DispatchAnnotations.Apply(symbols, ownership, variables, view, extraction, ref stats, task);
                DispatchCellAnnotations.Apply(symbols, variables, view, extraction, dispatchCells, ref stats, task);
                Staticantations.Apply(symbols, ownership, variables, view, extraction, staticFields, pointer, interfacePointer, ref stats, task);
                DictionaryAnnotations.Apply(symbols, ownership, variables, view, extraction, pointer, interfacePointer, ref stats, task);
                UnwindAnnotations.Apply(symbols, ownership, variables, view, extraction, ref stats, task);
                ExceptionAnnotations.Apply(symbols, ownership, variables, view, extraction, ref stats, task);
                PInvokeAnnotations.Apply(symbols, variables, view, extraction, pointer, interfacePointer, ref stats, task);
                StringAnnotations.Apply(symbols, ownership, view, image, strings, CollectionsMarshal.AsSpan(stringReferences), ref stats, task);
                RuntimeCodeAnnotations.Apply(symbols, view, extraction, code.Runtime, ref stats, task);
                RuntimeHelperAnnotations.Apply(symbols, variables, view, extraction, helpers, pointer, ref stats);
                ContextAnnotations.Apply(symbols, ownership, view, image, code.Context, ref stats, task);
                int processed = 0;
                foreach (ref readonly var reference in CollectionsMarshal.AsSpan(code.MetadataReferences)) {
                    if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();
                    Core.BNAddUserDataReference(view, stats.ImageBase + (reference.Instruction - image.ImageBase),
                        stats.ImageBase + (reference.Target - image.ImageBase));
                    ++stats.DataReferences;
                }
                FieldAnnotations.Store(view, image, code);
                complete = true;
            } finally {
                Core.BNEndBulkModifySymbols(view);
                symbols.Free();
            }
        } finally {
            foreach (nint type in propertyTypes) {
                if (type != 0)
                    Core.BNFreeType(type);
            }

            foreach (nint type in staticFields) {
                if (type != 0)
                    Core.BNFreeType(type);
            }

            foreach (nint type in runtimeTypes) {
                if (type != 0)
                    Core.BNFreeType(type);
            }

            foreach (nint array in arrayTypes) {
                if (array != 0)
                    Core.BNFreeType(array);
            }

            Core.BNFreeType(interfacePointer);
            Core.BNFreeType(headerType);
            Core.BNFreeType(pointer);
            Core.BNFreeType(voidType);
            ownership.Save(complete);
        }

        Core.BNUpdateAnalysis(view);
        stats.ApplySeconds = Stopwatch.GetElapsedTime(applyStart).TotalSeconds;
        return stats;
    }

    private static nint HeaderType(nint view, nint pointer) {
        BoolConfidence unsigned = new() { Confidence = 255 };
        // The core requires an empty C string for the default integer name
        byte emptyName = 0;
        nint u16 = Core.BNCreateIntegerType(2, &unsigned, &emptyName);
        nint u32 = Core.BNCreateIntegerType(4, &unsigned, &emptyName);
        nint builder = Core.BNCreateStructureBuilder();
        try {
            ReadOnlySpan<byte> names = "flags\0size_word\0related_type\0vtable_count\0interface_count\0hash\0"u8;
            ReadOnlySpan<nint> types = [u32, u32, pointer, u16, u16, u32];
            ReadOnlySpan<ulong> offsets = [0, 4, 8, 16, 18, 20];
            fixed (byte* text = names) {
                int position = 0;
                for (int i = 0; i < types.Length; ++i) {
                    var memberType = new TypeConfidence(types[i]);
                    Core.BNAddStructureBuilderMemberAtOffset(builder, &memberType, text + position, offsets[i], 0, 0, 0, 0, 0);
                    position += names[position..].IndexOf((byte)0) + 1;
                }
            }

            Core.BNSetStructureBuilderWidth(builder, 24);
            nint structure = Core.BNFinalizeStructureBuilder(builder);
            nint type = Core.BNCreateStructureType(structure);
            Core.BNFreeStructure(structure);
            try {
                fixed (byte* id = "aot-atlas:methodtable-header:v1\0"u8)
                fixed (byte* prefix = "atlas\0"u8)
                fixed (byte* leaf = "MethodTableHeader\0"u8)
                fixed (byte* join = "::\0"u8) {
                    byte** parts = stackalloc byte*[2] { prefix, leaf };
                    QualifiedName name = new() { Names = parts, Join = join, Count = 2 };
                    var actual = Core.BNDefineAnalysisType(view, id, &name, type);
                    nint reference = Core.BNCreateNamedTypeReferenceFromTypeAndId(id, &actual, type);
                    Core.BNFreeQualifiedName(&actual);
                    return reference;
                }
            } finally {
                Core.BNFreeType(type);
            }
        } finally {
            Core.BNFreeStructureBuilder(builder);
            Core.BNFreeType(u32);
            Core.BNFreeType(u16);
        }
    }
}
