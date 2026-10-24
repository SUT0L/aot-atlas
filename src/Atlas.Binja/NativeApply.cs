using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Atlas.Binja;

internal readonly record struct AnnotationArtifacts(ApplyStats Input, MapFormat Format, byte[] Fields);

internal readonly record struct NativeApplyMeasurement(
    AnalysisMeasurement ValidationAndOwnership,
    AnalysisMeasurement Read,
    AnalysisMeasurement Hash,
    AnalysisMeasurement Preparation,
    AnalysisMeasurement Evidence,
    AnalysisMeasurement Application,
    AnalysisMeasurement OwnershipCleanup,
    AnalysisMeasurement InputRevalidation,
    AnalysisMeasurement PublicationWait,
    int PreparationAttempts) {
    internal NativeApplyMeasurement Add(NativeApplyMeasurement other) => new(
        Add(ValidationAndOwnership, other.ValidationAndOwnership), Add(Read, other.Read), Add(Hash, other.Hash),
        Add(Preparation, other.Preparation), Add(Evidence, other.Evidence), Add(Application, other.Application),
        Add(OwnershipCleanup, other.OwnershipCleanup), Add(InputRevalidation, other.InputRevalidation),
        Add(PublicationWait, other.PublicationWait), PreparationAttempts + other.PreparationAttempts);

    private static AnalysisMeasurement Add(AnalysisMeasurement first, AnalysisMeasurement second) =>
        new(first.Seconds + second.Seconds, first.AllocatedBytes + second.AllocatedBytes);
}

internal static unsafe class NativeApply {
    private static readonly Guid ApplicationBuild = typeof(NativeApply).Module.ModuleVersionId;
    private static readonly Guid ExtractionBuild = typeof(Extraction).Module.ModuleVersionId;

    internal static ApplyStats Run(nint view, MapFormat format, nint task, CancellationToken cancellationToken = default) =>
        Run(view, format, task, out _, cancellationToken);

    internal static ApplyStats Run(nint view, MapFormat format, nint task,
        out NativeApplyMeasurement measurement, CancellationToken cancellationToken = default) {
        using var current = new AnnotationView(view);
        return Run(current, format, task, out measurement, cancellationToken);
    }

    internal static ApplyStats Run(AnnotationView currentView, MapFormat format, nint task,
        CancellationToken cancellationToken = default) => Run(currentView, format, task, out _, cancellationToken);

    internal static ApplyStats Run(AnnotationView currentView, MapFormat format, nint task,
        out NativeApplyMeasurement measurement, CancellationToken cancellationToken = default) =>
        Run(currentView, format, task, out measurement, out _, cancellationToken);

    internal static ApplyStats Run(AnnotationView currentView, MapFormat format, nint task,
        out NativeApplyMeasurement measurement, out AnnotationArtifacts artifacts, CancellationToken cancellationToken = default) {
        artifacts = default;
        nint view = currentView.Handle;
        measurement = default;
        long validationStart = Stopwatch.GetTimestamp();
        long validationAllocated = GC.GetAllocatedBytesForCurrentThread();
        cancellationToken.ThrowIfCancellationRequested();

        byte* viewKind = Core.BNGetViewType(view);
        bool pe = viewKind[0] == 'P' && viewKind[1] == 'E' && viewKind[2] == 0;

        Core.BNFreeString(viewKind);

        if (!pe)
            throw new NotSupportedException("AOT Atlas requires a PE view.");

        var validationMeasurement = AnalysisMeasurement.Since(validationStart, validationAllocated);
        AnnotationReconciliation? validatedOwnership = null;
        try {
            var preflight = AnnotationPublication.Run(view, current => {
                currentView.Update(current);
                long start = Stopwatch.GetTimestamp();
                long allocated = GC.GetAllocatedBytesForCurrentThread();

                // Load compatibility/provenance before extraction; unchanged receipts
                // reuse this immutable snapshot at publication instead of loading twice.
                validatedOwnership = new AnnotationReconciliation(current, cancellationToken: cancellationToken);
                validatedOwnership.Suspend();

                var ownership = AnalysisMeasurement.Since(start, allocated);
                validationMeasurement = new(validationMeasurement.Seconds + ownership.Seconds,
                    validationMeasurement.AllocatedBytes + ownership.AllocatedBytes);
            }, cancellationToken);

            Debug.Assert(validatedOwnership != null);
            measurement = measurement with {
                ValidationAndOwnership = validationMeasurement,
                PublicationWait = new(preflight.WaitSeconds, preflight.WaitAllocatedBytes)
            };

            while (true) {
                var stats = PrepareAndApply(currentView, format, task, out var attempt, out artifacts,
                    out bool published, validatedOwnership, cancellationToken);
                measurement = measurement.Add(attempt);

                if (published) {
                    Core.BNUpdateAnalysis(currentView.Handle);
                    stats.ExtractSeconds = measurement.Preparation.Seconds;
                    return stats;
                }

                cancellationToken.ThrowIfCancellationRequested();
            }
        } finally {
            long cleanupStart = Stopwatch.GetTimestamp();
            long cleanupAllocated = GC.GetAllocatedBytesForCurrentThread();
            validatedOwnership?.Dispose();
            var cleanup = AnalysisMeasurement.Since(cleanupStart, cleanupAllocated);
            measurement = measurement with { OwnershipCleanup = new(
                measurement.OwnershipCleanup.Seconds + cleanup.Seconds,
                measurement.OwnershipCleanup.AllocatedBytes + cleanup.AllocatedBytes) };
        }
    }

    private static ApplyStats PrepareAndApply(AnnotationView currentView, MapFormat format, nint task,
        out NativeApplyMeasurement measurement, out AnnotationArtifacts artifacts, out bool published,
        AnnotationReconciliation validatedOwnership, CancellationToken cancellationToken) {
        artifacts = default;
        cancellationToken.ThrowIfCancellationRequested();
        nint view = currentView.Handle;
        measurement = default;
        long allocated = GC.GetAllocatedBytesForCurrentThread();
        long start = Stopwatch.GetTimestamp();
        byte[] data;
        nint raw = RetainRawView(view);

        // Finish reading the raw view before constructing the extraction pipeline.
        try {
            ulong length = Core.BNGetViewLength(raw);
            int count = checked((int)length);
            nint buffer = Core.BNReadViewBuffer(raw, 0, length);
            if (buffer == 0)
                throw new IOException("Binary Ninja could not read the raw view.");

            try {
                cancellationToken.ThrowIfCancellationRequested();

                if (Core.BNGetDataBufferLength(buffer) != length)
                    throw new IOException("Binary Ninja returned an incomplete raw view.");

                data = new ReadOnlySpan<byte>(Core.BNGetDataBufferContents(buffer), count).ToArray();
            } finally {
                Core.BNFreeDataBuffer(buffer);
            }
        } finally {
            Core.BNFreeBinaryView(raw);
        }

        var readMeasurement = AnalysisMeasurement.Since(start, allocated);
        cancellationToken.ThrowIfCancellationRequested();

        allocated = GC.GetAllocatedBytesForCurrentThread();
        start = Stopwatch.GetTimestamp();
        Span<byte> inputHash = stackalloc byte[32];
        Hash(data, inputHash, cancellationToken);
        var hashMeasurement = AnalysisMeasurement.Since(start, allocated);
        cancellationToken.ThrowIfCancellationRequested();

        allocated = GC.GetAllocatedBytesForCurrentThread();
        start = Stopwatch.GetTimestamp();

        var image = new PeImage(data, takeOwnership: true);
        ulong imageBase = Core.BNGetImageBase(view);
        if (imageBase > ulong.MaxValue - image.ImageSize)
            throw new InvalidDataException("The rebased image exceeds the address space.");

        cancellationToken.ThrowIfCancellationRequested();
        var prepared = PreparedAnalysis.Read(image, mapFormat: format, cancellationToken: cancellationToken);
        var extraction = prepared.Extraction;
        var preparationMeasurement = AnalysisMeasurement.Since(start, allocated);

        ApplyStats stats = new() {
            InputBytes     = (ulong)data.Length,
            ImageBase      = imageBase,
            MethodTables   = (uint)extraction.Types.Types.Count,
            ExtractSeconds = preparationMeasurement.Seconds
        };

        stats = WithInputHash(stats, inputHash);

        allocated = GC.GetAllocatedBytesForCurrentThread();
        start = Stopwatch.GetTimestamp();
        var evidence = AnalysisEvidence.Read(prepared, stats.ImageBase, cancellationToken);
        var evidenceMeasurement = AnalysisMeasurement.Since(start, allocated);
        cancellationToken.ThrowIfCancellationRequested();

        bool applied = false;
        AnalysisMeasurement ownershipMeasurement = default;
        AnalysisMeasurement cleanupMeasurement = default;
        AnalysisMeasurement applyMeasurement = default;
        AnalysisMeasurement revalidationMeasurement = default;
        AnnotationArtifacts publishedArtifacts = default;

        var publication = AnnotationPublication.Run(view, current => {
            currentView.Update(current);
            long revalidationAllocated = GC.GetAllocatedBytesForCurrentThread();
            long revalidationStart = Stopwatch.GetTimestamp();
            bool matches = InputMatches(current, stats, cancellationToken);
            revalidationMeasurement = AnalysisMeasurement.Since(revalidationStart, revalidationAllocated);

            if (!matches)
                return;

            ulong currentBase = Core.BNGetImageBase(current);

            if (currentBase > ulong.MaxValue - image.ImageSize)
                throw new InvalidDataException("The rebased image exceeds the address space.");

            if (currentBase != stats.ImageBase) {
                long evidenceAllocated = GC.GetAllocatedBytesForCurrentThread();
                long evidenceStart = Stopwatch.GetTimestamp();
                stats.ImageBase = currentBase;
                evidence = AnalysisEvidence.Read(prepared, currentBase, cancellationToken);
                var rebased = AnalysisMeasurement.Since(evidenceStart, evidenceAllocated);
                evidenceMeasurement = new(evidenceMeasurement.Seconds + rebased.Seconds,
                    evidenceMeasurement.AllocatedBytes + rebased.AllocatedBytes);
            }

            long ownershipAllocated = GC.GetAllocatedBytesForCurrentThread();
            long ownershipStart = Stopwatch.GetTimestamp();

            long cleanupAllocated;
            long cleanupStart;

            bool resumed = validatedOwnership.TryResume(current);
            if (!resumed)
                validatedOwnership.Dispose();

            using (var reconciliation = resumed
                ? validatedOwnership : new AnnotationReconciliation(current, cancellationToken: cancellationToken)) {
                ownershipMeasurement = AnalysisMeasurement.Since(ownershipStart, ownershipAllocated);
                long applyAllocated = GC.GetAllocatedBytesForCurrentThread();
                stats = ApplyPrepared(current, format, task, prepared, evidence, reconciliation, stats,
                    out publishedArtifacts, cancellationToken);
                applyMeasurement = new(stats.ApplySeconds, GC.GetAllocatedBytesForCurrentThread() - applyAllocated);
                if (reconciliation.LegacyOwnershipMissing)
                    Plugin.Log(2, "Atlas ownership record missing; preexisting user annotations retained.");
                if (reconciliation.LegacyTagIdentityMissing)
                    Plugin.Log(2, "Legacy Atlas tag category unavailable; tag deletion identity cannot be recovered.");
                cleanupAllocated = GC.GetAllocatedBytesForCurrentThread();
                cleanupStart = Stopwatch.GetTimestamp();
            }

            cleanupMeasurement = AnalysisMeasurement.Since(cleanupStart, cleanupAllocated);
            applied = true;
        }, cancellationToken);

        published = applied;
        artifacts = publishedArtifacts;
        measurement = new(ownershipMeasurement, readMeasurement, hashMeasurement, preparationMeasurement,
            evidenceMeasurement, applyMeasurement, cleanupMeasurement, revalidationMeasurement,
            new(publication.WaitSeconds, publication.WaitAllocatedBytes), 1);

        return stats;
    }

    internal static bool InputMatches(nint view, ApplyStats stats, CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();
        nint raw = RetainRawView(view);

        try {
            ulong length = Core.BNGetViewLength(raw);
            if (length != stats.InputBytes)
                return false;

            cancellationToken.ThrowIfCancellationRequested();
            nint buffer = Core.BNReadViewBuffer(raw, 0, length);
            if (buffer == 0)
                throw new IOException("Binary Ninja could not read the raw view.");

            try {
                cancellationToken.ThrowIfCancellationRequested();
                if (Core.BNGetDataBufferLength(buffer) != length)
                    throw new IOException("Binary Ninja returned an incomplete raw view.");

                Span<byte> hash = stackalloc byte[32];
                Hash(new ReadOnlySpan<byte>(Core.BNGetDataBufferContents(buffer), checked((int)length)), hash,
                    cancellationToken);
                return hash.SequenceEqual(new ReadOnlySpan<byte>(stats.InputSha256, 32));
            } finally {
                Core.BNFreeDataBuffer(buffer);
            }
        } finally {
            Core.BNFreeBinaryView(raw);
        }
    }

    internal static bool InputCurrent(nint view, out MapFormat format, CancellationToken cancellationToken) {
        format = MapFormat.Auto;
        nint record;

        fixed (byte* key = "aot-atlas:apply-input\0"u8)
            record = Core.BNBinaryViewQueryMetadata(view, key);

        if (record == 0)
            return false;

        byte* data = null;

        try {
            if (Core.BNMetadataIsRaw(record) == 0)
                return false;

            nuint length = 0;
            data = Core.BNMetadataGetRaw(record, &length);
            var bytes = new ReadOnlySpan<byte>(data, checked((int)length));

            if (bytes.Length != 73 || !bytes[..8].SequenceEqual("ATINPUT1"u8)
                || bytes[72] > (byte)MapFormat.Metadata)
                return false;

            format = (MapFormat)bytes[72];
            if (new Guid(bytes.Slice(40, 16)) != ApplicationBuild || new Guid(bytes.Slice(56, 16)) != ExtractionBuild)
                return false;

            nint raw = RetainRawView(view);

            ApplyStats stats;
            try {
                stats = new() { InputBytes = Core.BNGetViewLength(raw) };
            } finally {
                Core.BNFreeBinaryView(raw);
            }

            stats = WithInputHash(stats, bytes.Slice(8, 32));
            return InputMatches(view, stats, cancellationToken);
        } finally {
            if (data != null)
                Core.BNFreeMetadataRaw(data);
            Core.BNFreeMetadata(record);
        }
    }

    private static nint RetainRawView(nint view) {
        // PE's parent is its Raw input. Parent access retains the native handle
        // directly; file view lookup instead waits for the UI thread on ABI 187.
        nint raw = Core.BNGetParentView(view);
        if (raw == 0)
            throw new InvalidDataException("The Binary Ninja PE view has no raw parent.");

        byte* kind = Core.BNGetViewType(raw);
        bool isRaw = kind[0] == 'R' && kind[1] == 'a' && kind[2] == 'w' && kind[3] == 0;
        Core.BNFreeString(kind);
        if (!isRaw) {
            Core.BNFreeBinaryView(raw);
            throw new InvalidDataException("The Binary Ninja PE parent is not a Raw view.");
        }
        return raw;
    }

    private static void Hash(ReadOnlySpan<byte> data, Span<byte> destination, CancellationToken cancellationToken) {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        while (!data.IsEmpty) {
            cancellationToken.ThrowIfCancellationRequested();
            int count = Math.Min(data.Length, 1024 * 1024);
            hash.AppendData(data[..count]);
            data = data[count..];
        }

        cancellationToken.ThrowIfCancellationRequested();
        int written = hash.GetHashAndReset(destination);
        Debug.Assert(written == 32);
    }

    private static ApplyStats WithInputHash(ApplyStats stats, ReadOnlySpan<byte> hash) {
        hash.CopyTo(new Span<byte>(stats.InputSha256, 32));
        return stats;
    }

    private static ApplyStats ApplyPrepared(nint view, MapFormat format, nint task, PreparedAnalysis prepared,
        AnalysisEvidence evidence, AnnotationReconciliation reconciliation, ApplyStats stats,
        out AnnotationArtifacts artifacts, CancellationToken cancellationToken) {
        artifacts = default;
        byte[] fieldRecords = "ATFLD001"u8.ToArray();
        var extraction = prepared.Extraction;
        var image = extraction.Image;

        if (task != 0) {
            if (Core.BNIsBackgroundTaskCancelled(task) != 0)
                throw new OperationCanceledException();

            fixed (byte* text = "AOT Atlas: applying metadata\0"u8)
                Core.BNSetBackgroundTaskProgressText(task, text);
        }

        long applyStart = Stopwatch.GetTimestamp();

        reconciliation.NormalizeSignedEnums();
        reconciliation.RetractFields();

        Span<byte> stamp = stackalloc byte[73];
        "ATINPUT1"u8.CopyTo(stamp);
        new ReadOnlySpan<byte>(stats.InputSha256, 32).CopyTo(stamp[8..]);
        ApplicationBuild.TryWriteBytes(stamp[40..]);
        ExtractionBuild.TryWriteBytes(stamp[56..]);
        stamp[72] = (byte)format;

        fixed (byte* key = "aot-atlas:apply-input\0"u8)
        fixed (byte* bytes = stamp) {
            nint record = Core.BNCreateMetadataRawData(bytes, (nuint)stamp.Length);

            try {
                Core.BNBinaryViewStoreMetadata(view, key, record, 3);
            } finally {
                Core.BNFreeMetadata(record);
            }
        }
        reconciliation.RememberInputFormat(format);

        var ownership = new TagOwnership(view);
        var variables = new DataVariables(view, reconciliation);

        var types = CollectionsMarshal.AsSpan(extraction.Types.Types);
        var pointers = CollectionsMarshal.AsSpan(extraction.Types.Pointers);

        byte[] arrayKinds = new byte[ushort.MaxValue + 1];

        int maxName = 0;
        int maxArray = 0;

        for (int i = 0; i < types.Length; ++i) {
            cancellationToken.ThrowIfCancellationRequested();

            string name = extraction.Names.Values[i];
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
        nint[] staticFields = new nint[extraction.Maps.Fields.Count];

        BoolConfidence qualifier = default;

        nint voidType = Core.BNCreateVoidType();
        nint pointer = 0;
        nint headerType = 0;
        nint interfacePointer = 0;

        try {
            var pointerTarget = new TypeConfidence(voidType);
            pointer = Core.BNCreatePointerTypeOfWidth(8, &pointerTarget, &qualifier, &qualifier, 0);
            headerType = HeaderType(view, pointer);
            var headerConfidence = new TypeConfidence(headerType);
            interfacePointer = Core.BNCreatePointerTypeOfWidth(8, &headerConfidence, &qualifier, &qualifier, 0);

            InstanceTypes.Apply(view, extraction, headerType, pointer, runtimeTypes, staticFields, task);

            if (prepared.Properties is { } properties) {
                PropertyTypes.Apply(
                    ownership, view, extraction, properties, runtimeTypes, pointer, propertyTypes, task);
            }

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

            var symbols = new Symbols(
                view, stats.ImageBase, checked(types.Length * 8 + (prepared.Code?.Context.Functions.Length ?? 0) * 4));

            Core.BNBeginBulkModifySymbols(view);

            try {
                fixed (byte* symbolName = nameBuffer) {
                    for (int i = 0; i < types.Length; ++i) {
                        cancellationToken.ThrowIfCancellationRequested();

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

                        if (entry.RelatedType != 0) {
                            Core.BNAddUserDataReference(
                                view, address + 8, stats.ImageBase + (entry.RelatedType - image.ImageBase));
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

                            for (int slot = 0; slot < slots.Count; ++slot) {
                                ulong target = pointers[slots.Start + slot];
                                if (target == 0 || (kind == 0 && !image.IsMapped(target, 1)))
                                    continue;

                                Core.BNAddUserDataReference(
                                    view, arrayAddress + (uint)slot * 8UL,
                                    stats.ImageBase + (target - image.ImageBase));
                            }
                        }
                    }
                }

                // Verified storage must precede method annotations that can materialize untyped placeholders.
                DictionaryAnnotations.Apply(
                    symbols, ownership, variables, view, extraction,
                    pointer, interfacePointer, ref stats, task);

                if (prepared.ManagedAbi is { } managedAbi) {
                    MethodAnnotations.Apply(
                        symbols, ownership, view, extraction, managedAbi,
                        displayTypes, headerType, voidType, pointer, ref stats, task);
                    PropertyFunctionAnnotations.Apply(
                        symbols, view, extraction, prepared.Properties!, displayTypes, voidType, ref stats, task);
                }

                FrozenAnnotations.Apply(
                    symbols, ownership, variables, view, extraction,
                    displayTypes, interfacePointer, ref stats, task);
                DispatchAnnotations.Apply(
                    symbols, ownership, variables, view, extraction, ref stats, task);
                if (prepared.DispatchCells is { } dispatchCells) {
                    DispatchCellAnnotations.Apply(
                        symbols, variables, view, extraction, dispatchCells, ref stats, task);
                }

                Staticantations.Apply(
                    symbols, ownership, variables, view, extraction,
                    staticFields, pointer, interfacePointer, ref stats, task);
                if (extraction.UnwindAnalysis.Unwind is not null)
                    UnwindAnnotations.Apply(symbols, ownership, variables, view, extraction, ref stats, task);

                if (extraction.UnwindAnalysis.Managed is not null)
                    ExceptionAnnotations.Apply(symbols, ownership, variables, view, extraction, ref stats, task);

                PInvokeAnnotations.Apply(
                    symbols, variables, view, extraction, pointer, interfacePointer, ref stats, task);
                StringAnnotations.Apply(
                    symbols, ownership, variables, view, image, prepared.Strings,
                    prepared.StringReferences, ref stats, task);

                if (prepared.Helpers is { } helpers)
                    RuntimeHelperAnnotations.Apply(symbols, variables, view, extraction, helpers, pointer, ref stats);

                if (prepared.Code is { } code) {
                    RuntimeCodeAnnotations.Apply(symbols, view, extraction, code.Runtime, ref stats, task);
                    ContextAnnotations.Apply(symbols, ownership, view, image, code.Context, ref stats, task);

                    int processed = 0;

                    foreach (ref readonly var reference in CollectionsMarshal.AsSpan(code.MetadataReferences)) {
                        if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                            throw new OperationCanceledException();

                        Core.BNAddUserDataReference(
                            view, stats.ImageBase + (reference.Instruction - image.ImageBase),
                            stats.ImageBase + (reference.Target - image.ImageBase));
                    }

                    fieldRecords = FieldAnnotations.Store(view, image, code, cancellationToken);
                }

                AnalysisAnnotations.Apply(ownership, view, evidence, ref stats, task);
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

            if (interfacePointer != 0)
                Core.BNFreeType(interfacePointer);
            if (headerType != 0)
                Core.BNFreeType(headerType);
            if (pointer != 0)
                Core.BNFreeType(pointer);
            Core.BNFreeType(voidType);

        }

        cancellationToken.ThrowIfCancellationRequested();
        var owned = reconciliation.Complete();
        stats.Symbols = owned.Symbols;
        stats.DataVariables = owned.Variables;
        stats.DataReferences = owned.References;
        stats.ApplySeconds = Stopwatch.GetElapsedTime(applyStart).TotalSeconds;
        artifacts = new(stats, format, fieldRecords);

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
                    Core.BNAddStructureBuilderMemberAtOffset(
                        builder, &memberType, text + position, offsets[i], 0, 0, 0, 0, 0);
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
                    QualifiedName name = new() {
                        Names = parts,
                        Join  = join,
                        Count = 2
                    };

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
