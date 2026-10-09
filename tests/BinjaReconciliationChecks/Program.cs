using System.Runtime.InteropServices;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.CompilerServices;
using System.Reflection;
using Atlas;
using Atlas.Binja;

internal static unsafe class Program {
    private static readonly nint View = 1;
    private static readonly nint Platform = 2;
    private static readonly nint TagType = 4;
    private static ulong imageBase = 0x10000000;

    private static void Main(string[] args) {
        NativeLibrary.SetDllImportResolver(typeof(Core).Assembly, (_, _, _) => NativeLibrary.Load(args[0]));
        nint first = Model.Type(1);
        nint second = Model.Type(2);
        nint analyst = Model.Type(99);

        if (args.Length == 2 && args[1] == "private-cache") {
            CheckPrivateCacheRecovery();
            return;
        }

        if (args.Length == 2 && args[1] == "enums") {
            CheckEnums();
            return;
        }

        if (args.Length == 2 && args[1] == "operations") {
            CheckOperationSerialization();
            return;
        }

        if (args.Length == 2 && args[1] == "snapshot-reuse") {
            CheckSnapshotTypeReuse();
            return;
        }

        if (args.Length == 2 && args[1] == "symbol-kinds") {
            CheckSymbolKinds();
            return;
        }

        if (args.Length == 2 && args[1] == "forward-types") {
            CheckForwardTypes();
            return;
        }

        if (args.Length == 2 && args[1] == "missing-receiver") {
            CheckMissingReceiverIdentity();
            return;
        }

        if (args.Length == 2) {
            CheckLegacy(first, args[1] == "legacy-atlas");
            return;
        }

        CheckTypeDependencies(first);

        Core.AddReference(View, Address(0x800), Address(0x810));
        DefineSymbol(0x600, "analyst", tracked: false);
        DefineVariable(0x610, analyst, tracked: false);
        nint external = Core.AddFunction(View, Platform, Address(0x700), 0, analyst);

        Apply(first, 1);
        Counts(1, 2, 2, 2, 3, 1, 0);
        Apply(first, 1);
        Counts(1, 2, 2, 2, 3, 1, 0);

        byte[] ownership = Ownership();
        try {
            using var owned = new AnnotationReconciliation(View);
            owned.RetractFields();
            Mutate(second, 2);
            throw new OperationCanceledException();
        } catch (OperationCanceledException) {
            Counts(1, 2, 2, 2, 3, 1, 0);
            Assert(Ownership().AsSpan().SequenceEqual(ownership), "Cancellation changed the persisted ownership generation.");
            Assert(VariableShape(0x20) == 1, "Cancellation did not restore the previous variable type.");
            Assert(FunctionShape(0x50) == 1, "Cancellation did not restore the previous automatic ABI.");
        }

        Model.FailWrite(1);
        try {
            Apply(second, 2);
            throw new InvalidOperationException("The injected snapshot failure was not observed.");
        } catch (IOException) {
            Counts(1, 2, 2, 2, 3, 1, 0);
            Assert(Ownership().AsSpan().SequenceEqual(ownership), "Failed serialization replaced the ownership generation.");
            Assert(VariableShape(0x20) == 1, "Failed serialization did not restore the previous variable.");
        } finally {
            Model.FailWrite(0);
        }

        Model.LoseReceipt();
        try {
            Apply(second, 2);
            throw new InvalidOperationException("The injected publication receipt loss was not observed.");
        } catch (IOException) {
            Counts(1, 2, 2, 2, 3, 1, 0);
            Assert(Ownership().AsSpan().SequenceEqual(ownership), "Lost publication receipt left a new ownership record after rollback.");
            Assert(VariableShape(0x20) == 1 && FunctionShape(0x50) == 1, "Lost publication receipt did not restore the previous generation.");
        }

        Model.Comment(Address(0x70));
        foreach (var inject in new Action[] { Model.LoseAbiReceipt, Model.LoseTypeReceipt }) {
            inject();
            try {
                Apply(second, 2);
                throw new InvalidOperationException("The injected annotation receipt loss was not observed.");
            } catch (IOException) {
                Counts(1, 2, 2, 2, 3, 1, 0);
                Assert(Ownership().AsSpan().SequenceEqual(ownership), "Lost annotation receipt changed the ownership generation.");
                Assert(VariableShape(0x20) == 1 && FunctionShape(0x50) == 1, "Lost annotation receipt left an unowned annotation.");
            }
        }
        Apply(second, 2);
        Counts(1, 2, 2, 2, 3, 1, 0);
        Assert(VariableShape(0x20) == 2 && FunctionShape(0x50) == 2, "Changed evidence did not replace the owned annotations.");

        nint changedConfidence = Model.Type(2UL | 1UL << 32);
        nint functionWithConfidence = Core.GetFunction(View, Platform, Address(0x50));
        Core.BNSetFunctionAutoType(functionWithConfidence, changedConfidence);
        Core.BNFreeFunction(functionWithConfidence);
        Apply(second, 2);
        Assert(FunctionShape(0x50) == (2UL | 1UL << 32), "An ABI confidence edit with an identical semantic type was overwritten.");

        CheckLocationOverride();

        var changedVariable = new TypeConfidence(second) { Confidence = 254 };
        Core.DefineVariable(View, Address(0x20), &changedVariable);
        fixed (byte* unchangedName = "atlas-2\0"u8) {
            nint metadataOnly = Core.BNCreateSymbol(3, unchangedName, unchangedName, unchangedName, Address(0x10), 2, 0, 42);
            Core.DefineSymbol(View, metadataOnly);
            Core.BNFreeSymbol(metadataOnly);
        }
        Apply(second, 2);
        DataVariable preservedVariable = default;
        Core.BNGetDataVariableAtAddress(View, Address(0x20), &preservedVariable);
        Assert(preservedVariable.Confidence == 254, "A variable confidence edit with an identical type was overwritten.");
        Core.BNFreeDataVariable(&preservedVariable);
        nint preservedSymbol = Core.BNGetSymbolByAddress(View, Address(0x10), 0);
        Assert(Core.BNGetSymbolBinding(preservedSymbol) == 2 && Core.BNGetSymbolOrdinal(preservedSymbol) == 42,
            "Symbol metadata edits with identical displayed names were overwritten.");
        Core.BNFreeSymbol(preservedSymbol);

        ApplyFields();
        Assert(Model.Count(6) == 1, "The first field annotation was not added.");
        ApplyFields();
        Assert(Model.Count(6) == 1, "Repeated field apply added another reference.");

        imageBase = 0x20000000;
        Model.Rebase(imageBase);
        Apply(second, 2);
        Counts(1, 2, 2, 2, 4, 1, 0);
        ApplyFields();
        Assert(Model.Count(6) == 1, "Rebased field ownership did not match the rebased function.");

        DefineSymbol(0x10, "renamed-by-analyst", tracked: false);
        DefineVariable(0x20, analyst, tracked: false);
        Model.UserType(Address(0x50), analyst);
        nint tag = GetTag();
        fixed (byte* text = "edited-by-analyst\0"u8)
            Core.SetTagData(tag, text);

        Apply(first, 1);
        Assert(VariableShape(0x20) == 99 && FunctionShape(0x50) == 99, "Analyst variable or ABI override was overwritten.");
        nint symbol = Core.BNGetSymbolByAddress(View, Address(0x10), 0);
        byte* name = Core.BNGetSymbolRawName(symbol);
        Assert(Marshal.PtrToStringUTF8((nint)name) == "renamed-by-analyst", "The analyst symbol was overwritten.");
        Core.BNFreeString(name);
        Core.BNFreeSymbol(symbol);
        Counts(1, 2, 2, 2, 4, 2, 0);

        using (var owned = new AnnotationReconciliation(View))
            owned.Complete();
        Counts(0, 2, 2, 1, 4, 1, 0);
        Assert(FunctionShape(0x700) == 99, "An unrelated automatic ABI was changed.");

        // An explicit user deletion becomes a durable exclusion. A later desired
        // plan must not recreate it merely because the host slot is empty.
        Apply(second, 2);
        Core.BNRemoveUserDataReference(View, Address(0x30), Address(0x42));
        Apply(second, 2);
        Assert(!HasReference(0x30, 0x42), "A user-deleted reference was recreated.");

        CheckWorkCount(second);
        CheckInvalidRecord();
        CheckSymbolBatches(second);
        CheckCancellation(second);
        CheckAnalysisWait();
        CheckPublication(first, second, analyst);
        CheckInputValidation();
        CheckFieldInput();
        CheckCurrentView();
        CheckAnalysisHold();
        CheckTagDeletion();

        Console.WriteLine("PASS: production reconciliation through ABI 187 shim: repeat, replacement, disappearance, recursive type dependencies, user edits, ABI confidence/location, field references, rebase, cancellation, serialization failure, lost publication receipt and retry.");
    }

    private static void CheckInputValidation() {
        byte[] savedOwnership = ReadRaw("aot-atlas:owned-annotations");
        byte[] generation = Ownership();
        int[] before = Enumerable.Range(0, 7).Select(Model.Count).ToArray();
        var inputMatches = typeof(NativeApply).GetMethod("InputMatches", BindingFlags.Static | BindingFlags.NonPublic)!;
        byte[] bytes = Enumerable.Range(0, 4096).Select(index => (byte)(index * 37)).ToArray();
        var stats = InputIdentity(bytes);

        SetRaw(bytes);
        AnnotationPublication.Run(View, _ => {
            Assert((bool)inputMatches.Invoke(null, [View, stats, CancellationToken.None])!, "Unchanged raw input failed revalidation.");
        });

        bytes[123] ^= 1;
        SetRaw(bytes);
        AnnotationPublication.Run(View, _ => {
            Assert(!(bool)inputMatches.Invoke(null, [View, stats, CancellationToken.None])!, "A same-length raw edit passed revalidation.");
        });

        SetRaw(bytes[..^1]);
        AnnotationPublication.Run(View, _ => {
            Assert(!(bool)inputMatches.Invoke(null, [View, stats, CancellationToken.None])!, "A raw size change passed revalidation.");
        });
        SetRaw(bytes);

        foreach (int stage in new[] { 1, 2 }) {
            using var cancellation = new CancellationTokenSource();
            var context = GCHandle.Alloc(cancellation);
            Model.RawCallback(stage, GCHandle.ToIntPtr(context), &CancelRawRead);

            try {
                AnnotationPublication.Run(View, _ => inputMatches.Invoke(null, [View, stats, cancellation.Token]));
                throw new Exception("Cancellation during raw revalidation was not observed.");
            } catch (TargetInvocationException error) when (error.InnerException is OperationCanceledException) {
                Assert(Ownership().AsSpan().SequenceEqual(generation), "Canceled revalidation changed the ownership generation.");
                Counts(before);
            } finally {
                Model.RawCallback(0, 0, null);
                context.Free();
            }
        }

        fixed (byte* key = "aot-atlas:owned-annotations\0"u8) {
            byte[] invalid = "invalid ownership"u8.ToArray();
            fixed (byte* value = invalid) {
                nint record = Core.BNCreateMetadataRawData(value, (nuint)invalid.Length);
                Core.StoreMetadataRaw(View, key, record, 3);
                Core.BNFreeMetadata(record);
            }

            int reads = Model.RawReads();
            try {
                NativeApply.Run(View, MapFormat.Auto, 0);
                throw new Exception("Invalid ownership passed application preflight.");
            } catch (InvalidDataException) {
                Assert(Model.RawReads() == reads, "Invalid ownership was rejected only after raw input preparation.");
                Counts(before);
            } finally {
                fixed (byte* value = generation) {
                    nint record = Core.BNCreateMetadataRawData(value, (nuint)generation.Length);
                    Core.StoreMetadataRaw(View, key, record, 3);
                    Core.BNFreeMetadata(record);
                }
            }
        }

        Assert(Model.NotificationCount() == 0 && Model.WaitCount(1) == 0 && Model.RawBuffers() == 0,
            "Raw revalidation retained a callback, view or read buffer.");
        StoreRaw("aot-atlas:owned-annotations", savedOwnership);
        Console.WriteLine("ABI shim: same-length/size raw edits detected under publication; cancellation after native read and before hashing preserved state; invalid ownership rejected before reading input.");
    }

    private static void SetRaw(byte[] bytes) {
        fixed (byte* pointer = bytes)
            Model.RawBytes(pointer, (nuint)bytes.Length);
    }

    private static void CheckCurrentView() {
        Model.CurrentPeView(9);
        AnnotationPublication.Run(View, current => Assert(current == 9,
            "Publication used a detached pre-rebase view."));
        Model.CurrentPeView(View);

        using var currentView = new AnnotationView(View);
        var waiting = Task.Run(() => AnalysisWait.Run(currentView, CancellationToken.None));
        Assert(SpinWait.SpinUntil(() => Model.WaitCount(0) == 1, 5000), "Replacement test did not start analysis.");
        Model.CurrentPeView(9);
        Assert(SpinWait.SpinUntil(() => Model.WaitCount(3) == 2, 5000), "Analysis did not resume on the replacement view.");
        Assert(Model.WaitCount(0) == 1 && Model.WaitCount(1) == 2,
            "A replaced view retained the caller's obsolete event or view reference.");
        Model.CompleteWait();
        Assert(!waiting.Wait(25), "Completion on the detached view completed the current-view operation.");
        Model.CompleteWait();
        Assert(waiting.Wait(1000) && currentView.Handle == 9, "Analysis did not complete on the replacement view.");
        Assert(Model.WaitCount(0) == 0 && Model.WaitCount(1) == 1,
            "Rebased analysis did not release both callback lifetimes.");
        Model.CurrentPeView(View);
        Console.WriteLine("ABI shim: publication resolves replaced views; analysis resumes on the replacement and ignores detached-view completion.");

        int retained = Model.WaitCount(1);
        Model.CurrentPeView(0);
        try {
            AnnotationPublication.Run(View, _ => throw new InvalidOperationException("A closed view was published."));
            throw new InvalidOperationException("Closing the view did not cancel publication.");
        } catch (OperationCanceledException) {
            Assert(Model.NotificationCount() == 0 && Model.WaitCount(1) == retained,
                "Closing the view retained a callback or view.");
        } finally {
            Model.CurrentPeView(View);
        }
        AnnotationPublication.Run(View, current => Assert(current == View,
            "Publication could not resume on the live view."));
        Console.WriteLine("ABI shim: closing the file cancels publication, releases its resources and permits later work on a live view.");
    }

    private static void CheckTagDeletion() {
        const ulong rva = 0xfe00;
        ApplyDataTag(4, rva, "canonical");
        nint deleted = DataTag(4, rva, "canonical");
        Core.BNRemoveUserDataTag(View, Address(rva), deleted);
        Core.BNFreeTag(deleted);

        for (int run = 0; run < 3; ++run) {
            ApplyDataTag(run == 0 ? 4 : 5, rva, "canonical");
            Assert(DataTagCount(4, rva) + DataTagCount(5, rva) == 0,
                "A deleted tag was recreated after receipt reload or category replacement.");
        }

        ApplyDataTag(6, rva, "unrelated category");
        Assert(DataTagCount(6, rva) == 1, "A deleted tag suppressed an unrelated category at the same site.");

        const ulong editedRva = rva + 16;
        ApplyDataTag(4, editedRva, "canonical");
        nint edited = DataTag(4, editedRva, "canonical");
        fixed (byte* value = "analyst text\0"u8)
            Core.SetTagData(edited, value);
        Core.BNFreeTag(edited);
        ApplyDataTag(4, editedRva, "canonical");
        Assert(DataTagCount(4, editedRva) == 2,
            "Edited tag preservation lost the separate canonical tag.");

        nint canonical = DataTag(4, editedRva, "canonical");
        Core.BNRemoveUserDataTag(View, Address(editedRva), canonical);
        Core.BNFreeTag(canonical);
        for (int run = 0; run < 3; ++run) {
            ApplyDataTag(4, editedRva, "canonical");
            Assert(DataTagCount(4, editedRva) == 1,
                "An old edited-tag receipt masked deletion of the canonical replacement.");
        }

        Console.WriteLine("ABI shim: deleted tag sites persist across receipt reload and category recreation; other categories remain creatable; edited tags retain their canonical companion without masking its later deletion.");
    }

    private static void CheckAnalysisHold() {
        Model.AnalysisHold(1);
        try {
            AnalysisWait.Run(View, default);
            throw new Exception("A held view entered an unfinishable analysis wait.");
        } catch (InvalidOperationException) {
            Assert(Model.WaitCount(0) == 0 && Model.WaitCount(1) == 0,
                "Held analysis retained a completion callback or view.");
        } finally {
            Model.AnalysisHold(0);
        }

        var waiting = Task.Run(() => {
            try {
                AnalysisWait.Run(View, default);
                throw new Exception("A hold acquired during analysis was not observed.");
            } catch (InvalidOperationException) {
            }
        });
        Assert(SpinWait.SpinUntil(() => Model.WaitCount(0) == 1, 5000), "Hold test did not start analysis.");
        Model.AnalysisHold(1);
        Assert(waiting.Wait(1000), "A late analysis hold blocked the operation indefinitely.");
        Assert(Model.WaitCount(0) == 0 && Model.WaitCount(1) == 0 && Model.WaitCount(3) == 1,
            "A late hold retained abandoned caller resources or unregistered its host callback.");
        Model.AnalysisHold(0);
        Model.CompleteWait();
        Model.ImmediateCompletion(1);
        AnalysisWait.Run(View, default);
        Model.ImmediateCompletion(0);
        Assert(Model.WaitCount(0) == 0 && Model.WaitCount(1) == 0, "Retry after release of an analysis hold leaked resources.");
        Console.WriteLine("ABI shim: initial and late analysis holds release caller resources; delayed callbacks stay safe and retry completes after hold release.");
    }

    private static void ApplyDataTag(nint type, ulong rva, string text) {
        byte[] bytes = Encoding.UTF8.GetBytes(text + '\0');
        AnnotationPublication.Run(View, view => {
            using var reconciliation = new AnnotationReconciliation(view);
            var ownership = new TagOwnership(view);
            DataTags.Set(ownership, view, type, Address(rva), bytes);
            reconciliation.Complete();
        });
    }

    private static int DataTagCount(nint type, ulong rva) {
        nuint count = 0;
        nint* tags = Core.BNGetUserDataTagsOfType(View, Address(rva), type, &count);
        Core.BNFreeTagList(tags, count);
        return checked((int)count);
    }

    private static nint DataTag(nint type, ulong rva, string text) {
        nuint count = 0;
        nint* tags = Core.BNGetUserDataTagsOfType(View, Address(rva), type, &count);
        try {
            for (nuint i = 0; i < count; ++i) {
                byte* value = Core.BNTagGetData(tags[i]);
                bool matches = Marshal.PtrToStringUTF8((nint)value) == text;
                Core.BNFreeString(value);
                if (matches)
                    return Core.BNNewTagReference(tags[i]);
            }
            throw new InvalidDataException("The expected tag is absent.");
        } finally {
            Core.BNFreeTagList(tags, count);
        }
    }

    private static ApplyStats InputIdentity(byte[] bytes) {
        ApplyStats stats = new() { InputBytes = (ulong)bytes.Length };
        SHA256.HashData(bytes, new Span<byte>(stats.InputSha256, 32));
        return stats;
    }

    private static void CheckFieldInput() {
        byte[] bytes = [1, 2, 3, 4];
        SetRaw(bytes);
        byte[] stamp = new byte[73];
        "ATINPUT1"u8.CopyTo(stamp);
        SHA256.HashData(bytes, stamp.AsSpan(8, 32));
        typeof(NativeApply).Module.ModuleVersionId.TryWriteBytes(stamp.AsSpan(40, 16));
        typeof(Extraction).Module.ModuleVersionId.TryWriteBytes(stamp.AsSpan(56, 16));
        stamp[72] = (byte)MapFormat.Metadata;
        StoreRaw("aot-atlas:apply-input", stamp);
        AnnotationPublication.Run(View, view => Assert(NativeApply.InputCurrent(view, out var format, default)
            && format == MapFormat.Metadata, "A matching producer/input stamp lost its source format."));

        byte[] fields = new byte[28];
        "ATFLD001"u8.CopyTo(fields);
        StoreRaw("aot-atlas:field-references", fields);
        var artifacts = new AnnotationArtifacts(InputIdentity(bytes), MapFormat.Metadata, fields);
        bytes[1] ^= 1;
        SetRaw(bytes);
        int before = Model.Count(6);
        using var currentView = new AnnotationView(View);
        Assert(!FieldAnnotations.TryApply(currentView, required: true, out int count, out var originalFormat, artifacts: artifacts)
            && count == 0 && originalFormat == MapFormat.Metadata && Model.Count(6) == before,
            "Changed raw input replayed stale field evidence or lost its original source format.");

        stamp.AsSpan(40, 16).Clear();
        StoreRaw("aot-atlas:apply-input", stamp);
        int reads = Model.RawReads();
        AnnotationPublication.Run(View, view => Assert(!NativeApply.InputCurrent(view, out _, default),
            "A different producer build passed field evidence validation."));
        Assert(Model.RawReads() == reads, "A mismatched producer build was detected after raw revalidation.");
        Console.WriteLine("ABI shim: field replay rejects changed raw input and producer builds, preserves original map format and leaves native fields unchanged.");
    }

    private static void CheckMissingReceiverIdentity() {
        byte[] raw = [1, 2, 3, 4];
        SetRaw(raw);
        byte[] stamp = new byte[73];
        "ATINPUT1"u8.CopyTo(stamp);
        SHA256.HashData(raw, stamp.AsSpan(8, 32));
        typeof(NativeApply).Module.ModuleVersionId.TryWriteBytes(stamp.AsSpan(40, 16));
        typeof(Extraction).Module.ModuleVersionId.TryWriteBytes(stamp.AsSpan(56, 16));
        stamp[72] = (byte)MapFormat.Metadata;

        byte[] fields = new byte[48];
        "ATFLD001"u8.CopyTo(fields);
        for (int i = 0; i < 2; ++i) {
            var entry = fields.AsSpan(8 + i * 20, 20);
            BinaryPrimitives.WriteUInt32LittleEndian(entry, (uint)(i + 1));
            BinaryPrimitives.WriteUInt32LittleEndian(entry[4..], 8);
            BinaryPrimitives.WriteUInt32LittleEndian(entry[8..], 0x50);
            BinaryPrimitives.WriteUInt32LittleEndian(entry[12..], (uint)(0x70 + i));
            BinaryPrimitives.WriteUInt32LittleEndian(entry[16..], 4);
        }
        void DefineReceiver(int index) {
            byte[] identifier = Encoding.UTF8.GetBytes($"aot-atlas:runtime-type:v1:{index:X8}\0");
            byte[] text = Encoding.UTF8.GetBytes($"Receiver{index}\0");
            fixed (byte* id = identifier)
            fixed (byte* nameText = text)
            fixed (byte* join = "::\0"u8) {
                byte** parts = stackalloc byte*[1] { nameText };
                var name = new QualifiedName { Names = parts, Join = join, Count = 1 };
                var actual = Core.BNDefineAnalysisType(View, id, &name, Model.Type((ulong)index));
                Core.BNFreeQualifiedName(&actual);
            }
        }
        nint function = Core.AddFunction(View, Platform, Address(0x50), 0, Model.Type(1));
        Core.BNFreeFunction(function);
        AnnotationPublication.Run(View, view => {
            using var reconciliation = new AnnotationReconciliation(view);
            DefineReceiver(1);
            StoreInput(stamp, tracked: true);
            fixed (byte* key = "aot-atlas:field-references\0"u8)
            fixed (byte* data = fields) {
                nint record = Core.BNCreateMetadataRawData(data, (nuint)fields.Length);
                Core.BNBinaryViewStoreMetadata(view, key, record, 3);
                Core.BNFreeMetadata(record);
            }
            reconciliation.RememberInputFormat(MapFormat.Metadata);
            reconciliation.Complete();
        });
        byte[] ownership = Ownership();
        using var currentView = new AnnotationView(View);
        Assert(!FieldAnnotations.TryApply(currentView, true, out int count, out var format)
            && count == 0 && format == MapFormat.Metadata && Model.Count(6) == 0
            && Ownership().AsSpan().SequenceEqual(ownership),
            "A missing saved receiver did not request source reconstruction and roll back earlier field writes.");
        var artifacts = new AnnotationArtifacts(InputIdentity(raw), MapFormat.Metadata, fields);
        try {
            FieldAnnotations.TryApply(currentView, true, out _, out _, artifacts: artifacts);
            throw new Exception("Fresh source evidence with a missing receiver was accepted.");
        } catch (InvalidOperationException) {
            Assert(Model.Count(6) == 0, "Invalid fresh receiver evidence left partial field references.");
        }
        DefineReceiver(2);
        Assert(FieldAnnotations.TryApply(currentView, true, out count, out format, artifacts: artifacts)
            && count == 2 && Model.Count(6) == 2,
            "Source reconstruction did not complete the same saved field operation.");
        Console.WriteLine("ABI shim: missing saved receiver identities roll back partial field replay; invalid fresh evidence fails and source reconstruction completes the accepted operation.");
    }

    private static void CheckPrivateCacheRecovery() {
        byte[] raw = [1, 2, 3, 4];
        SetRaw(raw);
        byte[] prior = new byte[73];
        "ATINPUT1"u8.CopyTo(prior);
        SHA256.HashData(raw, prior.AsSpan(8, 32));
        typeof(NativeApply).Module.ModuleVersionId.TryWriteBytes(prior.AsSpan(40, 16));
        typeof(Extraction).Module.ModuleVersionId.TryWriteBytes(prior.AsSpan(56, 16));
        prior[72] = (byte)MapFormat.Metadata;
        byte[] fields = "ATFLD001"u8.ToArray();
        AnnotationPublication.Run(View, view => {
            using var reconciliation = new AnnotationReconciliation(view);
            StoreInput(prior, tracked: true);
            fixed (byte* key = "aot-atlas:field-references\0"u8)
            fixed (byte* data = fields) {
                nint record = Core.BNCreateMetadataRawData(data, (nuint)fields.Length);
                reconciliation.StoreMetadata(key, record, 3);
                Core.BNFreeMetadata(record);
            }
            reconciliation.Complete();
        });

        byte[] changed = "analyst input identity"u8.ToArray();
        StoreInput(changed, tracked: false);
        StoreRaw("aot-atlas:field-references", "analyst field cache"u8.ToArray());
        using var currentView = new AnnotationView(View);
        Assert(!FieldAnnotations.TryApply(currentView, true, out _, out var format) && format == MapFormat.Metadata,
            "An overridden private cache became authoritative.");
        AnnotationPublication.Run(View, view => {
            using var reconciliation = new AnnotationReconciliation(view);
            StoreInput(prior, tracked: true);
            reconciliation.RememberInputFormat(MapFormat.Legacy);
            reconciliation.Complete();
        });
        var artifacts = new AnnotationArtifacts(InputIdentity(raw), MapFormat.Metadata, fields);
        Assert(FieldAnnotations.TryApply(currentView, true, out int count, out format, artifacts: artifacts)
            && count == 0 && format == MapFormat.Metadata && ReadInput().AsSpan().SequenceEqual(changed)
            && ReadRaw("aot-atlas:field-references").AsSpan().SequenceEqual("analyst field cache"u8),
            "Fresh source-derived artifacts failed to finish while preserving the private cache override.");
        AnnotationPublication.Run(View, view => {
            using var reconciliation = new AnnotationReconciliation(view);
            Assert(reconciliation.TryInputFormat(out var actual) && actual == MapFormat.Legacy,
                "A successful explicit map-format choice was lost behind an excluded cache.");
        });
        Model.NonRawMetadata("aot-atlas:apply-input");
        AnnotationPublication.Run(View, view => {
            using var reconciliation = new AnnotationReconciliation(view);
            StoreInput(prior, tracked: true);
            reconciliation.RememberInputFormat(MapFormat.Legacy);
            reconciliation.Complete();
        });
        Assert(FieldAnnotations.TryApply(currentView, true, out count, out format, artifacts: artifacts) && count == 0,
            "A nonraw private cache prevented fresh annotation recovery.");
        fixed (byte* key = "aot-atlas:apply-input\0"u8) {
            nint record = Core.BNBinaryViewQueryMetadata(View, key);
            Assert(Core.BNMetadataIsRaw(record) == 0, "A nonraw private cache override was replaced.");
            Core.BNFreeMetadata(record);
        }
        fixed (byte* key = "aot-atlas:owned-annotations\0"u8)
            Core.BNBinaryViewRemoveMetadata(View, key);
        AnnotationPublication.Run(View, view => {
            using var reconciliation = new AnnotationReconciliation(view);
            StoreInput(prior, tracked: true);
            reconciliation.RememberInputFormat(MapFormat.Metadata);
            reconciliation.Complete();
        });
        AnnotationPublication.Run(View, view => {
            using var reconciliation = new AnnotationReconciliation(view);
            Assert(reconciliation.TryInputFormat(out var actual) && actual == MapFormat.Metadata,
                "An existing unowned private cache erased the actual successful application format.");
        });
        Assert(Model.NotificationCount() == 0 && Model.WaitCount(1) == 1,
            "Private-record repair retained a publication callback or view.");
        Console.WriteLine("ABI shim: private cache edits are preserved; fresh source-derived artifacts finish without consuming overrides and explicit map-format choice survives receipt reload.");
    }

    private static void StoreRaw(string name, byte[] bytes) {
        byte[] key = Encoding.UTF8.GetBytes(name + '\0');
        fixed (byte* pointer = bytes)
        fixed (byte* namePointer = key) {
            nint record = Core.BNCreateMetadataRawData(pointer, (nuint)bytes.Length);
            Core.StoreMetadataRaw(View, namePointer, record, 3);
            Core.BNFreeMetadata(record);
        }
    }

    private static byte[] ReadRaw(string name) {
        byte[] key = Encoding.UTF8.GetBytes(name + '\0');
        fixed (byte* pointer = key) {
            nint record = Core.BNBinaryViewQueryMetadata(View, pointer);
            nuint length = 0;
            byte* bytes = Core.BNMetadataGetRaw(record, &length);
            try {
                return new ReadOnlySpan<byte>(bytes, checked((int)length)).ToArray();
            } finally {
                Core.BNFreeMetadataRaw(bytes);
                Core.BNFreeMetadata(record);
            }
        }
    }

    private static void CheckSnapshotReuse() {
        for (int candidate = 0; candidate < 2; ++candidate) {
            long allocated = GC.GetTotalAllocatedBytes(precise: true);
            int loads = Model.LibraryLoads();
            long start = Stopwatch.GetTimestamp();
            for (int i = 0; i < 32; ++i) {
                AnnotationReconciliation? snapshot = null;
                try {
                    AnnotationPublication.Run(View, view => {
                        snapshot = new AnnotationReconciliation(view);
                        snapshot.Suspend();
                    });
                    AnnotationPublication.Run(View, view => {
                        using var publication = candidate == 1 && snapshot!.TryResume(view)
                            ? snapshot : new AnnotationReconciliation(view);
                    });
                } finally {
                    snapshot?.Dispose();
                }
            }
            Assert(Model.LibraryLoads() - loads == (candidate == 0 ? 64 : 32), "Ownership snapshot reuse did not remove the duplicate native library load.");
            Console.WriteLine($"ABI shim ownership preflight candidate {candidate}: 32 paired validation/publication barriers, native snapshot loads {Model.LibraryLoads() - loads}; {Stopwatch.GetElapsedTime(start).TotalMilliseconds:F2} ms, managed allocation {GC.GetTotalAllocatedBytes(precise: true) - allocated:N0} B.");
        }
        byte[] original = ReadRaw("aot-atlas:owned-annotations");
        using var suspended = new AnnotationReconciliation(View);
        suspended.Suspend();
        StoreRaw("aot-atlas:owned-annotations", [.. original, 1]);
        AnnotationPublication.Run(View, view => Assert(!suspended.TryResume(view), "Changed ownership receipt reused its stale snapshot."));
        StoreRaw("aot-atlas:owned-annotations", original);
        AnnotationPublication.Run(View, view => Assert(suspended.TryResume(view), "Unchanged ownership receipt could not resume after a rejected generation."));
    }

    private static void CheckEnums() {
        const ulong signedShape = 0xc400000000000001;
        const ulong unsignedShape = 0x8400000000000001;
        nint signed = Model.Type(signedShape);
        nint unsigned = Model.Type(unsignedShape);
        byte[] raw = [1, 2, 3, 4];
        SetRaw(raw);

        void SetEnum(nint type) {
            fixed (byte* id = "aot-atlas:enum:v1:00000001\0"u8)
            fixed (byte* text = "Enum\0"u8) {
                byte** parts = stackalloc byte*[1] { text };
                var name = new QualifiedName { Names = parts, Join = text + 4, Count = 1 };
                var actual = Core.BNDefineAnalysisType(View, id, &name, type);
                Core.BNFreeQualifiedName(&actual);
            }
        }
        ulong EnumShape() {
            fixed (byte* id = "aot-atlas:enum:v1:00000001\0"u8) {
                nint type = Core.BNGetAnalysisTypeById(View, id);
                return type == 0 ? 0 : Model.Shape(type);
            }
        }

        AnnotationPublication.Run(View, view => {
            using var reconciliation = new AnnotationReconciliation(view);
            SetEnum(signed);
            reconciliation.Complete();
        });
        SetEnum(unsigned);
        Model.SnapshotUnsigned(1);
        AnnotationPublication.Run(View, view => {
            using var reconciliation = new AnnotationReconciliation(view);
            Assert(reconciliation.NormalizeSignedEnums() == 1 && EnumShape() == signedShape,
                "Lost signedness in both view and native snapshot prevented owned enum normalization.");
            SetEnum(Model.Type(signedShape + 1));
            reconciliation.Complete();
        });
        Assert(EnumShape() == signedShape + 1, "Fresh enum members were excluded after signedness normalization.");

        SetEnum(Model.Type(unsignedShape + 1));
        AnnotationPublication.Run(View, view => {
            using var reconciliation = new AnnotationReconciliation(view);
            Assert(reconciliation.NormalizeSignedEnums() == 1, "A changed source enum lost its prior signedness marker.");
            reconciliation.Complete();
        });
        Assert(EnumShape() == 0, "A source-removed enum was retained as an analyst signedness edit.");

        AnnotationPublication.Run(View, view => {
            using var reconciliation = new AnnotationReconciliation(view);
            SetEnum(signed);
            reconciliation.Complete();
        });
        SetEnum(Model.Type(unsignedShape + 7));
        AnnotationPublication.Run(View, view => {
            using var reconciliation = new AnnotationReconciliation(view);
            Assert(reconciliation.NormalizeSignedEnums() == 0, "An analyst member edit was normalized as a reload defect.");
            SetEnum(signed);
            reconciliation.Complete();
        });
        Assert(EnumShape() == unsignedShape + 7, "An analyst enum member edit was overwritten.");
        Model.SnapshotUnsigned(0);
        SetEnum(signed);
        fixed (byte* key = "aot-atlas:owned-annotations\0"u8)
            Core.BNBinaryViewRemoveMetadata(View, key);
        AnnotationPublication.Run(View, view => {
            using var reconciliation = new AnnotationReconciliation(view);
            SetEnum(Model.Type(signedShape + 9));
            reconciliation.Complete();
        });
        Assert(EnumShape() == signedShape + 9, "Legacy native automatic enum provenance failed to reconstruct its signedness marker.");
        Console.WriteLine("ABI shim: independent enum sign receipt repairs view/snapshot loss before changed/removed-source reconciliation and preserves edited members.");
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void CancelRawRead(nint context) => ((CancellationTokenSource)GCHandle.FromIntPtr(context).Target!).Cancel();

    private static ulong Address(ulong rva) => imageBase + rva;

    private static void CheckLegacy(nint type, bool atlasOrigin) {
        if (atlasOrigin) {
            using var reconciliation = new AnnotationReconciliation(View);
            DefineType(type);
            DefineSymbol(0x10, "methodtable::Legacy", tracked: true);
            DefineVariable(0x20, type, tracked: true);
            Core.BNAddUserDataReference(View, Address(0x30), Address(0x40));
            reconciliation.Complete();

            fixed (byte* key = "aot-atlas:owned-annotations\0"u8)
                Core.BNBinaryViewRemoveMetadata(View, key);
        } else {
            // Atlas's automatic type exists in both histories. Here, the analyst
            // independently created the same user-layer symbol, variable and ref.
            DefineType(type);
            DefineSymbol(0x10, "methodtable::Legacy", tracked: false);
            DefineVariable(0x20, type, tracked: false);
            Core.AddReference(View, Address(0x30), Address(0x40));
        }

        using var snapshot = new MemoryStream();
        using var writer = new BinaryWriter(snapshot, Encoding.UTF8, leaveOpen: true);
        nint symbol = Core.BNGetSymbolByAddress(View, Address(0x10), 0);
        writer.Write(Core.BNGetSymbolAddress(symbol));
        writer.Write(Core.BNGetSymbolType(symbol));
        writer.Write(Core.BNIsSymbolAutoDefined(symbol));
        writer.Write(Core.BNGetSymbolBinding(symbol));
        writer.Write(Core.BNGetSymbolOrdinal(symbol));
        foreach (byte* text in new nint[] { (nint)Core.BNGetSymbolShortName(symbol), (nint)Core.BNGetSymbolFullName(symbol), (nint)Core.BNGetSymbolRawName(symbol) }) {
            writer.Write(Marshal.PtrToStringUTF8((nint)text)!);
            Core.BNFreeString(text);
        }
        var nameSpace = Core.BNGetSymbolNameSpace(symbol);
        writer.Write((ulong)nameSpace.Count);
        writer.Write(Marshal.PtrToStringUTF8((nint)nameSpace.Join) ?? "");
        for (nuint i = 0; i < nameSpace.Count; ++i)
            writer.Write(Marshal.PtrToStringUTF8((nint)nameSpace.Names[i])!);
        Core.BNFreeNameSpace(&nameSpace);
        Core.BNFreeSymbol(symbol);

        DataVariable variable = default;
        Assert(Core.BNGetDataVariableAtAddress(View, Address(0x20), &variable) != 0, "Legacy variable missing.");
        writer.Write(variable.Address);
        writer.Write(variable.AutoDiscovered);
        writer.Write(variable.Confidence);
        writer.Write(Model.Shape(variable.Type));
        Core.BNFreeDataVariable(&variable);
        writer.Write(HasReference(0x30, 0x40));
        writer.Flush();
        Console.WriteLine("LEGACY STATE " + Convert.ToHexString(snapshot.ToArray()));

        AnnotationPublication.Run(View, _ => {
            using var reconciliation = new AnnotationReconciliation(View);
            reconciliation.Complete();
        });

        Assert(Model.Count(0) == 0, "A reconstructable legacy Atlas automatic type was not retired.");
        Assert(Model.Count(1) == 1 && VariableShape(0x20) == 1 && HasReference(0x30, 0x40),
            "An unidentifiable legacy user annotation was deleted.");
    }

    private static void CheckPublication(nint first, nint second, nint analyst) {
        const ulong rva = 0xf000;

        using (var reconciliation = new AnnotationReconciliation(View)) {
            DefineVariable(rva, first, tracked: true);
            reconciliation.Complete();
        }

        Action publishWithoutBoundary = () => {
            using var reconciliation = new AnnotationReconciliation(View);
            DefineVariable(rva, second, tracked: true);
            reconciliation.Complete();
        };

        foreach (int candidate in new[] { 0, 1, 2 }) {
            Model.RaceVariable(Address(rva), analyst);

            if (candidate == 0) {
                publishWithoutBoundary();
            } else if (candidate == 1) {
                lock (new Lock())
                    publishWithoutBoundary();
            } else {
                var context = GCHandle.Alloc(publishWithoutBoundary);

                try {
                    Model.ExecuteMainThread(GCHandle.ToIntPtr(context), &PublishOnMainThread);
                } finally {
                    context.Free();
                }
            }

            Model.JoinWriter();
            Assert(VariableShape(rva) == 2, $"Candidate {candidate} did not reproduce an overwritten analyst edit.");
        }

        Model.RaceVariable(Address(rva), analyst);
        int runs = 0;
        long start = Stopwatch.GetTimestamp();

        AnnotationPublication.Run(View, _ => {
            ++runs;
            Model.RepeatBarrier();
            using var reconciliation = new AnnotationReconciliation(View);
            DefineVariable(rva, first, tracked: true);
            reconciliation.Complete();
        });

        Model.JoinWriter();
        Assert(runs == 1 && VariableShape(rva) == 99, "The barrier did not serialize the competing writer after Atlas publication.");
        Assert(Model.NotificationCount() == 0 && Model.WaitCount(1) == 0, "Immediate publication retained a callback or view.");

        AnnotationPublication.Run(View, _ => {
            using var reconciliation = new AnnotationReconciliation(View);
            DefineVariable(rva, second, tracked: true);
            reconciliation.Complete();
        });

        Assert(VariableShape(rva) == 99, "Publication after a serialized analyst edit overwrote the analyst type.");

        using (var afterCommit = new CancellationTokenSource()) {
            AnnotationPublication.Run(View, _ => {
                using var reconciliation = new AnnotationReconciliation(View, cancellationToken: afterCommit.Token);
                DefineVariable(0xf040, first, tracked: true);
                reconciliation.Complete();
                afterCommit.Cancel();
            }, afterCommit.Token);

            Assert(VariableShape(0xf040) == 1,
                "Cancellation after ownership commit hid a successfully published annotation.");
        }

        Model.DelayedBarrier(1);
        using var cancellation = new CancellationTokenSource();
        var canceled = Task.Run(() => {
            try {
                AnnotationPublication.Run(View, _ => ++runs, cancellation.Token);
                throw new Exception("Canceled delayed publication completed successfully.");
            } catch (OperationCanceledException) {
            }
        });

        Assert(SpinWait.SpinUntil(() => Model.NotificationCount() == 1, 5000), "Delayed publication did not register.");
        cancellation.Cancel();
        Assert(canceled.Wait(1000), "Cancellation remained blocked on a pending barrier.");
        Model.CompleteBarrier();
        Assert(runs == 1 && Model.NotificationCount() == 0 && Model.WaitCount(1) == 0,
            "Canceled delayed publication executed or leaked a callback or view.");

        var delayed = Task.Run(() => AnnotationPublication.Run(View, _ => ++runs));
        Assert(SpinWait.SpinUntil(() => Model.NotificationCount() == 1, 5000), "Publication retry did not register.");
        Thread.Sleep(25);
        Model.CompleteBarrier();
        Assert(delayed.Wait(1000) && runs == 2, "Publication retry did not complete.");
        Assert(delayed.Result.WaitSeconds >= 0.020 && delayed.Result.WaitAllocatedBytes >= 0,
            "Publication measurement omitted its delayed barrier wait or mixed callback allocations into waiting-thread allocation.");

        Model.DelayedBarrier(0);
        byte[] generation = Ownership();
        using var midPublishCancellation = new CancellationTokenSource();

        try {
            AnnotationPublication.Run(View, _ => {
                using var reconciliation = new AnnotationReconciliation(View, cancellationToken: midPublishCancellation.Token);
                DefineVariable(0xf010, first, tracked: true);
                midPublishCancellation.Cancel();
                reconciliation.Complete();
            }, midPublishCancellation.Token);

            throw new Exception("Cancellation within publication was not observed.");
        } catch (OperationCanceledException) {
            Assert(Ownership().AsSpan().SequenceEqual(generation), "Canceled publication changed the committed ownership generation.");
            DataVariable variable = default;
            Assert(Core.BNGetDataVariableAtAddress(View, Address(0xf010), &variable) == 0,
                "Canceled publication left a partially published variable.");
        }

        Assert(Model.NotificationCount() == 0 && Model.WaitCount(1) == 0, "Canceled publication retained a callback or view.");

        Model.FailWrite(1);

        try {
            AnnotationPublication.Run(View, _ => {
                using var reconciliation = new AnnotationReconciliation(View);
                DefineVariable(0xf020, first, tracked: true);
                reconciliation.Complete();
            });

            throw new Exception("Publication did not propagate its serialization failure.");
        } catch (IOException) {
            Assert(Ownership().AsSpan().SequenceEqual(generation), "Failed callback publication changed the ownership generation.");
            DataVariable variable = default;
            Assert(Core.BNGetDataVariableAtAddress(View, Address(0xf020), &variable) == 0,
                "Failed callback publication left a variable behind.");
        } finally {
            Model.FailWrite(0);
        }

        Model.DelayedBarrier(1);
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        using var activeCancellation = new CancellationTokenSource();
        var active = Task.Run(() => {
            try {
                AnnotationPublication.Run(View, _ => {
                    using var reconciliation = new AnnotationReconciliation(View, cancellationToken: activeCancellation.Token);
                    DefineVariable(0xf030, first, tracked: true);
                    entered.Set();
                    release.Wait();
                    reconciliation.Complete();
                }, activeCancellation.Token);

                throw new Exception("Concurrent cancellation of publication was not observed.");
            } catch (OperationCanceledException) {
            }
        });

        Assert(SpinWait.SpinUntil(() => Model.NotificationCount() == 1, 5000), "Active cancellation did not register.");
        var callback = Task.Run(Model.CompleteBarrier);
        Assert(entered.Wait(1000), "Publication callback did not begin.");
        activeCancellation.Cancel();
        Assert(!active.Wait(50) && Model.NotificationCount() == 1 && Model.WaitCount(1) == 2,
            "Cancellation released the callback context or view before publication unwound.");
        release.Set();
        Assert(Task.WaitAll([active, callback], 1000), "Canceled publication did not unregister after rollback.");
        Assert(Ownership().AsSpan().SequenceEqual(generation), "Concurrent cancellation changed the ownership generation.");
        Assert(Model.NotificationCount() == 0 && Model.WaitCount(1) == 0, "Concurrent cancellation retained a callback or view.");
        Model.DelayedBarrier(0);

        Console.WriteLine($"ABI shim: baseline, Atlas-only lock and main-thread dispatch lost a concurrent user edit; notification barrier preserved it, rejected reentrant duplicate delivery, canceled before/during publication and retried; scenario {Stopwatch.GetElapsedTime(start).TotalMilliseconds:F1} ms.");
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void PublishOnMainThread(nint pointer) => ((Action)GCHandle.FromIntPtr(pointer).Target!)();

    private static void CheckCancellation(nint type) {
        int[] before = Enumerable.Range(0, 7).Select(Model.Count).ToArray();
        byte[] generation = Ownership();
        byte[] priorStamp = "prior input identity"u8.ToArray();
        StoreInput(priorStamp, tracked: false);

        using var cancellation = new CancellationTokenSource();

        try {
            using var owned = new AnnotationReconciliation(View, cancellationToken: cancellation.Token);
            StoreInput("replacement input identity"u8.ToArray(), tracked: true);
            Mutate(type, 2);

            for (ulong i = 0; i < 128; ++i) {
                DefineVariable(0x3000 + i * 8, type, tracked: true);

                if (i == 63)
                    cancellation.Cancel();
            }

            throw new Exception("Late annotation cancellation was not observed.");
        } catch (OperationCanceledException) {
            Counts(before);
            Assert(Ownership().AsSpan().SequenceEqual(generation), "Late cancellation changed the owned generation.");
            Assert(ReadInput().AsSpan().SequenceEqual(priorStamp), "Late cancellation did not restore the input identity stamp.");
        }

        Apply(type, 2);
        Counts(before);
        Assert(ReadInput().AsSpan().SequenceEqual(priorStamp), "Retry changed an unowned prior input stamp.");
    }

    private static void StoreInput(byte[] bytes, bool tracked) {
        fixed (byte* key = "aot-atlas:apply-input\0"u8)
        fixed (byte* data = bytes) {
            nint metadata = Core.BNCreateMetadataRawData(data, (nuint)bytes.Length);

            try {
                if (tracked)
                    Core.BNBinaryViewStoreMetadata(View, key, metadata, 3);
                else
                    Core.StoreMetadataRaw(View, key, metadata, 3);
            } finally {
                Core.BNFreeMetadata(metadata);
            }
        }
    }

    private static byte[] ReadInput() {
        fixed (byte* key = "aot-atlas:apply-input\0"u8) {
            nint metadata = Core.BNBinaryViewQueryMetadata(View, key);
            nuint length = 0;
            byte* bytes = Core.BNMetadataGetRaw(metadata, &length);

            try {
                return new ReadOnlySpan<byte>(bytes, checked((int)length)).ToArray();
            } finally {
                Core.BNFreeMetadataRaw(bytes);
                Core.BNFreeMetadata(metadata);
            }
        }
    }

    private static void CheckAnalysisWait() {
        var blocking = Task.Run(() => Core.BNUpdateAnalysisAndWait(View));
        Assert(SpinWait.SpinUntil(() => Model.BlockingWaitEntered() != 0, 5000),
            "Blocking-wait comparison did not enter the native call.");

        using (var canceled = new CancellationTokenSource()) {
            canceled.Cancel();
            Assert(!blocking.Wait(50), "A blocking native wait unexpectedly observed managed cancellation.");
        }

        Model.ReleaseBlockingWait();
        Assert(blocking.Wait(1000), "Blocking-wait comparison did not release.");

        Model.FailCompletionRegistration(1);
        try {
            AnalysisWait.Run(View, default);
            throw new Exception("Failed analysis-event registration completed successfully.");
        } catch (IOException) {
            Assert(Model.WaitCount(0) == 0 && Model.WaitCount(1) == 0 && Model.WaitCount(3) == 0,
                "Failed analysis-event registration retained caller resources.");
        } finally {
            Model.FailCompletionRegistration(0);
        }

        Model.ImmediateCompletion(1);
        AnalysisWait.Run(View, default);
        Assert(Model.WaitCount(0) == 0 && Model.WaitCount(1) == 0,
            "Synchronous completion leaked its registration or view.");
        Model.ImmediateCompletion(0);

        using var cancellation = new CancellationTokenSource();
        var waiting = Task.Run(() => {
            try {
                AnalysisWait.Run(View, cancellation.Token);
                throw new Exception("Canceled analysis wait completed successfully.");
            } catch (OperationCanceledException) {
                return;
            }
        });

        Assert(SpinWait.SpinUntil(() => Model.WaitCount(0) == 1, 5000), "Analysis wait did not register.");
        Assert(Core.BNGetAnalysisState(View) == 2 && !waiting.IsCompleted,
            "The queued-update experiment did not distinguish idle state from acknowledged analysis completion.");
        byte[] generation = Ownership();
        cancellation.Cancel();
        Assert(waiting.Wait(1000), "Analysis cancellation remained blocked on the host.");
        Assert(Model.WaitCount(0) == 0 && Model.WaitCount(1) == 0 && Model.WaitCount(3) == 1,
            "A cancelled wait retained abandoned caller resources or unregistered its host callback.");
        Assert(Ownership().AsSpan().SequenceEqual(generation), "Analysis wait cancellation changed completed metadata.");
        var retry = Task.Run(() => AnalysisWait.Run(View, default));
        Assert(SpinWait.SpinUntil(() => Model.WaitCount(3) == 2, 5000), "Retry did not request host analysis.");
        Model.CompleteWait();
        Assert(!retry.Wait(25), "A cancelled wait's late callback completed its retry.");
        Model.CompleteWait();
        Assert(retry.Wait(1000), "Retry did not observe host analysis completion.");
        Assert(Model.WaitCount(0) == 0 && Model.WaitCount(1) == 0,
            "Retry retained its event or view reference.");

        CheckUndeliveredCompletions();

        Model.CancelTask(0);
        using (var background = new BackgroundCancellation(3)) {
            Model.CancelTask(1);
            Assert(SpinWait.SpinUntil(() => background.Token.IsCancellationRequested, 1000),
                "Background cancellation did not reach the standard token.");
        }

        Model.CancelTask(0);
        var disposal = new BackgroundCancellation(3);
        Model.BlockBackgroundQuery(1);
        Assert(SpinWait.SpinUntil(() => Model.BackgroundQueryEntered() != 0, 1000),
            "Disposal test did not enter the native cancellation query.");
        var disposing = Task.Run(disposal.Dispose);
        Assert(!disposing.Wait(25), "Disposal returned while its native query still used the task.");
        Model.BlockBackgroundQuery(0);
        Assert(disposing.Wait(1000), "Disposal did not drain its final native query.");
        int queries = Model.BackgroundQueries();
        Thread.Sleep(75);
        Assert(Model.BackgroundQueries() == queries, "Disposal allowed later native cancellation queries.");
        Console.WriteLine("ABI shim: late receipt rollback preserved input stamp; registration failure, immediate/late callbacks, cancellation/retry and final background-query disposal preserve ownership.");
    }

    private static void CheckUndeliveredCompletions() {
        // The host need not deliver an obsolete view's callback. Repeating this
        // operation must release Atlas-owned resources without native cancellation.
        for (int iteration = 0; iteration < 64; ++iteration) {
            using var cancellation = new CancellationTokenSource();
            var waiting = Task.Run(() => {
                try {
                    AnalysisWait.Run(View, cancellation.Token);
                    throw new Exception("An abandoned analysis wait completed successfully.");
                } catch (OperationCanceledException) {
                }
            });

            Assert(SpinWait.SpinUntil(() => Model.WaitCount(3) == iteration + 1, 5000),
                "The undelivered-completion test did not register its event.");
            cancellation.Cancel();
            Assert(waiting.Wait(1000), "An undelivered callback blocked cancellation.");
            Assert(Model.WaitCount(0) == 0 && Model.WaitCount(1) == 0,
                "Repeated cancellation retained Atlas-owned native resources.");
        }

        // Deliver every old callback while a new live wait owns a different cookie.
        var retry = Task.Run(() => AnalysisWait.Run(View, default));
        Assert(SpinWait.SpinUntil(() => Model.WaitCount(3) == 65, 5000), "Retry did not register.");
        for (int iteration = 0; iteration < 64; ++iteration)
            Model.CompleteWait();

        Assert(!retry.Wait(25), "An old opaque context completed a new analysis wait.");
        Model.CompleteWait();
        Assert(retry.Wait(1000), "The final live callback did not complete its wait.");
        Assert(Model.WaitCount(0) == 0 && Model.WaitCount(1) == 0 && Model.WaitCount(3) == 0,
            "Late completion delivery leaked event or view references.");
        Console.WriteLine("ABI shim: 64 undelivered callbacks retain no Atlas event/view references; late delivery cannot complete a newer wait and the live retry finishes.");
    }

    private static void CheckWorkCount(nint type) {
        int[] before = Enumerable.Range(0, 7).Select(Model.Count).ToArray();

        for (int run = 0; run < 3; ++run) {
            long retainedBefore = GC.GetTotalMemory(forceFullCollection: true);
            long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
            long start = Stopwatch.GetTimestamp();

            using (var owned = new AnnotationReconciliation(View)) {
                owned.RetractFields();
                Mutate(type, 2);

                for (ulong i = 0; i < 128; ++i) {
                    DefineVariable(0x1000 + i * 8, type, tracked: true);
                    Core.BNAddUserDataReference(View, Address(0x1000 + i * 8), Address(0x2000 + i * 8));
                }

                owned.Complete();
            }

            double milliseconds = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            long allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
            long retained = GC.GetTotalMemory(forceFullCollection: true) - retainedBefore;
            using var process = Process.GetCurrentProcess();

            Assert(Model.Count(2) == before[2] + 128 && Model.Count(3) == before[3] + 128,
                "Repeated bulk replacement accumulated annotations.");
            Console.WriteLine($"ABI shim expansion {run + 1}: 256 additional facts, complete read/write/publication/cleanup; "
                + $"{milliseconds:F2} ms, allocated {allocated:N0} B, retained managed delta {retained:N0} B, "
                + $"process peak working set {process.PeakWorkingSet64:N0} B.");
        }

        CheckSnapshotReuse();
        Apply(type, 2);
        Counts(before);
    }

    private static void CheckInvalidRecord() {
        int[] before = Enumerable.Range(0, 7).Select(Model.Count).ToArray();
        fixed (byte* key = "aot-atlas:owned-annotations\0"u8) {
            nint original = Core.BNBinaryViewQueryMetadata(View, key);
            nuint length = 0;
            byte* raw = Core.BNMetadataGetRaw(original, &length);
            byte[] bytes = new ReadOnlySpan<byte>(raw, checked((int)length)).ToArray();
            Core.BNFreeMetadataRaw(raw);

            try {
                using var input = new BinaryReader(new MemoryStream(bytes));
                input.ReadBytes(8);
                int libraryLength = input.ReadInt32();

                using var output = new MemoryStream();
                using var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
                writer.Write("ATOWN001"u8);
                writer.Write(libraryLength);
                writer.Write(input.ReadBytes(libraryLength));
                writer.Write(1);
                writer.Write((byte)1);
                writer.Write(0x10UL);
                writer.Write(0UL);
                writer.Write("");
                writer.Write(false);
                writer.Write(false);
                writer.Write(0);
                writer.Write(-1);
                writer.Write(-1);
                writer.Write(0UL);
                writer.Write((byte)0);
                writer.Write(false);
                writer.Write(0);

                byte[] malformed = output.ToArray();
                fixed (byte* value = malformed) {
                    nint metadata = Core.BNCreateMetadataRawData(value, (nuint)malformed.Length);
                    Core.StoreMetadataRaw(View, key, metadata, 3);
                    Core.BNFreeMetadata(metadata);
                }

                try {
                    using var owned = new AnnotationReconciliation(View);
                    throw new InvalidOperationException("A symbol record without a symbol snapshot was accepted.");
                } catch (InvalidDataException error) {
                    Assert(error.Message.Contains("Symbol") && error.Message.Contains("invalid shape"),
                        "Malformed symbol state did not produce an actionable ownership-record error.");
                    Counts(before);
                }
            } finally {
                Core.StoreMetadataRaw(View, key, original, 3);
                Core.BNFreeMetadata(original);
            }
        }
    }

    private static void CheckSymbolBatches(nint type) {
        int[] before = Enumerable.Range(0, 7).Select(Model.Count).ToArray();
        foreach (string name in new[] { "Atlas::Pending::One", "Atlas::Pending::Two", "Atlas::Pending::Two" }) {
            using var owned = new AnnotationReconciliation(View);
            Mutate(type, 2);
            var symbols = new Symbols(View, imageBase, 4);
            Core.BNBeginBulkModifySymbols(View);

            try {
                byte[] bytes = Encoding.UTF8.GetBytes(name + '\0');
                fixed (byte* text = bytes) {
                    symbols.Define(Address(0x300), 0, text);
                    symbols.Define(Address(0x300), 0, text);
                }
                fixed (byte* alternative = "Atlas::LaterProducer\0"u8)
                    symbols.Define(Address(0x300), 0, alternative);
            } finally {
                Core.BNEndBulkModifySymbols(View);
                symbols.Free();
            }

            owned.Complete();
            nint symbol = Core.BNGetSymbolByAddress(View, Address(0x300), 0);
            Assert(symbol != 0, "An unchanged desired symbol was retracted after a repeated batch.");
            byte* actual = Core.BNGetSymbolRawName(symbol);
            Assert(Marshal.PtrToStringUTF8((nint)actual) == name,
                "The first accepted symbol did not retain precedence across repeated batches.");
            Core.BNFreeString(actual);
            Core.BNFreeSymbol(symbol);
        }

        Apply(type, 2);
        Counts(before);
    }

    private static void CheckForwardTypes() {
        nint type = Model.ForwardType();
        for (int run = 0; run < 2; ++run) {
            using (var owned = new AnnotationReconciliation(View)) {
                DefineVariable(0x300, type, tracked: true);
                owned.Complete();
            }
            Assert(Model.LastLibraryEntries() == 7,
                "A forward declaration was omitted, duplicated or substituted for a complete definition.");
            for (int node = 0; node < 12; ++node)
                Assert(Model.GraphVisits(node) == run + 1,
                    "Snapshot traversal missed a dependency or revisited a shared native type.");
            Assert(Model.Count(0) == 0 && VariableShape(0x300) == 0x1000000000000000UL,
                "Snapshotting forward declarations created view types or changed the annotation.");
        }
        using (var owned = new AnnotationReconciliation(View))
            owned.Complete();
        Assert(Model.Count(2) == 0, "Reloading forward declarations prevented stale annotation cleanup.");
        Console.WriteLine("ABI shim: structures, bases, pointers, arrays, function returns/parameters and fragments "
            + "retain incomplete references; shared types are visited once and complete definitions survive reload.");
    }

    private static void CheckSymbolKinds() {
        foreach (byte kind in new byte[] { 3, 0, 3 }) {
            using (var owned = new AnnotationReconciliation(View)) {
                var symbols = new Symbols(View, imageBase, 1);
                Core.BNBeginBulkModifySymbols(View);
                try {
                    fixed (byte* name = "unchanged_name\0"u8) {
                        symbols.Define(Address(0x300), kind, name);
                        symbols.Define(Address(0x300), kind, name);
                    }
                    fixed (byte* alternative = "later_producer\0"u8)
                        symbols.Define(Address(0x300), kind, alternative);
                } finally {
                    Core.BNEndBulkModifySymbols(View);
                    symbols.Free();
                }
                owned.Complete();
            }

            nint symbol = Core.BNGetSymbolByAddress(View, Address(0x300), 0);
            try {
                Assert(symbol != 0 && Core.BNGetSymbolType(symbol) == kind,
                    "An unchanged symbol name retained its previous function/data kind.");
                byte* name = Core.BNGetSymbolRawName(symbol);
                try {
                    Assert(Marshal.PtrToStringUTF8((nint)name) == "unchanged_name",
                        "Changing a symbol's kind lost the first producer's precedence.");
                } finally {
                    Core.BNFreeString(name);
                }
            } finally {
                Core.BNFreeSymbol(symbol);
            }
        }
        Console.WriteLine("ABI shim: same-name symbols change function/data kind while retaining first-producer precedence.");
    }

    private static void CheckSnapshotTypeReuse() {
        nint shared = Model.Type(7);
        nint distinct = Model.Type(8);
        nint equalButDistinct = Model.Type(7);
        for (int run = 0; run < 3; ++run) {
            int exports = Model.LibraryExports();
            long allocated = GC.GetAllocatedBytesForCurrentThread();
            long start = Stopwatch.GetTimestamp();
            using (var owned = new AnnotationReconciliation(View)) {
                for (ulong i = 0; i < 256; ++i)
                    DefineVariable(0x1000 + i * 8, shared, tracked: true);
                DefineVariable(0x2000, distinct, tracked: true);
                DefineVariable(0x2010, equalButDistinct, tracked: true);
                owned.Complete();
            }
            double milliseconds = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            long bytes = GC.GetAllocatedBytesForCurrentThread() - allocated;
            int exported = Model.LibraryExports() - exports;
            Console.WriteLine($"ABI shim snapshot reuse {run + 1}: 258 variables, {exported} native exports, "
                + $"{Model.LastLibraryEntries()} snapshot types; {milliseconds:F2} ms, {bytes:N0} B managed allocation.");
            for (ulong i = 0; i < 256; ++i)
                Assert(VariableShape(0x1000 + i * 8) == 7, "A shared snapshot lost its variable type.");
            Assert(VariableShape(0x2000) == 8 && VariableShape(0x2010) == 7,
                "Sharing snapshot slots confused distinct native types.");
            Assert(exported == 3 && Model.LastLibraryEntries() == 3,
                "Snapshot saving re-exported native types shared by multiple annotations.");
        }
        using (var owned = new AnnotationReconciliation(View))
            owned.Complete();
        Assert(Model.Count(2) == 0, "Shared snapshots prevented stale variables from retracting.");
    }

    private static void CheckOperationSerialization() {
        Model.DelayedBarrier(1);
        static int Restore() => ((delegate* unmanaged[Cdecl]<nint, int>)&Plugin.RestoreEnumTypes)(View);
        var first = Task.Run(Restore);
        Assert(SpinWait.SpinUntil(() => Model.NotificationCount() == 1, 5000),
            "The first operation did not reach publication.");
        var second = Task.Run(Restore);
        Assert(SpinWait.SpinUntil(() => Model.FileReferences() == 2, 5000),
            "The competing operation did not enter the file queue.");
        Assert(!second.Wait(50) && Model.NotificationCount() == 1,
            "A competing operation did not wait for the active operation.");
        Model.CompleteBarrier();
        Assert(first.Wait(5000) && first.Result == 0, "The first operation failed.");
        Assert(SpinWait.SpinUntil(() => Model.NotificationCount() == 1, 5000),
            "The queued operation did not reach publication.");
        Model.CompleteBarrier();
        Assert(second.Wait(5000) && second.Result == 0, "The queued operation failed.");
        Assert(Model.NotificationCount() == 0 && Model.WaitCount(1) == 0,
            "Queued operations retained a callback or view.");
        Model.DelayedBarrier(0);
        Assert(Restore() == 0, "The completed operations left the file locked.");

        Model.DelayedBarrier(1);
        first = Task.Run(Restore);
        Assert(SpinWait.SpinUntil(() => Model.NotificationCount() == 1, 5000),
            "The cancellation test did not start its active operation.");
        var run = typeof(Plugin).GetMethod("Run", BindingFlags.NonPublic | BindingFlags.Static)!;
        var operation = typeof(Plugin).GetNestedType("Operation", BindingFlags.NonPublic)!;
        second = Task.Run(() => (int)run.Invoke(null,
            new object?[] { View, MapFormat.Auto, (nint)3, Enum.Parse(operation, "RestoreEnums"), null })!);
        Assert(SpinWait.SpinUntil(() => Model.FileReferences() == 2, 5000),
            "The cancellable operation did not enter the file queue.");
        Assert(!second.Wait(50) && Model.NotificationCount() == 1,
            "A cancellable queued operation entered publication early.");
        Model.CancelTask(1);
        Assert(second.Wait(5000) && second.Result == 2,
            "A queued operation did not observe background cancellation.");
        Model.CancelTask(0);
        Assert(!first.IsCompleted && Model.NotificationCount() == 1 && Model.FileReferences() == 1,
            "Canceling a queued operation released another operation's file ownership.");
        Model.CompleteBarrier();
        Assert(first.Wait(5000) && first.Result == 0, "Queued cancellation interrupted the active operation.");

        first = Task.Run(Restore);
        Assert(SpinWait.SpinUntil(() => Model.NotificationCount() == 1, 5000),
            "The closed-view test did not start publication.");
        second = Task.Run(Restore);
        Assert(SpinWait.SpinUntil(() => Model.FileReferences() == 2, 5000),
            "The closed-view successor did not enter the file queue.");
        Assert(!second.Wait(50) && Model.NotificationCount() == 1,
            "The closed-view test did not queue its second operation.");
        Model.CurrentPeView(0);
        Model.CompleteBarrier();
        Assert(first.Wait(5000) && first.Result == 2, "Closing the active view did not cancel its operation.");
        Assert(second.Wait(5000) && second.Result == 2,
            "A queued operation did not cancel when its file was already closed.");
        Model.CurrentPeView(View);
        Model.DelayedBarrier(0);
        Assert(Restore() == 0 && Model.NotificationCount() == 0 && Model.WaitCount(1) == 0
            && Model.FileReferences() == 0,
            "Cancellation left the file locked or retained native resources.");
        Console.WriteLine("ABI shim: explicit operations publish serially; queued cancellation preserves active ownership, "
            + "and closed-view cancellation releases the next operation for a live retry.");
    }

    private static void CheckLocationOverride() {
        nint type = Model.Type(3);
        using (var owned = new AnnotationReconciliation(View)) {
            owned.RetractFields();
            Mutate(Model.Type(2), 2);
            nint function = Core.BNAddFunctionForAnalysis(View, Platform, Address(0x90), 0, 0);
            Core.BNApplyAutoDiscoveredFunctionType(function, type);
            Core.BNFreeFunction(function);
            owned.Complete();
        }
        nint current = Core.GetFunction(View, Platform, Address(0x90));
        Core.BNSetFunctionAutoType(current, Model.Type(3UL | 1UL << 40));
        Core.BNFreeFunction(current);
        using (var owned = new AnnotationReconciliation(View)) {
            owned.RetractFields();
            Mutate(Model.Type(2), 2);
            current = Core.BNGetAnalysisFunction(View, Platform, Address(0x90));
            Core.BNApplyAutoDiscoveredFunctionType(current, type);
            Core.BNFreeFunction(current);
            owned.Complete();
        }
        Assert(FunctionShape(0x90) == (3UL | 1UL << 40), "An ABI register location edit with an identical semantic type was overwritten.");
        Apply(Model.Type(2), 2);
        Assert(FunctionShape(0x90) == (3UL | 1UL << 40), "A function with a released automatic ABI was deleted when its metadata fact disappeared.");
    }

    private static void CheckTypeDependencies(nint type) {
        Model.Edge("aot-atlas:A", "aot-atlas:B", 1);
        Model.Edge("aot-atlas:B", "aot-atlas:A", 1);
        byte** parts = stackalloc byte*[1];
        for (int run = 0; run < 2; ++run) {
            using (var owned = new AnnotationReconciliation(View)) {
                foreach (string name in new[] { "A", "B" }) {
                    byte[] id = Encoding.UTF8.GetBytes("aot-atlas:" + name + '\0');
                    byte[] text = Encoding.UTF8.GetBytes(name + '\0');
                    fixed (byte* identifier = id)
                    fixed (byte* leaf = text)
                    fixed (byte* join = "::\0"u8) {
                        parts[0] = leaf;
                        var qualified = new QualifiedName { Names = parts, Join = join, Count = 1 };
                        var actual = Core.BNDefineAnalysisType(View, identifier, &qualified, type);
                        Core.BNFreeQualifiedName(&actual);
                    }
                }
                owned.Complete();
            }
            if (run == 1)
                Model.Edge("analyst", "aot-atlas:A", 1);
            using (var owned = new AnnotationReconciliation(View))
                owned.Complete();
            Assert(Model.Count(0) == (run == 0 ? 0 : 2), "Stale recursive types did not respect surviving analyst dependencies.");
        }
        Model.Edge("analyst", "aot-atlas:A", 0);
        using (var owned = new AnnotationReconciliation(View))
            owned.Complete();
        Assert(Model.Count(0) == 0, "Previously retained types did not retract after their last analyst dependency disappeared.");
    }

    private static void Apply(nint type, int generation) {
        using var owned = new AnnotationReconciliation(View);
        owned.RetractFields();
        Mutate(type, generation);
        owned.Complete();
    }

    private static void Mutate(nint type, int generation) {
        DefineType(type);
        DefineSymbol(0x10, "atlas-" + generation, tracked: true);
        DefineVariable(0x20, type, tracked: true);
        Core.BNAddUserDataReference(View, Address(0x30), Address((ulong)(0x40 + generation)));
        nint function = Core.BNGetAnalysisFunction(View, Platform, Address(0x50));
        if (function == 0)
            function = Core.BNAddFunctionForAnalysis(View, Platform, Address(0x50), 0, 0);
        Core.BNApplyAutoDiscoveredFunctionType(function, type);
        Core.BNFreeFunction(function);
        if (generation == 1) {
            function = Core.BNGetAnalysisFunction(View, Platform, Address(0x70));
            if (function == 0)
                function = Core.BNAddFunctionForAnalysis(View, Platform, Address(0x70), 0, 0);
            Core.BNFreeFunction(function);
        }

        nint tag = GetTag();
        byte[] text = Encoding.UTF8.GetBytes("tag-" + generation + '\0');
        var owned = AnnotationReconciliation.Current!;
        fixed (byte* value = text) {
            if (tag != 0 && owned.ContainsTag(tag)) {
                Core.BNTagSetData(tag, value);
            } else {
                tag = Core.BNCreateTag(TagType, value);
                owned.RegisterTag(tag, Address(0x60), data: true);
                Core.BNAddUserDataTag(View, Address(0x60), tag);
            }
        }
        Core.BNFreeTag(tag);

        byte[] stamp = [(byte)generation, 0xA7];
        fixed (byte* key = "aot-atlas:apply-input\0"u8)
        fixed (byte* value = stamp) {
            nint metadata = Core.BNCreateMetadataRawData(value, 2);
            Core.BNBinaryViewStoreMetadata(View, key, metadata, 3);
            Core.BNFreeMetadata(metadata);
        }
    }

    private static void DefineType(nint type) {
        fixed (byte* id = "aot-atlas:test-type:v1\0"u8)
        fixed (byte* text = "Test\0"u8)
        fixed (byte* join = "::\0"u8) {
            byte** parts = stackalloc byte*[1] { text };
            var name = new QualifiedName { Names = parts, Join = join, Count = 1 };
            var actual = Core.BNDefineAnalysisType(View, id, &name, type);
            Core.BNFreeQualifiedName(&actual);
        }
    }

    private static void DefineSymbol(ulong rva, string name, bool tracked) {
        byte[] bytes = Encoding.UTF8.GetBytes(name + '\0');
        fixed (byte* text = bytes) {
            nint symbol = Core.BNCreateSymbol(3, text, text, text, Address(rva), 0, 0, 0);
            if (tracked)
                Core.BNDefineUserSymbol(View, symbol);
            else
                Core.DefineSymbol(View, symbol);
            Core.BNFreeSymbol(symbol);
        }
    }

    private static void DefineVariable(ulong rva, nint type, bool tracked) {
        var confidence = new TypeConfidence(type);
        if (tracked)
            Core.BNDefineUserDataVariable(View, Address(rva), &confidence);
        else
            Core.DefineVariable(View, Address(rva), &confidence);
    }

    private static nint GetTag() {
        nuint count = 0;
        nint* tags = Core.BNGetUserDataTagsOfType(View, Address(0x60), TagType, &count);
        nint tag = count == 0 ? 0 : tags[count - 1];
        Core.BNFreeTagList(tags, count);
        return tag;
    }

    private static void ApplyFields() {
        using var owned = new AnnotationReconciliation(View, fieldsOnly: true);
        nint function = Core.BNGetAnalysisFunction(View, Platform, Address(0x50));
        fixed (byte* text = "Test\0"u8)
        fixed (byte* join = "::\0"u8) {
            byte** parts = stackalloc byte*[1] { text };
            var name = new QualifiedName { Names = parts, Join = join, Count = 1 };
            Core.BNAddUserTypeFieldReference(function, 3, Address(0x51), &name, 8, 4);
        }
        Core.BNFreeFunction(function);
        owned.Complete();
    }

    private static byte[] Ownership() {
        fixed (byte* key = "aot-atlas:owned-annotations\0"u8) {
            nint metadata = Core.BNBinaryViewQueryMetadata(View, key);
            nuint length = 0;
            byte* bytes = Core.BNMetadataGetRaw(metadata, &length);
            byte[] hash = SHA256.HashData(new ReadOnlySpan<byte>(bytes, checked((int)length)));
            Core.BNFreeMetadataRaw(bytes);
            Core.BNFreeMetadata(metadata);
            return hash;
        }
    }

    private static bool HasReference(ulong from, ulong to) {
        nuint count = 0;
        ulong* references = Core.BNGetDataReferencesFrom(View, Address(from), &count);
        bool found = new ReadOnlySpan<ulong>(references, checked((int)count)).Contains(Address(to));
        Core.BNFreeDataReferences(references);
        return found;
    }

    private static ulong VariableShape(ulong rva) {
        DataVariable variable = default;
        Assert(Core.BNGetDataVariableAtAddress(View, Address(rva), &variable) != 0, "A required data variable disappeared.");
        ulong shape = Model.Shape(variable.Type);
        Core.BNFreeDataVariable(&variable);
        return shape;
    }

    private static ulong FunctionShape(ulong rva) {
        nint function = Core.GetFunction(View, Platform, Address(rva));
        Assert(function != 0, "A required function disappeared.");
        nint type = Core.BNGetFunctionType(function);
        ulong shape = Model.Shape(type);
        Core.BNFreeType(type);
        Core.BNFreeFunction(function);
        return shape;
    }

    private static void Counts(params int[] expected) {
        for (int i = 0; i < expected.Length; ++i)
            Assert(Model.Count(i) == expected[i], $"Host state {i}: expected {expected[i]}, actual {Model.Count(i)}.");
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new InvalidDataException(message);
    }
}

internal static partial class Model {
    [LibraryImport("binaryninjacore", EntryPoint = "ModelNonRawMetadata", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial void NonRawMetadata(string key);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelSnapshotUnsigned")]
    internal static partial void SnapshotUnsigned(byte value);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelLibraryLoads")]
    internal static partial int LibraryLoads();
    [LibraryImport("binaryninjacore", EntryPoint = "ModelAnalysisHold")]
    internal static partial void AnalysisHold(byte held);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelCurrentPeView")]
    internal static partial void CurrentPeView(nint view);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelRawBytes")]
    internal static unsafe partial void RawBytes(byte* bytes, nuint length);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelRawCallback")]
    internal static unsafe partial void RawCallback(int stage, nint context, delegate* unmanaged[Cdecl]<nint, void> callback);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelRawReads")]
    internal static partial int RawReads();
    [LibraryImport("binaryninjacore", EntryPoint = "ModelRawBuffers")]
    internal static partial int RawBuffers();
    [LibraryImport("binaryninjacore", EntryPoint = "BNExecuteOnMainThreadAndWait")]
    internal static unsafe partial void ExecuteMainThread(nint context, delegate* unmanaged[Cdecl]<nint, void> callback);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelRaceVariable")]
    internal static partial void RaceVariable(ulong address, nint type);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelJoinWriter")]
    internal static partial void JoinWriter();
    [LibraryImport("binaryninjacore", EntryPoint = "ModelDelayedBarrier")]
    internal static partial void DelayedBarrier(byte delayed);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelNotificationCount")]
    internal static partial int NotificationCount();
    [LibraryImport("binaryninjacore", EntryPoint = "ModelFileReferences")]
    internal static partial int FileReferences();
    [LibraryImport("binaryninjacore", EntryPoint = "ModelCompleteBarrier")]
    internal static partial void CompleteBarrier();
    [LibraryImport("binaryninjacore", EntryPoint = "ModelRepeatBarrier")]
    internal static partial void RepeatBarrier();
    [LibraryImport("binaryninjacore", EntryPoint = "ModelReleaseBlockingWait")]
    internal static partial void ReleaseBlockingWait();
    [LibraryImport("binaryninjacore", EntryPoint = "ModelBlockingWaitEntered")]
    internal static partial byte BlockingWaitEntered();
    [LibraryImport("binaryninjacore", EntryPoint = "ModelFailCompletionRegistration")]
    internal static partial void FailCompletionRegistration(byte value);

    [LibraryImport("binaryninjacore", EntryPoint = "ModelBlockBackgroundQuery")]
    internal static partial void BlockBackgroundQuery(byte value);

    [LibraryImport("binaryninjacore", EntryPoint = "ModelBackgroundQueryEntered")]
    internal static partial byte BackgroundQueryEntered();

    [LibraryImport("binaryninjacore", EntryPoint = "ModelBackgroundQueries")]
    internal static partial int BackgroundQueries();

    [LibraryImport("binaryninjacore", EntryPoint = "ModelImmediateCompletion")]
    internal static partial void ImmediateCompletion(byte value);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelCancelTask")]
    internal static partial void CancelTask(byte value);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelWaitCount")]
    internal static partial int WaitCount(int kind);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelCompleteWait")]
    internal static partial void CompleteWait();
    [LibraryImport("binaryninjacore", EntryPoint = "ModelEdge", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial void Edge(string source, string target, byte active);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelType")]
    internal static partial nint Type(ulong shape);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelForwardType")]
    internal static partial nint ForwardType();
    [LibraryImport("binaryninjacore", EntryPoint = "ModelGraphVisits")]
    internal static partial int GraphVisits(int node);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelLibraryExports")]
    internal static partial int LibraryExports();
    [LibraryImport("binaryninjacore", EntryPoint = "ModelLastLibraryEntries")]
    internal static partial int LastLibraryEntries();
    [LibraryImport("binaryninjacore", EntryPoint = "ModelFailWrite")]
    internal static partial void FailWrite(byte value);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelLoseReceipt")]
    internal static partial void LoseReceipt();
    [LibraryImport("binaryninjacore", EntryPoint = "ModelLoseAbiReceipt")]
    internal static partial void LoseAbiReceipt();
    [LibraryImport("binaryninjacore", EntryPoint = "ModelLoseTypeReceipt")]
    internal static partial void LoseTypeReceipt();
    [LibraryImport("binaryninjacore", EntryPoint = "ModelComment")]
    internal static partial void Comment(ulong address);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelUserType")]
    internal static partial void UserType(ulong address, nint type);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelRebase")]
    internal static partial void Rebase(ulong imageBase);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelCount")]
    internal static partial int Count(int kind);
    [LibraryImport("binaryninjacore", EntryPoint = "ModelShape")]
    internal static partial ulong Shape(nint type);
}
