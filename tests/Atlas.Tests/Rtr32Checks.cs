using System.Buffers.Binary;
using Atlas;
using Atlas.Binja;

internal static class Rtr32Checks {
    internal static void Run() {
        var format = NativeAotFormat.ForVersion(32, 0);
        Assert(format.NormalizeInvokeFlags(0x3f) == 0xbb, "Compact invoke flags lost a semantic bit.");
        Assert(format.NormalizeFieldFlags(0xf) == 0xa3, "Compact field flags lost a semantic bit.");
        Assert(format.ExternalTypeMapSection == RtrSectionId.SharedExternalTypeMap
            && format.ProxyTypeMapSection == RtrSectionId.SharedProxyTypeMap, "Current type map sections are wrong.");
        var old = NativeAotFormat.ForVersion(16, 0);
        Assert(old.NormalizeInvokeFlags(0xbb) == 0xbb && old.NormalizeFieldFlags(0xa3) == 0xa3,
            "Legacy reflection flags changed.");
        Assert(old.ExternalTypeMapSection == RtrSectionId.ExternalTypeMap
            && old.ProxyTypeMapSection == RtrSectionId.ProxyTypeMap, "Legacy type map sections changed.");

        SparseContracts();
        DictionaryRecipe();
        DispatchHelper();
        Console.WriteLine("RTR 32: compact flags, physical type map sections, sparse dispatch contracts, damaged-contract recovery, GVM dictionary recipe continuation and dispatch helper proof passed.");
    }

    private static void DispatchHelper() {
        // Runtime/amd64/DispatchResolve.asm: cache hit followed by the miss argument saves.
        byte[] direct = [
            0x4c, 0x8b, 0x11, 0x4d, 0x39, 0x13, 0x75, 0x06,
            0x49, 0x8b, 0x43, 0x08, 0xff, 0xe0,
            0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x89, 0x54, 0x24, 0x10,
            0x4c, 0x89, 0x44, 0x24, 0x18, 0x4c, 0x89, 0x4c, 0x24, 0x20
        ];
        Assert(Recognizes(direct), "The source-defined dispatch helper was not recognized.");
        byte[] cet = [0xf3, 0x0f, 0x1e, 0xfa, .. direct];
        Assert(Recognizes(cet), "CET changed dispatch helper recognition.");
        byte[] guarded = new byte[64];
        direct.AsSpan(0, 12).CopyTo(guarded);
        guarded[7] = 10;
        guarded[12] = 0xff;
        guarded[13] = 0x25;
        BinaryPrimitives.WriteInt32LittleEndian(guarded.AsSpan(14), 64 - 18 - 8);
        direct.AsSpan(14).CopyTo(guarded.AsSpan(18));
        Assert(Recognizes(guarded), "The guarded dispatch helper was not recognized.");
        BinaryPrimitives.WriteInt32LittleEndian(guarded.AsSpan(14), 64 - 18 - 7);
        Assert(!Recognizes(guarded), "A truncated guard pointer was accepted.");

        foreach (int offset in new[] { 0, 2, 4, 6, 7, 11, 13, 17, 33 }) {
            byte[] changed = (byte[])direct.Clone();
            changed[offset] ^= 1;
            Assert(!Recognizes(changed), $"Changed dispatch semantics at byte {offset} were accepted.");
        }
        Assert(!Recognizes(direct[..^1]), "A truncated dispatch helper was accepted.");
        Assert(!CodeFlow.IsIndexedDispatchHelper(PeFixture.Create(direct, ".data", 0x40000040), 0x140001000),
            "Nonexecutable dispatch helper bytes were accepted.");

        static bool Recognizes(byte[] bytes) =>
            CodeFlow.IsIndexedDispatchHelper(PeFixture.Create(bytes, ".text", 0x60000020), 0x140001000);
    }

    private static void SparseContracts() {
        // Three cells: the first two share interface 0/slot 7; the last uses interface 1/slot 9.
        byte[] encoded = [24, 1, 2, 2, 38, 0, 0, 14, 16, 2, 18];
        var array = new NativeArray(encoded);
        Assert(array.Count == 3 && array.MoveNext() && array.Index == 0 && array.Vertex == 6,
            "First sparse array payload moved.");
        Assert(array.MoveNext() && array.Index == 2 && array.Vertex == 9 && !array.MoveNext(),
            "Second sparse array payload moved.");

        var healthy = Contracts(encoded);
        Assert(healthy.Failures.IsEmpty && healthy.Entries.Length == 2,
            "Healthy sparse dispatch contracts were rejected.");
        Assert(healthy.Entries[0].CellCount == 2 && healthy.Entries[0].Slot == 7
            && healthy.Entries[0].Type == 0x1111 && healthy.Entries[1].CellCount == 1
            && healthy.Entries[1].Slot == 9 && healthy.Entries[1].Type == 0x2222,
            "Sparse anchors did not cover the declared cells.");
        Assert(healthy.Find(0x140001100) == 0 && healthy.Find(0x140001110) == 0
            && healthy.Find(0x140001120) == 1 && healthy.Find(0x140001130) < 0,
            "Dispatch address lookup crossed a contract boundary.");

        byte[] damagedFirst = (byte[])encoded.Clone();
        damagedFirst[6] = 254;
        var suffix = Contracts(damagedFirst);
        Assert(suffix.Failures.Length == 1 && suffix.Failures[0].CellIndex == 0
            && suffix.Entries.Length == 1 && suffix.Entries[0].CellIndex == 2
            && suffix.Entries[0].CellCount == 1 && suffix.Find(0x140001100) < 0
            && suffix.Find(0x140001120) == 0, "A damaged first contract hid or expanded the valid suffix.");

        byte[] damagedLast = (byte[])encoded.Clone();
        damagedLast[9] = 254;
        var prefix = Contracts(damagedLast);
        Assert(prefix.Failures.Length == 1 && prefix.Entries.Length == 1
            && prefix.Entries[0].CellCount == 2 && prefix.Find(0x140001120) < 0,
            "A damaged last contract changed the valid prefix.");

        var overlapping = Contracts(encoded, overlap: true);
        Assert(overlapping.Failures.Length == 2 && overlapping.Entries.IsEmpty,
            "Conflicting interface/GVM regions published duplicate cell identities.");

        var overlong = Contracts(encoded, 103);
        Assert(overlong.Failures.Length == 1 && overlong.Entries[0].CellCount == 2
            && overlong.Entries[1].CellCount == 0 && overlong.Find(0x140001120) < 0,
            "An invalid sparse run became a proven dispatch contract.");
    }

    private static DispatchCellMetadata Contracts(byte[] encoded, int cells = 3, bool overlap = false) {
        byte[] data = Header(32, 0, overlap ? (ushort)4 : (ushort)2, 256 + cells * 16);
        Row(data, 0, RtrSectionId.InterfaceDispatchCellInfoRegion, 128, encoded.Length);
        Row(data, 1, RtrSectionId.InterfaceDispatchCellRegion, 256, cells * 16);
        if (overlap) {
            Row(data, 2, RtrSectionId.GvmDispatchCellInfoRegion, 128, encoded.Length);
            Row(data, 3, RtrSectionId.GvmDispatchCellRegion, 256, cells * 16);
        }
        encoded.CopyTo(data, 128);
        var image = PeFixture.Create(data, ".data", 0xc0000040);
        var header = ReadyToRun.Read(image);
        var metadata = new MetadataBuilder(default, 7);
        var native = new NativeLayout(default, [], metadata.SignatureBuilder);
        var memory = new RuntimeMemory(image, new HydratedRegion());
        return new DispatchCellMetadata(image, header, memory, [0x1111, 0x2222], metadata,
            native, MapFormat.Metadata, new MethodTables(), default);
    }

    private static void DictionaryRecipe() {
        byte[] layout = new byte[256];
        int at = Put(layout, 0, 0x40);
        at = Put(layout, at, (uint)(64 - at), 0);
        at = Put(layout, 64, 2, 3, 1, 6, 4);
        "Echo"u8.CopyTo(layout.AsSpan(at));
        at += 4;
        at = Put(layout, at, (uint)(200 - at), 1, 0x16, 1, 0x26);
        Put(layout, 200, 1, 1, 1, 0x14, 0x14);

        foreach (bool retain in new[] { false, true }) {
            var current = Recipes(layout, 32, 0, retain);
            Assert(current.Dictionaries.SignatureGaps.IsEmpty
                && current.Native.ExternalTypes.Keys.Order().SequenceEqual(new ulong[] { 0x1111, 0x2222, 0x3333 }),
                "GVM recipe prevented later dictionary type roots.");
            if (retain) {
                var recipes = current.Dictionaries.RecipeEntries;
                Assert(recipes.Length == 2 && recipes[0].Kind == DictionaryFixup.GvmDispatchCell
                    && recipes[0].Method.Identity.Name == "Echo" && recipes[0].Method.Arguments.Count == 1
                    && recipes[1].Kind == DictionaryFixup.TypeHandle, "GVM method payload or following recipe was lost.");
            }
            var legacy = Recipes(layout, 18, 5, retain);
            Assert(legacy.Dictionaries.SignatureGaps.SequenceEqual(new[] { new DictionarySignatureGap(64, 69, 3, 2) })
                && legacy.Native.ExternalTypes.Count == 0, "GVM recipe was accepted in an older wire grammar.");
        }
    }

    private static (GenericDictionaries Dictionaries, NativeLayout Native) Recipes(byte[] layout, ushort major, ushort minor, bool retain) {
        byte[] data = Header(major, minor, 1, 128 + layout.Length);
        Row(data, 0, RtrSectionId.NativeLayoutInfo, 128, layout.Length);
        layout.CopyTo(data, 128);
        var image = PeFixture.Create(data, ".rdata", 0x40000040);
        var header = ReadyToRun.Read(image);
        var metadata = new MetadataBuilder(default, 7);
        var native = new NativeLayout(image.FileMemory(header.Find(RtrSectionId.NativeLayoutInfo).Start, layout.Length),
            [0x1111, 0x2222, 0x3333], metadata.SignatureBuilder, takeOwnership: true);
        var templates = new TemplateMaps();
        templates.Methods.Add(new MethodTemplate { LayoutOffset = 0 });
        var dictionaries = new GenericDictionaries();
        if (retain)
            dictionaries.Read(image, header, metadata, native, templates, MapFormat.Legacy);
        else
            dictionaries.ReadSignatures(image, header, metadata, native, templates, MapFormat.Legacy);
        return (dictionaries, native);
    }

    internal static void Producer(string path) {
        var image = PeImage.ReadFile(path);
        var header = ReadyToRun.Read(image);
        Assert(header.Major == 32, "Expected an upstream compiler-produced RTR 32 image.");
        var metadata = MetadataBuilder.FromImage(image, header);
        metadata.ReadDefinitions();
        var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        var maps = ReflectionMaps.Decode(image, header, metadata, fixups);
        var prepared = new PreparedAnalysis(image, header, metadata, maps, fixups);
        var extraction = prepared.Extraction;
        var contracts = extraction.DispatchCellMetadata;
        var cells = prepared.DispatchCells!;
        var code = prepared.Code!;
        Assert(contracts.Failures.IsEmpty && extraction.DictionarySignatureGaps.IsEmpty,
            "A compiler-produced metadata source was left partial.");
        int interfaceCount = 0;
        int gvmCount = 0;
        foreach (var info in contracts.Entries) {
            Assert(info.CellCount is >= 1 and <= 100 && info.Type != 0, "Producer dispatch contract is incomplete.");
            if (info.IsGvm) {
                gvmCount += info.CellCount;
                Assert(info.Method.Name == "Echo" && info.Arguments.Count == 1,
                    "GVM source declarations or generic arguments changed.");
            } else {
                interfaceCount += info.CellCount;
            }
        }
        Assert(interfaceCount == cells.CellEntries.Length && gvmCount == cells.GvmCellEntries.Length && gvmCount == 4,
            "A metadata-backed dispatch cell disappeared during analysis.");
        int interfaceUses = cells.CellEntries.ToArray().Sum(cell => cell.Uses.Count);
        Assert(interfaceUses > 0 && code.DispatchCellUseEntries.ToArray().All(use => use.Target != 0
            && CodeFlow.IsIndexedDispatchHelper(image, use.Target)),
            "Current direct dispatch helper calls were not linked to their cells.");
        Assert(code.UnprovenDispatchCellUseEntries.ToArray().Any(use => use.Cell == 0
            && CodeFlow.IsIndexedDispatchHelper(image, use.Target)),
            "Dictionary-loaded dispatch cells disappeared instead of reporting unavailable static identities.");
        Assert(cells.Rejected.ToArray().All(rejected => rejected.Address != 0),
            "An unknown dynamic cell was published as a rejected cell at address zero.");
        Assert(extraction.Dictionaries.RecipeEntries.ToArray().Any(recipe => recipe.Kind == DictionaryFixup.GvmDispatchCell),
            "Reflection-rooted Generic<T> did not retain its GVM recipe.");

        var gvmSlots = extraction.Dictionaries.SlotEntries.ToArray().Where(slot =>
            extraction.Dictionaries.RecipeEntries[slot.Recipe].Kind == DictionaryFixup.GvmDispatchCell).ToArray();
        Assert(gvmSlots.Length == 2 && gvmSlots.All(slot => slot.Status == DictionarySlotStatus.Verified
            && slot.GvmCellMetadata != 0), "Generic<string>/Generic<object> dictionaries did not bind to their GVM contracts.");
        foreach (var slot in gvmSlots) {
            var cell = cells.GvmCellEntries.ToArray().Single(cell => cell.Address == slot.Value);
            Assert(cells.DictionarySlotPositions.Slice(cell.DictionarySlots.Start, cell.DictionarySlots.Count).ToArray()
                .Any(position => extraction.Dictionaries.SlotEntries[position].Address == slot.Address),
                "A GVM cell lost its dictionary source relationship.");
        }

        var normal = AnalysisEvidence.Read(prepared, image.ImageBase);
        const ulong delta = 0x10000000;
        var rebased = AnalysisEvidence.Read(prepared, image.ImageBase + delta);
        Assert(rebased.References.ToHashSet().SetEquals(normal.References.Select(reference =>
            new AnalysisReference(reference.From + delta, reference.To + delta))), "Dispatch evidence did not rebase consistently.");
        foreach (var cell in cells.GvmCellEntries) {
            var info = contracts.Entries[cell.Metadata - 1];
            ulong witness = header.Find(info.Section).Start + (uint)info.Vertex;
            Assert(normal.References.Contains(new(cell.Address, witness))
                && normal.References.Contains(new(witness, cell.Address))
                && normal.Tags.Any(tag => tag.Kind == AnalysisEvidenceKind.DispatchCell && tag.Address == cell.Address),
                "Binja publication omitted a GVM cell or its source contract.");
        }
        PartialMethodSignature(prepared);
        PartialGenericSignatures(prepared);
        GlobalModuleIdentity(prepared.Extraction);
        PartialDispatchHelper(prepared);
        Console.WriteLine($"{path}: {interfaceCount} interface cells, {gvmCount} GVM cells, {interfaceUses} proved interface uses, {code.UnprovenDispatchCellUseEntries.Length} unproven uses, GVM recipe, partial metadata and rebased host evidence passed.");
    }

    private static void PartialDispatchHelper(PreparedAnalysis healthy) {
        var source = healthy.Extraction;
        ulong target = healthy.Code!.DispatchCellUseEntries[0].Target;
        ref readonly var section = ref source.Image.Sections[source.Image.FindSection(target)];
        byte[] bytes = source.Image.Bytes.ToArray();
        bytes[section.FileOffset + checked((int)(target - source.Image.ImageBase - section.Rva))] = 0x90;
        var image = new PeImage(bytes);
        var header = ReadyToRun.Read(image);
        var metadata = MetadataBuilder.FromImage(image, header);
        metadata.ReadDefinitions();
        var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        var maps = ReflectionMaps.Decode(image, header, metadata, fixups);
        var partial = new PreparedAnalysis(image, header, metadata, maps, fixups);
        Assert(partial.Code!.DispatchCellUseEntries.ToArray().All(use => use.Target != target)
            && partial.Code.UnprovenDispatchCellUseEntries.ToArray().Any(use => use.Target == target && use.Cell != 0),
            "An unproved helper retained accepted uses or hid known-cell call witnesses.");
        Assert(partial.DispatchCells!.CellEntries.Length == healthy.DispatchCells!.CellEntries.Length
            && partial.DispatchCells.GvmCellEntries.Length == healthy.DispatchCells.GvmCellEntries.Length,
            "Unrecognized helper code discarded independently known metadata cells.");
    }

    private static void PartialMethodSignature(PreparedAnalysis healthy) {
        var source = healthy.Extraction;
        var uses = source.Metadata.Methods.ToArray().GroupBy(method => method.SignatureOffset)
            .ToDictionary(group => group.Key, group => group.Count());
        var target = source.Maps.Methods.First(entry => entry.MetadataOffset != 0
            && entry.Signature != 0 && entry.Entrypoint != 0
            && uses[source.Metadata.ReadMethodDefinition(entry.MetadataOffset).SignatureOffset] == 1
            && source.Signatures.MethodSignatures[entry.Signature].GenericParameterCount == 0);
        var definition = source.Metadata.ReadMethodDefinition(target.MetadataOffset);
        var prepared = DamagedSignature(source, definition);
        var partial = prepared.Extraction;
        var mapped = partial.Maps.Methods.Single(entry => entry.Vertex == target.Vertex);
        Assert(mapped.Name == target.Name && mapped.Entrypoint == target.Entrypoint && mapped.Signature == 0,
            "A corrupt method signature discarded independently valid reflection facts.");
        UnknownMethodAbi(prepared, target.MetadataOffset);
        Assert(partial.Metadata.ProjectionDiagnostics.Count != 0 && partial.Metadata.Facts.Status != MetadataFactStatus.Valid,
            "Damaged method metadata reported a complete publication.");
        var name = partial.Metadata.Facts.Field(new MetadataMethodId(target.MetadataOffset).Record, MetadataFieldName.Name).Reference;
        Assert(name.IsAvailable && partial.Metadata.Facts.Name(new(name.Value.Offset)).Text.Value == target.Name,
            "A failed signature projection invalidated the independent name fact.");
        foreach (var original in source.Traces.MethodEntries) {
            if (original.SignatureOffset != definition.SignatureOffset)
                continue;
            var retained = partial.Traces.MethodEntries.ToArray().Single(method => method.Offset == original.Offset);
            Assert(retained.Name == original.Name && retained.Entrypoint == original.Entrypoint
                && retained.Signature == 0 && retained.SignatureStatus != MetadataFactStatus.Valid,
                "Trace extraction discarded valid facts or hid its failed signature projection.");
        }
    }

    private static void PartialGenericSignatures(PreparedAnalysis healthy) {
        var source = healthy.Extraction;
        foreach (string name in new[] { "Generic", "Echo" }) {
            var method = source.Metadata.Methods.ToArray().First(method => method.Name == name);
            var prepared = DamagedSignature(source, method);
            var partial = prepared.Extraction;
            Assert(partial.Generics.MethodEntries.Length == source.Generics.MethodEntries.Length
                && partial.Dictionaries.RecipeEntries.Length == source.Dictionaries.RecipeEntries.Length
                && partial.DictionarySignatureGaps.IsEmpty,
                "An unavailable generic signature hid independently bounded method arguments or later recipes.");
            Assert(prepared.DispatchCells!.GvmCellEntries.Length == healthy.DispatchCells!.GvmCellEntries.Length
                && prepared.DispatchCells.CellEntries.Length == healthy.DispatchCells.CellEntries.Length,
                "An unavailable generic signature hid physical dispatch cells.");

            var slots = partial.Dictionaries.SlotEntries.ToArray().Where(slot =>
                partial.Dictionaries.RecipeEntries[slot.Recipe].Kind == DictionaryFixup.GvmDispatchCell).ToArray();

            if (name == "Generic") {
                var methods = partial.Generics.MethodEntries.ToArray().Where(entry => entry.MetadataOffset == method.Offset).ToArray();
                Assert(methods.Length == 2 && methods.All(entry => entry.Name == name && entry.Signature == 0
                    && entry.SignatureStatus != MetadataFactStatus.Valid && entry.Arguments.Count == 1),
                    "Generic<string>/Generic<object> lost their independently encoded identity or arguments.");
                UnknownMethodAbi(prepared, method.Offset);
            } else {
                var contracts = partial.DispatchCellMetadata.Entries.ToArray().Where(entry => entry.IsGvm).ToArray();
                Assert(contracts.Length == 4 && contracts.All(entry => entry.Status != MetadataFactStatus.Valid
                    && entry.Method.Name == "Echo" && entry.Method.Signature == 0 && entry.Arguments.Count == 0),
                    "Unavailable GVM composition arity became invented arguments or erased known contracts.");
                Assert(partial.DispatchCellMetadata.Failures.Length == 4,
                    "Unknown GVM argument counts were not reported as partial extraction.");
                Assert(slots.Length == 2 && slots.All(slot => slot.Status == DictionarySlotStatus.Unresolved
                    && slot.GvmCellMetadata != 0),
                    "An unavailable GVM contract was treated as a verified dictionary binding.");
            }
            var evidence = AnalysisEvidence.Read(prepared, partial.Image.ImageBase);
            foreach (var slot in slots)
                Assert(evidence.References.Contains(new(slot.Address, slot.Value)),
                    "An unavailable semantic binding hid the known dictionary pointer-to-cell relationship.");
            Assert(evidence.Tags.Any(tag => tag.Kind == AnalysisEvidenceKind.Status && tag.Text.Contains("metadata::status=partial", StringComparison.Ordinal)),
                "Host evidence hid unavailable generic metadata.");
        }
    }

    private static void UnknownMethodAbi(PreparedAnalysis prepared, uint metadataOffset) {
        var abi = prepared.ManagedAbi!;
        int matched = 0;
        for (int index = 0; index < abi.RuntimeCount; ++index) {
            var method = new MethodRecord(prepared.Extraction, index);
            if (method.MetadataOffset != metadataOffset)
                continue;
            var row = abi.MethodEntries[index];
            Assert(method.MethodSignature.IsEmpty && row.Status == AbiStatus.UnknownSignature
                && row.Parameters.Count == 0,
                "An unavailable method signature invented ABI parameters or a known ABI status.");
            ++matched;
        }
        Assert(matched != 0, "The damaged declaration had no runtime ABI rows.");
    }

    private static void GlobalModuleIdentity(Extraction source) {
        Assert(source.PInvokes.MethodEntries.Length != 0, "Producer did not retain any P/Invoke fixups for the module identity check.");
        var module = source.Maps.Types.First(entry => entry.IsGlobalModule);
        uint offsetMask = (1U << (32 - source.Header.MetadataHandleBits)) - 1;
        var type = new MetadataTypeId(module.Handle & offsetMask);
        var name = source.Metadata.Facts.Field(type.Record, MetadataFieldName.Name).Reference;
        Assert(name.IsAvailable, "Producer global module has no source name.");
        var text = source.Metadata.Facts.Name(new(name.Value.Offset));
        Assert(text.Source.IsAvailable && text.Bytes.Length != 0, "Producer global module name has no original bytes.");
        var storage = source.Header.Find(RtrSectionId.EmbeddedMetadata);
        var section = source.Image.Sections[source.Image.FindSection(storage.Start)];
        int metadataFileOffset = section.FileOffset + checked((int)(storage.Start - source.Image.ImageBase - section.Rva));
        byte[] bytes = source.Image.Bytes.ToArray();
        bytes.AsSpan(metadataFileOffset + text.Source.Offset, text.Bytes.Length).Fill((byte)'x');
        var renamed = Extraction.Read(new PeImage(bytes));
        Assert(renamed.Maps.Types.Count(entry => entry.IsGlobalModule) == source.Maps.Types.Count(entry => entry.IsGlobalModule)
            && renamed.PInvokes.MethodEntries.Length == source.PInvokes.MethodEntries.Length
            && renamed.PInvokes.ModuleEntries.Length == source.PInvokes.ModuleEntries.Length,
            "Renaming a global module changed P/Invoke identity or dropped its fixups.");
    }

    private static PreparedAnalysis DamagedSignature(Extraction source, MetadataMethod method) {
        var storage = source.Header.Find(RtrSectionId.EmbeddedMetadata);
        var section = source.Image.Sections[source.Image.FindSection(storage.Start)];
        int metadataFileOffset = section.FileOffset + checked((int)(storage.Start - source.Image.ImageBase - section.Rva));
        byte[] bytes = source.Image.Bytes.ToArray();
        bytes[metadataFileOffset + checked((int)method.SignatureOffset)] = 255;
        var image = new PeImage(bytes);
        var header = ReadyToRun.Read(image);
        var metadata = MetadataBuilder.FromImage(image, header);
        metadata.ReadDefinitions();
        var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        var maps = ReflectionMaps.Decode(image, header, metadata, fixups);
        return new PreparedAnalysis(image, header, metadata, maps, fixups);
    }

    private static byte[] Header(ushort major, ushort minor, ushort sections, int length) {
        byte[] data = new byte[length];
        "RTR\0"u8.CopyTo(data);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), major);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(6), minor);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12), sections);
        data[14] = 16;
        data[15] = 1;
        return data;
    }

    private static void Row(byte[] data, int index, RtrSectionId id, int offset, int length) {
        var row = data.AsSpan(16 + index * 16);
        BinaryPrimitives.WriteInt32LittleEndian(row, (int)id);
        BinaryPrimitives.WriteInt32LittleEndian(row[4..], length);
        BinaryPrimitives.WriteUInt64LittleEndian(row[8..], 0x140001000UL + (uint)offset);
    }

    private static int Put(byte[] bytes, int offset, params uint[] values) {
        foreach (uint value in values) {
            bytes[offset++] = 15;
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), value);
            offset += 4;
        }
        return offset;
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new InvalidDataException(message);
    }
}
