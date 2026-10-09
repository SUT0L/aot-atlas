using Atlas;
using System.Buffers.Binary;

internal static class DictionaryStageChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        RootOracle();
        VersionOracle();
        LegacyTokenOracle();
        Assert(ExtractionPlan.Prerequisites(ExtractionStage.DictionaryBindings)
            == (ExtractionStage.RuntimeTypes | ExtractionStage.MemberLayouts));
        Assert(ExtractionPlan.Required(ExtractionStage.DictionaryBindings)
            == (ExtractionStage.RuntimeTypes | ExtractionStage.MemberLayouts | ExtractionStage.DictionaryBindings));

        foreach (string binary in binaries) {
            byte[] original = File.ReadAllBytes(binary);
            var bound = Extract(original, ExtractionStage.DictionaryBindings);
            var members = Extract(original, ExtractionStage.MemberLayouts);
            var types = Extract(original, ExtractionStage.RuntimeTypes);

            EqualFacts(bound, members);
            EqualFacts(bound, types);
            EqualGraph(bound, members);
            Assert(bound.Fields.Fields.SequenceEqual(members.Fields.Fields));
            Assert(bound.Fields.FieldTypes.SequenceEqual(members.Fields.FieldTypes));
            Assert(bound.Shared.Templates.SequenceEqual(members.Shared.Templates));
            AssertMissing(members);
            AssertMissing(types);
            Assert(bound.DictionarySignatureGaps.SequenceEqual(members.DictionarySignatureGaps));

            var recipes = bound.Dictionaries.Recipes;
            var section = bound.Header.Find(RtrSectionId.NativeLayoutInfo);
            var staticData = recipes.LastOrDefault(recipe => recipe.Kind == DictionaryFixup.StaticData);

            if (staticData.Kind != 0) {
                var reader = new NativeReader(
                    bound.Image.FileSpan(section.Start, checked((int)section.Length)), staticData.Offset);
                reader.Unsigned();
                bound.Layout.TypeSignature(ref reader);

                byte[] damaged = (byte[])original.Clone();
                int offset = bound.Image.FileRange(section.Start).Start + reader.Position;
                Assert(damaged[offset] is 2 or 4);
                damaged[offset] = 6; // Same one-byte grammar, invalid storage discriminator 3.

                foreach (var stage in new[] {
                    ExtractionStage.RuntimeTypes,
                    ExtractionStage.MemberLayouts,
                    ExtractionStage.Dispatch
                }) {
                    var healthy = Extract(original, stage);
                    var recovered = Extract(damaged, stage);

                    EqualFacts(healthy, recovered);
                    EqualGraph(healthy, recovered);
                    Assert(recovered.DictionarySignatureGaps.IsEmpty);

                    if (stage == ExtractionStage.MemberLayouts)
                        Assert(healthy.Fields.FieldTypes.SequenceEqual(recovered.Fields.FieldTypes));
                }

                Reject(damaged, ExtractionStage.DictionaryBindings, "static-data kind");
                Reject(damaged, ExtractionStage.All, "static-data kind");
            }

            var methodDictionary = recipes.FirstOrDefault(recipe => recipe.Kind == DictionaryFixup.MethodDictionary);

            if (methodDictionary.Kind != 0) {
                // A method definition has valid NativeLayout grammar, but cannot be
                // interpreted as an instantiated generic method dictionary.
                byte[] damaged = (byte[])original.Clone();
                int offset = bound.Image.FileRange(section.Start).Start
                    + checked((int)methodDictionary.Method.Offset);
                Assert(damaged[offset] == methodDictionary.Method.Flags * 2
                    && (methodDictionary.Method.Flags & 1) != 0);
                damaged[offset] = (byte)(damaged[offset] & ~2);

                var recovered = Extract(damaged, ExtractionStage.MemberLayouts);
                EqualFacts(members, recovered);
                EqualGraph(Extract(damaged, ExtractionStage.RuntimeTypes), recovered);
                Assert(recovered.DictionarySignatureGaps.IsEmpty);
                Assert(members.Fields.FieldTypes.SequenceEqual(recovered.Fields.FieldTypes));

                Reject(damaged, ExtractionStage.DictionaryBindings, "no generic method arguments");
                Reject(damaged, ExtractionStage.All, "no generic method arguments");
            }

            if (bound.Dictionaries.Slots.Count != 0) {
                // A dictionary target need not be read to discover type/signature roots.
                // Redirect only its NativeReferences cell to the unmapped image end.
                var instance = bound.Dictionaries.Instances.First(instance => instance.Slots.Count != 0);
                int reference = Array.IndexOf(bound.NativeReferences, instance.Address);
                Assert(reference >= 0 && !bound.Layout.ExternalTypes.ContainsKey(instance.Address));

                var references = bound.Header.Find(RtrSectionId.NativeReferences);
                ulong address = references.Start + (uint)reference * 4UL;
                byte[] damaged = (byte[])original.Clone();
                BinaryPrimitives.WriteInt32LittleEndian(
                    damaged.AsSpan(bound.Image.FileRange(address).Start),
                    checked((int)((long)(bound.Image.ImageBase + bound.Image.ImageSize) - (long)address)));

                var recovered = Extract(damaged, ExtractionStage.MemberLayouts);
                EqualFacts(members, recovered);
                EqualGraph(members, recovered);
                Assert(members.Fields.FieldTypes.SequenceEqual(recovered.Fields.FieldTypes));

                Reject(damaged, ExtractionStage.DictionaryBindings, "No initialized bytes");
                Reject(damaged, ExtractionStage.All, "No initialized bytes");
            }

            if (recipes.Count != 0) {
                var first = recipes[0];
                byte[] unsupported = (byte[])original.Clone();
                int offset = bound.Image.FileRange(section.Start).Start + first.Offset;
                Assert((unsupported[offset] & 1) == 0);
                unsupported[offset] = 0xfc; // Unknown variable-length kind 0x7e.

                var partial = Extract(unsupported, ExtractionStage.MemberLayouts);
                Assert(partial.DictionarySignatureGaps.Length > 0);
                var gap = partial.DictionarySignatureGaps[0];
                var layout = bound.Dictionaries.Layouts.First(layout => layout.Recipes.Start == 0);
                Assert(gap == new DictionarySignatureGap(layout.Offset, first.Offset, 0x7e, layout.SlotCount));

                var strictPrefix = Extract(unsupported, ExtractionStage.DictionaryBindings);
                Assert(strictPrefix.DictionarySignatureGaps.SequenceEqual(partial.DictionarySignatureGaps));
                Assert(strictPrefix.Dictionaries.Layouts[0].Recipes.Count == 0
                    && strictPrefix.Dictionaries.Layouts[0].UnsupportedKind == 0x7e);

                byte[] reserved = (byte[])original.Clone();
                reserved[offset] = 0;
                Reject(reserved, ExtractionStage.RuntimeTypes, "reserved null");
                Reject(reserved, ExtractionStage.MemberLayouts, "reserved null");
            }

            var restored = Extract(original, ExtractionStage.DictionaryBindings);
            EqualFacts(bound, restored);
            EqualGraph(bound, restored);
            Assert(bound.Dictionaries.Layouts.SequenceEqual(restored.Dictionaries.Layouts));
            Assert(bound.Dictionaries.Recipes.SequenceEqual(restored.Dictionaries.Recipes));
            Assert(bound.Dictionaries.Slots.SequenceEqual(restored.Dictionaries.Slots));

            Console.WriteLine($"{binary}: {bound.Templates.Methods.Count} method templates, {recipes.Count} recipes; closure IDs and independent facts preserved; semantic/grammar boundaries and restored bindings passed.");
        }
    }

    // Four hand-derived recipes introduce roots through direct types, a method owner,
    // a nonempty method instantiation and static storage. Duplicate bags must not
    // duplicate the method arguments in the shared signature graph.
    private static void RootOracle() {
        byte[] blob = new byte[256];
        blob[0] = 0x80;
        Put(blob, 1, 63);
        blob[6] = 0;

        int at = Put(blob, 64, 4, 1, 6, 4, 1, 0x16);
        at = Put(blob, at, 1);
        blob[at++] = (byte)'M';
        int origin = at;
        at = Put(blob, at, (uint)(192 - origin), 1, 0x26, 1, 0x13, 0x26, 4, 5, 0x36, 1);
        Put(blob, 192, 1, 1, 0, 0x15);

        byte[] data = new byte[128 + blob.Length];
        "RTR\0"u8.CopyTo(data);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), 16);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12), 1);
        data[14] = 24;
        data[15] = 1;
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(16), (int)RtrSectionId.NativeLayoutInfo);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(24), 0x140001080);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(32), 0x140001080UL + (uint)blob.Length);
        blob.CopyTo(data, 128);

        var image = PeFixture.Create(data, ".rdata", 0x40000040);
        var header = ReadyToRun.Read(image);
        var section = header.Find(RtrSectionId.NativeLayoutInfo);
        var metadata = new Metadata(default, 7);
        var native = new NativeLayout(
            image.FileMemory(section.Start, checked((int)section.Length)),
            [0x1111, 0x2222, 0x3333, 0x4444], metadata.SignatureBuilder, takeOwnership: true);

        var templates = new TemplateMaps();
        templates.Methods.Add(new MethodTemplate { LayoutOffset = 0 });
        templates.Types.Add(new TypeTemplate(0, 0, 0, default));
        templates.Types.Add(new TypeTemplate(0, 0, 0, default));

        var dictionaries = new GenericDictionaries();
        dictionaries.Read(image, header, metadata, native, templates, MapFormat.Legacy);

        Assert(native.ExternalTypes.SequenceEqual(new Dictionary<ulong, int> {
            [0x1111] = 1,
            [0x2222] = 2,
            [0x3333] = 4,
            [0x4444] = 7
        }));
        Assert(metadata.SignatureBuilder.Nodes.Length == 8 && metadata.SignatureBuilder.Methods.Length == 2);
        Assert(metadata.SignatureBuilder.Edges.SequenceEqual(new[] { 4, 5 }));
        Assert(dictionaries.Layouts.Count == 1
            && dictionaries.Recipes.Count == 4 && dictionaries.SignatureGaps.IsEmpty);
        Assert(dictionaries.MethodLayouts.SequenceEqual(new[] { 1 })
            && dictionaries.TypeLayouts.SequenceEqual(new[] { 1, 1 }));
        Assert(dictionaries.Recipes[1].Method.Arguments.Start == 0
            && dictionaries.Recipes[1].Method.Arguments.Count == 1);
        Assert(metadata.SignatureBuilder.RenderType(dictionaries.Recipes[2].Type) == "mt_ref_3333<T>");
    }

    private static int Put(byte[] data, int offset, params uint[] values) {
        foreach (uint value in values) {
            data[offset++] = 15;
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), value);
            offset += 4;
        }

        return offset;
    }

    private static void VersionOracle() {
        foreach (var version in new (ushort Major, ushort Minor, bool Instance)[] {
            (9, 1, false), (10, 1, false), (12, 0, false),
            (16, 0, true), (18, 4, true), (18, 5, true)
        }) {
            byte[] blob = new byte[128];
            int origin = Put(blob, 0, 0x40);
            Put(blob, origin, (uint)(64 - origin), 0);
            bool integer = version.Major == 9;
            if (integer)
                Put(blob, 64, 2, 0x20, 7, 1, 0x26);
            else
                Put(blob, 64, 2, 0x20, 6, 0x16, 3, 1, 0x26);

            byte[] data = new byte[128 + blob.Length];
            "RTR\0"u8.CopyTo(data);
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), version.Major);
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(6), version.Minor);
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12), 1);
            bool lengths = version.Major == 18;
            data[14] = lengths ? (byte)16 : (byte)24;
            data[15] = 1;
            BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(16), (int)RtrSectionId.NativeLayoutInfo);
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), lengths ? (uint)blob.Length : 1);
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(24), 0x140001080);
            if (!lengths)
                BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(32), 0x140001100);
            blob.CopyTo(data, 128);

            var image = PeFixture.Create(data, ".rdata", 0x40000040);
            var header = ReadyToRun.Read(image);
            var storage = header.Find(RtrSectionId.NativeLayoutInfo);
            var templates = new TemplateMaps();
            templates.Methods.Add(new MethodTemplate { LayoutOffset = 0 });

            var fullMetadata = new Metadata(default, header.MetadataHandleBits);
            var fullNative = new NativeLayout(image.FileMemory(storage.Start, (int)storage.Length),
                [0x1111, 0x2222, 0x3333], fullMetadata.SignatureBuilder, takeOwnership: true);
            var full = new GenericDictionaries();
            full.Read(image, header, fullMetadata, fullNative, templates, MapFormat.Legacy);

            var narrowMetadata = new Metadata(default, header.MetadataHandleBits);
            var narrowNative = new NativeLayout(image.FileMemory(storage.Start, (int)storage.Length),
                [0x1111, 0x2222, 0x3333], narrowMetadata.SignatureBuilder, takeOwnership: true);
            var narrow = new GenericDictionaries();
            narrow.ReadSignatures(image, header, narrowMetadata, narrowNative, templates, MapFormat.Legacy);

            Assert(fullMetadata.SignatureBuilder.Nodes.SequenceEqual(narrowMetadata.SignatureBuilder.Nodes));
            Assert(full.SignatureGaps.SequenceEqual(narrow.SignatureGaps));
            Assert(full.Recipes.Count == (version.Instance || integer ? 2 : 0));
            Assert(fullNative.ExternalTypes.Count == (version.Instance ? 3 : integer ? 1 : 0));
            if (integer)
                Assert(full.Recipes[0].Kind == DictionaryFixup.IntegerValue && full.Recipes[0].EncodedKind == 0x20);
            Assert(version.Instance || integer ? full.SignatureGaps.IsEmpty
                : full.SignatureGaps.SequenceEqual(new[] { new DictionarySignatureGap(64, 69, 0x20, 2) }));
        }
    }

    private static void LegacyTokenOracle() {
        byte[] blob = new byte[320];
        int origin = Put(blob, 0, 0x40);
        Put(blob, origin, (uint)(64 - origin), 0);

        int at = Put(blob, 64, 4, 7);
        at = Put(blob, at, (uint)(160 - at), 8);
        at = Put(blob, at, (uint)(192 - at), 0x22, 6);
        at = Put(blob, at, (uint)(192 - at), 1, 0x26);
        Assert(at == 114);

        at = Put(blob, 160, 0x16, 1);
        blob[at] = (byte)'F';
        at = Put(blob, 192, 1, 0x36, 1);
        blob[at++] = (byte)'M';
        Put(blob, at, (uint)(256 - at), 1, 6);
        Put(blob, 256, 1, 1, 0, 0x15);

        byte[] data = new byte[128 + blob.Length];
        "RTR\0"u8.CopyTo(data);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), 10);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(6), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12), 1);
        data[14] = 24;
        data[15] = 1;
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(16), (int)RtrSectionId.NativeLayoutInfo);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(24), 0x140001080);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(32), 0x140001080UL + (uint)blob.Length);
        blob.CopyTo(data, 128);

        var image = PeFixture.Create(data, ".rdata", 0x40000040);
        var header = ReadyToRun.Read(image);
        var storage = header.Find(RtrSectionId.NativeLayoutInfo);
        var metadata = new Metadata(default, 8);
        var native = new NativeLayout(image.FileMemory(storage.Start, (int)storage.Length),
            [0x1111, 0x2222, 0x3333, 0x4444], metadata.SignatureBuilder, takeOwnership: true);
        var templates = new TemplateMaps();
        templates.Methods.Add(new MethodTemplate { LayoutOffset = 0 });
        var dictionaries = new GenericDictionaries();
        dictionaries.Read(image, header, metadata, native, templates, MapFormat.Legacy);

        Assert(dictionaries.Recipes.Count == 4 && dictionaries.SignatureGaps.IsEmpty);
        Assert(dictionaries.Layouts[0].Length == 50);
        Assert(dictionaries.Recipes[0].FieldName == "F" && dictionaries.Recipes[0].PayloadOffset == 160
            && dictionaries.Recipes[0].Length == 10);
        Assert(dictionaries.Recipes[1].Method.Offset == 192 && dictionaries.Recipes[1].Length == 10);
        Assert(dictionaries.Recipes[2].Method.Offset == 192 && dictionaries.Recipes[2].Length == 15);
        Assert(dictionaries.Recipes[3].Offset == 104
            && metadata.SignatureBuilder.Nodes[dictionaries.Recipes[3].Type].TypeAddress == 0x3333);

        Put(data, 128 + 165, 0); // Empty field name retains valid string grammar.
        var emptyImage = PeFixture.Create(data, ".rdata", 0x40000040);
        var emptyHeader = ReadyToRun.Read(emptyImage);
        var emptyStorage = emptyHeader.Find(RtrSectionId.NativeLayoutInfo);
        var narrowMetadata = new Metadata(default, 8);
        var narrowNative = new NativeLayout(emptyImage.FileMemory(emptyStorage.Start, (int)emptyStorage.Length),
            [0x1111, 0x2222, 0x3333, 0x4444], narrowMetadata.SignatureBuilder, takeOwnership: true);
        var narrow = new GenericDictionaries();
        narrow.ReadSignatures(emptyImage, emptyHeader, narrowMetadata, narrowNative, templates, MapFormat.Legacy);
        Assert(narrowMetadata.SignatureBuilder.Nodes.SequenceEqual(metadata.SignatureBuilder.Nodes));
        Assert(narrowMetadata.SignatureBuilder.Edges.SequenceEqual(metadata.SignatureBuilder.Edges));
        Assert(narrowMetadata.SignatureBuilder.Methods.SequenceEqual(metadata.SignatureBuilder.Methods));

        var retained = new GenericDictionaries();
        retained.Read(emptyImage, emptyHeader, narrowMetadata, narrowNative, templates, MapFormat.Legacy);
        Assert(retained.Recipes[0].FieldName == "" && retained.Recipes[0].PayloadOffset == 160
            && retained.Recipes[0].Length == 10 && retained.Recipes.Count == 4);
    }

    private static Extraction Extract(byte[] bytes, ExtractionStage stages) {
        var image = new PeImage(bytes);
        var header = ReadyToRun.Read(image);
        var section = header.Find(RtrSectionId.EmbeddedMetadata);
        var metadata = new Metadata(
            image.FileMemory(section.Start, checked((int)section.Length)),
            header.MetadataHandleBits, header.Format.LegacyMetadataConstants);
        metadata.ReadDefinitions();

        var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        var maps = new ReflectionMaps();
        maps.Read(image, header, metadata, fixups);

        return new Extraction(image, header, metadata, maps, fixups, stages);
    }

    private static void EqualFacts(Extraction left, Extraction right) {
        Assert(left.Types.Types.SequenceEqual(right.Types.Types)
            && left.Types.Pointers.SequenceEqual(right.Types.Pointers));
        Assert(left.Names.Values.SequenceEqual(right.Names.Values)
            && left.Names.Complete.SequenceEqual(right.Names.Complete));
        Assert(left.Gc.Layouts.SequenceEqual(right.Gc.Layouts) && left.Gc.Runs.SequenceEqual(right.Gc.Runs));
        Assert(left.Frozen.Objects.SequenceEqual(right.Frozen.Objects)
            && left.Frozen.RuntimeTypes.SequenceEqual(right.Frozen.RuntimeTypes));
    }

    private static void EqualGraph(Extraction left, Extraction right) {
        Assert(left.Metadata.SignatureBuilder.Nodes.SequenceEqual(right.Metadata.SignatureBuilder.Nodes));
        Assert(left.Metadata.SignatureBuilder.Edges.SequenceEqual(right.Metadata.SignatureBuilder.Edges));
        Assert(left.Metadata.SignatureBuilder.Methods.SequenceEqual(right.Metadata.SignatureBuilder.Methods));
        Assert(left.Metadata.TypeSignatureHandles.SequenceEqual(right.Metadata.TypeSignatureHandles));
        Assert(left.Layout.ExternalTypes.SequenceEqual(right.Layout.ExternalTypes));
    }

    private static void AssertMissing(Extraction extraction) {
        bool rejected = false;

        try {
            _ = extraction.Dictionaries;
        } catch (InvalidOperationException) {
            rejected = true;
        }

        Assert(rejected);
    }

    private static void Reject(byte[] data, ExtractionStage stage, string message) {
        bool rejected = false;

        try {
            _ = Extract(data, stage);
        } catch (InvalidDataException failure) when (failure.Message.Contains(message, StringComparison.Ordinal)) {
            rejected = true;
        }

        Assert(rejected);
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Dictionary stage assertion failed.");
    }
}
