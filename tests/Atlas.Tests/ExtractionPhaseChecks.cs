using System.Buffers.Binary;
using Atlas;
using System.Text.Json;

internal static class ExtractionPhaseChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        for (int bits = 1; bits <= (int)ExtractionStage.All; ++bits) {
            var requested = (ExtractionStage)bits;
            var expected = requested;

            if ((requested & (ExtractionStage.RuntimeTypes | ExtractionStage.MemberLayouts | ExtractionStage.Dispatch
                | ExtractionStage.MethodTracing | ExtractionStage.DictionaryBindings
                | ExtractionStage.PInvokes | ExtractionStage.Enums)) != 0)
                expected |= ExtractionStage.RuntimeTypes;

            if ((requested & ExtractionStage.DictionaryBindings) != 0)
                expected |= ExtractionStage.MemberLayouts;

            Assert(ExtractionPlan.Required(requested) == expected,
                "Declared stage closure differs from public capability requirements.");
            Assert(ExtractionPlan.Required(expected) == expected, "Stage closure is not idempotent.");
        }

        Assert(ExtractionPlan.Prerequisites(ExtractionStage.Resources) == ExtractionStage.None,
            "Resources require unrelated runtime work.");
        Assert(ExtractionPlan.Prerequisites(ExtractionStage.Linkage) == ExtractionStage.None,
            "Linkage requires unrelated runtime work.");
        Assert(ExtractionPlan.Prerequisites(ExtractionStage.PInvokes) == ExtractionStage.RuntimeTypes,
            "PInvoke provenance lacks runtime types.");

        var pinvokeStages = CommandPlan.For("pinvoke")!.Stages.GetValueOrDefault();
        var enumStages = CommandPlan.For("enums")!.Stages.GetValueOrDefault();
        var searchStages = CommandPlan.For("search")!.Stages.GetValueOrDefault();
        Assert(ExtractionPlan.Required(pinvokeStages)
            == (ExtractionStage.RuntimeTypes | ExtractionStage.PInvokes), "PInvoke CLI requests unrelated sources.");
        Assert(ExtractionPlan.Required(enumStages)
            == (ExtractionStage.RuntimeTypes | ExtractionStage.Enums), "Enum CLI requests field projection.");
        Assert(CommandPlan.For("fields")?.Stages == ExtractionStage.MemberLayouts,
            "Fields CLI requests unrelated projections.");
        Assert((searchStages & ExtractionStage.Linkage) != 0, "Code names omit exported identities.");
        Assert((searchStages & (ExtractionStage.Resources | ExtractionStage.PInvokes
            | ExtractionStage.Enums | ExtractionStage.DictionaryBindings)) == 0,
            "Code search requests unrelated projections.");
        Assert(CommandPlan.For("properties")!.Stages
            == (ExtractionStage.RuntimeTypes | ExtractionStage.MemberLayouts
                | ExtractionStage.MethodTracing | ExtractionStage.Dispatch),
            "Property projection depends on unrelated linkage.");

        using (var stream = new MemoryStream()) {
            using (var json = new Utf8JsonWriter(stream)) {
                json.WriteStartObject();
                ExtractionStatusOutput.Write(json, ExtractionStage.Resources, []);
                json.WriteEndObject();
            }

            using var document = JsonDocument.Parse(stream.ToArray());
            var status = document.RootElement.GetProperty("extraction_stages");
            Assert(status.GetProperty("runtime_types").GetString() == "not_requested",
                "Independent source status claims runtime types.");
            Assert(status.GetProperty("resources").GetString() == "available", "Requested resource status missing.");
            Assert(status.GetProperty("dictionary_signatures").GetString() == "not_requested",
                "Unread dictionary grammar claims completeness.");
            Assert(status.GetProperty("signature_graph_closure").GetString() == "not_requested",
                "Absent graph claims closure.");
        }

        foreach (string binary in binaries) {
            byte[] original = File.ReadAllBytes(binary);
            var image = new PeImage(original);
            var header = ReadyToRun.Read(image);
            var sourceMetadata = new Metadata(default, header.MetadataHandleBits);
            var independent = new Extraction(image, header, sourceMetadata, new ReflectionMaps(), [],
                ExtractionStage.Resources | ExtractionStage.Linkage);

            Assert(independent.Stages == (ExtractionStage.Resources | ExtractionStage.Linkage),
                "Independent source request constructed runtime stages.");
            Assert(sourceMetadata.SignatureBuilder.Nodes.Length == 1,
                "Independent sources mutated the signature graph.");
            Missing(() => independent.Types);
            Missing(() => independent.Memory);
            Missing(() => independent.Layout);
            Missing(() => independent.Signatures);
            Missing(() => independent.PInvokes);
            Missing(() => independent.Fields);
            Missing(() => independent.Traces);

            var healthy = Extract(original, ExtractionStage.RuntimeTypes);
            Missing(() => healthy.Resources);
            Missing(() => healthy.Linkage);
            Missing(() => healthy.PInvokes);

            byte[] badLinkage = (byte[])original.Clone();
            int nt = BinaryPrimitives.ReadInt32LittleEndian(badLinkage.AsSpan(60));

            // A complete PE/RTR image with only the optional import-directory extent damaged.
            BinaryPrimitives.WriteUInt32LittleEndian(badLinkage.AsSpan(nt + 24 + 112 + 8 + 4), 1);

            if (image.Directories[1].Rva == 0)
                BinaryPrimitives.WriteUInt32LittleEndian(badLinkage.AsSpan(nt + 24 + 112 + 8), image.Sections[0].Rva);

            EqualTypes(healthy, Extract(badLinkage, ExtractionStage.RuntimeTypes));
            Reject(badLinkage, ExtractionStage.Linkage, "Truncated import directory");
            RejectEarly(badLinkage, "Truncated import directory");

            var resourceIndex = header.Find(RtrSectionId.ResourceIndex);

            if (resourceIndex.Length != 0) {
                byte[] badResources = (byte[])original.Clone();
                badResources[image.FileRange(resourceIndex.Start).Start] = 255;

                EqualTypes(healthy, Extract(badResources, ExtractionStage.RuntimeTypes));
                Reject(badResources, ExtractionStage.Resources, "Invalid NativeHashtable header");
                RejectEarly(badResources, "Invalid NativeHashtable header");
            }

            var healthyMembers = Extract(original, ExtractionStage.MemberLayouts);
            Assert(ReferenceEquals(healthyMembers.Bindings, healthyMembers.Fields.Bindings),
                "Field projection created another binding owner.");
            Assert(ReferenceEquals(healthyMembers.Signatures, healthyMembers.Bindings.Signatures),
                "Binding index did not use the published graph.");
            Missing(() => healthyMembers.Enums);

            var enumOnly = Extract(original, ExtractionStage.Enums);
            Missing(() => enumOnly.Fields);
            Missing(() => enumOnly.Shared);
            Assert(ReferenceEquals(enumOnly.Signatures, enumOnly.Bindings.Signatures),
                "Enum projection did not use the published graph.");

            var enumField = enumOnly.Enums.Members.FirstOrDefault();

            if (enumOnly.Enums.Members.Count != 0) {
                var field = enumOnly.Metadata.Fields[enumField.Field];
                var reader = enumOnly.Metadata.Reader(field.Offset);
                reader.Unsigned(); // flags
                reader.Unsigned(); // name
                reader.Unsigned(); // signature offset
                int start = reader.Position;
                uint value = reader.Unsigned();

                byte[] badEnum = (byte[])original.Clone();
                int metadataFile = image.FileRange(header.Find(RtrSectionId.EmbeddedMetadata).Start).Start;
                uint kindMask = (1U << header.MetadataHandleBits) - 1;
                WriteUnsigned(badEnum.AsSpan(metadataFile + start),
                    (value & ~kindMask) | 1, reader.Position - start);

                EqualTypes(healthy, Extract(badEnum, ExtractionStage.RuntimeTypes));
                var independentMembers = Extract(badEnum, ExtractionStage.MemberLayouts);
                Assert(healthyMembers.Fields.FieldTypes.SequenceEqual(independentMembers.Fields.FieldTypes),
                    "Enum constant fault changed field identities.");
                Assert(healthyMembers.Fields.Fields.SequenceEqual(independentMembers.Fields.Fields),
                    "Enum constant fault changed field layouts.");

                Reject(badEnum, ExtractionStage.Enums, "Enum constant has unsupported NativeFormat kind");
                Reject(badEnum, ExtractionStage.All, "Enum constant has unsupported NativeFormat kind");
            }

            RetainedInputs(original);

            // Removing the independent source faults restores full progress and all core IDs.
            EqualTypes(healthy, Extract(original, ExtractionStage.All));
            Console.WriteLine($"{Path.GetFileName(binary)}: independent resources/linkage, explicit omitted getters, corrupt source isolation ({enumOnly.Enums.Members.Count} enum constants), healthy runtime IDs and recovery passed.");
        }
    }

    private static void WriteUnsigned(Span<byte> destination, uint value, int size) {
        if (size == 5) {
            destination[0] = 15;
            BinaryPrimitives.WriteUInt32LittleEndian(destination[1..], value);
            return;
        }

        uint encoded = (value << size) | ((1U << (size - 1)) - 1);

        for (int i = 0; i < size; ++i)
            destination[i] = (byte)(encoded >> (8 * i));
    }

    private static Extraction Extract(byte[] bytes, ExtractionStage stages) {
        var image = new PeImage(bytes);
        var header = ReadyToRun.Read(image);

        if ((stages & ~(ExtractionStage.Resources | ExtractionStage.Linkage)) == 0)
            return new Extraction(
                image, header, new Metadata(default, header.MetadataHandleBits), new ReflectionMaps(), [], stages);

        var section = header.Find(RtrSectionId.EmbeddedMetadata);
        var metadata = new Metadata(
            section.Length == 0 ? default : image.FileMemory(section.Start, checked((int)section.Length)),
            header.MetadataHandleBits, header.Format.LegacyMetadataConstants);
        metadata.ReadDefinitions();

        var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        var maps = new ReflectionMaps();
        maps.Read(image, header, metadata, fixups);

        return new Extraction(image, header, metadata, maps, fixups, stages);
    }

    private static void EqualTypes(Extraction left, Extraction right) {
        Assert(left.Types.Types.SequenceEqual(right.Types.Types), "Runtime type IDs changed.");
        Assert(left.Types.Pointers.SequenceEqual(right.Types.Pointers), "Runtime argument IDs changed.");
        Assert(left.Names.Values.SequenceEqual(right.Names.Values), "Runtime names changed.");
        Assert(left.Gc.Layouts.SequenceEqual(right.Gc.Layouts) && left.Gc.Runs.SequenceEqual(right.Gc.Runs),
            "GC layouts changed.");
        Assert(left.Frozen.Objects.SequenceEqual(right.Frozen.Objects), "Frozen object facts changed.");
    }

    private static void RetainedInputs(byte[] original) {
        var expected = Extract(original, ExtractionStage.All);

        foreach (int fault in new[] { 0, 1, 2 }) {
            var image = new PeImage((byte[])original.Clone());
            var header = ReadyToRun.Read(image);
            var section = header.Find(RtrSectionId.EmbeddedMetadata);
            var metadata = new Metadata(image.FileMemory(section.Start, checked((int)section.Length)),
                header.MetadataHandleBits, header.Format.LegacyMetadataConstants);
            metadata.ReadDefinitions();

            var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
            var maps = new ReflectionMaps();
            maps.Read(image, header, metadata, fixups);
            var before = metadata.SignatureBuilder.Publish();

            var directory = image.Directories[1];
            var resource = header.Find(RtrSectionId.ResourceIndex);
            int resourceOffset = resource.Length == 0 ? -1 : image.FileRange(resource.Start).Start;
            byte resourceHeader = resourceOffset < 0 ? (byte)0 : image.FileData[resourceOffset];

            int constant = metadata.Fields.FindIndex(field => (field.Flags & 0x8050) == 0x8050
                && field.DefaultValue != 0
                && metadata.SignatureBuilder.Nodes[field.Signature].Kind == SignatureKind.Named
                && expected.Enums.Definitions.Any(definition => definition.Signature == field.Signature));
            MetadataField savedField = constant < 0 ? default : metadata.Fields[constant];
            string error;

            if (fault == 0) {
                image.Directories[1] = new(directory.Rva == 0 ? image.Sections[0].Rva : directory.Rva, 1);
                error = "Truncated import directory";
            } else if (fault == 1) {
                if (resourceOffset < 0)
                    continue;

                image.FileData[resourceOffset] = 255;
                error = "Invalid NativeHashtable header";
            } else {
                if (constant < 0)
                    continue;

                var changed = savedField;
                changed.DefaultValue = (changed.DefaultValue & ~((1U << header.MetadataHandleBits) - 1)) | 1;
                metadata.Fields[constant] = changed;
                error = "Enum constant has unsupported NativeFormat kind";
            }

            bool rejected = false;

            try {
                _ = new Extraction(image, header, metadata, maps, fixups);
            } catch (InvalidDataException failure) when (failure.Message.Contains(error, StringComparison.Ordinal)) {
                rejected = true;
            }

            Assert(rejected, "Accepted optional-source fault was not rejected.");
            Assert(ReferenceEquals(before, metadata.SignatureBuilder.Publish()),
                "Failed optional source changed prior publication.");

            image.Directories[1] = directory;

            if (resourceOffset >= 0)
                image.FileData[resourceOffset] = resourceHeader;

            if (constant >= 0)
                metadata.Fields[constant] = savedField;

            var recovered = new Extraction(image, header, metadata, maps, fixups);
            EqualTypes(expected, recovered);
            Assert(expected.Signatures.Nodes.SequenceEqual(recovered.Signatures.Nodes),
                "Recovered signature node IDs/order changed.");
            Assert(expected.Signatures.Edges.SequenceEqual(recovered.Signatures.Edges),
                "Recovered signature edge IDs/order changed.");
            Assert(expected.Signatures.Methods.SequenceEqual(recovered.Signatures.Methods),
                "Recovered signature method IDs/order changed.");
        }
    }

    private static void RejectEarly(byte[] bytes, string message) {
        var image = new PeImage(bytes);
        var header = ReadyToRun.Read(image);
        var section = header.Find(RtrSectionId.EmbeddedMetadata);
        var metadata = new Metadata(
            section.Length == 0 ? default : image.FileMemory(section.Start, checked((int)section.Length)),
            header.MetadataHandleBits, header.Format.LegacyMetadataConstants);
        metadata.ReadDefinitions();

        var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        var maps = new ReflectionMaps();
        maps.Read(image, header, metadata, fixups);
        var before = metadata.SignatureBuilder.Publish();
        bool rejected = false;

        try {
            _ = new Extraction(image, header, metadata, maps, fixups);
        } catch (InvalidDataException error) when (error.Message.Contains(message, StringComparison.Ordinal)) {
            rejected = true;
        }

        Assert(rejected, "Selected independent source fault did not reject extraction.");
        Assert(ReferenceEquals(before, metadata.SignatureBuilder.Publish()),
            "Independent source failure mutated caller-owned signature state.");
    }

    private static void Missing(Func<object> read) {
        try {
            _ = read();
        } catch (InvalidOperationException) {
            return;
        }

        throw new InvalidDataException("An unrequested extraction capability published empty or eager results.");
    }

    private static void Reject(byte[] bytes, ExtractionStage stage, string message) {
        try {
            _ = Extract(bytes, stage);
        } catch (InvalidDataException error) when (error.Message.Contains(message, StringComparison.Ordinal)) {
            return;
        }

        throw new InvalidDataException($"Requested {stage} did not report its invalid source: {message}.");
    }

    private static void Assert(bool condition, string error) {
        if (!condition)
            throw new InvalidDataException(error);
    }
}
