using Atlas;
using System.Buffers.Binary;

internal static class TraceStageChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        foreach (string binary in binaries) {
            byte[] original = File.ReadAllBytes(binary);
            var full = Extract(original, ExtractionStage.All);
            var types = Extract(original, ExtractionStage.RuntimeTypes);
            var fields = Extract(original, ExtractionStage.MemberLayouts);

            EqualTypes(full, types);
            EqualTypes(full, fields);
            Assert(full.Fields.Fields.SequenceEqual(fields.Fields.Fields));
            Assert(full.Fields.FieldTypes.SequenceEqual(fields.Fields.FieldTypes));
            Assert(full.Shared.Templates.SequenceEqual(fields.Shared.Templates));
            Missing(types);
            Missing(fields);

            var tracing = Extract(original, ExtractionStage.MethodTracing);
            Assert(tracing.Stages == (ExtractionStage.RuntimeTypes | ExtractionStage.MethodTracing));
            Assert(tracing.Traces.Methods.SequenceEqual(full.Traces.Methods));
            Assert(tracing.Traces.ParameterNames.SequenceEqual(full.Traces.ParameterNames));
            Assert(tracing.Traces.Lines.SequenceEqual(full.Traces.Lines));
            Assert(tracing.Traces.Documents.SequenceEqual(full.Traces.Documents));
            Assert(tracing.Traces.Points.SequenceEqual(full.Traces.Points));

            byte[] absent = (byte[])original.Clone();

            for (int i = 0; i < full.Header.Sections.Length; ++i) {
                var row = full.Header.Sections[i];

                if (row.Id is not ((int)RtrSectionId.StackTraceMethodMapping
                    or (int)RtrSectionId.StackTraceLineMapping or (int)RtrSectionId.StackTraceDocuments))
                    continue;

                var bytes = absent.AsSpan(
                    full.Header.FileOffset + 16 + i * full.Header.EntrySize, full.Header.EntrySize);

                if (full.Header.EntrySize == 16)
                    BinaryPrimitives.WriteUInt32LittleEndian(bytes[4..], 0);
                else
                    BinaryPrimitives.WriteUInt64LittleEndian(bytes[16..], row.Start);
            }

            var noTracingSources = Extract(absent, ExtractionStage.All);
            EqualTypes(full, noTracingSources);
            Assert(noTracingSources.Traces.Methods.Count == 0
                && noTracingSources.Traces.Lines.Count == 0 && noTracingSources.Traces.Documents.Count == 0);

            var section = full.Header.Find(RtrSectionId.StackTraceMethodMapping);

            if (full.Traces.Methods.Count == 0) {
                Console.WriteLine($"{Path.GetFileName(binary)}: {(section.Length == 0 ? "absent" : "present-empty")} traces available when requested; independent stage outputs equal.");
                continue;
            }

            Assert(section.Length > 4);
            int start = full.Image.FileRange(section.Start).Start;
            byte[] damaged = (byte[])original.Clone();
            damaged.AsSpan(start + checked((int)section.Length) - 4, 4).Clear();

            var damagedTypes = Extract(damaged, ExtractionStage.RuntimeTypes);
            var damagedFields = Extract(damaged, ExtractionStage.MemberLayouts);
            EqualTypes(types, damagedTypes);
            EqualTypes(fields, damagedFields);
            Assert(fields.Fields.Fields.SequenceEqual(damagedFields.Fields.Fields));
            Assert(fields.Fields.FieldTypes.SequenceEqual(damagedFields.Fields.FieldTypes));
            Assert(fields.Shared.Templates.SequenceEqual(damagedFields.Shared.Templates));
            EqualMetadata(types.Metadata, damagedTypes.Metadata);
            EqualMetadata(fields.Metadata, damagedFields.Metadata);

            AssertRejected(damaged, ExtractionStage.MethodTracing);
            AssertRejected(damaged, ExtractionStage.All);

            var restored = Extract(original, ExtractionStage.All);
            Assert(restored.Traces.Methods.SequenceEqual(full.Traces.Methods));
            EqualTypes(full, restored);
            EqualMetadata(full.Metadata, restored.Metadata);

            Console.WriteLine($"{Path.GetFileName(binary)}: {full.Traces.Methods.Count} trace records; types and fields preserve facts and parser state through late trace corruption; requested tracing rejects it; restored full extraction equals original.");
        }
    }

    private static Extraction Extract(byte[] bytes, ExtractionStage stages) {
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

        return new Extraction(image, header, metadata, maps, fixups, stages);
    }

    private static void EqualTypes(Extraction left, Extraction right) {
        Assert(left.Types.Types.SequenceEqual(right.Types.Types));
        Assert(left.Types.Pointers.SequenceEqual(right.Types.Pointers));
        Assert(left.Names.Values.SequenceEqual(right.Names.Values));
        Assert(left.Names.Complete.SequenceEqual(right.Names.Complete));
        Assert(left.Gc.Layouts.SequenceEqual(right.Gc.Layouts));
        Assert(left.Gc.Runs.SequenceEqual(right.Gc.Runs));
        Assert(left.Frozen.Objects.SequenceEqual(right.Frozen.Objects));
        Assert(left.Frozen.RuntimeTypes.SequenceEqual(right.Frozen.RuntimeTypes));
    }

    private static void EqualMetadata(Metadata left, Metadata right) {
        Assert(left.SignatureBuilder.Nodes.SequenceEqual(right.SignatureBuilder.Nodes));
        Assert(left.SignatureBuilder.Methods.SequenceEqual(right.SignatureBuilder.Methods));
        Assert(left.SignatureBuilder.Edges.SequenceEqual(right.SignatureBuilder.Edges));
        Assert(left.TypeSignatureHandles.SequenceEqual(right.TypeSignatureHandles));

        var leftScopes = left.ReferencedScopes.ToArray();
        var rightScopes = right.ReferencedScopes.ToArray();
        Assert(leftScopes.Length == rightScopes.Length);

        for (int i = 0; i < leftScopes.Length; ++i) {
            Assert(leftScopes[i].PublicKeyOrToken.Span.SequenceEqual(rightScopes[i].PublicKeyOrToken.Span));
            Assert(leftScopes[i] with { PublicKeyOrToken = default }
                == rightScopes[i] with { PublicKeyOrToken = default });
        }
    }

    private static void Missing(Extraction extraction) {
        bool rejected = false;

        try {
            _ = extraction.Traces;
        } catch (InvalidOperationException) {
            rejected = true;
        }

        Assert(rejected);
    }

    private static void AssertRejected(byte[] bytes, ExtractionStage stage) {
        bool rejected = false;

        try {
            _ = Extract(bytes, stage);
        } catch (InvalidDataException error) when (error.Message.Contains("Stack-trace entrypoint", StringComparison.Ordinal)) {
            rejected = true;
        }

        Assert(rejected);
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Trace stage assertion failed.");
    }
}
