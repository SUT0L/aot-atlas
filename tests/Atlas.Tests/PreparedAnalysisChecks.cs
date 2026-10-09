using System.Buffers.Binary;
using Atlas;
using Atlas.Binja;

internal static class PreparedAnalysisChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        foreach (string binary in binaries) {
            byte[] original = File.ReadAllBytes(binary);
            var healthy = Prepare(original);
            var image = healthy.Extraction.Image;
            var evidence = AnalysisEvidence.Read(healthy, image.ImageBase);

            Assert(healthy.ManagedAbi is not null && healthy.GcInfo is not null,
                "Fixture must retain healthy managed analysis.");
            Assert(healthy.Strings.Items.Count != 0, "Fixture must retain independent native strings.");
            Assert(healthy.Extraction.Frozen.RuntimeTypes.Count != 0,
                "Fixture must retain reciprocal frozen runtime type bindings.");
            CheckPointers(healthy, evidence, image.ImageBase);
            CheckRuntimeTypes(healthy, evidence, image.ImageBase);
            Assert(evidence.Tags.Any(tag => tag.Kind == AnalysisEvidenceKind.GcInfo),
                "Healthy managed preparation omitted GC annotations.");
            Assert(evidence.Tags.All(tag => !tag.Text.Contains('\0')),
                "Native host annotation contains an unrepresentable NUL.");

            const ulong relocatedBase = 0x280000000;
            var relocated = AnalysisEvidence.Read(healthy, relocatedBase);
            ulong delta = relocatedBase - image.ImageBase;
            Assert(relocated.Tags.Select(tag => (tag.Kind, tag.Address)).ToHashSet()
                .SetEquals(evidence.Tags.Select(tag => (tag.Kind, tag.Address + delta))),
                "Rebasing changed annotation identity or omitted a tag.");
            Assert(relocated.References.ToHashSet().SetEquals(evidence.References.Select(reference =>
                new AnalysisReference(reference.From + delta, reference.To + delta))),
                "Rebased reference endpoints do not retain their image RVAs.");
            CheckPointers(healthy, relocated, relocatedBase);
            CheckRuntimeTypes(healthy, relocated, relocatedBase);

            PreparedAnalysis.ValidateSignatures(healthy.Extraction.Metadata, healthy.Extraction.Signatures);
            Reject(() => PreparedAnalysis.ValidateSignatures(
                healthy.Extraction.Metadata, new SignatureBuilder().Publish()));
            Reject(() => AnalysisEvidence.Read(healthy, ulong.MaxValue));

            int row = image.FileRange(image.ImageBase + image.ExceptionRva).Start;
            uint unwindRva = BinaryPrimitives.ReadUInt32LittleEndian(original.AsSpan(row + 8));
            Assert((unwindRva & 1) == 0, "Fixture must have a direct first unwind header.");
            byte[] damaged = (byte[])original.Clone();
            int unwindHeader = image.FileRange(image.ImageBase + unwindRva).Start;
            damaged[unwindHeader] = (byte)((damaged[unwindHeader] & ~7) | 7);

            var partial = Prepare(damaged);
            var partialEvidence = AnalysisEvidence.Read(partial, image.ImageBase);
            Assert(partial.ManagedAbi is null && partial.Properties is null && partial.Code is null
                && partial.GcInfo is null && partial.GenericContexts is null,
                "An unavailable unwind source published dependent managed work.");
            Assert(partial.Strings.Items.SequenceEqual(healthy.Strings.Items),
                "An unwind failure disabled independent native string discovery.");
            Assert(partial.FunctionPointers.Values.Count != 0
                && partial.FunctionPointers.References.All(reference =>
                    reference.Source == FatPointerSource.ClassConstructor),
                "Independent constructor descriptors were lost or dependent pointer facts survived.");
            Assert(partialEvidence.Tags.Any(tag => tag.Kind == AnalysisEvidenceKind.Status
                && tag.Text.Contains("unwind=unavailable", StringComparison.Ordinal)),
                "Host preparation omitted the optional-source failure status.");
            Assert(partialEvidence.Tags.All(tag => tag.Kind != AnalysisEvidenceKind.GcInfo),
                "Failed GC prerequisites produced host annotations.");
            CheckPointers(partial, partialEvidence, image.ImageBase);
            CheckRuntimeTypes(partial, partialEvidence, image.ImageBase);

            var restored = Prepare(original);
            var restoredEvidence = AnalysisEvidence.Read(restored, image.ImageBase);
            Assert(restoredEvidence.Tags.SequenceEqual(evidence.Tags),
                "Restored preparation did not reproduce healthy annotations.");
            Assert(restoredEvidence.References.ToHashSet().SetEquals(evidence.References),
                "Restored preparation did not reproduce healthy reference endpoints.");

            Console.WriteLine($"Managed host preparation: {binary}; unwind isolation, native strings/constructors, GC/type evidence, graph namespaces and normal/rebased references passed without Binary Ninja.");
        }
    }

    private static void CheckPointers(PreparedAnalysis prepared, AnalysisEvidence evidence, ulong imageBase) {
        var image = prepared.Extraction.Image;
        var references = evidence.References.ToHashSet();

        foreach (var pointer in prepared.FunctionPointers.Values) {
            ulong descriptor = imageBase + (pointer.Descriptor - image.ImageBase);
            var tag = evidence.Tags.Single(tag =>
                tag.Kind == AnalysisEvidenceKind.FunctionPointer && tag.Address == descriptor);

            ulong body = BinaryPrimitives.ReadUInt64LittleEndian(
                prepared.Extraction.Memory.Read(pointer.Descriptor, 8));
            ulong context = BinaryPrimitives.ReadUInt64LittleEndian(
                prepared.Extraction.Memory.Read(pointer.Descriptor + 8, 8));
            ulong rebasedBody = imageBase + (body - image.ImageBase);
            ulong rebasedContext = imageBase + (context - image.ImageBase);

            Assert(tag.Text.Contains($"body=0x{rebasedBody:X}::context=0x{rebasedContext:X}", StringComparison.Ordinal),
                "Pointer annotation disagrees with the independently stored descriptor pair.");
            Assert(references.Contains(new AnalysisReference(descriptor, rebasedBody))
                && references.Contains(new AnalysisReference(descriptor + 8, rebasedContext)),
                "Descriptor body/context references are absent or point to tagged addresses.");
        }
    }

    private static void CheckRuntimeTypes(PreparedAnalysis prepared, AnalysisEvidence evidence, ulong imageBase) {
        var extraction = prepared.Extraction;
        var references = evidence.References.ToHashSet();

        foreach (var association in extraction.Frozen.RuntimeTypes) {
            var instance = extraction.Frozen.Objects[association.ObjectIndex];
            var type = extraction.Types.Types[association.TypeIndex];
            ulong address = imageBase + (extraction.Frozen.Start - extraction.Image.ImageBase)
                + (uint)instance.Offset;
            ulong typeField = imageBase + (extraction.Frozen.Start - extraction.Image.ImageBase)
                + (uint)instance.Data.Start;
            ulong typeAddress = imageBase + (type.Address - extraction.Image.ImageBase);
            ulong cache = imageBase + (type.WritableData - extraction.Image.ImageBase);

            Assert(evidence.Tags.Any(tag => tag.Kind == AnalysisEvidenceKind.RuntimeType
                && tag.Address == address && tag.Text.Contains("reciprocal_eetype_cache", StringComparison.Ordinal)),
                "Frozen runtime type annotation lost its reciprocal-cache provenance.");
            Assert(references.Contains(new AnalysisReference(typeField, typeAddress))
                && references.Contains(new AnalysisReference(cache, address)),
                "Frozen payload/type/cache references do not describe the reciprocal binding.");
        }
    }

    private static PreparedAnalysis Prepare(byte[] bytes) {
        var image = new PeImage(bytes);
        var header = ReadyToRun.Read(image);
        var section = header.Find(RtrSectionId.EmbeddedMetadata);
        var metadata = new Metadata(image.FileMemory(section.Start, checked((int)section.Length)),
            header.MetadataHandleBits, header.Format.LegacyMetadataConstants);
        metadata.ReadDefinitions();

        var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        var maps = new ReflectionMaps();
        maps.Read(image, header, metadata, fixups);

        return new PreparedAnalysis(image, header, metadata, maps, fixups);
    }

    private static void Reject(Action action) {
        try {
            action();
        } catch (Exception error) when (error is ArgumentException or InvalidDataException) {
            return;
        }

        throw new Exception("Invalid host preparation boundary was accepted.");
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
