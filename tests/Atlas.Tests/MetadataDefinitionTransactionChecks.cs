using Atlas;

internal static class MetadataDefinitionTransactionChecks {
    internal static void Run(ReadOnlySpan<string> paths) {
        foreach (string path in paths) {
            var image = PeImage.ReadFile(path);
            var header = ReadyToRun.Read(image);
            var section = header.Find(RtrSectionId.EmbeddedMetadata);
            byte[] bytes = image.FileSpan(section.Start, checked((int)section.Length)).ToArray();
            var decoded = new Metadata(bytes, header.MetadataHandleBits, header.Format.LegacyMetadataConstants);
            decoded.ReadDefinitions();

            if (decoded.Methods.Count == 0)
                throw new Exception("The late-failure fixture has no method signatures.");

            MetadataMethod first = decoded.Methods[0];
            MetadataMethod last = decoded.Methods[^1];
            int changed = ArityOffset(decoded, last.SignatureOffset);
            int priorValue = ArityOffset(decoded, first.SignatureOffset);

            if (priorValue == changed)
                throw new Exception("The fixture needs distinct prior and damaged records.");

            uint priorHandle = ((uint)priorValue << header.MetadataHandleBits) | 0x3F;
            var expected = new Metadata(bytes, header.MetadataHandleBits, header.Format.LegacyMetadataConstants);
            expected.ReadMethod(first.Offset);
            expected.TypeSignature(priorHandle);
            expected.ReadDefinitions();

            byte saved = bytes[changed];
            bytes[changed] = 0xFE; // NativeFormat signed -1: invalid generic arity.

            // This deliberately borrowed fixture models a source that can be
            // repaired. Public constructors copy their caller's bytes.
            var subject = new Metadata(bytes, header.MetadataHandleBits,
                header.Format.LegacyMetadataConstants, takeOwnership: true);
            subject.ReadMethod(first.Offset);
            int priorSignature = subject.TypeSignature(priorHandle);
            MetadataMethod priorMethod = subject.Methods[0];
            uint[] priorHandles = subject.Handles.ToArray();
            var priorGraph = subject.PublishedSignatures;

            for (int replay = 0; replay < 3; ++replay) {
                bool rejected = false;

                try {
                    subject.ReadDefinitions();
                } catch (InvalidDataException error) when (error.Message.Contains("generic parameter count", StringComparison.Ordinal)) {
                    rejected = true;
                }

                Check(rejected && ReferenceEquals(priorGraph, subject.PublishedSignatures));
                Check(subject.Scopes.Count == 0 && subject.Types.Count == 0 && subject.Fields.Count == 0);
                Check(subject.Methods.Count == 1 && subject.Methods[0].Equals(priorMethod));
                Check(subject.Handles.SequenceEqual(priorHandles) && subject.MethodIndex.Count == 1);
                Check(subject.TypeSignature(priorHandle) == priorSignature);
            }

            bytes[changed] = saved;
            subject.ReadDefinitions();

            Check(subject.Types.SequenceEqual(expected.Types));
            Check(subject.Methods.SequenceEqual(expected.Methods));
            Check(subject.Fields.SequenceEqual(expected.Fields));
            Check(subject.Handles.SequenceEqual(expected.Handles));
            Check(subject.SignatureBuilder.Nodes.SequenceEqual(expected.SignatureBuilder.Nodes));
            Check(subject.SignatureBuilder.Edges.SequenceEqual(expected.SignatureBuilder.Edges));
            Check(subject.SignatureBuilder.Methods.SequenceEqual(expected.SignatureBuilder.Methods));

            Console.WriteLine($"{Path.GetFileName(path)}: late definition failure preserves prior records/publication; repair retries with identical metadata and signature IDs.");
        }
    }

    private static int ArityOffset(Metadata metadata, uint signature) {
        var reader = metadata.Reader(signature);
        reader.Unsigned();
        int offset = reader.Position;
        reader.Signed();

        if (reader.Position != offset + 1)
            throw new Exception("The fixture requires a one-byte generic arity.");

        return offset;
    }

    private static void Check(bool condition) {
        if (!condition)
            throw new Exception("Metadata definition transaction invariant failed.");
    }
}
