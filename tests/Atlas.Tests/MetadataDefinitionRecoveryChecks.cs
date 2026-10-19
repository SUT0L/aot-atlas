using Atlas;

internal static class MetadataDefinitionRecoveryChecks {
    internal static void Run(ReadOnlySpan<string> paths) {
        foreach (string path in paths) {
            byte[] original = File.ReadAllBytes(path);
            var image = new PeImage(original);
            var header = ReadyToRun.Read(image);
            var healthy = Metadata.FromImage(image, header);
            var methods = healthy.MethodDefinitions.ToArray();
            if (methods.Length < 2)
                throw new Exception("Recovery fixture requires distinct method signatures.");
            var first = methods[0];
            var last = methods.Last(method => method.SignatureOffset != first.SignatureOffset);
            var signature = new MetadataRecordId(MetadataRecordKind.MethodSignature, last.SignatureOffset);
            var arity = healthy.Facts.Field(signature, MetadataFieldName.GenericParameterCount);
            if (arity.Source.Length != 1)
                throw new Exception("Recovery fixture requires a one-byte generic arity.");
            int blobStart = image.FileRange(header.Find(RtrSectionId.EmbeddedMetadata).Start).Start;
            byte[] damaged = (byte[])original.Clone();
            damaged[blobStart + arity.Source.Offset] = 0xFE; // signed -1
            var damagedImage = new PeImage(damaged);
            var partial = Metadata.FromImage(damagedImage, ReadyToRun.Read(damagedImage));
            var publication = partial.PublishedSignatures;
            string expected = healthy.ReadMethodSignature(first.SignatureOffset).Render(first.Name);

            Check(partial.TypeDefinitions.Length == healthy.TypeDefinitions.Length
                && partial.MethodDefinitions.Length == healthy.MethodDefinitions.Length);
            Check(partial.ReadMethodDefinition(last.Offset).Name == last.Name
                && !partial.Facts.GenericArity(new(last.Offset)).IsAvailable
                && partial.ProjectionDiagnostics.Count != 0);
            for (int repeat = 0; repeat < 3; ++repeat) {
                Check(partial.ReadMethodSignature(first.SignatureOffset).Render(first.Name) == expected);
                Check(ReferenceEquals(publication, partial.PublishedSignatures));
            }
            var restoredImage = new PeImage(original);
            var restored = Metadata.FromImage(restoredImage, ReadyToRun.Read(restoredImage));
            Check(restored.ProjectionDiagnostics.Count == 0
                && restored.ReadMethodSignature(last.SignatureOffset).Render(last.Name)
                    == healthy.ReadMethodSignature(last.SignatureOffset).Render(last.Name));
            Check(healthy.Bytes[arity.Source.Offset] != partial.Bytes[arity.Source.Offset]);
            Console.WriteLine($"{Path.GetFileName(path)}: damaged arity retains method names, declarations and healthy sibling signatures; corrected input restores the full snapshot.");
        }
    }

    private static void Check(bool condition) {
        if (!condition)
            throw new Exception("Metadata definition recovery invariant failed.");
    }
}
