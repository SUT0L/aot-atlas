using System.Security.Cryptography;
using Atlas;

internal static class ManagedTemplateChecks {
    internal static void Run(string binary) {
        var image = new PeImage(File.ReadAllBytes(binary));
        var header = ReadyToRun.Read(image);
        var section = header.Find(313);
        var metadata = new Metadata(image.FileMemory(section.Start, checked((int)section.Length)),
            header.MetadataHandleBits, header.Major < 10);
        metadata.ReadDefinitions();
        var fixups = RuntimeTables.Fixups(image, header.Find(308));
        var maps = new ReflectionMaps();
        maps.Read(image, header, metadata, fixups, MapFormat.Auto);
        var extraction = new Extraction(image, header, metadata, maps, fixups);
        var abi = new ManagedAbi(extraction);

        int index = maps.Methods.FindIndex(method => method.Name == "Generic"
            && extraction.Names.Values[extraction.Types.Index[method.DeclaringType]] == "Functions");
        Assert(index >= 0);
        var entry = maps.Methods[index];
        var template = extraction.Templates.Methods.Single(value => value.Method.Entrypoint == entry.Entrypoint);
        Assert(abi.CompatibleTemplate(extraction, index, template));

        for (int mutation = 0; mutation < 10; ++mutation) {
            var changed = template;
            var signature = metadata.Signatures.Methods[template.Method.Identity.Signature];
            switch (mutation) {
                case 0: changed.Method.Entrypoint = 0; break;
                case 1: changed.Method.Identity.Name = "Different"; break;
                case 2: changed.UniversalCanonical = true; break;
                case 3: changed.AsyncVariant = true; break;
                case 4: changed.Method.Flags ^= 2; break;
                case 5: changed.Method.DeclaringType = signature.ReturnType; break;
                case 6: changed.Method.Arguments = default; break;
                case 7: signature.CallingConvention ^= 2; break;
                case 8: signature.GenericParameterCount += 1; break;
                case 9: signature.ReturnType = metadata.Signatures.Edges[signature.Parameters.Start]; break;
            }
            changed.Method.Identity.Signature = metadata.Signatures.Methods.Count;
            metadata.Signatures.Methods.Add(signature);
            Assert(!abi.CompatibleTemplate(extraction, index, changed));
            metadata.Signatures.Methods.RemoveAt(metadata.Signatures.Methods.Count - 1);
        }

        Assert(abi.CompatibleTemplate(extraction, index, template));
        Console.WriteLine($"{Convert.ToHexStringLower(SHA256.HashData(image.FileData))}: shared generic template agrees; 10 conflicting witnesses rejected.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Generic template compatibility disagrees with the fixture identity.");
    }
}
