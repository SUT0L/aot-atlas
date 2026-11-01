using System.Buffers.Binary;
using System.Text;
using Atlas;

internal static class SignatureParserStateChecks {
    internal static void Run() {
        foreach (int bits in new[] { 7, 8 }) {
            var source = new Fixture(bits, 4096);
            uint seed = source.Handle(1, 0x3D);
            uint variable = source.Handle(70, 0x3F);
            uint bad = source.Handle(2, 0x7F);

            source.Record(3000, variable);
            source.Record(3032, source.Handle(100, 0x25));
            source.Record(3064, source.Handle(110, 0x25));
            source.Record(3096, source.Handle(380, 0x25));
            source.Record(1, 0, 900);
            source.Text(900, "Seed");
            source.Record(10, 0, 0, seed, 0, 0);
            source.Record(30, seed, 2, source.Handle(3000, 0x3E), bad); // reserve arguments, parse a valid child, then fail
            source.Record(50, seed);
            source.Record(70, 0);

            source.Record(80, source.Handle(80, 0x37));
            source.Record(90, 0, 0, source.Handle(3032, 0x3E), 0, 0);
            source.Record(100, 90);
            source.Record(110, 120);
            source.Record(120, 0, 0, source.Handle(3064, 0x3E), 0, 0);

            source.Record(200, 0, 0, 210, 900, 0, 0, 0);
            source.Record(210, 0, 900);
            source.Record(250, 0, 0, source.Handle(3000, 0x3E), 1, seed, 1, bad);
            source.Record(280, seed, 2, seed, source.Handle(3000, 0x3E));

            source.Record(300, source.Handle(310, 0x30), 900);
            source.Record(310, source.Handle(320, 0x39), 0);
            source.Record(320, 0, 900, 1, 2, 3, 4, 0, 0);
            source.Record(330, source.Handle(320, 0x38), 900); // invalid reference parent kind
            source.Record(340, seed, 2, source.Handle(300, 0x3D), bad);
            source.Record(360, variable);
            source.Record(370, seed, 2, source.Handle(360, 0x3E), bad);
            source.Record(380, 390);
            source.Record(390, 0, 0, seed, 0, 0);
            source.Record(410, seed, 2, source.Handle(3096, 0x3E), bad);
            source.Record(430, source.Handle(3000, 0x3E), 33, 0, 0);
            source.Record(440, seed, uint.MaxValue);

            var metadata = new MetadataBuilder(source.Bytes, bits, legacyConstants: false, takeOwnership: true);
            int seedId = metadata.TypeSignature(seed);
            int methodId = metadata.MethodSignature(10);
            int aliasId = metadata.TypeSignature(source.Handle(50, 0x3E));
            Assert(seedId == 1 && methodId == 1 && aliasId == seedId);
            Assert(metadata.SignatureBuilder.RenderType(seedId) == "Seed");

            // The shared graph can already contain another parser's published nodes.
            byte[] nativeSource = [0xAA];
            var native = new NativeLayout(nativeSource, [], metadata.SignatureBuilder, takeOwnership: true);
            var nativeReader = new NativeReader(nativeSource);
            int nativeId = native.TypeSignature(ref nativeReader);
            Assert(metadata.SignatureBuilder.RenderType(nativeId) == "System.Byte");

            var prior = Snapshot.Read(metadata);

            for (int repeat = 0; repeat < 2; ++repeat) {
                Reject(() => metadata.TypeSignature(source.Handle(30, 0x3C)));
                Reject(() => metadata.MethodSignature(250));
                prior.AssertUnchanged(metadata);

                nativeReader.Position = 0;
                Assert(native.TypeSignature(ref nativeReader) == nativeId && nativeReader.Position == 1);
            }

            foreach (var operation in new Action[] {
                () => metadata.TypeSignature(source.Handle(80, 0x37)),
                () => metadata.MethodSignature(90),
                () => metadata.TypeSignature(source.Handle(110, 0x25)),
                () => metadata.TypeSignature(source.Handle(200, 0x3A)),
                () => metadata.DefinitionName(200),
                () => metadata.TypeSignature(source.Handle(330, 0x3D)),
                () => metadata.TypeSignature(source.Handle(340, 0x3C)),
                () => metadata.TypeSignature(source.Handle(370, 0x3C)),
                () => metadata.TypeSignature(source.Handle(410, 0x3C)),
                () => metadata.TypeSignature(source.Handle(430, 0x01)),
                () => metadata.TypeSignature(source.Handle(440, 0x3C)),
            }) {
                Reject(operation);
                Reject(operation);
                prior.AssertUnchanged(metadata);
            }

            int scoped = metadata.TypeSignature(source.Handle(300, 0x3D));
            Assert(scoped == prior.Nodes.Length
                && metadata.SignatureBuilder.Nodes[scoped].MetadataScope == source.Handle(320, 0x39));
            var scope = metadata.ReferencedScopes.Single();
            Assert(scope.Name == "Seed" && scope.Major == 1 && scope.Revision == 4);

            int good = metadata.TypeSignature(source.Handle(280, 0x3C));
            Assert(metadata.SignatureBuilder.RenderType(good) == "Seed<Seed,T>");
            Assert(metadata.TypeSignature(seed) == seedId && metadata.MethodSignature(10) == methodId);
            Assert(metadata.TypeSignature(source.Handle(50, 0x3E)) == aliasId);
            Assert(metadata.MethodSignature(390) == prior.Methods.Length);

            var corrected = (byte[])source.Bytes.Clone();
            source.Write(corrected, 30, seed, 2, source.Handle(3000, 0x3E), seed);
            var replacement = new MetadataBuilder(corrected, bits);
            Assert(replacement.TypeSignature(seed) == seedId && replacement.MethodSignature(10) == methodId);
            Assert(replacement.SignatureBuilder.RenderType(replacement.TypeSignature(source.Handle(30, 0x3C)))
                == "Seed<T,Seed>");

            Depth(bits);
        }

        Console.WriteLine("Signature parser state: repeated late failures, type/method cycles, name replay, aliases, retained scopes, stable prior IDs and healthy progress passed.");
    }

    internal static void Binaries(ReadOnlySpan<string> binaries) {
        foreach (string binary in binaries) {
            var original = Open(File.ReadAllBytes(binary));
            var traces = new TraceMaps(original.Image, original.Header, original.Metadata, original.Fixups);
            var declared = original.Metadata.Methods.Select(method => method.SignatureOffset).ToHashSet();
            var traceOnly = traces.Methods.First(method => method.SignatureOffset != 0
                && !declared.Contains(method.SignatureOffset));

            var reader = original.Metadata.Reader(traceOnly.SignatureOffset);
            reader.Unsigned();
            int arity = reader.Position;
            reader.Signed();
            Assert(reader.Position == arity + 1);

            byte[] changed = (byte[])original.Image.FileData.Clone();
            int start = original.Image.FileRange(original.Header.Find(RtrSectionId.EmbeddedMetadata).Start).Start;
            changed[start + arity] = 0xFE; // native-format signed -1
            var damaged = Open(changed);
            var prior = Snapshot.Read(damaged.Metadata);
            var arityFact = damaged.Metadata.RecordField(
                new(MetadataRecordKind.MethodSignature, traceOnly.SignatureOffset),
                MetadataFieldName.GenericParameterCount).Int32;
            Assert(arityFact.Value == -1 && !arityFact.IsAvailable
                && (arityFact.Status & MetadataFactStatus.InvalidNumeric) != 0
                && arityFact.Source == new MetadataSourceRange(arity, 1));

            for (int repeat = 0; repeat < 2; ++repeat) {
                Reject(() => damaged.Metadata.MethodSignature(traceOnly.SignatureOffset));
                prior.AssertUnchanged(damaged.Metadata);
            }

            var partial = new TraceMaps(damaged.Image, damaged.Header, damaged.Metadata, damaged.Fixups);
            Assert(partial.Methods.Count == traces.Methods.Count);
            int unavailable = 0;
            int healthy = 0;

            for (int i = 0; i < partial.Methods.Count; ++i) {
                var before = traces.Methods[i];
                var after = partial.Methods[i];
                Assert(after.Entrypoint == before.Entrypoint && after.Name == before.Name
                    && after.SignatureOffset == before.SignatureOffset);
                if (after.SignatureOffset == traceOnly.SignatureOffset) {
                    Assert(after.Signature == 0
                        && (after.SignatureStatus & MetadataFactStatus.Unresolved) != 0);
                    ++unavailable;
                } else if (before.Signature != 0) {
                    Assert(after.Signature != 0 && after.SignatureStatus == before.SignatureStatus
                        && damaged.Metadata.SignatureBuilder.RenderMethod(after.Name, after.Signature)
                            == original.Metadata.SignatureBuilder.RenderMethod(before.Name, before.Signature));
                    ++healthy;
                }
            }
            Assert(unavailable != 0 && healthy != 0);

            var completed = Snapshot.Read(damaged.Metadata);
            var replayed = new TraceMaps(damaged.Image, damaged.Header, damaged.Metadata, damaged.Fixups);
            Assert(replayed.MethodEntries.SequenceEqual(partial.MethodEntries));
            completed.AssertUnchanged(damaged.Metadata);

            foreach (var priorHandle in prior.Handles)
                Assert(damaged.Metadata.TypeSignature(priorHandle.Key) == priorHandle.Value);

            var restored = Open(original.Image.FileData);
            Assert(new TraceMaps(restored.Image, restored.Header, restored.Metadata, restored.Fixups)
                .Methods.Count == traces.Methods.Count);

            Console.WriteLine($"{Path.GetFileName(binary)}: invalid trace arity preserves healthy signatures, prior IDs and repeated parsing; corrected source parses.");
        }
    }

    private static void Depth(int bits) {
        var source = new Fixture(bits, 8192);
        for (int i = 0; i < 258; ++i) {
            source.Record(16 + i * 16, source.Handle((uint)(24 + i * 16), 0x32));
            source.Record(24 + i * 16, source.Handle((uint)(32 + i * 16), 0x3E));
        }

        var metadata = new MetadataBuilder(source.Bytes, bits, legacyConstants: false, takeOwnership: true);
        var prior = Snapshot.Read(metadata);
        Reject(() => metadata.TypeSignature(source.Handle(16, 0x3E)));
        Reject(() => metadata.TypeSignature(source.Handle(16, 0x3E)));
        prior.AssertUnchanged(metadata);

        // 128 specification/pointer pairs reach a named leaf at the allowed depth of 256.
        var bounded = new Fixture(bits, 8192);
        for (int i = 0; i < 128; ++i) {
            bounded.Record(16 + i * 16, bounded.Handle((uint)(24 + i * 16), 0x32));
            uint element = i == 127 ? bounded.Handle(4096, 0x3D)
                : bounded.Handle((uint)(32 + i * 16), 0x3E);
            bounded.Record(24 + i * 16, element);
        }
        bounded.Record(4096, 0, 4200);
        bounded.Text(4200, "Leaf");

        var accepted = new MetadataBuilder(bounded.Bytes, bits, legacyConstants: false, takeOwnership: true);
        int signature = accepted.TypeSignature(bounded.Handle(16, 0x3E));
        var nodes = accepted.SignatureBuilder.Nodes;
        for (int i = 0; i < 128; ++i) {
            Assert(nodes[signature].Kind == SignatureKind.Pointer);
            signature = nodes[signature].Element;
        }
        Assert(nodes[signature].Kind == SignatureKind.ParameterName && nodes[signature].Name == "Leaf");
    }

    private static (PeImage Image, ReadyToRun Header, MetadataBuilder Metadata, ulong[] Fixups) Open(byte[] bytes) {
        var image = new PeImage(bytes);
        var header = ReadyToRun.Read(image);
        var section = header.Find(RtrSectionId.EmbeddedMetadata);
        var metadata = MetadataBuilder.FromImage(image, header);
        metadata.ReadDefinitions();

        return (image, header, metadata, RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable)));
    }

    private static void Reject(Action operation) {
        try {
            operation();
        } catch (Exception error) when (error is InvalidDataException or NotSupportedException or OverflowException) {
            return;
        }

        throw new Exception("Malformed signature fixture was accepted.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Signature parser state assertion failed.");
    }

    private sealed record Snapshot(
        SignatureNode[] Nodes, MethodSignature[] Methods, int[] Edges, KeyValuePair<uint, int>[] Handles
    ) {
        internal static Snapshot Read(MetadataBuilder metadata)
            => new(metadata.SignatureBuilder.Nodes.ToArray(), metadata.SignatureBuilder.Methods.ToArray(),
                metadata.SignatureBuilder.Edges.ToArray(),
                metadata.TypeSignatureHandles.OrderBy(pair => pair.Key).ToArray());

        internal void AssertUnchanged(MetadataBuilder metadata) {
            Assert(metadata.SignatureBuilder.Nodes.SequenceEqual(Nodes)
                && metadata.SignatureBuilder.Methods.SequenceEqual(Methods)
                && metadata.SignatureBuilder.Edges.SequenceEqual(Edges)
                && metadata.TypeSignatureHandles.OrderBy(pair => pair.Key).SequenceEqual(Handles));
        }
    }

    private sealed class Fixture(int bits, int size = 1024) {
        internal readonly byte[] Bytes = new byte[size];

        internal uint Handle(uint offset, uint kind) => (offset << bits) | kind;

        internal void Record(int offset, params uint[] values) => Write(Bytes, offset, values);

        internal void Write(byte[] data, int offset, params uint[] values) {
            foreach (uint value in values)
                offset = Number(data, offset, value);
        }

        internal void Text(int offset, string value) {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            offset = Number(Bytes, offset, (uint)bytes.Length);
            bytes.CopyTo(Bytes, offset);
        }

        private static int Number(byte[] data, int offset, uint value)
            => NativeFixture.Unsigned(data, offset, value);
    }
}
