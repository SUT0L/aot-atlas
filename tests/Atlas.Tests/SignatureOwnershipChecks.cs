using System.Buffers.Binary;
using System.Reflection;
using Atlas;
using System.Text.Json;

internal static class SignatureOwnershipChecks {
    internal static void Run() {
        PublishedBindings();
        NativeContinuation();
        PublicationCompanions();
        ExtensionBoundary();

        foreach (int bits in new[] { 7, 8 })
            RejectedRootAcquisition(bits);

        RejectMixedParserOwners();
        ConsumerOwnershipChecks.Run();
        Console.WriteLine("Signature ownership: node/edge/method rewrites preserve published binding/display identities, independent continuation preserves IDs, failed roots restore the same publication, and rejected root acquisition recovers.");
    }

    private static void ExtensionBoundary() {
        var clone = typeof(TypeBindings).GetMethod("WithSignatures", BindingFlags.NonPublic | BindingFlags.Instance)!;

        foreach (string rewrite in new[] { "named node", "nested edge", "method" }) {
            var builder = new SignatureBuilder();
            int a = builder.AddNode(new() { Kind = SignatureKind.Named, Name = "A", MetadataScope = 1 });
            int b = builder.AddNode(new() { Kind = SignatureKind.Named, Name = "B", MetadataScope = 1 });
            int outer = builder.AddNode(new() { Kind = SignatureKind.Named, Name = "Outer" });
            int inner = builder.AddNode(new() { Kind = SignatureKind.Named, Name = "Inner" });
            builder.AddEdge(a);
            int nested = builder.AddNode(new() {
                Kind = SignatureKind.Instantiation,
                Element = inner,
                Arguments = new(0, 1)
            });
            builder.AddEdge(nested);
            int root = builder.AddNode(new() {
                Kind = SignatureKind.Instantiation,
                Element = outer,
                Arguments = new(1, 1)
            });
            int method = builder.AddMethod(new() { ReturnType = a, Parameters = new(1, 1) });

            var graph = builder.Publish();
            var bindings = new TypeBindings(new MethodTables(), new ReflectionMaps(), graph);
            Assert(graph.RenderType(root) == "Outer<Inner<A>>"
                && graph.RenderMethod("M", method) == "M(Inner<A>) -> A");
            Assert(ReferenceEquals(clone.Invoke(bindings, [graph]), bindings));

            int wrapper = builder.AddNode(new() { Kind = SignatureKind.SzArray, Element = root });
            var extended = builder.Publish();
            var accepted = (TypeBindings)clone.Invoke(bindings, [extended])!;
            Assert(ReferenceEquals(accepted.Signatures, extended)
                && extended.RenderType(wrapper) == "Outer<Inner<A>>[]");

            switch (rewrite) {
                case "named node":
                    builder.SetNode(a, graph.Nodes[b]);
                    break;

                case "nested edge":
                    builder.SetEdge(0, b);
                    break;

                case "method":
                    builder.SetMethod(method, new() { ReturnType = b, Parameters = new(1, 1) });
                    break;
            }

            var changed = builder.Publish();
            bool rejected = false;

            try {
                clone.Invoke(bindings, [changed]);
            } catch (TargetInvocationException error) when (error.InnerException is ArgumentException) {
                rejected = true;
            }

            Assert(rejected && graph.RenderType(root) == "Outer<Inner<A>>"
                && graph.RenderMethod("M", method) == "M(Inner<A>) -> A");
        }

        // Node counts can remain equal while an earlier publication lacks newly
        // published method/edge IDs; those tables are part of the same boundary.
        foreach (bool appendMethod in new[] { true, false }) {
            var builder = new SignatureBuilder();
            int a = builder.AddNode(new() { Kind = SignatureKind.Named, Name = "A" });
            var earlier = builder.Publish();

            if (appendMethod)
                builder.AddMethod(new() { ReturnType = a });
            else
                builder.AddEdge(a);

            var later = builder.Publish();
            var bindings = new TypeBindings(new MethodTables(), new ReflectionMaps(), later);
            bool rejected = false;

            try {
                clone.Invoke(bindings, [earlier]);
            } catch (TargetInvocationException error) when (error.InnerException is ArgumentException) {
                rejected = true;
            }

            Assert(rejected);
        }
    }

    internal static void Binaries(ReadOnlySpan<string> paths) {
        foreach (string path in paths) {
            var image = PeImage.ReadFile(path);
            var header = ReadyToRun.Read(image);
            var builder = MetadataBuilder.FromImage(image, header);
            builder.ReadDefinitions();
            var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
            var maps = ReflectionMaps.Decode(image, header, builder, fixups);
            var extraction = new Extraction(image, header, builder, maps, fixups);
            var metadata = extraction.Metadata;
            var graph = metadata.PublishedSignatures;
            var abi = new ManagedAbi(extraction);
            var healthy = new PropertyProjections(extraction, abi);
            var methods = metadata.MethodDefinitions.ToArray();
            var fields = metadata.FieldDefinitions.ToArray();

            foreach (var method in methods.Reverse()) {
                Assert(metadata.ReadMethodDefinition(method.Offset).Equals(method));
                _ = metadata.ReadMethodSignature(method.SignatureOffset).Render(method.Name);
            }
            foreach (var field in fields.Reverse())
                Assert(metadata.ReadFieldDefinition(field.Offset).Equals(field));

            var repeated = new PropertyProjections(extraction, abi);
            Assert(healthy.Projections.SequenceEqual(repeated.Projections));
            Assert(ReferenceEquals(graph, metadata.PublishedSignatures)
                && graph.Nodes.SequenceEqual(extraction.Signatures.Nodes)
                && metadata.MethodDefinitions.SequenceEqual(methods)
                && metadata.FieldDefinitions.SequenceEqual(fields));
            ConsumerOwnershipChecks.Binary(extraction);
            Console.WriteLine($"{Path.GetFileName(path)}: reversed metadata queries preserve the frozen graph and every property projection.");
        }

        if (paths.Length >= 2)
            SourceOrigins(paths[0], paths[1]);
    }

    private static void SourceOrigins(string firstPath, string secondPath) {
        var first = Load(firstPath);
        var second = Load(secondPath);
        bool differentIdentity = false;

        foreach (var entry in first.Maps.Types) {
            if (entry.Signature < second.Signatures.Nodes.Length
                && first.Bindings.Resolve(entry.Signature) != 0
                && first.Signatures.RenderType(entry.Signature) != second.Signatures.RenderType(entry.Signature)) {
                differentIdentity = true;
                break;
            }
        }

        Assert(differentIdentity);
        bool rejected = false;

        try {
            _ = new TypeBindings(first.Types, first.Maps, second.Signatures);
        } catch (ArgumentException) {
            rejected = true;
        }

        Assert(rejected);

        var types = first.Maps.Types.ToArray();
        var derived = first.Maps.DerivedTypes.ToArray();
        var methods = first.Maps.Methods.ToArray();
        var fields = first.Maps.Fields.ToArray();
        var arguments = first.Maps.GenericArguments.ToArray();
        var format = first.Maps.Format;
        var firstGraph = first.Signatures;
        var secondGraph = second.Signatures;
        rejected = false;

        try {
            first.Maps.Read(first.Image, first.Header, MetadataBuilder.FromImage(second.Image, second.Header), first.CommonFixups);
        } catch (ArgumentException) {
            rejected = true;
        }

        Assert(rejected && format == first.Maps.Format
            && types.SequenceEqual(first.Maps.Types)
            && derived.SequenceEqual(first.Maps.DerivedTypes)
            && methods.SequenceEqual(first.Maps.Methods)
            && fields.SequenceEqual(first.Maps.Fields)
            && arguments.SequenceEqual(first.Maps.GenericArguments)
            && ReferenceEquals(firstGraph, first.Signatures)
            && ReferenceEquals(secondGraph, second.Signatures));

        rejected = false;

        try {
            _ = new Extraction(first.Image, first.Header, MetadataBuilder.FromImage(second.Image, second.Header), first.Maps,
                first.CommonFixups, ExtractionStage.RuntimeTypes);
        } catch (ArgumentException) {
            rejected = true;
        }

        Assert(rejected && ReferenceEquals(firstGraph, first.Signatures)
            && ReferenceEquals(secondGraph, second.Signatures));

        _ = Extraction.Read(first.Image, ExtractionStage.Resources | ExtractionStage.Linkage);
        Assert(ReferenceEquals(firstGraph, first.Signatures)
            && ReferenceEquals(secondGraph, second.Signatures));

        Console.WriteLine("Real source namespaces: different declarations at the same map ID reject foreign graph binding and parser rebinding without mutation; independent resources/linkage remain available.");

        static Extraction Load(string path) {
            var image = new PeImage(File.ReadAllBytes(path));
            var header = ReadyToRun.Read(image);
            var section = header.Find(RtrSectionId.EmbeddedMetadata);
            var metadata = MetadataBuilder.FromImage(image, header);
            metadata.ReadDefinitions();

            var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
            var maps = new ReflectionMaps();
            maps.Read(image, header, metadata, fixups);

            return new Extraction(image, header, metadata, maps, fixups);
        }
    }

    private static void RejectMixedParserOwners() {
        foreach (int bits in new[] { 7, 8 }) {
            var metadata = new MetadataBuilder(new byte[64], bits);
            var builder = new SignatureBuilder();
            var graph = builder.Publish();
            var layout = new NativeLayout(new byte[64], [], builder, takeOwnership: true);
            bool rejected = false;

            try {
                layout.MethodEntry(0, metadata, MapFormat.Metadata);
            } catch (ArgumentException) {
                rejected = true;
            }

            Assert(rejected && ReferenceEquals(graph, builder.Publish())
                && metadata.SignatureBuilder.Nodes.Length == 1);
        }
    }

    private static void PublicationCompanions() {
        foreach (bool renderBeforeMutation in new[] { true, false }) {
            var builder = new SignatureBuilder();
            builder.AddNode(new() { Kind = SignatureKind.Named, Name = new string('A', 5000) });
            var earlier = builder.Publish();

            if (renderBeforeMutation)
                Assert(earlier.RenderType(1) == "sig_ref_1");

            builder.AddNode(new() { Kind = SignatureKind.Named, Name = "Later" });
            var later = builder.Publish();

            if (!renderBeforeMutation)
                Assert(earlier.RenderType(1) == "sig_ref_1");

            Assert(earlier.HasAbbreviatedReferences);
            Assert(builder.HasAbbreviatedReferences && later.HasAbbreviatedReferences);
        }

        var metadata = new MetadataBuilder(new byte[16], 7);
        var graph = metadata.SignatureBuilder.Publish();
        uint variable = (4U << 7) | 0x3F;
        Assert(metadata.TypeSignature(variable) == 1);

        var snapshot = metadata.Publish();
        using var stream = new MemoryStream();

        using (var json = new Utf8JsonWriter(stream)) {
            json.WriteStartObject();
            MetadataIdentityOutput.Write(json, snapshot);
            json.WriteEndObject();
        }

        using var result = JsonDocument.Parse(stream.ToArray());
        var serialized = result.RootElement.GetProperty("signature_graph");
        Assert(serialized.GetProperty("types").GetArrayLength() == 1
            && serialized.GetProperty("handles").EnumerateObject().Count() == 1);

        using var unused = new MemoryStream();
        using var writer = new Utf8JsonWriter(unused);
        bool rejected = false;

        try {
            MetadataIdentityOutput.Write(writer, snapshot, new SignatureBuilder().Publish());
        } catch (ArgumentException) {
            rejected = true;
        }

        Assert(rejected && unused.Length == 0);
    }

    private static void PublishedBindings() {
        var tables = new MethodTables();
        var maps = new ReflectionMaps();
        var builder = new SignatureBuilder();

        Add(new() { Address = 0x1000, Flags = 0x14U << 26, BaseSize = 24 });
        Add(new() { Address = 0x2000, Flags = 0x14U << 26, BaseSize = 24 });
        Add(new() { Address = 0x3000, Flags = (0x18U << 26) | (2U << 16), RelatedType = 0x1000 });
        Add(new() { Address = 0x4000, Flags = (0x18U << 26) | (2U << 16), RelatedType = 0x2000 });
        Add(new() { Address = 0x5000, Flags = (0x14U << 26) | (3U << 16), GenericArity = 2 });
        Add(new() {
            Address = 0x6000,
            Flags = (0x14U << 26) | 0x02000000,
            GenericDefinition = 0x5000,
            Arguments = new(0, 2)
        });
        Add(new() {
            Address = 0x7000,
            Flags = (0x14U << 26) | 0x02000000,
            GenericDefinition = 0x5000,
            Arguments = new(2, 2)
        });
        tables.Pointers.AddRange([0x1000, 0x2000, 0x2000, 0x1000]);

        builder.AddNode(new() { Kind = SignatureKind.Named, Name = "A" });
        builder.AddNode(new() { Kind = SignatureKind.Named, Name = "B" });
        builder.AddNode(new() { Kind = SignatureKind.SzArray, Element = 1 });
        builder.AddNode(new() { Kind = SignatureKind.Named, Name = "Pair" });
        builder.AddEdge(1);
        builder.AddEdge(2);
        builder.AddNode(new() { Kind = SignatureKind.Instantiation, Element = 4, Arguments = new(0, 2) });
        builder.AddEdge(5);
        builder.AddMethod(new() { ReturnType = 3, Parameters = new(2, 1) });

        foreach (var (signature, address) in new (int, ulong)[] { (1, 0x1000), (2, 0x2000), (4, 0x5000) })
            maps.Types.Add(new() { Signature = signature, MethodTable = address });

        var graph = builder.Publish();
        var bindings = new TypeBindings(tables, maps, graph);
        Assert(ReferenceEquals(graph, builder.Publish()) && ReferenceEquals(graph, bindings.Signatures));
        Assert(bindings.Resolve(3) == 3 && bindings.Resolve(5) == 6);
        Assert(graph.RenderMethod("M", 1) == "M(Pair<A,B>) -> A[]");

        builder.SetNode(3, new() { Kind = SignatureKind.SzArray, Element = 2 });
        builder.SetEdge(0, 2);
        builder.SetEdge(1, 1);
        builder.SetMethod(1, new() { ReturnType = 2 });
        int wrapper = builder.AddNode(new() { Kind = SignatureKind.Modified, Element = 3 });

        Assert(bindings.Resolve(3) == 3 && bindings.Resolve(5) == 6);
        Assert(graph.RenderType(3) == "A[]" && graph.RenderType(5) == "Pair<A,B>");
        Assert(graph.RenderMethod("M", 1) == "M(Pair<A,B>) -> A[]");
        Assert(wrapper == graph.Nodes.Length);

        bool unpublishedRejected = false;

        try {
            bindings.Resolve(wrapper);
        } catch (IndexOutOfRangeException) {
            unpublishedRejected = true;
        }

        Assert(unpublishedRejected);

        var next = builder.Publish();
        var fresh = new TypeBindings(tables, maps, next);
        Assert(!ReferenceEquals(graph, next) && fresh.Resolve(3) == 4
            && fresh.Resolve(5) == 7 && fresh.Resolve(wrapper) == 4);
        Assert(next.RenderType(3) == "B[]" && next.RenderType(5) == "Pair<B,A>"
            && next.RenderMethod("M", 1) == "M() -> B");

        long allocated;

        using (var measurement = new AllocationMeasurement()) {
            for (int i = 0; i < 1000; ++i)
                Assert(ReferenceEquals(next, builder.Publish()));

            allocated = measurement.AllocatedBytes;
        }

        Assert(allocated == 0);

        void Add(MethodTable table) {
            tables.Index.Add(table.Address, tables.Types.Count);
            tables.Types.Add(table);
        }
    }

    private static void NativeContinuation() {
        byte[] data = new byte[128];
        Put(data, 0, 6);
        new byte[] { 0x46, 0x2A, 0x08, 0x0E }.CopyTo(data, 32);

        var builder = new SignatureBuilder();
        var layout = new NativeLayout(data, [0x1234, 0x5678], builder, takeOwnership: true);
        var reader = new NativeReader(data);
        int original = layout.TypeSignature(ref reader);
        var graph = builder.Publish();
        Assert(graph.RenderType(original) == "mt_ref_1234");

        for (int i = 0; i < 1000; ++i) {
            reader.Position = 32;
            bool failed = false;

            try {
                layout.TypeSignature(ref reader);
            } catch (InvalidDataException) {
                failed = true;
            }

            Assert(failed && reader.Position == 32 && ReferenceEquals(graph, builder.Publish()));
            Assert(graph.Nodes.SequenceEqual(builder.Nodes) && graph.Edges.SequenceEqual(builder.Edges));
        }

        Put(data, 32, 0x85);
        reader.Position = 32;
        int appended = layout.TypeSignature(ref reader);
        var continued = builder.Publish();

        Assert(appended == graph.Nodes.Length && continued.RenderType(appended) == "System.Int32");
        Assert(graph.Nodes.Length == 2 && graph.RenderType(original) == "mt_ref_1234");
    }

    private static void RejectedRootAcquisition(int bits) {
        var metadata = new MetadataBuilder(new byte[64], bits);
        var builder = metadata.SignatureBuilder;
        var graph = builder.Publish();
        var begin = typeof(SignatureBuilder).GetMethod("BeginRead", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var rollback = typeof(SignatureBuilder).GetMethod("RollbackRead", BindingFlags.NonPublic | BindingFlags.Instance)!;
        object checkpoint = begin.Invoke(builder, null)!;
        uint variable = (1U << bits) | 0x3F;

        try {
            bool rejected = false;

            try {
                metadata.TypeSignature(variable);
            } catch (InvalidOperationException) {
                rejected = true;
            }

            Assert(rejected);
            rejected = false;

            try {
                builder.Publish();
            } catch (InvalidOperationException) {
                rejected = true;
            }

            Assert(rejected);
        } finally {
            rollback.Invoke(builder, [checkpoint]);
        }

        Assert(ReferenceEquals(graph, builder.Publish()));
        int valid = metadata.TypeSignature(variable);
        Assert(valid == 1 && builder.Publish().RenderType(valid) == "T");
        Assert(metadata.TypeSignature(variable) == valid && graph.Nodes.Length == 1);
    }

    private static void Put(byte[] data, int offset, uint value) {
        data[offset] = 15;
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset + 1), value);
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Published signature ownership differs from the hand-derived identities.");
    }
}
