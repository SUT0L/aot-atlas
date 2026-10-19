using System.Buffers.Binary;
using Atlas;

internal static class ConsumerOwnershipChecks {
    internal static void Run() {
        byte[] data = new byte[40];
        "RTR\0"u8.CopyTo(data);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), 16);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12), 1);
        data[14] = 24;
        data[15] = 1;
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(16), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(24), 0x140001000);

        var image = PeFixture.Create(data, ".rdata", 0x40000040);
        var header = ReadyToRun.Read(image);
        var unrelated = Build("Not.Delegate");
        Assert(ManagedFunctionPointerConsumers.Read(unrelated.Metadata, unrelated.Traces, unrelated.Graph).Length == 0,
            "A same-name method on an unrelated type became a delegate initializer.");

        var foreign = new SignatureBuilder();
        Populate(foreign, "System.Delegate");
        Reject(() => ManagedFunctionPointerConsumers.Read(unrelated.Metadata, unrelated.Traces, foreign.Publish()));

        var valid = Build("System.Delegate");
        Assert(ManagedFunctionPointerConsumers.Read(valid.Metadata, valid.Traces, valid.Graph)
            .SequenceEqual(new[] { new FunctionPointerConsumer(0x1234, 8) }),
            "An independently specified CoreLib delegate initializer was lost.");
        Reject(() => ManagedFunctionPointerConsumers.Read(valid.Metadata, unrelated.Traces, valid.Graph));

        var incomplete = Build("System.Delegate", priorGraph: true);
        Reject(() => ManagedFunctionPointerConsumers.Read(incomplete.Metadata, incomplete.Traces, incomplete.Graph));

        (Metadata Metadata, TraceMaps Traces, Signatures Graph) Build(string declaring, bool priorGraph = false) {
            var builder = new MetadataBuilder(default, 7);
            builder.Scopes.Add(new MetadataScope {
                Offset = 1,
                Name = "System.Private.CoreLib",
                Culture = ""
            });
            var prior = builder.PublishedSignatures;
            Populate(builder.SignatureBuilder, declaring);
            var traces = new TraceMaps(image, header, builder, []);
            traces.Methods.Add(new TraceMethod {
                DeclaringType = 1,
                Signature = 1,
                Name = "InitializeClosedInstanceWithoutNullCheck",
                Entrypoint = 0x1234
            });
            var snapshot = builder.Publish();
            return (snapshot, traces, priorGraph ? prior : snapshot.PublishedSignatures);
        }

        Console.WriteLine("Consumer ownership: foreign metadata graphs, crossed trace origins and missing prior roots reject; exact delegate initializer remains available.");
    }

    internal static void Binary(Extraction extraction) {
        var metadata = extraction.Metadata;
        var expected = ManagedFunctionPointerConsumers.Read(metadata, extraction.Traces, extraction.Signatures);
        var foreign = MetadataBuilder.FromImage(extraction.Image, extraction.Header);
        foreign.ReadDefinitions();
        var foreignTraces = new TraceMaps(extraction.Image, extraction.Header, foreign, extraction.CommonFixups);

        Reject(() => ManagedFunctionPointerConsumers.Read(metadata, foreignTraces, extraction.Signatures));
        Reject(() => ManagedFunctionPointerConsumers.Read(
            foreign.Publish(), extraction.Traces, foreign.SignatureBuilder.Publish()));
        Assert(ManagedFunctionPointerConsumers.Read(metadata, extraction.Traces, extraction.Signatures)
            .SequenceEqual(expected), "Rejected trace origins altered prior consumers.");

        var owner = extraction.Maps.Types.First(entry => extraction.Bindings.Resolve(entry.Signature) != 0);
        int ownerIndex = extraction.Types.Index[owner.MethodTable] + 1;
        var extension = SignatureBuilder.FromSnapshot(metadata.PublishedSignatures);
        int element = extension.AddNode(new SignatureNode {
            Kind = SignatureKind.Modified,
            Element = owner.Signature
        });
        int pointer = extension.AddNode(new SignatureNode {
            Kind = SignatureKind.Pointer,
            Element = element
        });
        var graph = extension.Publish();
        var lateAbi = new ManagedAbi(extraction, graph);

        Assert(lateAbi.Signatures.Nodes[pointer].Element == element,
            "ABI publication lost a late pointer element.");
        Assert(lateAbi.ResolveValue(pointer, ownerIndex).Kind == AbiKind.Pointer,
            "ABI cannot resolve a late pointer from its own publication.");
        Assert(lateAbi.ResolveValue(element, ownerIndex).Binding == extraction.Bindings.Resolve(owner.Signature),
            "ABI pointer element borrowed an earlier extraction graph.");
        Assert(pointer >= extraction.Signatures.Nodes.Length,
            "Fixture failed to append an identity beyond the extraction publication.");

        Console.WriteLine("Real consumer origins: crossed parsed traces reject and late ABI pointer/element resolution retains its publication.");
    }

    private static void Populate(SignatureBuilder builder, string declaring) {
        const uint scope = (1U << 7) | 0x38;
        builder.AddNode(new SignatureNode { Kind = SignatureKind.Named, Name = declaring, MetadataScope = scope });
        builder.AddNode(new SignatureNode { Kind = SignatureKind.Named, Name = "System.Object", MetadataScope = scope });
        builder.AddNode(new SignatureNode { Kind = SignatureKind.Named, Name = "System.IntPtr", MetadataScope = scope });
        builder.AddNode(new SignatureNode { Kind = SignatureKind.Named, Name = "System.Void", MetadataScope = scope });
        builder.AddEdge(2);
        builder.AddEdge(3);
        builder.AddMethod(new MethodSignature {
            CallingConvention = 0x20,
            ReturnType = 4,
            Parameters = new(0, 2)
        });
    }

    private static void Reject(Action action) {
        try {
            action();
        } catch (Exception error) when (error is ArgumentException or InvalidOperationException) {
            return;
        }

        throw new Exception("Foreign or incomplete consumer graph was accepted.");
    }

    private static void Assert(bool condition, string error) {
        if (!condition)
            throw new Exception(error);
    }
}
