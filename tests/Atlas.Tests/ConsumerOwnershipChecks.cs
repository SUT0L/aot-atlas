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
        var metadata = new Metadata(default, 7);
        metadata.Scopes.Add(new MetadataScope {
            Offset = 1,
            Name = "System.Private.CoreLib",
            Culture = ""
        });

        var own = metadata.SignatureBuilder;
        Populate(own, "Not.Delegate");
        var earlier = own.Publish();
        var traces = new TraceMaps(image, header, metadata, []);
        traces.Methods.Add(new TraceMethod {
            DeclaringType = 1,
            Signature = 1,
            Name = "InitializeClosedInstanceWithoutNullCheck",
            Entrypoint = 0x1234
        });

        Assert(ManagedFunctionPointerConsumers.Read(metadata, traces, earlier).Length == 0,
            "A same-name method on an unrelated type became a delegate initializer.");

        var foreign = new SignatureBuilder();
        Populate(foreign, "System.Delegate");
        Reject(() => ManagedFunctionPointerConsumers.Read(metadata, traces, foreign.Publish()));

        var declaring = own.Nodes[1];
        own.SetNode(1, declaring with { Name = "System.Delegate" });
        var valid = own.Publish();
        Assert(ManagedFunctionPointerConsumers.Read(metadata, traces, valid)
            .SequenceEqual(new[] { new FunctionPointerConsumer(0x1234, 8) }),
            "An independently specified CoreLib delegate initializer was lost.");

        var otherMetadata = new Metadata(default, 7);
        Populate(otherMetadata.SignatureBuilder, "System.Delegate");
        otherMetadata.Scopes.Add(metadata.Scopes[0]);
        Reject(() => ManagedFunctionPointerConsumers.Read(
            otherMetadata, traces, otherMetadata.SignatureBuilder.Publish()));

        var absent = new Metadata(default, 7);
        var absentGraph = absent.SignatureBuilder.Publish();
        var absentTraces = new TraceMaps(image, header, absent, []);
        Populate(absent.SignatureBuilder, "System.Delegate");
        absent.Scopes.Add(metadata.Scopes[0]);
        absentTraces.Methods.Add(traces.Methods[0]);
        Reject(() => ManagedFunctionPointerConsumers.Read(absent, absentTraces, absentGraph));

        Console.WriteLine("Consumer ownership: foreign metadata graphs, crossed trace origins and missing prior roots reject; exact delegate initializer remains available.");
    }

    internal static void Binary(Extraction extraction) {
        var metadata = extraction.Metadata;
        var expected = ManagedFunctionPointerConsumers.Read(metadata, extraction.Traces, extraction.Signatures);
        var foreign = new Metadata(metadata.Data, metadata.HandleBits, extraction.Header.Format.LegacyMetadataConstants);
        foreign.ReadDefinitions();
        var foreignTraces = new TraceMaps(extraction.Image, extraction.Header, foreign, extraction.CommonFixups);

        Reject(() => ManagedFunctionPointerConsumers.Read(metadata, foreignTraces, extraction.Signatures));
        Reject(() => ManagedFunctionPointerConsumers.Read(
            foreign, extraction.Traces, foreign.SignatureBuilder.Publish()));
        Assert(ManagedFunctionPointerConsumers.Read(metadata, extraction.Traces, extraction.Signatures)
            .SequenceEqual(expected), "Rejected trace origins altered prior consumers.");

        var owner = extraction.Maps.Types.First(entry => extraction.Bindings.Resolve(entry.Signature) != 0);
        int ownerIndex = extraction.Types.Index[owner.MethodTable] + 1;
        int element = metadata.SignatureBuilder.AddNode(new SignatureNode {
            Kind = SignatureKind.Modified,
            Element = owner.Signature
        });
        int pointer = metadata.SignatureBuilder.AddNode(new SignatureNode {
            Kind = SignatureKind.Pointer,
            Element = element
        });
        var graph = metadata.SignatureBuilder.Publish();
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
