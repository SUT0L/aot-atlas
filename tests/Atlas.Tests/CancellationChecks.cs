using Atlas;

internal static class CancellationChecks {
    internal static void RunFixups() {
        var image = PeFixture.Create(new byte[16], ".rdata", 0x40000040);
        var section = new RtrSection(308, 0, image.ImageBase + 0x1000, 16);

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Cancel(() => RuntimeTables.Fixups(image, section, cancellation.Token));

        var retry = RuntimeTables.Fixups(image, section);
        Assert(retry.AsSpan().SequenceEqual(new ulong[] {
            image.ImageBase + 0x1000, image.ImageBase + 0x1004,
            image.ImageBase + 0x1008, image.ImageBase + 0x100C
        }), "Fixup table reading could not retry after cancellation.");
        Console.WriteLine("Cancellation: canceled fixup read rejected and healthy retry preserved all four entries.");
    }

    internal static void Run(ReadOnlySpan<string> binaries) {
        CheckBatches();

        foreach (string binary in binaries)
            CheckPreparation(binary);
    }

    private static void CheckBatches() {
        byte[] body = [0x90, 0xC3];
        var image = PeFixture.Create(body, ".text", 0x60000020);

        using (var cancellation = new CancellationTokenSource()) {
            cancellation.Cancel();
            Cancel(() => new CodeFlow(image, [image.ImageBase + 0x1000], [], cancellation.Token));
        }

        Assert(image.FileSpan(image.ImageBase + 0x1000, body.Length).SequenceEqual(body),
            "Canceled instruction decoding changed its immutable image.");
        Assert(new CodeFlow(image, [image.ImageBase + 0x1000], []).InstructionCount == 2,
            "Function decoding could not retry after cancellation.");

        image = PeFixture.Create("Retry\0"u8.ToArray(), ".rdata", 0x40000040);

        using (var cancellation = new CancellationTokenSource()) {
            cancellation.Cancel();
            Cancel(() => new NativeStrings(image, [], cancellation.Token));
        }

        var strings = new NativeStrings(image, []);
        Assert(strings.Entries.Length == 1 && !strings.Entries[0].Wide
            && image.FileData.AsSpan(strings.Entries[0].Data.Start, strings.Entries[0].Data.Count)
                .SequenceEqual("Retry"u8),
            "String record scanning could not retry after cancellation.");
        Console.WriteLine("Cancellation: instruction and string reads reject canceled tokens and preserve healthy retry.");
    }

    private static void CheckPreparation(string binary) {
        byte[] bytes = File.ReadAllBytes(binary);
        var image = new PeImage(bytes);
        var header = ReadyToRun.Read(image);
        var metadata = MetadataBuilder.FromImage(image, header);

        using (var early = new CancellationTokenSource()) {
            early.Cancel();
            Cancel(() => metadata.ReadDefinitions(early.Token));
            Assert(metadata.Types.Count == 0 && metadata.Methods.Count == 0,
                "Early cancellation published metadata definitions.");
        }

        metadata.ReadDefinitions();
        Assert(metadata.Methods.Count != 0, "Metadata definition parsing could not retry after cancellation.");

        using (var cancellation = new CancellationTokenSource()) {
            cancellation.Cancel();
            Cancel(() => Extraction.Read(image, cancellationToken: cancellation.Token));
        }

        var retry = Extraction.Read(image,
            ExtractionStage.MemberLayouts | ExtractionStage.MethodTracing | ExtractionStage.Dispatch);
        var names = retry.Names.Values.ToArray();
        var abi = new ManagedAbi(retry);
        var gc = new MethodGcMap(image, header, retry.Unwind, retry.Managed);
        Assert(gc.MethodEntries.Length != 0 && gc.MethodEntries.ToArray().Any(method => method.Info is not null),
            "Cancellation fixture must contain decoded GC methods.");

        using (var early = new CancellationTokenSource()) {
            early.Cancel();
            Cancel(() => new ManagedAbi(retry, early.Token));
            Cancel(() => new MethodGcMap(image, header, retry.Unwind, retry.Managed, early.Token));
            Cancel(() => retry.Metadata.Constant(0, early.Token));
            Cancel(() => new PropertyProjections(retry, abi, early.Token));
            Cancel(() => new CodeFlow(retry, abi, early.Token));
        }

        Assert(retry.Names.Values.SequenceEqual(names), "Canceled products altered retained runtime names.");
        Assert(new PropertyProjections(retry, abi).ProjectionEntries.Length != 0,
            "Property preparation could not retry after cancellation.");
        Assert(bytes.AsSpan().SequenceEqual(File.ReadAllBytes(binary)), "Preparation changed fixture bytes.");
        Console.WriteLine($"Cancellation: {binary}; canceled reads preserve input bytes, runtime names and healthy retry.");
    }

    private static void Cancel(Action action) {
        try {
            action();
        } catch (OperationCanceledException) {
            return;
        }

        throw new Exception("Cancellation was not observed.");
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
