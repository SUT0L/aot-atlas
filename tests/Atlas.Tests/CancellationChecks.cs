using System.Diagnostics;
using Atlas;

internal static class CancellationChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        CheckLongBatches();

        foreach (string binary in binaries)
            CheckPreparation(binary);
    }

    private static void CheckLongBatches() {
        var warm = PeFixture.Create([0x90, 0xC3], ".text", 0x60000020);
        _ = new CodeFlow(warm, [warm.ImageBase + 0x1000], []);

        byte[] body = new byte[32 * 1024 * 1024];
        Array.Fill(body, (byte)0x90);
        body[^1] = 0xC3;
        var image = PeFixture.Create(body, ".text", 0x60000020);

        using (var cancellation = new CancellationTokenSource()) {
            cancellation.CancelAfter(20);
            long allocated = GC.GetAllocatedBytesForCurrentThread();
            long start = Stopwatch.GetTimestamp();

            Cancel(() => new CodeFlow(image, [image.ImageBase + 0x1000], [], cancellation.Token));
            Assert(GC.GetAllocatedBytesForCurrentThread() - allocated > 16 * 1024,
                "Function cancellation did not reach the instruction batch.");
            Assert(Stopwatch.GetElapsedTime(start).TotalSeconds < 5,
                "Function cancellation did not bound the long instruction batch.");
        }

        Assert(image.FileSpan(image.ImageBase + 0x1000, body.Length).SequenceEqual(body),
            "Canceled instruction decoding changed its immutable image.");
        Assert(new CodeFlow(warm, [warm.ImageBase + 0x1000], []).InstructionCount == 2,
            "Function decoding could not retry after cancellation.");

        image = PeFixture.Create(new byte[32 * 1024 * 1024], ".rdata", 0x40000040);

        using (var cancellation = new CancellationTokenSource()) {
            cancellation.CancelAfter(20);
            Cancel(() => new NativeStrings(image, [], cancellation.Token));
        }

        Assert(new NativeStrings(PeFixture.Create("Retry\0"u8.ToArray(), ".rdata", 0x40000040), [])
            .Entries.Length == 1, "String record scanning could not retry after cancellation.");
        Console.WriteLine("Cancellation: long instruction and string batches stopped during work; immutable bytes and retry preserved.");
    }

    private static void CheckPreparation(string binary) {
        byte[] bytes = File.ReadAllBytes(binary);
        var image = new PeImage(bytes);
        var header = ReadyToRun.Read(image);
        var section = header.Find(RtrSectionId.EmbeddedMetadata);
        var data = image.FileMemory(section.Start, checked((int)section.Length));
        var metadata = new Metadata(data, header.MetadataHandleBits, header.Format.LegacyMetadataConstants);

        using (var early = new CancellationTokenSource()) {
            early.Cancel();
            Cancel(() => metadata.ReadDefinitions(early.Token));
            Assert(metadata.Types.Count == 0 && metadata.Methods.Count == 0,
                "Early cancellation published metadata definitions.");
        }

        using (var cancellation = new CancellationTokenSource()) {
            cancellation.CancelAfter(1);
            Cancel(() => metadata.ReadDefinitions(cancellation.Token));
            Assert(metadata.Types.Count == 0 && metadata.Methods.Count == 0,
                "Late definition cancellation published a partial parser state.");
        }

        metadata.ReadDefinitions();
        var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        var maps = ReflectionMaps.Decode(image, header, metadata, fixups);
        var publication = metadata.SignatureBuilder.Publish();
        int methods = metadata.Methods.Count;
        int fields = metadata.Fields.Count;
        var mappedMethods = maps.MethodEntries.ToArray();

        using (var cancellation = new CancellationTokenSource()) {
            cancellation.CancelAfter(1);
            Cancel(() => new Extraction(image, header, metadata, maps, fixups, cancellationToken: cancellation.Token));
        }

        Assert(ReferenceEquals(publication, metadata.SignatureBuilder.Publish())
            && methods == metadata.Methods.Count && fields == metadata.Fields.Count
            && maps.MethodEntries.SequenceEqual(mappedMethods),
            "Canceled extraction changed previously prepared metadata or maps.");

        var retry = new Extraction(image, header, metadata, maps, fixups,
            ExtractionStage.MemberLayouts | ExtractionStage.MethodTracing);
        var names = retry.Names.Values.ToArray();
        publication = retry.Metadata.SignatureBuilder.Publish();

        using (var early = new CancellationTokenSource()) {
            early.Cancel();
            Cancel(() => new ManagedAbi(retry, early.Token));
            Cancel(() => new MetadataMembers(retry.Metadata, early.Token));
        }

        Assert(ReferenceEquals(publication, retry.Metadata.SignatureBuilder.Publish())
            && retry.Names.Values.SequenceEqual(names), "Canceled products altered the previous extraction.");

        var complete = new Extraction(image, header, metadata, maps, fixups);
        var abi = new ManagedAbi(complete);
        publication = complete.Metadata.SignatureBuilder.Publish();

        using (var cancellation = new CancellationTokenSource()) {
            cancellation.CancelAfter(1);
            Cancel(() => new PropertyProjections(complete, abi, cancellation.Token));
        }

        Assert(ReferenceEquals(publication, complete.Metadata.SignatureBuilder.Publish()),
            "Canceled property records adopted a partial metadata draft.");

        using (var cancellation = new CancellationTokenSource()) {
            cancellation.CancelAfter(5);
            Cancel(() => new CodeFlow(complete, abi, cancellation.Token));
        }

        Assert(ReferenceEquals(publication, complete.Metadata.SignatureBuilder.Publish()),
            "Canceled late function preparation altered the existing metadata namespace.");
        Assert(new PropertyProjections(complete, abi).ProjectionEntries.Length != 0,
            "Property preparation could not retry after cancellation.");
        Assert(bytes.AsSpan().SequenceEqual(File.ReadAllBytes(binary)), "Preparation changed fixture bytes.");
        Console.WriteLine($"Cancellation: {binary}; early/record/phase cancellation preserved prior namespaces, parser state and selective retry.");
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
