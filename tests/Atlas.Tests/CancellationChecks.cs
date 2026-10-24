using System.Diagnostics;
using Atlas;

internal static class CancellationChecks {
    internal static void RunTimedFixups() {
        const int bytes = 64 * 1024 * 1024;
        var image = PeFixture.Create(new byte[bytes], ".rdata", 0x40000040);
        var section = new RtrSection(308, 0, image.ImageBase + 0x1000, bytes);

        using var cancellation = new CancellationTokenSource();
        long allocated = GC.GetAllocatedBytesForCurrentThread();
        long start = Stopwatch.GetTimestamp();
        cancellation.CancelAfter(10);
        Assert(!cancellation.IsCancellationRequested,
            "The fixup cancellation test started with an already cancelled token.");

        Cancel(() => RuntimeTables.Fixups(image, section, cancellation.Token));

        long elapsedBytes = GC.GetAllocatedBytesForCurrentThread() - allocated;
        Assert(elapsedBytes >= bytes * 2L,
            "Fixup cancellation happened before the full table destination was allocated.");
        Assert(Stopwatch.GetElapsedTime(start).TotalMilliseconds >= 10,
            "Fixup cancellation happened before the scheduled timer elapsed.");
        Assert(Stopwatch.GetElapsedTime(start).TotalSeconds < 5,
            "Fixup cancellation did not bound the long table read.");

        var small = PeFixture.Create(new byte[16], ".rdata", 0x40000040);
        var retry = RuntimeTables.Fixups(small,
            new RtrSection(308, 0, small.ImageBase + 0x1000, 16));
        Assert(retry.Length == 4 && retry[0] == small.ImageBase + 0x1000
            && retry[3] == small.ImageBase + 0x100C,
            "Fixup table reading could not retry after timed cancellation.");
        Console.WriteLine("Cancellation: timed fixup traversal stopped after destination allocation and retry passed.");
    }

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
        var metadata = MetadataBuilder.FromImage(image, header);

        using (var early = new CancellationTokenSource()) {
            early.Cancel();
            Cancel(() => metadata.ReadDefinitions(early.Token));
            Assert(metadata.Types.Count == 0 && metadata.Methods.Count == 0,
                "Early cancellation published metadata definitions.");
        }

        using (var cancellation = new CancellationTokenSource()) {
            cancellation.CancelAfter(1);
            Cancel(() => metadata.ReadDefinitions(cancellation.Token));
            Assert(bytes.AsSpan().SequenceEqual(File.ReadAllBytes(binary)),
                "Canceled metadata construction changed caller bytes.");
        }

        var accepted = Extraction.Read(image);
        var snapshot = accepted.Metadata;
        var maps = accepted.Maps;
        var publication = accepted.Signatures;
        int methods = snapshot.MethodDefinitions.Length;
        int fields = snapshot.FieldDefinitions.Length;
        var mappedMethods = maps.MethodEntries.ToArray();

        using (var cancellation = new CancellationTokenSource()) {
            cancellation.CancelAfter(1);
            Cancel(() => Extraction.Read(image, cancellationToken: cancellation.Token));
        }

        Assert(ReferenceEquals(publication, accepted.Signatures)
            && methods == snapshot.MethodDefinitions.Length && fields == snapshot.FieldDefinitions.Length
            && maps.MethodEntries.SequenceEqual(mappedMethods),
            "Canceled extraction changed previously prepared metadata or maps.");

        var retry = Extraction.Read(image, ExtractionStage.MemberLayouts | ExtractionStage.MethodTracing);
        var names = retry.Names.Values.ToArray();
        publication = retry.Signatures;

        using (var early = new CancellationTokenSource()) {
            early.Cancel();
            Cancel(() => new ManagedAbi(retry, early.Token));
            Cancel(() => retry.Metadata.Constant(0, early.Token));
        }

        Assert(ReferenceEquals(publication, retry.Signatures)
            && retry.Names.Values.SequenceEqual(names), "Canceled products altered the previous extraction.");

        var complete = Extraction.Read(image);
        var abi = new ManagedAbi(complete);
        publication = complete.Signatures;

        using (var cancellation = new CancellationTokenSource()) {
            cancellation.CancelAfter(1);
            Cancel(() => new PropertyProjections(complete, abi, cancellation.Token));
        }

        Assert(ReferenceEquals(publication, complete.Signatures),
            "Canceled property records adopted a partial metadata draft.");

        using (var cancellation = new CancellationTokenSource()) {
            cancellation.CancelAfter(5);
            Cancel(() => new CodeFlow(complete, abi, cancellation.Token));
        }

        Assert(ReferenceEquals(publication, complete.Signatures),
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
