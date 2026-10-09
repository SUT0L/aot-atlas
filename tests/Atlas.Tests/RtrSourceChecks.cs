using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using Atlas;

internal static class RtrSourceChecks {
    private const ulong SectionStart = 0x140001000;

    internal static void Run() {
        foreach (bool embedded in new[] { false, true }) {
            var first = Create(embedded, 128, 0x11);
            var second = Create(embedded, 192, 0x22);
            var firstHeader = ReadyToRun.Read(first);
            var secondHeader = ReadyToRun.Read(second);
            var correct = new ResourceMap(second, secondHeader);
            Assert(correct.ResourceEntries.Length == 1 && correct.Bytes[0] == 0x22);
            var absentMetadata = Metadata.FromImage(second, secondHeader);
            absentMetadata.ReadDefinitions();
            Assert(absentMetadata.Bytes.IsEmpty && absentMetadata.ScopeDefinitions.IsEmpty);
            Reject<ArgumentException>(() => _ = new ResourceMap(second, firstHeader));

            var clone = new PeImage((byte[])second.FileData.Clone());
            Assert(new ResourceMap(clone, secondHeader).Bytes[0] == 0x22);

            byte[] changedBytes = (byte[])second.FileData.Clone();
            changedBytes[512 + 96] = 0xCC;
            var changed = new PeImage(changedBytes);
            Assert(new ResourceMap(changed, secondHeader).Bytes[0] == 0x22);
            Assert(new Extraction(changed, secondHeader, new Metadata(default, 7), new ReflectionMaps(), [],
                ExtractionStage.Resources).Resources.Bytes[0] == 0x22);

            int headerLength = 16 + 2 * secondHeader.EntrySize;
            byte[] duplicateBytes = (byte[])second.FileData.Clone();
            second.FileData.AsSpan(secondHeader.FileOffset, headerLength)
                .CopyTo(duplicateBytes.AsSpan(512 + 256));
            var duplicate = new PeImage(duplicateBytes);
            Assert(second.FileData.AsSpan(secondHeader.FileOffset, headerLength)
                .SequenceEqual(duplicate.FileData.AsSpan(secondHeader.FileOffset, headerLength)));
            Reject<InvalidDataException>(() => _ = new ResourceMap(duplicate, secondHeader));

            var metadata = new Metadata(default, 7);
            var publication = metadata.PublishedSignatures;
            var maps = new ReflectionMaps();
            var memory = new RuntimeMemory(second, default);
            var unwind = new UnwindTables(second);
            var managed = new ManagedUnwind(second, unwind, null);

            Reject<ArgumentException>(() => _ = Metadata.FromImage(second, firstHeader));
            Reject<ArgumentException>(() => _ = ReflectionMaps.Decode(second, firstHeader, metadata, []));
            Reject<ArgumentException>(() => _ = new TraceMaps(second, firstHeader, metadata, []));
            Reject<ArgumentException>(() => _ = new Extraction(second, firstHeader, metadata, maps, [],
                ExtractionStage.Resources));
            Reject<ArgumentException>(() => _ = Hydration.Read(second, firstHeader));
            Reject<ArgumentException>(() => _ = new UnwindAnalysis(second, firstHeader, memory));
            Reject<ArgumentException>(() => _ = new MethodGcMap(second, firstHeader, unwind, managed));
            Reject<ArgumentException>(() => _ = new FatFunctionPointers(second, firstHeader, memory, null, null));
            Reject<ArgumentException>(() => _ = new Atlas.RuntimeHelpers(second, firstHeader, memory, unwind));
            Reject<ArgumentException>(() => _ = new StaticStorage(second, firstHeader, memory, [], [], []));
            Reject<ArgumentException>(() => new MethodTableBuilder().Read(second, firstHeader, memory));
            Assert(ReferenceEquals(publication, metadata.PublishedSignatures)
                && maps.TypeEntries.IsEmpty && maps.MethodEntries.IsEmpty && maps.FieldEntries.IsEmpty);
            Assert(new ResourceMap(second, secondHeader).Bytes[0] == 0x22);
        }

        var (retained, sourceBytes) = RetainedHeader();
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        Assert(!sourceBytes.IsAlive && retained.Sections.Length == 2);
        GC.KeepAlive(retained);
        Console.WriteLine("RTR source validation: legacy/embedded foreign rows reject at public decoders; equivalent clones and unrelated edits remain valid; duplicate headers reject and retained headers do not keep file bytes alive.");
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static (ReadyToRun Header, WeakReference SourceBytes) RetainedHeader() {
        var image = Create(true, 192, 0x22);
        return (ReadyToRun.Read(image), new WeakReference(image.FileData));
    }

    private static PeImage Create(bool embedded, int payloadOffset, byte payload) {
        byte[] bytes = new byte[384];
        "RTR\0"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(4), embedded ? (ushort)18 : (ushort)16);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(6), embedded ? (ushort)4 : (ushort)0);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(12), 2);
        bytes[14] = embedded ? (byte)16 : (byte)24;
        bytes[15] = 1;

        int rowSize = bytes[14];
        Row(bytes.AsSpan(16), embedded, RtrSectionId.ResourceIndex, SectionStart + 80, 10);
        Row(bytes.AsSpan(16 + rowSize), embedded, RtrSectionId.ResourceData,
            SectionStart + (uint)payloadOffset, 1);

        uint hash = unchecked(0x6DA3B944U + BitOperations.RotateLeft(0x6DA3B944U, 8));
        byte[] index = [0, 2, 4, (byte)hash, 2, 0, 2, (byte)'R', 0, 2];
        index.CopyTo(bytes.AsSpan(80));
        bytes[128] = 0xAA;
        bytes[payloadOffset] = payload;

        return PeFixture.Create(bytes, ".rdata", 0x40000040);
    }

    private static void Row(Span<byte> bytes, bool embedded, RtrSectionId id, ulong start, uint length) {
        BinaryPrimitives.WriteInt32LittleEndian(bytes, (int)id);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes[4..], embedded ? length : 1U);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes[8..], start);

        if (!embedded)
            BinaryPrimitives.WriteUInt64LittleEndian(bytes[16..], start + length);
    }

    private static void Reject<T>(Action action) where T : Exception {
        try {
            action();
        } catch (T) {
            return;
        }

        throw new Exception($"Expected {typeof(T).Name} for foreign RTR source.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("RTR source assertion failed.");
    }
}
