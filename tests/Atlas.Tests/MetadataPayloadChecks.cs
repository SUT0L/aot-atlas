using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Atlas;

internal static class MetadataPayloadChecks {
    private const int ScopeOffset = 1024;
    private const int ArrayOffset = 4096;

    internal static void Run() {
        foreach (int bits in new[] { 7, 8 }) {
            RepeatedPayloads(bits);
            BatchFailureAndRetry(bits);
            BatchBudget(bits);
            EarlyCancellation(bits);
        }

        CancellationDuringDecode();
        OutputValues();
        Console.WriteLine("Metadata payloads: ordered aliases, bounded batch allocation, late failure/cancellation rollback, healthy retry and JSON values passed.");
    }

    private static void RepeatedPayloads(int bits) {
        uint[] offsets = Enumerable.Repeat(256U, 128).ToArray();
        var metadata = new Metadata(Create(bits, 32768, offsets, [256, 512, 256]), bits);
        metadata.AttributePayload(256);
        GC.Collect();
        long before = GC.GetAllocatedBytesForCurrentThread();
        var attributes = metadata.ScopeAttributePayloads(ScopeOffset);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Check(attributes.Count == 128, "Repeated attributes lost their positions.");
        foreach (var attribute in attributes)
            CheckArray(attribute, 32768);

        Check(allocated < 2_000_000, "Repeated immutable payloads were materialized for every occurrence.");
        var module = metadata.ScopeAttributePayloads(ScopeOffset, module: true);
        Check(module.Select(attribute => attribute.Offset).SequenceEqual([256U, 512U, 256U]),
            "Module attribute order changed while skipping assembly attributes.");
        CheckArray(module[0], 32768);
        CheckArray(module[2], 32768);
        Check(module[1].FixedArgumentValues[0].Value is "Protocol.Marker", "Type-valued attribute changed.");
        Console.WriteLine($"Metadata scope aliases ({bits}-bit): 128 attributes / 4,194,304 logical values, {allocated:N0} allocated B.");
    }

    private static void BatchFailureAndRetry(int bits) {
        byte[] bytes = Create(bits, 8, [512, 512, 384], []);
        // A deliberately borrowed source permits repairing the injected fault.
        var metadata = new Metadata(bytes, bits, legacyConstants: false, takeOwnership: true);
        var before = metadata.PublishedSignatures;

        for (int replay = 0; replay < 2; ++replay) {
            Reject(() => metadata.ScopeAttributePayloads(ScopeOffset), "named attribute argument flags");
            CheckUnchanged(metadata, before);
        }

        Put(bytes, 384, Handle(224, 0x27, bits), 0, 0);
        var repaired = metadata.ScopeAttributePayloads(ScopeOffset);
        Check(repaired.Select(attribute => attribute.Offset).SequenceEqual([512U, 512U, 384U]),
            "Healthy retry lost accepted scope entries.");
        Check(repaired[0].Type == "Protocol.Marker"
            && repaired[0].FixedArgumentValues[0].Value is "Protocol.Marker",
            "Healthy retry reused a retracted signature.");

        var independent = new Metadata(bytes, bits).ScopeAttributePayloads(ScopeOffset);
        Check(independent[0].Type == repaired[0].Type
            && independent[0].FixedArgumentValues[0].Equals(repaired[0].FixedArgumentValues[0]),
            "Repaired batch differs from a fresh read.");
    }

    private static void BatchBudget(int bits) {
        var exact = new Metadata(Create(bits, 999998, [256], []), bits);
        CheckArray(exact.ScopeAttributePayloads(ScopeOffset)[0], 999998);

        var overflow = new Metadata(Create(bits, 999999, [256], []), bits);
        var before = overflow.PublishedSignatures;
        Reject(() => overflow.ScopeAttributePayloads(ScopeOffset), "one million");
        CheckUnchanged(overflow, before);

        var distinct = new Metadata(Create(bits, 500000, [512, 256, 320], []), bits);
        before = distinct.PublishedSignatures;
        Reject(() => distinct.ScopeAttributePayloads(ScopeOffset), "one million");
        CheckUnchanged(distinct, before);
        CheckArray(distinct.AttributePayload(256), 500000);
    }

    private static void EarlyCancellation(int bits) {
        var metadata = new Metadata(Create(bits, 8, [512, 256], []), bits);
        var before = metadata.PublishedSignatures;
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Cancel(() => metadata.Constant(Handle(ArrayOffset, 3, bits), cancellation.Token), cancellation.Token);
        Cancel(() => metadata.AttributePayload(256, cancellation.Token), cancellation.Token);
        Cancel(() => metadata.ScopeAttributePayloads(ScopeOffset, cancellationToken: cancellation.Token), cancellation.Token);
        CheckUnchanged(metadata, before);
        Check(metadata.ScopeAttributePayloads(ScopeOffset).Count == 2, "Early cancellation prevented healthy retry.");
    }

    private static void CancellationDuringDecode() {
        new Metadata(Create(7, 8192, [512, 256], []), 7).ScopeAttributePayloads(ScopeOffset);
        var metadata = new Metadata(Create(7, 980000, [512, 256], []), 7);
        var before = metadata.PublishedSignatures;
        using var cancellation = new CancellationTokenSource();
        cancellation.CancelAfter(1);
        long start = Stopwatch.GetTimestamp();
        bool canceled = false;
        try {
            var result = metadata.ScopeAttributePayloads(ScopeOffset, cancellationToken: cancellation.Token);
            Check(!cancellation.IsCancellationRequested && result.Count == 2,
                "Payload decoding completed after cancellation.");
        } catch (OperationCanceledException error) when (error.CancellationToken == cancellation.Token) {
            canceled = true;
        }

        cancellation.CancelAfter(Timeout.Infinite);
        Check(Stopwatch.GetElapsedTime(start).TotalSeconds < 2, "Payload cancellation did not bound decoding work.");
        if (canceled)
            CheckUnchanged(metadata, before);

        var healthy = metadata.ScopeAttributePayloads(ScopeOffset);
        Check(healthy.Count == 2 && healthy[0].FixedArgumentValues[0].Value is "Protocol.Marker",
            "Canceled payload batch could not make healthy progress.");
        CheckArray(healthy[1], 980000);
    }

    private static void OutputValues() {
        byte[] headerBytes = new byte[32];
        "RTR\0"u8.CopyTo(headerBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(headerBytes.AsSpan(4), 18);
        BinaryPrimitives.WriteUInt16LittleEndian(headerBytes.AsSpan(6), 5);
        BinaryPrimitives.WriteUInt16LittleEndian(headerBytes.AsSpan(12), 1);
        headerBytes[14] = 16;
        headerBytes[15] = 1;
        BinaryPrimitives.WriteUInt32LittleEndian(headerBytes.AsSpan(16), (uint)RtrSectionId.ResourceData);
        BinaryPrimitives.WriteUInt64LittleEndian(headerBytes.AsSpan(24), 0x140001000);
        var image = PeFixture.Create(headerBytes, ".rdata", 0x40000040);
        var header = ReadyToRun.Read(image);
        var metadata = new Metadata(Create(7, 8, [256, 512, 256], [512]), 7);
        metadata.ReadDefinitions();
        using var stream = new MemoryStream();
        using (var json = JsonOutput.CreateWriter(stream, default))
            MetadataOutput.Write(json, "test", metadata, new MetadataMembers(metadata), image, header, 0);

        using var document = JsonDocument.Parse(stream.ToArray());
        var scope = document.RootElement.GetProperty("scope_attributes").GetProperty(ScopeOffset.ToString());
        var assembly = scope.GetProperty("assembly");
        Check(assembly.GetArrayLength() == 3, "JSON omitted a repeated attribute.");
        foreach (int index in new[] { 0, 2 }) {
            var values = assembly[index].GetProperty("fixed_arguments")[0].GetProperty("value");
            Check(values.GetArrayLength() == 8 && values.EnumerateArray().All(value => value.GetBoolean()),
                "JSON changed array-valued attributes.");
        }

        Check(assembly[1].GetProperty("fixed_arguments")[0].GetProperty("value").GetString() == "Protocol.Marker"
            && scope.GetProperty("module")[0].GetProperty("offset").GetUInt32() == 512,
            "JSON changed attribute ordering or module selection.");

        var interrupted = new Metadata(Create(7, 980000, [512, 256], []), 7);
        interrupted.ReadDefinitions();
        var members = new MetadataMembers(interrupted);
        var before = interrupted.PublishedSignatures;
        using var cancellation = new CancellationTokenSource();
        var writer = JsonOutput.CreateWriter(Stream.Null, cancellation.Token);
        cancellation.CancelAfter(1);
        try {
            Cancel(() => MetadataOutput.Write(writer, "test", interrupted, members, image, header, 0,
                cancellationToken: cancellation.Token), cancellation.Token);
            CheckUnchanged(interrupted, before);
        } finally {
            try {
                writer.Dispose();
            } catch (OperationCanceledException error) when (error.CancellationToken == cancellation.Token) {
            }
        }

        using var retry = JsonOutput.CreateWriter(Stream.Null, default);
        MetadataOutput.Write(retry, "test", interrupted, members, image, header, 0);
    }

    private static byte[] Create(int bits, int arrayLength, ReadOnlySpan<uint> assembly, ReadOnlySpan<uint> module) {
        byte[] data = new byte[ArrayOffset + arrayLength + 16];
        BinaryPrimitives.WriteUInt32LittleEndian(data, 0xDEADDFFD);
        Put(data, 4, 1, ScopeOffset);
        Text(data, 32, "Protocol");
        Text(data, 64, "Marker");
        Text(data, 96, "Wire");
        Put(data, 128, Handle(160, 0x30, bits), 64);
        Put(data, 160, Handle(192, 0x39, bits), 32);
        Put(data, 192, 0, 96);
        Put(data, 224, Handle(128, 0x3d, bits));
        Put(data, 256, Handle(224, 0x27, bits), 1, Handle(ArrayOffset, 3, bits), 0);
        Put(data, 320, Handle(224, 0x27, bits), 1, Handle(ArrayOffset, 3, bits), 0);
        Put(data, 384, Handle(224, 0x27, bits), 1, Handle(128, 0x3d, bits), 1, 448);
        Put(data, 448, 2);
        Put(data, 512, Handle(224, 0x27, bits), 1, Handle(128, 0x3d, bits), 0);

        int position = Put(data, ScopeOffset, 0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (uint)assembly.Length);
        foreach (uint offset in assembly)
            position = Put(data, position, offset);
        position = Put(data, position, 0, 0, (uint)module.Length);
        foreach (uint offset in module)
            position = Put(data, position, offset);

        position = Put(data, ArrayOffset, (uint)arrayLength);
        data.AsSpan(position, arrayLength).Fill(1);
        return data;
    }

    private static uint Handle(int offset, uint kind, int bits) => ((uint)offset << bits) | kind;

    private static int Put(byte[] data, int offset, params uint[] values) {
        foreach (uint value in values) {
            data[offset++] = 15;
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), value);
            offset += 4;
        }
        return offset;
    }

    private static void Text(byte[] data, int offset, string value) {
        Put(data, offset, (uint)Encoding.UTF8.GetByteCount(value));
        Encoding.UTF8.GetBytes(value, data.AsSpan(offset + 5));
    }

    private static void CheckArray(MetadataAttributePayload attribute, int count) {
        Check(attribute.Type == "Protocol.Marker" && attribute.FixedArgumentValues.Length == 1,
            "Attribute identity or arity changed.");
        var argument = attribute.FixedArgumentValues[0];
        Check(argument.Kind == "array" && argument.Type == "bool[]", "Array kind changed.");
        var values = (ReadOnlyCollection<object>)argument.Value!;
        Check(values.Count == count && values.All(value => value is true), "Encoded Boolean values changed.");
    }

    private static void CheckUnchanged(Metadata metadata, Signatures before) {
        Check(ReferenceEquals(metadata.PublishedSignatures, before)
            && !metadata.SignatureDeclarations.Any() && !metadata.ReferencedScopes.Any(),
            "Rejected payload batch retained signatures or referenced scopes.");
    }

    private static void Reject(Action read, string diagnostic) {
        try {
            read();
        } catch (InvalidDataException error) when (error.Message.Contains(diagnostic, StringComparison.Ordinal)) {
            return;
        }
        throw new Exception("Payload batch did not reject the injected fault.");
    }

    private static void Cancel(Action read, CancellationToken token) {
        try {
            read();
        } catch (OperationCanceledException error) when (error.CancellationToken == token) {
            return;
        }
        throw new Exception("Payload read ignored cancellation.");
    }

    private static void Check(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
