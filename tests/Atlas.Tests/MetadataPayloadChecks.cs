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
            PartialPayloads(bits);
            ValueBudget(bits);
            EarlyCancellation(bits);
        }
        CancellationDuringConstruction();
        OutputValues();
        Console.WriteLine("Metadata payloads: frozen aliases, typed arrays, partial sibling recovery, value limits, construction/query cancellation and JSON values passed.");
    }

    private static void RepeatedPayloads(int bits) {
        uint[] offsets = Enumerable.Range(0, 128).Select(i => (i & 1) == 0 ? 256U : 320U).ToArray();
        var metadata = Metadata.Read(Create(bits, 32768, offsets, [256, 512, 256]), new(bits));
        var expected = metadata.AttributePayload(256);
        Check(ReferenceEquals(expected.FixedArgumentValues[0].Value,
            metadata.Constant(Handle(ArrayOffset, 3, bits)).Value),
            "Attribute and standalone constant queries copied the same immutable array.");
        _ = metadata.ScopeAttributePayloads(ScopeOffset);
        long before = GC.GetAllocatedBytesForCurrentThread();
        var attributes = metadata.ScopeAttributePayloads(ScopeOffset);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Check(attributes.Count == 128, "Repeated attributes lost their positions.");
        foreach (var attribute in attributes) {
            CheckArray(attribute, 32768);
            Check(ReferenceEquals(attribute.FixedArgumentValues[0].Value, expected.FixedArgumentValues[0].Value),
                "Repeated immutable payloads were copied for each occurrence.");
        }
        Check(allocated == 0, "Frozen payload lookup allocated new storage.");
        var module = metadata.ScopeAttributePayloads(ScopeOffset, module: true);
        Check(module.Select(attribute => attribute.Offset).SequenceEqual([256U, 512U, 256U]),
            "Module attribute order changed.");
        Check(module[1].FixedArgumentValues[0].Value is "Protocol.Marker", "Type-valued attribute changed.");
    }

    private static void PartialPayloads(int bits) {
        byte[] bytes = Create(bits, 8, [512, 512, 384], []);
        var partial = Metadata.Read(bytes, new(bits));
        var before = partial.PublishedSignatures;
        Check(partial.AttributePayload(512).FixedArgumentValues[0].Value is "Protocol.Marker",
            "A malformed sibling discarded a healthy payload.");
        Check(!partial.TryAttributePayload(384, out _) && partial.ProjectionDiagnostics.Count != 0,
            "Malformed named argument flags were hidden.");
        var scope = partial.Facts.Scope(new(MetadataRecordKind.ScopeDefinition, ScopeOffset));
        Check(scope.CustomAttributes.Count == 3
            && scope.CustomAttributes[0].Value == scope.CustomAttributes[1].Value,
            "Partial scope lost ordered duplicate declarations.");
        Put(bytes, 384, Handle(224, 0x27, bits), 0, 0);
        var repaired = Metadata.Read(bytes, new(bits));
        Check(repaired.ScopeAttributePayloads(ScopeOffset).Select(attribute => attribute.Offset)
            .SequenceEqual([512U, 512U, 384U]), "Corrected source lost accepted entries.");
        Check(!partial.TryAttributePayload(384, out _) && ReferenceEquals(before, partial.PublishedSignatures),
            "Correcting caller bytes changed an earlier snapshot.");
    }

    private static void ValueBudget(int bits) {
        var exact = Metadata.Read(Create(bits, 999999, [256], []), new(bits));
        CheckArray(exact.AttributePayload(256), 999999);
        var overflow = Metadata.Read(Create(bits, 1000000, [256], []), new(bits));
        Check(!overflow.TryAttributePayload(256, out _) && overflow.ProjectionDiagnostics.Count != 0,
            "Payload value limit was not reported.");
        Check(overflow.Facts.Field(new(MetadataRecordKind.ConstantBooleanArray, ArrayOffset), MetadataFieldName.Value).Items.Count == 1000000,
            "A projection limit discarded the raw array.");
    }

    private static void EarlyCancellation(int bits) {
        byte[] bytes = Create(bits, 8, [512, 256], []);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Cancel(() => Metadata.Read(bytes, new(bits), cancellationToken: cancellation.Token), cancellation.Token);
        var metadata = Metadata.Read(bytes, new(bits));
        var before = metadata.PublishedSignatures;
        Cancel(() => metadata.Constant(Handle(ArrayOffset, 3, bits), cancellation.Token), cancellation.Token);
        Cancel(() => metadata.AttributePayload(256, cancellation.Token), cancellation.Token);
        Cancel(() => metadata.ScopeAttributePayloads(ScopeOffset, cancellationToken: cancellation.Token), cancellation.Token);
        Check(ReferenceEquals(before, metadata.PublishedSignatures)
            && metadata.ScopeAttributePayloads(ScopeOffset).Count == 2, "Canceled query changed frozen payloads.");
    }

    private static void CancellationDuringConstruction() {
        byte[] bytes = Create(7, 980000, [512, 256], []);
        using var cancellation = new CancellationTokenSource();
        cancellation.CancelAfter(1);
        long start = Stopwatch.GetTimestamp();
        Cancel(() => Metadata.Read(bytes, new(7), cancellationToken: cancellation.Token), cancellation.Token);
        Check(Stopwatch.GetElapsedTime(start).TotalSeconds < 2, "Cancellation did not bound construction work.");
        var healthy = Metadata.Read(bytes, new(7));
        Check(healthy.ScopeAttributePayloads(ScopeOffset).Count == 2,
            "Healthy construction after cancellation lost scope entries.");
        CheckArray(healthy.AttributePayload(256), 980000);
    }

    private static void OutputValues() {
        var metadata = new MetadataBuilder(Create(7, 8, [256, 512, 256], [512]), 7);
        metadata.ReadDefinitions();
        using var stream = new MemoryStream();
        using (var json = JsonOutput.CreateWriter(stream, default))
            MetadataOutput.Write(json, "test", metadata.Publish(), 0);

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

        var interrupted = new MetadataBuilder(Create(7, 980000, [512, 256], []), 7).Publish();
        var before = interrupted.PublishedSignatures;
        using var cancellation = new CancellationTokenSource();
        var writer = JsonOutput.CreateWriter(Stream.Null, cancellation.Token);
        cancellation.CancelAfter(1);
        try {
            Cancel(() => MetadataOutput.Write(writer, "test", interrupted, 0,
                cancellationToken: cancellation.Token), cancellation.Token);
            Check(ReferenceEquals(interrupted.PublishedSignatures, before)
                && interrupted.ScopeAttributePayloads(ScopeOffset).Count == 2,
                "Canceled serialization changed frozen metadata.");
        } finally {
            try {
                writer.Dispose();
            } catch (OperationCanceledException error) when (error.CancellationToken == cancellation.Token) {
            }
        }

        using var retry = JsonOutput.CreateWriter(Stream.Null, default);
        MetadataOutput.Write(retry, "test", interrupted, 0);
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
        var values = (ReadOnlyCollection<bool>)argument.Value!;
        Check(values.Count == count && values.All(value => value is true), "Encoded Boolean values changed.");
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
