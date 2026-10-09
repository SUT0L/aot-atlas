using System.Buffers.Binary;
using Atlas;

internal static class MetadataScopeJournalChecks {
    internal static void Run() {
        long small = ReadScalars(16);
        long large = ReadScalars(512);

        if (small != large)
            throw new Exception("Scalar metadata reads allocate in proportion to unrelated referenced scopes.");

        Console.WriteLine($"Metadata scope journal: 1024 Boolean reads allocate {large} B at both 16 and 512 scopes.");
    }

    private static long ReadScalars(int scopeCount) {
        byte[] bytes = new byte[128 + 96 * scopeCount];
        bytes[1] = 1;
        bytes[2] = 2;
        bytes[3] = (byte)'A';

        for (int i = 0; i < scopeCount; ++i) {
            int offset = 128 + 96 * i;
            Put(bytes, offset, Handle(offset + 16, 0x30), 2);
            Put(bytes, offset + 16, Handle(offset + 32, 0x39), 0);
            Put(bytes, offset + 32, 0, 2, 0, 0, 0, 0, 0, 0);
        }

        var metadata = new Metadata(bytes, 7);

        for (int i = 0; i < scopeCount; ++i)
            metadata.ReadTypeSignature(Handle(128 + 96 * i, 0x3D));

        for (int i = 0; i < 4096; ++i)
            metadata.Constant(Handle(1, 4));

        var publication = metadata.PublishedSignatures;
        long allocated;

        using (var measurement = new AllocationMeasurement()) {
            for (int i = 0; i < 1024; ++i) {
                MetadataValue value = metadata.Constant(Handle(1, 4));

                if (value.Kind != "bool" || value.Value is not true)
                    throw new Exception("Scalar Boolean oracle disagrees with its encoded byte.");
            }

            allocated = measurement.AllocatedBytes;
        }

        if (!ReferenceEquals(publication, metadata.PublishedSignatures)
            || metadata.ReferencedScopes.Count() != scopeCount)
            throw new Exception("Scalar reads changed the retained metadata publication or scopes.");

        return allocated;
    }

    private static uint Handle(int offset, uint kind) => ((uint)offset << 7) | kind;

    private static void Put(byte[] bytes, int offset, params uint[] values) {
        foreach (uint value in values) {
            bytes[offset++] = 15;
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset, 4), value);
            offset += 4;
        }
    }
}
