using Atlas;
using System.Buffers.Binary;
using System.Text;

internal static class NativeLayoutStateChecks {
    private readonly record struct State(
        SignatureNode[] Nodes, int[] Edges, MethodSignature[] Methods,
        KeyValuePair<ulong, int>[] ExternalTypes
    ) {
        internal static State Read(NativeLayout layout, SignatureBuilder signatures)
            => new(signatures.Nodes.ToArray(), signatures.Edges.ToArray(),
                signatures.Methods.ToArray(), layout.ExternalTypes.ToArray());

        internal void Equal(NativeLayout layout, SignatureBuilder signatures) {
            Assert(Nodes.SequenceEqual(signatures.Nodes)
                && Edges.SequenceEqual(signatures.Edges)
                && Methods.SequenceEqual(signatures.Methods)
                && ExternalTypes.SequenceEqual(layout.ExternalTypes));
        }
    }

    private static int Put(byte[] data, int offset, params uint[] values) {
        foreach (uint value in values) {
            data[offset++] = 15;
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), value);
            offset += 4;
        }

        return offset;
    }

    private static byte[] Encoded(params uint[] values) {
        byte[] data = new byte[values.Length * 5];
        Put(data, 0, values);

        return data;
    }

    internal static void Run() {
        foreach (byte[] invalid in new[] {
            new byte[] { 0x46, 0x2A, 0x08, 0x0E },
            Encoded(0x23, 6, 0x85, 7),
            Encoded(0x2A, 6, 1, 7, 1),
            Encoded(0xB, 1, 1, 0, 6),
            Encoded(0xB, 0, 2, 6, 0x85, 7),
            new byte[] { 0x16, 0, 0, 0x22 },
            Enumerable.Repeat((byte)0x24, 257).Append((byte)0x2A).ToArray(),
            Encoded(0x26),
            Encoded(0x1F5)
        })
            CheckTypeFailure(invalid);

        CheckNativeMethods();
        CheckLegacyEntry();

        foreach (int bits in new[] { 7, 8 })
            CheckMetadataEntry(bits);

        Console.WriteLine("NativeLayout state: completed caches, reader rollback, orphan-edge/external cleanup, method/argument boundaries, both handle formats, stable prior IDs, repeated failure and healthy continuation passed.");
    }

    private static void CheckTypeFailure(byte[] invalid) {
        byte[] data = new byte[32 + Math.Max(5, invalid.Length)];
        Put(data, 0, 6);
        invalid.CopyTo(data, 32);

        var signatures = new SignatureBuilder();
        signatures.AddNode(new SignatureNode { Kind = SignatureKind.Named, Name = "PreviouslyPublished" });
        var layout = new NativeLayout(data, [0x1234, 0x5678], signatures, takeOwnership: true);
        var prefix = new NativeReader(data);
        int prior = layout.TypeSignature(ref prefix);

        var saved = State.Read(layout, signatures);
        string? first = null;

        for (int replay = 0; replay < 1000; ++replay) {
            var reader = new NativeReader(data, 32);
            string? error = null;

            try {
                layout.TypeSignature(ref reader);
            } catch (InvalidDataException failure) {
                error = failure.Message;
            }

            Assert(error is not null && (first is null || first == error));
            first ??= error;
            Assert(reader.Position == 32);
            saved.Equal(layout, signatures);

            prefix.Position = 0;
            Assert(layout.TypeSignature(ref prefix) == prior && prefix.Position == 5);
        }

        Put(data, 32, 0x85);
        var restored = new NativeReader(data, 32);
        int valid = layout.TypeSignature(ref restored);

        Assert(valid == saved.Nodes.Length && signatures.RenderType(valid) == "System.Int32");
        Assert(signatures.Nodes[1].Name == "PreviouslyPublished" && layout.ExternalTypes[0x1234] == prior);
    }

    private static void Identity(byte[] data, int offset, string name, int signature) {
        int origin = Put(data, offset, (uint)name.Length);
        Encoding.UTF8.GetBytes(name, data.AsSpan(origin));
        origin += name.Length;
        Put(data, origin, (uint)(signature - origin));
    }

    private static void CheckNativeMethods() {
        byte[] data = new byte[512];
        Identity(data, 0, "Good", 128);
        Put(data, 128, 0, 0, 0x15);

        Identity(data, 32, "Bad", 160);
        Put(data, 160, 1, 1, 2, 6, 0x85, 7);

        Identity(data, 64, "Overflow", 224);
        Put(data, 224, 0, uint.MaxValue);

        var signatures = new SignatureBuilder();
        var layout = new NativeLayout(data, [0x1234], signatures, takeOwnership: true);
        var prior = layout.Method(0);
        Assert(layout.MethodSignature(128) == prior.Signature);
        var saved = State.Read(layout, signatures);

        foreach (uint offset in new uint[] { 32, 64, uint.MaxValue }) {
            string? first = null;

            for (int replay = 0; replay < 1000; ++replay) {
                string? error = null;

                try {
                    layout.Method(offset);
                } catch (Exception failure) when (failure is InvalidDataException or OverflowException) {
                    error = failure.Message;
                }

                Assert(error is not null && (first is null || first == error));
                first ??= error;
                saved.Equal(layout, signatures);

                var cached = layout.Method(0);
                Assert(cached.Signature == prior.Signature && cached.End == prior.End && cached.Name == prior.Name);
            }
        }

        foreach (uint offset in new uint[] { 160, 224, uint.MaxValue }) {
            for (int replay = 0; replay < 1000; ++replay) {
                bool rejected = false;
                try {
                    layout.MethodSignature(offset);
                } catch (Exception error) when (error is InvalidDataException or OverflowException) {
                    rejected = true;
                }
                Assert(rejected);
                saved.Equal(layout, signatures);
                Assert(layout.MethodSignature(128) == prior.Signature);
            }
        }

        Put(data, 185, 0x145);
        var restored = layout.Method(32);
        Assert(layout.MethodSignature(160) == restored.Signature);
        Assert(restored.Signature == saved.Methods.Length);
        Assert(signatures.RenderMethod(restored.Name, restored.Signature)
            == "Bad(System.Int32, System.String) -> mt_ref_1234 [native_cc=0x1]");
    }

    private static void CheckLegacyEntry() {
        byte[] native = new byte[256];
        Put(native, 0, 1, 6);
        Identity(native, 10, "L", 128);
        Put(native, 21, 2, 0x16, 7);
        Put(native, 128, 1, 2, 0, 0x15);

        var metadata = new MetadataBuilder(default, 7);
        var layout = new NativeLayout(native, [0x1234, 0x5678], metadata.SignatureBuilder, takeOwnership: true);
        State saved = State.Read(layout, metadata.SignatureBuilder);

        for (int replay = 0; replay < 1000; ++replay) {
            bool rejected = false;

            try {
                layout.MethodEntry(0, metadata, MapFormat.Legacy);
            } catch (InvalidDataException error) when (error.Message.Contains("kind 0x7", StringComparison.Ordinal)) {
                rejected = true;
            }

            Assert(rejected);

            if (replay == 0)
                saved = State.Read(layout, metadata.SignatureBuilder);
            saved.Equal(layout, metadata.SignatureBuilder);
            Assert(layout.ExternalTypes.Count == 1 && layout.ExternalTypes.ContainsKey(0x1234));
        }

        Put(native, 31, 0x85);
        var restored = layout.MethodEntry(0, metadata, MapFormat.Legacy);
        Assert(restored.Identity.Signature == 1
            && restored.Arguments.Start == 0 && restored.Arguments.Count == 2);
        Assert(metadata.SignatureBuilder.RenderType(metadata.SignatureBuilder.Edges[restored.Arguments.Start])
            == "mt_ref_5678");
    }

    private static void CheckMetadataEntry(int bits) {
        uint Handle(int offset, uint kind) => ((uint)offset << bits) | kind;

        byte[] data = new byte[1024];
        Put(data, 32, 0);
        Put(data, 64, 1);
        Put(data, 768, Handle(32, 0x3F));
        Put(data, 800, Handle(64, 0x2C));
        Put(data, 128, 0x10, 2, Handle(768, 0x3E), 1, Handle(800, 0x3E), 0);
        Put(data, 256, 0, 0, 512, 128, 0, 2, 640, 672, 0);
        Put(data, 512, 1);
        data[517] = (byte)'M';

        var metadata = new MetadataBuilder(data, bits, legacyConstants: false, takeOwnership: true);
        int priorMetadata = metadata.TypeSignature(Handle(32, 0x3F));

        byte[] native = new byte[128];
        Put(native, 0, 6);
        Put(native, 32, 1, 6, (0x28U << (32 - bits)) | 256, 2, 0x16, 7);

        var layout = new NativeLayout(native, [0x1234, 0x5678], metadata.SignatureBuilder, takeOwnership: true);
        var reader = new NativeReader(native);
        int priorNative = layout.TypeSignature(ref reader);

        string? first = null;
        State saved = State.Read(layout, metadata.SignatureBuilder);

        for (int replay = 0; replay < 1000; ++replay) {
            string? error = null;

            try {
                layout.MethodEntry(32, metadata, MapFormat.Metadata);
            } catch (InvalidDataException failure) {
                error = failure.Message;
            }

            Assert(error is not null && (first is null || first == error));
            first ??= error;

            if (replay == 0)
                saved = State.Read(layout, metadata.SignatureBuilder);
            saved.Equal(layout, metadata.SignatureBuilder);
            Assert(metadata.TypeSignature(Handle(32, 0x3F)) == priorMetadata);
            Assert(metadata.String(512) == "M");
            Assert(layout.ExternalTypes.Count == 1 && layout.ExternalTypes[0x1234] == priorNative);

            reader.Position = 0;
            Assert(layout.TypeSignature(ref reader) == priorNative);
        }

        Put(native, 57, 0x85);
        var restored = layout.MethodEntry(32, metadata, MapFormat.Metadata);
        Assert(restored.Identity.Signature == 1 && restored.DeclaringType == priorNative);
        Assert(restored.Arguments.Start == 1 && restored.Arguments.Count == 2);
        Assert(metadata.SignatureBuilder.RenderType(metadata.SignatureBuilder.Edges[restored.Arguments.Start])
            == "mt_ref_5678");
        Assert(metadata.SignatureBuilder.RenderType(metadata.SignatureBuilder.Edges[restored.Arguments.Start + 1])
            == "System.Int32");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("NativeLayout state assertion failed.");
    }
}
