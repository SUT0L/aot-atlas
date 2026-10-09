using Atlas;
using System.Buffers.Binary;
using System.Text;

internal static class MetadataValueChecks {
    private static void Assert(bool value) {
        if (!value)
            throw new Exception("Metadata value assertion failed.");
    }

    private static int Put(byte[] data, int offset, params uint[] values) {
        foreach (uint value in values) {
            data[offset++] = 15;
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), value);
            offset += 4;
        }

        return offset;
    }

    private static void Text(byte[] data, int offset, string value) {
        int size = Encoding.UTF8.GetByteCount(value);

        Put(data, offset, (uint)size);
        Encoding.UTF8.GetBytes(value, data.AsSpan(offset + 5));
    }

    private static void Reject(Action read) {
        try {
            read();
        } catch (InvalidDataException) {
            return;
        }

        throw new Exception("Malformed metadata value was accepted.");
    }

    internal static void Run() {
        foreach (int bits in new[] { 7, 8 }) {
            uint H(int offset, uint kind) => ((uint)offset << bits) | kind;
            var data = new byte[2048];

            Text(data, 32, "Protocol");
            Text(data, 64, "Marker");
            Text(data, 96, "Wire");

            Put(data, 128, H(160, 0x30), 64); // Marker type reference
            Put(data, 160, H(192, 0x39), 32);
            Put(data, 192, 0, 96);
            Put(data, 224, H(128, 0x3d)); // Attribute constructor MemberReference
            Put(data, 256, H(224, 0x27), 2, H(64, 0x1a), H(400, 0x11), 1, 352);
            Put(data, 352, 0, 96, H(128, 0x3d), H(400, 0x11));

            Put(data, 400, unchecked((uint)-7));
            Put(data, 432, 3, unchecked((uint)-1), 7, 123456);
            Put(data, 464, 2, H(64, 0x1a), H(512, 0x14));
            Put(data, 496, 1, H(496, 0x0d));
            Put(data, 528, 70000); // Outside UInt16
            data[560] = 2; // Outside Boolean
            data[576] = 31;
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(577), ulong.MaxValue);

            Put(data, 600, 0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 256, 0, 0, 1, 256);
            Put(data, 720, H(400, 0x11), H(128, 0x3d));
            Put(data, 752, H(128, 0x3d), H(432, 0x10));

            Put(data, 784, 0xd800); // A Char is an exact UTF16 code unit, including lone surrogates.
            Put(data, 816, H(848, 0x37)); // TypeSpecification -> SZArraySignature -> type reference.
            Put(data, 848, H(128, 0x3d));
            Put(data, 880, 2, H(816, 0x3e), H(512, 0x14));

            var metadata = new Metadata(data, bits, legacyConstants: false, takeOwnership: true);
            Assert(metadata.Constant(0).Kind == "absent");

            var typeValue = metadata.Constant(H(816, 0x3e));
            Assert(typeValue.Kind == "type" && (string)typeValue.Value! == "Protocol.Marker[]");

            var typeValues = (System.Collections.ObjectModel.ReadOnlyCollection<MetadataValue>)metadata.Constant(H(880, 0x0d)).Value!;
            Assert(typeValues[0] == typeValue && typeValues[1].Kind == "null");

            Assert((ushort)metadata.Constant(H(784, 8)).Value! == 0xd800);
            Assert(metadata.Constant(H(512, 0x14)).Kind == "null");
            Assert(metadata.Constant(H(data.Length, 0x14)).Kind == "null");
            Assert((int)metadata.Constant(H(400, 0x11)).Value! == -7);
            Assert((ulong)metadata.Constant(H(576, 0x20)).Value! == ulong.MaxValue);

            var array = metadata.Constant(H(432, 0x10));
            Assert(array.Type == "int32[]"
                && ((System.Collections.ObjectModel.ReadOnlyCollection<object>)array.Value!).SequenceEqual(new object[] { -1, 7, 123456 }));

            var strings = (System.Collections.ObjectModel.ReadOnlyCollection<MetadataValue>)metadata.Constant(H(464, 0x19)).Value!;
            Assert((string)strings[0].Value! == "Marker" && strings[1].Kind == "null");

            var enumeration = metadata.Constant(H(720, 0x0c));
            Assert(enumeration.Type == "Protocol.Marker"
                && (int)((MetadataValue)enumeration.Value!).Value! == -7);

            var enumArray = metadata.Constant(H(752, 0x0b));
            Assert(enumArray.Type == "Protocol.Marker" && ((MetadataValue)enumArray.Value!).Kind == "array");

            var attribute = metadata.AttributePayload(256);
            Assert(attribute.Type == "Protocol.Marker");
            Assert((string)attribute.FixedArgumentValues[0].Value! == "Marker"
                && (int)attribute.FixedArgumentValues[1].Value! == -7);
            Assert(attribute.NamedArgumentValues[0].Name == "Wire"
                && (int)attribute.NamedArgumentValues[0].Value.Value! == -7);
            Assert(metadata.ScopeAttributePayloads(600).Single().Offset == 256);
            Assert(metadata.ScopeAttributePayloads(600, module: true).Single().Offset == 256);

            Reject(() => metadata.Constant(H(496, 0x0d)));
            Reject(() => metadata.Constant(H(528, 0x1c)));
            Reject(() => metadata.Constant(H(560, 4)));
            Reject(() => metadata.Constant(H(2048, 0x11)));
            Reject(() => new Metadata(new byte[] { 0, 2, 15 }, bits).Constant(H(1, 0x10)));

            Put(data, 352, 2);
            Reject(() => metadata.AttributePayload(256));

            Put(data, 352, 0);

            // Invalid constructor kinds fail even when their target record is readable.
            Put(data, 256, H(224, 0x11));
            Reject(() => metadata.AttributePayload(256));
        }

        var legacy = new Metadata(new byte[] { 0, 255 }, 8, legacyConstants: true);
        Assert((byte)legacy.Constant((1U << 8) | 7).Value! == 255);

        HandleArrayBudget();

        Console.WriteLine("Metadata values: both handle formats, constants, arrays, attributes, TypeSpecification values, invalid encodings and shared allocation budgets passed.");
    }

    private static void HandleArrayBudget() {
        foreach (int bits in new[] { 7, 8 }) {
            // The first child repeats this array. Each declaration fits in the
            // blob, but its nested result capacities exceed the shared budget.
            const int count = 20_000;
            var bytes = new byte[count + 16];
            uint handle = (1U << bits) | 0x0d;
            Put(bytes, 1, count, handle);

            var metadata = new Metadata(bytes, bits, legacyConstants: false, takeOwnership: true);
            bool rejected = false;

            try {
                metadata.Constant(handle);
            } catch (InvalidDataException error) {
                rejected = error.Message.Contains("one million", StringComparison.Ordinal);
            }

            Assert(rejected);

            // Rejection does not prevent an independent scalar read.
            bytes[^1] = 1;
            Assert((byte)metadata.Constant(((uint)(bytes.Length - 1) << bits) | 6).Value! == 1);
        }
    }
}
