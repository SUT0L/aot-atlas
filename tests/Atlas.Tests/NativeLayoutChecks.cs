using System.Buffers.Binary;
using Atlas;

internal static class NativeLayoutChecks {
    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("NativeLayout assertion failed.");
    }

    private static int Put(byte[] data, int offset, params uint[] values) {
        foreach (uint value in values) {
            data[offset] = 15;
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset + 1), value);
            offset += 5;
        }
        return offset;
    }

    internal static void Run() {
        byte[] data = new byte[1024];
        new byte[] { 0x46, 0x0C, 0x24, 0x08, 0x44, 0x68, 0x82 }.CopyTo(data, 0);
        Put(data, 32, 0x2A, 6, 1, 7, 2, unchecked((uint)-2), 0);
        data[80] = 2;
        data[81] = (byte)'M';
        Put(data, 82, 128 - 82);
        new byte[] { 10, 2, 12 }.CopyTo(data, 77);
        Put(data, 87, 1, 0x145);
        Put(data, 128, 3, 1, 2, 0x14, 6, 0xB, 6, 1, 0x15, 0x85);
        data[200] = 2;
        data[201] = (byte)'N';
        Put(data, 202, 240 - 202);
        int end = Put(data, 240, 2, 65, 0x15);
        for (int i = 0; i < 65; ++i)
            end = Put(data, end, 0x85);

        var signatures = new Signatures();
        var layout = new NativeLayout(data, [0x1234, 0x5678], signatures);
        var reader = new NativeReader(data);
        int generic = layout.TypeSignature(ref reader);
        Assert(reader.Position == 6 && signatures.RenderType(generic) == "mt_ref_1234<T[],TM1&>");
        Assert(layout.TypeSignature(ref reader) == generic && reader.Position == 7);

        reader.Position = 32;
        var array = signatures.Nodes[layout.TypeSignature(ref reader)];
        Assert(reader.Position == 67 && array.Value == 2);
        Assert(array.Sizes.Count == 1 && signatures.Edges[array.Sizes.Start] == 7);
        Assert(array.LowerBounds.Count == 2 && signatures.Edges[array.LowerBounds.Start] == -2);
        Assert(signatures.Edges[array.LowerBounds.Start + 1] == 0);

        var method = layout.Method(80);
        Assert(method.Name == "M" && method.End == 87 && layout.Method(80).Signature == method.Signature);
        Assert(signatures.RenderMethod(method.Name, method.Signature) == "M(mt_ref_1234, delegate* unmanaged<System.Int32,System.Void>) -> TM [native_cc=0x3]");
        var many = signatures.Methods[layout.Method(200).Signature];
        Assert(many.Parameters.Count == 65 && many.CallingConvention == 2 && many.GenericParameterCount == 0);

        var metadata = new Metadata(default, 7);
        var entry = layout.MethodEntry(77, metadata, MapFormat.Legacy);
        Assert(entry.Flags == 5 && entry.Entrypoint == 0x5678 && entry.Identity.Signature == method.Signature);
        Assert(signatures.Nodes[entry.DeclaringType].TypeAddress == 0x1234);
        Assert(entry.Arguments.Count == 1 && signatures.RenderType(signatures.Edges[entry.Arguments.Start]) == "System.String");

        var tables = new MethodTables();
        tables.Types.Add(new MethodTable { Address = 0x1234 });
        tables.Index.Add(0x1234, 0);
        var maps = new ReflectionMaps();
        maps.Types.Add(new TypeMapEntry { MethodTable = 0x1234, Name = "N.Pair`2" });
        layout.BindTypes(tables, new RuntimeNames(tables, maps));
        Assert(signatures.RenderType(generic, ["A"], ["Unused", "B"]) == "N.Pair`2<A[],B&>");
        Assert(signatures.RenderMethod(method.Name, method.Signature, methodArguments: ["Result"]) == "M(N.Pair`2, delegate* unmanaged<System.Int32,System.Void>) -> Result [native_cc=0x3]");

        foreach (byte[] invalid in new byte[][] {
            [0x02], [0x24, 0x24, 0x02], [0x0C], [0x84], [0x0E],
            [0x54, 0, 6], [0x16, 0x10], [0x46, 0], [0x16, 6, 0],
        }) {
            bool failed = false;
            try {
                var broken = new NativeLayout(invalid, [], new Signatures());
                reader = new NativeReader(invalid);
                broken.TypeSignature(ref reader);
            } catch (InvalidDataException) {
                failed = true;
            }

            Assert(failed);
        }

        foreach (byte[] invalid in new byte[][] { [0x20], [8, 2], [0, 0] }) {
            bool failed = false;
            try {
                new NativeLayout(invalid, [], new Signatures()).MethodEntry(0, metadata, MapFormat.Legacy);
            } catch (InvalidDataException) {
                failed = true;
            }

            Assert(failed);
        }

        foreach (uint count in new uint[] { 0, 2 }) {
            Put(data, 87, count);
            bool failed = false;
            try {
                new NativeLayout(data, [0x1234, 0x5678], new Signatures()).MethodEntry(77, metadata, MapFormat.Legacy);
            } catch (InvalidDataException) {
                failed = true;
            }

            Assert(failed);
        }

        Console.WriteLine("NativeLayout: shared lookbacks, runtime references, structural substitution, array bounds, native calling conventions, method entries, and 65 parameters passed.");
    }
}
