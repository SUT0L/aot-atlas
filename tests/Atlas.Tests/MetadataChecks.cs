using System.Buffers.Binary;
using System.Text;
using Atlas;

internal static class MetadataChecks {
    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Metadata assertion failed.");
    }

    private static int Put(byte[] data, int offset, params uint[] values) {
        foreach (uint value in values) {
            data[offset] = 15;
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset + 1), value);
            offset += 5;
        }
        return offset;
    }

    private static void Text(byte[] data, int offset, string value) {
        int count = Encoding.UTF8.GetByteCount(value);
        Put(data, offset, (uint)count);
        Encoding.UTF8.GetBytes(value, data.AsSpan(offset + 5));
    }

    internal static void Run() {
        foreach (int bits in new[] { 7, 8 }) {
            uint Handle(int offset, uint kind) => ((uint)offset << bits) | kind;
            byte[] data = new byte[4096];
            Text(data, 32, "N");
            Text(data, 48, "Outer`1");
            Text(data, 80, "Inner");

            Put(data, 128, 0); // ScopeReference, followed by namespace and two nested types
            Put(data, 160, Handle(128, 0x39), 32);
            Put(data, 192, Handle(160, 0x30), 48);
            Put(data, 224, Handle(192, 0x3D), 80);
            Put(data, 240, 0, 32);

            Put(data, 256, 0);
            Put(data, 288, 1);
            Put(data, 320, Handle(256, 0x3F));
            Put(data, 352, Handle(288, 0x2C));
            Put(data, 384, Handle(192, 0x3D), 2, Handle(320, 0x37), Handle(352, 0x02));
            Put(data, 432, Handle(224, 0x3D), 2, 1, 3, 2, unchecked((uint)-2), 0);
            data[480] = 1;
            Put(data, 481, Handle(224, 0x3D), Handle(384, 0x3C));
            Put(data, 512, 5, 2, Handle(256, 0x3F), 1, Handle(384, 0x3C), 1, Handle(288, 0x2C));
            Put(data, 560, 512);
            Put(data, 592, Handle(592, 0x3E));
            Put(data, 624, 0);

            int position = Put(data, 656, 0x20, 0, Handle(256, 0x3F), 65);
            for (int i = 0; i < 65; ++i)
                position = Put(data, position, Handle(288, 0x2C));
            Put(data, position, 0);

            var metadata = new Metadata(data, bits);
            int nested = metadata.TypeSignature(Handle(224, 0x3D));
            Assert(metadata.Signatures.RenderType(nested) == "N.Outer`1+Inner");

            int formal = metadata.TypeSignature(Handle(240, 0x3D));
            Assert(metadata.Signatures.Nodes[formal].Kind == SignatureKind.ParameterName);
            Assert(metadata.Signatures.RenderType(formal) == "N");

            int generic = metadata.TypeSignature(Handle(384, 0x3C));
            Assert(metadata.Signatures.RenderType(generic) == "N.Outer`1<T[],TM1&>");
            Assert(metadata.Signatures.RenderType(generic, ["System.Int32"], ["Unused", "System.String"]) == "N.Outer`1<System.Int32[],System.String&>");

            int array = metadata.TypeSignature(Handle(432, 0x01));
            Assert(metadata.Signatures.RenderType(array) == "N.Outer`1+Inner[,]");
            var node = metadata.Signatures.Nodes[array];
            Assert(node.Sizes.Count == 1 && metadata.Signatures.Edges[node.Sizes.Start] == 3);
            Assert(node.LowerBounds.Count == 2 && metadata.Signatures.Edges[node.LowerBounds.Start] == -2);

            Assert(metadata.Signatures.RenderType(metadata.TypeSignature(Handle(480, 0x2D))) == "N.Outer`1<T[],TM1&> modopt(N.Outer`1+Inner)");
            Assert(metadata.Signatures.RenderType(metadata.TypeSignature(Handle(560, 0x25))) == "delegate*[cc=0x5]<N.Outer`1<T[],TM1&>,...,TM1,T>");

            int signature = metadata.MethodSignature(512);
            Assert(metadata.Signatures.Methods[signature].GenericParameterCount == 2);
            Assert(metadata.Signatures.RenderMethod("M", signature) == "M(N.Outer`1<T[],TM1&>, ..., TM1) -> T [cc=0x5]");
            Assert(metadata.Signatures.Methods[metadata.MethodSignature(656)].Parameters.Count == 65);

            Assert(metadata.TypeSignature(Handle(624, 0x3E)) == 0);

            int nodeCount = metadata.Signatures.Nodes.Count, edgeCount = metadata.Signatures.Edges.Count;
            for (int i = 0; i < 1000; ++i)
                Assert(metadata.TypeSignature(Handle(384, 0x3C)) == generic);
            Assert(metadata.Signatures.Nodes.Count == nodeCount && metadata.Signatures.Edges.Count == edgeCount);

            bool failed = false;
            try {
                metadata.TypeSignature(Handle(592, 0x3E));
            } catch (InvalidDataException) {
                failed = true;
            }
            Assert(failed);

            Put(data, 160, Handle(128, 0x34), 32);
            failed = false;
            try {
                new Metadata(data, bits).TypeSignature(Handle(224, 0x3D));
            } catch (InvalidDataException) {
                failed = true;
            }
            Assert(failed);

            data = new byte[4096];
            BinaryPrimitives.WriteUInt32LittleEndian(data, 0xDEADDFFD);
            Put(data, 4, 1, 64);
            Put(data, 64, 0, 1024, 0, 1, 0, 0, 0, 0, 0, 128);
            Put(data, 128, Handle(64, 0x38), 0, 0, 2, 256, 384, 0);
            Put(data, 192, 0, 1056);
            Put(data, 256, 192, 1088, 2, 320, 352);
            Put(data, 320, 192, 1120, 0);
            Put(data, 352, 192, 1152, 0);
            Put(data, 384, 192, 1184, 1, 320);
            Text(data, 1024, "Source");
            Text(data, 1056, "Target");
            Text(data, 1088, "Parent");
            Text(data, 1120, "A");
            Text(data, 1152, "B");
            Text(data, 1184, "Other");

            metadata = new Metadata(data, bits);
            metadata.ReadDefinitions();
            Assert(metadata.Forwarders.Select(f => f.Name).SequenceEqual(new[] { "Parent", "Parent+A", "Parent+B", "Other", "Other+A" }));
            Assert(metadata.Forwarders.All(f => f.Assembly == "Target" && f.SourceScope == 64));

            Put(data, 320, 192, 1120, 1, 256);
            failed = false;
            try {
                new Metadata(data, bits).ReadDefinitions();
            } catch (InvalidDataException) {
                failed = true;
            }
            Assert(failed);
        }
        Console.WriteLine("Metadata: 7/8-bit references, structured substitution, array bounds, modifiers, varargs, shared forwarders, and cycles passed.");
        foreach (int bits in new[] { 7, 8 }) {
            var empty = new MetadataMembers(new Metadata(default, bits));
            Assert(empty.Properties.Count == 0 && empty.Events.Count == 0 && empty.Parameters.Count == 0
                && empty.GenericParameters.Count == 0 && empty.Handles.Count == 0 && empty.Accessors.Count == 0);

            byte[] data = new byte[256];
            Put(data, 32, 0, 0, 128, 1, 96, 0, 0);
            Put(data, 96, 2, 160);
            Put(data, 128, 0, 0, 0);
            var metadata = new Metadata(data, bits);
            metadata.Types.Add(new MetadataType { Properties = new IndexRange(0, 1) });
            metadata.Handles.Add(32);
            metadata.MethodIndex.Add(160, 0);
            metadata.Methods.Add(new MetadataMethod { Offset = 160 });
            var members = new MetadataMembers(metadata);
            Assert(members.Properties.Count == 1 && members.Accessors.Count == 1
                && members.Accessors[0].Semantics == 2 && members.Accessors[0].Method == 160);

            for (int mutation = 0; mutation < 2; ++mutation) {
                Put(data, 32, 0, 0, 128, mutation == 0 ? 1U : 256U, 96, 0, 0);
                Put(data, 96, 2, mutation == 0 ? 0U : 160U);
                bool failed = false;
                try {
                    new MetadataMembers(metadata);
                } catch (InvalidDataException) {
                    failed = true;
                }
                Assert(failed);
            }
        }
        Console.WriteLine("Metadata members: empty state, accessor identity and collection extent boundaries passed.");

        var definitions = new Metadata(default, 7);
        definitions.MethodIndex.Add(32, 0);
        byte[] invokeMap = new byte[64];
        new byte[] { 0, 2, 4, 0, 2 }.CopyTo(invokeMap, 0);
        Put(invokeMap, 5, 0x80, 32);
        byte[] layout = new byte[128];
        Text(layout, 32, "M");
        Put(layout, 38, 10);
        Assert(ReflectionMaps.SelectFormat(12, invokeMap, [], [], definitions) == MapFormat.Metadata);
        Assert(ReflectionMaps.SelectFormat(12, invokeMap, [], layout, new Metadata(default, 7)) == MapFormat.Legacy);
        Assert(ReflectionMaps.SelectFormat(12, [], [], [], definitions) == MapFormat.Metadata);
        Assert(ReflectionMaps.SelectFormat(9, [], [], [], definitions) == MapFormat.Legacy);
        Assert(ReflectionMaps.SelectFormat(16, [], [], [], definitions) == MapFormat.Metadata);
        foreach (byte[] nativeLayout in new[] { layout, Array.Empty<byte>() }) {

            bool failed = false;
            try {
                ReflectionMaps.SelectFormat(12, invokeMap, [], nativeLayout, nativeLayout.Length == 0 ? new Metadata(default, 7) : definitions);
            } catch (InvalidDataException) {
                failed = true;
            }
            Assert(failed);
        }
        Assert(ReflectionMaps.SelectFormat(12, invokeMap, [], layout, definitions, MapFormat.Legacy) == MapFormat.Legacy);
        Assert(ReflectionMaps.SelectFormat(12, invokeMap, [], layout, definitions, MapFormat.Metadata) == MapFormat.Metadata);
        Put(invokeMap, 5, 0x84, 32);
        Assert(ReflectionMaps.SelectFormat(12, invokeMap, [], [], definitions) == MapFormat.Legacy);
        Console.WriteLine("Reflection maps: legacy/metadata evidence, unresolved grammars, and explicit format inputs passed.");
    }
}
