using Atlas;
using System.Buffers.Binary;
using System.Text;

internal static class MetadataIdentityChecks {
    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Metadata identity assertion failed.");
    }

    private static int Put(byte[] data, int offset, params uint[] values) {
        foreach (uint value in values) {
            data[offset++] = 15;
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), value);
            offset += 4;
        }

        return offset;
    }

    private static void Text(byte[] data, int offset, string text) {
        Put(data, offset, (uint)Encoding.UTF8.GetByteCount(text));
        Encoding.UTF8.GetBytes(text, data.AsSpan(offset + 5));
    }

    internal static void Run() {
        foreach (int bits in new[] { 7, 8 }) {
            uint H(int offset, uint kind) => ((uint)offset << bits) | kind;
            byte[] data = new byte[2048];

            Text(data, 32, "Collision");
            Text(data, 64, "Packet");
            Text(data, 96, "Left");
            Text(data, 128, "Right");
            Text(data, 160, "Inner");
            Text(data, 192, "T");
            Text(data, 224, "en-AU");

            Put(data, 256, H(320, 0x30), 64);
            Put(data, 288, H(352, 0x30), 64);
            Put(data, 320, H(400, 0x39), 32);
            Put(data, 352, H(480, 0x39), 32);

            int key = Put(data, 400, 1, 96, 1, 2, 3, 4, 2);
            data[key] = 0xAA;
            data[key + 1] = 0xBB;
            Put(data, key + 2, 224);
            Put(data, 480, 0, 128, 4, 3, 2, 1, 0, 0);

            Put(data, 560, H(256, 0x3d), 160); // nested reference inherits assembly scope
            Put(data, 592, 0, 192); // stack trace formal has no assembly identity
            Put(data, 624, H(656, 0x37));
            Put(data, 656, H(288, 0x3d));
            Put(data, 720, 0, 0, 0, 64, 0, 0, 0); // ownerless definition: scope remains unknown

            MetadataRecordId[] roots = [
                new(MetadataRecordKind.TypeReference, 256), new(MetadataRecordKind.TypeReference, 288),
                new(MetadataRecordKind.TypeReference, 560), new(MetadataRecordKind.TypeReference, 592),
                new(MetadataRecordKind.TypeSpecification, 624), new(MetadataRecordKind.TypeDefinition, 720)
            ];
            var m = Metadata.Read(data, new(bits), roots);
            var graph = m.PublishedSignatures;
            int left = m.ReadTypeSignature(H(256, 0x3D)).Index;
            int right = m.ReadTypeSignature(H(288, 0x3D)).Index;
            var declarations = m.SignatureDeclarations.ToArray();
            var retainedScopes = m.ReferencedScopes.ToArray();

            // Display equality does not prove assembly/type identity.
            Assert(graph.RenderType(left) == "Collision.Packet");
            Assert(graph.RenderType(left) == graph.RenderType(right));
            Assert(left != right);
            Assert(m.TypeSignatureHandles.Single(s => s.Key == H(256, 0x3d)).Value == left);
            Assert(graph.Nodes[left].MetadataScope == H(400, 0x39));
            Assert(graph.Nodes[right].MetadataScope == H(480, 0x39));

            int nested = m.ReadTypeSignature(H(560, 0x3d)).Index;
            Assert(graph.Nodes[nested].MetadataScope == H(400, 0x39));
            Assert(graph.RenderType(nested) == "Collision.Packet+Inner");

            int formal = m.ReadTypeSignature(H(592, 0x3d)).Index;
            Assert(graph.Nodes[formal].Kind == SignatureKind.ParameterName);
            Assert(graph.Nodes[formal].MetadataScope == 0);

            int ownerless = m.ReadTypeSignature(H(720, 0x3a)).Index;
            Assert(graph.Nodes[ownerless].MetadataScope == 0);

            int array = m.ReadTypeSignature(H(624, 0x3e)).Index;
            Assert(graph.Nodes[graph.Nodes[array].Element].MetadataScope == H(480, 0x39));
            Assert(m.TypeSignatureHandles.Single(s => s.Key == H(624, 0x3e)).Value == array);
            Assert(m.TypeSignatureHandles.Single(s => s.Key == H(656, 0x37)).Value == array);

            var scopes = m.ReferencedScopes.ToArray();
            Assert(scopes.Length == 2);
            Assert(scopes[0].Name == "Left" && scopes[0].Culture == "en-AU");
            Assert(scopes[0].Major == 1 && scopes[0].Revision == 4);
            Assert(scopes[0].PublicKeyOrToken.Span.SequenceEqual(new byte[] { 0xAA, 0xBB }));
            Assert(scopes[1].Name == "Right" && scopes[1].PublicKeyOrToken.IsEmpty);
            Assert(m.ReadTypeSignature(H(256, 0x3d)).Index == left && m.ReferencedScopes.Count() == 2);

            var invalid = (byte[])data.Clone();
            Put(invalid, 480, 0, 128, 70000);

            var partial = Metadata.Read(invalid, new(bits), roots);
            Assert(partial.ProjectionDiagnostics.Count != 0
                && !partial.Facts.Field(new(MetadataRecordKind.ScopeReference, 480), MetadataFieldName.MajorVersion).UInt32.IsAvailable);
            Assert(ReferenceEquals(graph, m.PublishedSignatures)
                && declarations.SequenceEqual(m.SignatureDeclarations)
                && retainedScopes.SequenceEqual(m.ReferencedScopes));
        }
    }
}
