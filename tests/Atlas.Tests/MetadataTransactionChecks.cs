using Atlas;
using System.Buffers.Binary;
using System.Text;

internal static class MetadataTransactionChecks {
    internal static void Run() {
        foreach (int bits in new[] { 7, 8 }) {
            CheckRecords(bits);
            CheckPublicSignatures(bits);
            CheckAliases(bits);

            uint Handle(int offset, uint kind) => ((uint)offset << bits) | kind;
            var bytes = new byte[1024];

            Text(bytes, 32, "Namespace");
            Text(bytes, 64, "Type");
            Text(bytes, 96, "Assembly");

            Put(bytes, 128, Handle(160, 0x30), 64);
            Put(bytes, 160, Handle(192, 0x39), 32);
            Put(bytes, 192, 0, 96);
            Put(bytes, 224, Handle(128, 0x3D));

            // A valid type value completes its signature before the second
            // value fails. The enclosing operation must retract that root.
            Put(bytes, 256, 2, Handle(128, 0x3D), Handle(400, 1));
            var metadata = new Metadata(bytes, bits, legacyConstants: false, takeOwnership: true);
            var before = metadata.SignatureBuilder.Publish();
            Reject(() => metadata.Constant(Handle(256, 0x0D)));
            Unchanged(metadata, before);

            Put(bytes, 256, 2, Handle(128, 0x3D), Handle(400, 0x14));
            var values = (System.Collections.ObjectModel.ReadOnlyCollection<MetadataValue>)metadata.Constant(Handle(256, 0x0D)).Value!;
            Check((string)values[0].Value! == "Namespace.Type" && values[1].Kind == "null");
            Check(metadata.ReferencedScopes.Single().Name == "Assembly");

            // Attribute arguments create a root before a malformed named
            // argument. Earlier successful roots must survive this failure.
            Put(bytes, 288, Handle(224, 0x27), 1, Handle(128, 0x3D), 1, 352);
            Put(bytes, 352, 2);
            before = metadata.SignatureBuilder.Publish();
            var declarations = metadata.SignatureDeclarations;
            var scopes = metadata.ReferencedScopes;
            using var declarationIterator = declarations.GetEnumerator();
            using var scopeIterator = scopes.GetEnumerator();
            Check(declarationIterator.MoveNext() && scopeIterator.MoveNext());
            Reject(() => metadata.AttributePayload(288));
            Check(ReferenceEquals(before, metadata.SignatureBuilder.Publish()));
            Check(metadata.TypeSignature(Handle(128, 0x3D)) == 1);
            Check(!declarationIterator.MoveNext() && !scopeIterator.MoveNext()
                && ReferenceEquals(declarations.Single().Value.Publication, before)
                && declarations.Single().Value.Render() == "Namespace.Type"
                && scopes.Single().Name == "Assembly");
        }

        Console.WriteLine("Metadata transactions: collections, signature scopes, failed alias batches and repaired/cached retries preserve prior records/publications for 7/8-bit handles.");
    }

    private static void CheckAliases(int bits) {
        uint Handle(int offset, uint kind) => ((uint)offset << bits) | kind;
        byte[] bytes = ScopeFixture(bits);
        uint seed = Handle(128, 0x3D);
        uint firstAlias = Handle(640, 0x3E);
        uint secondAlias = Handle(672, 0x3E);
        Put(bytes, 640, seed);
        Put(bytes, 672, firstAlias);
        Put(bytes, 704, 3, firstAlias, secondAlias, Handle(928, 1));
        Put(bytes, 736, seed);
        Put(bytes, 768, Handle(736, 0x27), 1, firstAlias, 1, 832);
        Put(bytes, 832, 2);
        Put(bytes, 864, 2, firstAlias, Handle(896, 0x3C));
        Put(bytes, 896, secondAlias, 1, Handle(928, 1));
        Put(bytes, 928, seed, 0, 0, 0);

        var metadata = RetainedMetadata(bytes, bits);
        var publication = metadata.PublishedSignatures;
        var declarations = metadata.SignatureDeclarations.ToArray();

        for (int replay = 0; replay < 1000; ++replay) {
            Reject(() => metadata.Constant(Handle(704, 0x0D)));
            Reject(() => metadata.Constant(Handle(864, 0x0D)));
            Reject(() => metadata.AttributePayload(768));
            Check(ReferenceEquals(publication, metadata.PublishedSignatures));
            Check(metadata.SignatureDeclarations.Select(entry => entry.Key)
                .SequenceEqual(declarations.Select(entry => entry.Key)));
        }

        Put(bytes, 704, 3, firstAlias, secondAlias, Handle(928, 0x14));
        var values = (System.Collections.ObjectModel.ReadOnlyCollection<MetadataValue>)
            metadata.Constant(Handle(704, 0x0D)).Value!;
        Check(values.Count == 3 && values[2].Kind == "null");
        Check((string)values[0].Value! == "Namespace.Type"
            && (string)values[1].Value! == "Namespace.Type");
        Check(metadata.ReadTypeSignature(firstAlias).Render() == "Namespace.Type"
            && metadata.ReadTypeSignature(secondAlias).Render() == "Namespace.Type");
        Check(ReferenceEquals(publication, metadata.PublishedSignatures));
        Check(metadata.SignatureDeclarations.Count() == declarations.Length + 2);

        // A later failed operation reuses both aliases without retracting them.
        Reject(() => metadata.AttributePayload(768));
        Check(metadata.SignatureDeclarations.Count() == declarations.Length + 2);
        Put(bytes, 832, 0, 576, seed, Handle(928, 0x14));
        var attribute = metadata.AttributePayload(768);
        Check(attribute.Type == "Namespace.Type"
            && attribute.FixedArgumentValues.Length == 1
            && attribute.NamedArgumentValues.Length == 1);
    }

    private static void CheckRecords(int bits) {
        foreach (bool method in new[] { true, false }) {
            byte[] bytes = ScopeFixture(bits);
            byte[] malformed = method ? [0, 0, 0, 0, 0, 2, 84, 2] : [0, 0, 0, 0, 0, 0, 4, 84, 31];
            int start = bytes.Length - malformed.Length;
            malformed.CopyTo(bytes, start);
            uint offset = (uint)start + 1;
            var metadata = RetainedMetadata(bytes, bits);
            var graph = metadata.PublishedSignatures;
            var methods = metadata.MethodDefinitions.ToArray();
            var fields = metadata.FieldDefinitions.ToArray();
            var handles = metadata.DefinitionHandles.ToArray();
            var declarations = metadata.SignatureDeclarations;
            var scopes = metadata.ReferencedScopes;

            for (int replay = 0; replay < 3; ++replay) {
                if (method)
                    Reject(() => metadata.ReadMethodDefinition(offset));
                else
                    Reject(() => metadata.ReadFieldDefinition(offset));

                Check(metadata.MethodDefinitions.SequenceEqual(methods)
                    && metadata.FieldDefinitions.SequenceEqual(fields)
                    && metadata.DefinitionHandles.SequenceEqual(handles));
                Check(metadata.ReadMethodDefinition(448).Equals(methods[0])
                    && metadata.ReadFieldDefinition(512).Equals(fields[0]));
                CheckPublicState(metadata, graph, declarations, scopes);
            }

            if (method)
                bytes.AsSpan(start + 1).Clear();
            else
                bytes[^1] = 0;

            if (method) {
                var corrected = metadata.ReadMethodDefinition(offset);
                Check(corrected.Offset == offset && corrected.Parameters.Count == 0
                    && corrected.GenericParameters.Count == 0 && corrected.Attributes.Count == 0);
                Check(metadata.MethodDefinitions.Length == methods.Length + 1
                    && metadata.DefinitionHandles.SequenceEqual(handles));
                Check(metadata.ReadMethodDefinition(offset).Equals(corrected));
            } else {
                var corrected = metadata.ReadFieldDefinition(offset);
                Check(corrected.Offset == offset && corrected.Attributes.Count == 2);
                Check(metadata.FieldDefinitions.Length == fields.Length + 1
                    && metadata.DefinitionHandles[..handles.Length].SequenceEqual(handles)
                    && metadata.DefinitionHandles[handles.Length..].SequenceEqual([42U, 0U]));
                Check(metadata.ReadFieldDefinition(offset).Equals(corrected));
            }

            CheckPublicState(metadata, graph, declarations, scopes);
        }
    }

    private static void CheckPublicSignatures(int bits) {
        uint Handle(int offset, uint kind) => ((uint)offset << bits) | kind;

        foreach (bool method in new[] { true, false }) {
            byte[] bytes = ScopeFixture(bits);
            Text(bytes, 832, "OtherNamespace");
            Text(bytes, 864, "OtherType");
            Text(bytes, 896, "OtherAssembly");
            Put(bytes, 640, Handle(672, 0x30), 864);
            Put(bytes, 672, Handle(704, 0x39), 832);
            Put(bytes, 704, 0, 896);
            Put(bytes, 768, 0, 0, Handle(640, 0x3D), 1, Handle(928, 1), 0);
            Put(bytes, 928, Handle(640, 0x3D), 33, 0, 0);

            var metadata = RetainedMetadata(bytes, bits);
            var graph = metadata.PublishedSignatures;
            var declarations = metadata.SignatureDeclarations;
            var scopes = metadata.ReferencedScopes;
            var methods = metadata.MethodDefinitions.ToArray();
            var fields = metadata.FieldDefinitions.ToArray();
            var handles = metadata.DefinitionHandles.ToArray();

            for (int replay = 0; replay < 3; ++replay) {
                if (method)
                    Reject(() => metadata.ReadMethodSignature(768));
                else
                    Reject(() => metadata.ReadTypeSignature(Handle(928, 1)));

                Check(metadata.MethodDefinitions.SequenceEqual(methods)
                    && metadata.FieldDefinitions.SequenceEqual(fields)
                    && metadata.DefinitionHandles.SequenceEqual(handles));
                CheckPublicState(metadata, graph, declarations, scopes);
                Check(metadata.ReadTypeSignature(Handle(128, 0x3D)).Render() == "Namespace.Type");
                Check(ReferenceEquals(graph, metadata.ReadMethodSignature(288).Publication));
            }

            Put(bytes, 928, Handle(640, 0x3D), 1, 0, 0);
            var expected = RetainedMetadata(bytes, bits);

            if (method) {
                var corrected = metadata.ReadMethodSignature(768);
                Check(corrected.Render("Corrected") == expected.ReadMethodSignature(768).Render("Corrected"));
            } else {
                var corrected = metadata.ReadTypeSignature(Handle(928, 1));
                Check(corrected.Render() == expected.ReadTypeSignature(Handle(928, 1)).Render());
            }

            Check(metadata.SignatureBuilder.Nodes.SequenceEqual(expected.SignatureBuilder.Nodes)
                && metadata.SignatureBuilder.Edges.SequenceEqual(expected.SignatureBuilder.Edges)
                && metadata.SignatureBuilder.Methods.SequenceEqual(expected.SignatureBuilder.Methods));
            Check(metadata.ReferencedScopes.Select(scope => scope.Name)
                .SequenceEqual(expected.ReferencedScopes.Select(scope => scope.Name)));
            Check(scopes.Single().Name == "Assembly" && declarations.Single().Value.Render() == "Namespace.Type");
        }
    }

    private static byte[] ScopeFixture(int bits) {
        uint Handle(int offset, uint kind) => ((uint)offset << bits) | kind;
        var bytes = new byte[1024];
        Text(bytes, 32, "Namespace");
        Text(bytes, 64, "Type");
        Text(bytes, 96, "Assembly");
        Text(bytes, 576, "Member");
        Put(bytes, 128, Handle(160, 0x30), 64);
        Put(bytes, 160, Handle(192, 0x39), 32);
        Put(bytes, 192, 0, 96);
        Put(bytes, 288, 0, 0, Handle(128, 0x3D), 0, 0);
        Put(bytes, 448, 0, 0, 576, 288, 1, 42, 0, 0);
        Put(bytes, 512, 0, 576, 224, 0, 0, 1, 84);

        return bytes;
    }

    private static Metadata RetainedMetadata(byte[] bytes, int bits) {
        var metadata = new Metadata(bytes, bits, legacyConstants: false, takeOwnership: true);
        metadata.ReadMethodDefinition(448);
        metadata.ReadFieldDefinition(512);
        metadata.ReadTypeSignature(((uint)128 << bits) | 0x3D);
        metadata.ReadMethodSignature(288);

        return metadata;
    }

    private static void CheckPublicState(
        Metadata metadata,
        Signatures graph,
        IEnumerable<KeyValuePair<uint, SignatureType>> declarations,
        IEnumerable<MetadataScopeReference> scopes) {
        Check(ReferenceEquals(graph, metadata.PublishedSignatures));
        Check(metadata.SignatureDeclarations.Select(entry => (entry.Key, entry.Value.Render()))
            .SequenceEqual(declarations.Select(entry => (entry.Key, entry.Value.Render()))));
        Check(metadata.ReferencedScopes.Select(scope => (scope.Offset, scope.Name))
            .SequenceEqual(scopes.Select(scope => (scope.Offset, scope.Name))));
        Check(declarations.All(entry => ReferenceEquals(graph, entry.Value.Publication)));
    }

    private static void Unchanged(Metadata metadata, Signatures before) {
        Check(ReferenceEquals(before, metadata.SignatureBuilder.Publish()));
        Check(!metadata.TypeSignatureHandles.Any() && !metadata.ReferencedScopes.Any());
    }

    private static void Reject(Action action) {
        try {
            action();
        } catch (InvalidDataException) {
            return;
        }

        throw new Exception("Malformed compound metadata input was accepted.");
    }

    private static void Check(bool condition) {
        if (!condition)
            throw new Exception("Metadata transaction invariant failed.");
    }

    private static void Put(byte[] bytes, int offset, params uint[] values) {
        foreach (uint value in values) {
            bytes[offset++] = 15;
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset, 4), value);
            offset += 4;
        }
    }

    private static void Text(byte[] bytes, int offset, string text) {
        int length = Encoding.UTF8.GetByteCount(text);
        Put(bytes, offset, (uint)length);
        Encoding.UTF8.GetBytes(text, bytes.AsSpan(offset + 5));
    }
}
