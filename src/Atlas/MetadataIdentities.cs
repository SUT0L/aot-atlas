namespace Atlas;

public readonly record struct MetadataScopeReference {
    public readonly uint Offset;
    public readonly uint Flags;
    public readonly string Name;
    public readonly ushort Major;
    public readonly ushort Minor;
    public readonly ushort Build;
    public readonly ushort Revision;
    internal ReadOnlyMemory<byte> PublicKeyOrToken { get; init; }
    public readonly string Culture;
    public ReadOnlySpan<byte> PublicKeyBytes => PublicKeyOrToken.Span;

    internal MetadataScopeReference(
        uint offset,
        uint flags,
        string name,
        ushort major,
        ushort minor,
        ushort build,
        ushort revision,
        ReadOnlyMemory<byte> publicKeyOrToken,
        string culture) {
        Offset = offset;
        Flags = flags;
        Name = name;
        Major = major;
        Minor = minor;
        Build = build;
        Revision = revision;
        PublicKeyOrToken = publicKeyOrToken;
        Culture = culture;
    }
}

public sealed partial class Metadata {
    private Dictionary<uint, MetadataScopeReference> referencedScopes => state.ReferencedScopes;

    public IEnumerable<MetadataScopeReference> ReferencedScopes {
        get => Array.AsReadOnly(referencedScopes.Values.ToArray());
    }

    internal IEnumerable<KeyValuePair<uint, int>> TypeSignatureHandles {
        get {
            foreach (var signature in signatureIndex)
                yield return signature;
        }
    }

    public IEnumerable<KeyValuePair<uint, SignatureType>> SignatureDeclarations {
        get {
            var publication = SignatureBuilder.Publish();
            var declarations = new KeyValuePair<uint, SignatureType>[signatureIndex.Count];
            int position = 0;

            foreach (var signature in signatureIndex)
                declarations[position++] = new(signature.Key, publication.Types[signature.Value]);

            return Array.AsReadOnly(declarations);
        }
    }

    private void ReadScopeReference(uint offset) {
        if (referencedScopes.ContainsKey(offset))
            return;

        var reader = Reader(offset);
        uint flags = reader.Unsigned();
        string name = String(reader.Unsigned());

        ushort major = checked((ushort)reader.Unsigned());
        ushort minor = checked((ushort)reader.Unsigned());
        ushort build = checked((ushort)reader.Unsigned());
        ushort revision = checked((ushort)reader.Unsigned());

        uint length = reader.Unsigned();
        int start = reader.Position;
        reader.Take(checked((int)length));
        string culture = String(reader.Unsigned());

        state.ReferencedScopeOrder.EnsureCapacity(checked(state.ReferencedScopeOrder.Count + 1));
        referencedScopes.Add(offset, new(
            offset, flags, name,
            major, minor, build, revision,
            Data.Slice(start, (int)length), culture));
        state.ReferencedScopeOrder.Add(offset);
    }

    private uint DefinitionScope(uint offset) {
        // DefinitionName already validated this ancestry and populated its namespace.
        for (int depth = 0; depth <= 256; ++depth) {
            if (TypeIndex.TryGetValue(offset, out int index))
                return Types[index].Scope;

            var reader = Reader(offset);
            reader.Unsigned();
            reader.Unsigned();

            uint ns = reader.Unsigned();
            reader.Unsigned();
            reader.Unsigned();
            reader.Unsigned();
            uint enclosing = reader.Unsigned();

            if (enclosing == 0)
                return ns == 0 ? 0 : namespaces[ns].Scope;

            offset = enclosing;
        }

        throw new InvalidDataException("Type definition scope exceeds the supported nesting depth.");
    }
}
