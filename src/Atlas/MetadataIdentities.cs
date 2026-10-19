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

internal sealed partial class MetadataBuilder {
    private void ReadScopeReference(uint offset) {
        if (referencedScopes.ContainsKey(offset))
            return;
        var id = Id(MetadataRecordKind.ScopeReference, offset);
        var key = RecordField(id, MetadataFieldName.PublicKeyOrToken).Items;
        byte[] bytes = new byte[key.Count];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = checked((byte)key[i].UInt32.Value);
        referencedScopes.Add(offset, new(offset,
            UInt(id, MetadataFieldName.Flags), Name(id),
            checked((ushort)UInt(id, MetadataFieldName.MajorVersion)),
            checked((ushort)UInt(id, MetadataFieldName.MinorVersion)),
            checked((ushort)UInt(id, MetadataFieldName.BuildNumber)),
            checked((ushort)UInt(id, MetadataFieldName.RevisionNumber)),
            bytes, Name(id, MetadataFieldName.Culture)));
    }

    private uint DefinitionScope(uint offset) {
        if (TypeIndex.TryGetValue(offset, out int index))
            return Types[index].Scope;
        uint ns = DefinitionNamespace(offset);
        if (ns == 0)
            return 0;
        NamespaceName(ns, 0);
        return namespaces[ns].Scope;
    }

    private uint DefinitionNamespace(uint offset) {
        for (int depth = 0; depth <= 256; depth++) {
            if (TypeIndex.TryGetValue(offset, out int index))
                return Types[index].Namespace;
            var owner = TypeOwnership(Id(MetadataRecordKind.TypeDefinition, offset));
            if (owner.Enclosing == 0)
                return owner.Namespace;
            offset = owner.Enclosing;
        }
        throw new InvalidDataException("Type definition namespace exceeds the supported nesting depth.");
    }
}
