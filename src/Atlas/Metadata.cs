using System.Collections.Frozen;
using System.Collections.ObjectModel;

namespace Atlas;

public readonly struct IndexRange(int start, int count) {
    public readonly int Start = start;
    public readonly int Count = count;

    public int End => Start + Count;
}

public struct MetadataScope {
    public uint Offset;
    public uint Flags;

    public uint RootNamespace;
    public string Name;

    public ushort Major;
    public ushort Minor;
    public ushort Build;
    public ushort Revision;

    internal ReadOnlyMemory<byte> PublicKey;
    public ReadOnlySpan<byte> PublicKeyBytes => PublicKey.Span;
    public string Culture;
}

public struct MetadataType {
    public uint Offset;
    public uint Scope;
    public uint Flags;

    public uint BaseType;
    public uint Namespace;
    public uint EnclosingType;

    public uint Size;
    public uint Packing;

    public string Name;

    public IndexRange NestedTypes;
    public IndexRange Methods;
    public IndexRange Fields;
    public IndexRange Properties;
    public IndexRange Events;

    public IndexRange GenericParameters;
    public IndexRange Interfaces;
    public IndexRange Attributes;
}

public struct MetadataMethod {
    public uint Offset;
    public uint Flags;
    public uint ImplementationFlags;

    public uint SignatureOffset;
    public string Name;

    public IndexRange Parameters;
    public IndexRange GenericParameters;
    public IndexRange Attributes;

    internal int Signature;
    public uint UniqueOwner;
    public bool Shared;
}

public struct MetadataField {
    public uint Offset;
    public uint Flags;
    public MetadataFactStatus FlagsStatus;

    public uint SignatureOffset;
    public uint DefaultValue;
    public MetadataFactStatus DefaultValueStatus;
    public uint ExplicitOffset;
    public MetadataFactStatus ExplicitOffsetStatus;

    public string Name;
    public IndexRange Attributes;
    internal int Signature;
}

public readonly struct MetadataForwarder(uint offset, uint sourceScope, string name, string assembly) {
    public readonly uint Offset = offset;
    public readonly uint SourceScope = sourceScope;
    public readonly string Name = name;
    public readonly string Assembly = assembly;
}

public readonly struct MetadataAttribute(
    uint ownerType,
    uint ownerMethod,
    uint offset,
    uint constructor,
    int type) {
    public readonly uint OwnerType = ownerType;
    public readonly uint OwnerMethod = ownerMethod;
    public readonly uint Offset = offset;
    public readonly uint Constructor = constructor;
    internal readonly int Type = type;
}

public readonly record struct MetadataProjectionDiagnostic(uint Handle, string Projection, string Error);

public sealed class Metadata {
    internal readonly ReadOnlyMemory<byte> Data;
    public ReadOnlySpan<byte> Bytes => Data.Span;
    public int HandleBits { get; }
    public bool LegacyConstants { get; }
    public MetadataFacts Facts { get; }
    public Signatures PublishedSignatures { get; }
    public MetadataMembers Members { get; }
    public bool IsComplete => Facts.Status == MetadataFactStatus.Valid && diagnostics.Count == 0;

    private readonly MetadataScope[] scopes;
    private readonly MetadataType[] types;
    private readonly MetadataMethod[] methods;
    private readonly MetadataField[] fields;
    private readonly MetadataForwarder[] forwarders;
    private readonly MetadataAttribute[] attributes;
    private readonly uint[] handles;
    private readonly FrozenDictionary<uint, string> strings;
    private readonly FrozenDictionary<uint, string> names;
    private readonly FrozenDictionary<uint, int> signatureIndex;
    private readonly FrozenDictionary<uint, int> methodSignatureIndex;
    private readonly FrozenDictionary<uint, MetadataConstantData> constants;
    private readonly FrozenDictionary<uint, MetadataAttributePayload> attributePayloads;
    private readonly FrozenDictionary<(uint Offset, bool Module), ReadOnlyCollection<MetadataAttributePayload>> scopePayloads;
    private readonly ReadOnlyCollection<MetadataScopeReference> referencedScopes;
    private readonly ReadOnlyCollection<MetadataProjectionDiagnostic> diagnostics;
    private readonly FrozenDictionary<(uint Handle, string Projection), string> projectionErrors;

    internal FrozenDictionary<uint, int> TypeIndex { get; }
    internal FrozenDictionary<uint, int> MethodIndex { get; }
    internal FrozenDictionary<uint, int> FieldIndex { get; }
    internal ReadOnlySpan<MetadataScope> Scopes => scopes;
    internal ReadOnlySpan<MetadataType> Types => types;
    internal ReadOnlySpan<MetadataMethod> Methods => methods;
    internal ReadOnlySpan<MetadataField> Fields => fields;
    internal ReadOnlySpan<uint> Handles => handles;

    public ReadOnlySpan<MetadataScope> ScopeDefinitions => scopes;
    public ReadOnlySpan<MetadataType> TypeDefinitions => types;
    public ReadOnlySpan<MetadataMethod> MethodDefinitions => methods;
    public ReadOnlySpan<MetadataField> FieldDefinitions => fields;
    public ReadOnlySpan<MetadataForwarder> TypeForwarders => forwarders;
    public ReadOnlySpan<MetadataAttribute> AttributeDefinitions => attributes;
    public ReadOnlySpan<uint> DefinitionHandles => handles;
    public IReadOnlyList<MetadataProjectionDiagnostic> ProjectionDiagnostics => diagnostics;
    public IReadOnlyList<MetadataScopeReference> ReferencedScopes => referencedScopes;
    internal IEnumerable<KeyValuePair<uint, int>> TypeSignatureHandles => signatureIndex;

    public IEnumerable<KeyValuePair<uint, SignatureType>> SignatureDeclarations {
        get {
            foreach (var entry in signatureIndex)
                yield return new(entry.Key, PublishedSignatures.Types[entry.Value]);
        }
    }

    internal Metadata(MetadataBuilder source, MetadataFacts facts, Signatures signatures, MetadataMembers members) {
        Data = source.Data;
        HandleBits = source.HandleBits;
        LegacyConstants = source.LegacyConstants;
        Facts = facts;
        PublishedSignatures = signatures;
        Members = members;
        scopes = source.Scopes.ToArray();
        types = source.Types.ToArray();
        methods = source.Methods.ToArray();
        fields = source.Fields.ToArray();
        forwarders = source.Forwarders.ToArray();
        attributes = source.Attributes.ToArray();
        handles = source.Handles.ToArray();
        strings = source.Strings.ToFrozenDictionary();
        names = source.DefinitionNames.ToFrozenDictionary();
        signatureIndex = source.SignatureIndex.ToFrozenDictionary();
        methodSignatureIndex = source.MethodSignatureIndex.ToFrozenDictionary();
        constants = source.Constants.ToFrozenDictionary();
        attributePayloads = source.AttributePayloads.ToFrozenDictionary();
        scopePayloads = source.ScopePayloads.ToFrozenDictionary();
        referencedScopes = Array.AsReadOnly(source.ReferencedScopes.ToArray());
        diagnostics = Array.AsReadOnly(source.Diagnostics.ToArray());
        projectionErrors = source.Diagnostics.ToFrozenDictionary(
            diagnostic => (diagnostic.Handle, diagnostic.Projection), diagnostic => diagnostic.Error);
        TypeIndex = source.TypeIndex.ToFrozenDictionary();
        MethodIndex = source.MethodIndex.ToFrozenDictionary();
        FieldIndex = source.FieldIndex.ToFrozenDictionary();
    }

    public static Metadata FromImage(PeImage image, ReadyToRun header,
        CancellationToken cancellationToken = default) =>
        MetadataBuilder.FromImage(image, header, cancellationToken).Publish(cancellationToken);

    public static Metadata Read(ReadOnlyMemory<byte> source, MetadataEncoding encoding,
        ReadOnlySpan<MetadataRecordId> roots = default, CancellationToken cancellationToken = default) {
        var builder = new MetadataBuilder(source.ToArray(), encoding, cancellationToken);
        foreach (var root in roots)
            builder.AddRoot(root);
        return builder.Publish(cancellationToken);
    }

    public string String(uint offset) => offset == 0 ? "" : Lookup(strings, offset, "string");
    public string DefinitionName(uint offset, int depth = 0) => Lookup(names, offset, "type name");
    public MetadataMethod ReadMethodDefinition(uint offset) => methods[Lookup(MethodIndex, offset, "method")];
    public MetadataField ReadFieldDefinition(uint offset) => fields[Lookup(FieldIndex, offset, "field")];
    public SignatureType ReadTypeSignature(uint handle) => handle >> HandleBits == 0
        ? PublishedSignatures.Types[0]
        : PublishedSignatures.Types[Lookup(signatureIndex, handle, "type signature")];
    public SignatureMethod ReadMethodSignature(uint offset) => offset == 0
        ? PublishedSignatures.MethodSignatures[0]
        : PublishedSignatures.MethodSignatures[Lookup(methodSignatureIndex, offset, "method signature")];
    internal int TypeSignature(uint handle) => handle >> HandleBits == 0
        ? 0 : Lookup(signatureIndex, handle, "type signature");
    internal int MethodSignature(uint offset) => offset == 0
        ? 0 : Lookup(methodSignatureIndex, offset, "method signature");
    internal int ReadMethod(uint offset) => Lookup(MethodIndex, offset, "method");
    public SignatureType TypeSignatureAt(int position) =>
        ReadTypeSignature((types[position].Offset << HandleBits) | 0x3A);
    public SignatureMethod MethodSignatureAt(int position) => ReadMethodSignature(methods[position].SignatureOffset);
    public SignatureType FieldSignatureAt(int position) => PublishedSignatures.Types[fields[position].Signature];
    public SignatureType AttributeTypeAt(int position) => PublishedSignatures.Types[attributes[position].Type];

    public MetadataValue Constant(uint handle, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        return handle == 0 ? new(0, "absent", null) : Lookup(constants, handle, "constant").WithHandle(handle);
    }

    public bool TryConstant(uint handle, out MetadataValue value) => TryConstant(handle, out value, out _);

    public bool TryConstant(uint handle, out MetadataValue value, out string? error) {
        if (handle == 0) {
            value = new(0, "absent", null);
            error = null;
            return true;
        }
        bool found = constants.TryGetValue(handle, out var stored);
        value = found ? stored.WithHandle(handle) : default;
        error = found ? null : ProjectionError(handle, "constant");
        return found;
    }

    public MetadataAttributePayload AttributePayload(uint offset, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        return Lookup(attributePayloads, offset, "attribute payload");
    }

    public bool TryAttributePayload(uint offset, out MetadataAttributePayload value) =>
        TryAttributePayload(offset, out value, out _);

    public bool TryAttributePayload(uint offset, out MetadataAttributePayload value, out string? error) {
        bool found = attributePayloads.TryGetValue(offset, out value);
        error = found ? null : ProjectionError((offset << HandleBits) | (uint)MetadataRecordKind.CustomAttribute, "attribute payload");
        return found;
    }

    public ReadOnlyCollection<MetadataAttributePayload> ScopeAttributePayloads(uint offset,
        bool module = false, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        return Lookup(scopePayloads, (offset, module), "scope attribute payload");
    }

    public bool TryScopeAttributePayloads(uint offset, bool module,
        out ReadOnlyCollection<MetadataAttributePayload> values) =>
        TryScopeAttributePayloads(offset, module, out values, out _);

    public bool TryScopeAttributePayloads(uint offset, bool module,
        out ReadOnlyCollection<MetadataAttributePayload> values, out string? error) {
        bool found = scopePayloads.TryGetValue((offset, module), out var result);
        values = result ?? Array.AsReadOnly(Array.Empty<MetadataAttributePayload>());
        error = found ? null : ProjectionError((offset << HandleBits) | (uint)MetadataRecordKind.ScopeDefinition,
            module ? "module attributes" : "scope attributes");
        return found;
    }

    public bool TryReadTypeSignature(uint handle, out SignatureType signature) {
        bool found = handle >> HandleBits == 0 || signatureIndex.ContainsKey(handle);
        signature = found ? ReadTypeSignature(handle) : default;
        return found;
    }

    public bool TryReadMethodSignature(uint offset, out SignatureMethod signature) {
        bool found = offset != 0 && methodSignatureIndex.ContainsKey(offset);
        signature = found ? ReadMethodSignature(offset) : default;
        return found;
    }

    private string ProjectionError(uint handle, string projection) {
        return projectionErrors.TryGetValue((handle, projection), out string? error)
            ? error : $"Metadata {projection} projection for 0x{handle:X} is unavailable.";
    }

    private static TValue Lookup<TKey, TValue>(FrozenDictionary<TKey, TValue> table, TKey key, string projection)
        where TKey : notnull => table.TryGetValue(key, out TValue? result)
            ? result
            : throw new InvalidDataException($"Metadata {projection} projection for {key} is unavailable.");
}
