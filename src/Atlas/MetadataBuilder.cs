using System.Collections.ObjectModel;
using System.Runtime.InteropServices;

namespace Atlas;

internal sealed partial class MetadataBuilder {
    internal readonly ReadOnlyMemory<byte> Data;
    internal readonly MetadataEncoding Encoding;
    internal int HandleBits => Encoding.HandleBits;
    internal bool LegacyConstants => Encoding.LegacyConstants;
    internal ReadOnlySpan<byte> Bytes => Data.Span;
    internal ReadOnlySpan<MetadataType> TypeDefinitions => CollectionsMarshal.AsSpan(Types);
    internal ReadOnlySpan<MetadataMethod> MethodDefinitions => CollectionsMarshal.AsSpan(Methods);
    internal ReadOnlySpan<MetadataField> FieldDefinitions => CollectionsMarshal.AsSpan(Fields);
    internal ReadOnlySpan<uint> DefinitionHandles => CollectionsMarshal.AsSpan(Handles);
    private readonly MetadataFacts.Builder facts;
    private readonly CancellationToken constructionCancellation;
    private bool definitionsRead;
    private bool published;

    internal readonly List<MetadataScope> Scopes = new();
    internal readonly List<MetadataType> Types = new();
    internal readonly List<MetadataMethod> Methods = new();
    internal readonly List<MetadataField> Fields = new();
    internal readonly List<MetadataForwarder> Forwarders = new();
    internal readonly List<MetadataAttribute> Attributes = new();
    internal readonly List<uint> Handles = new();
    internal readonly Dictionary<uint, int> TypeIndex = new();
    internal readonly Dictionary<uint, int> MethodIndex = new();
    internal readonly Dictionary<uint, int> FieldIndex = new();
    private readonly Dictionary<uint, int> scopeIndex = new();
    internal readonly Dictionary<uint, string> Strings = new();
    private readonly Dictionary<uint, (uint Scope, string Name)> namespaces = new();
    internal readonly Dictionary<uint, string> DefinitionNames = new();
    internal readonly Dictionary<uint, MetadataConstantData> Constants = new();
    internal readonly Dictionary<uint, MetadataAttributePayload> AttributePayloads = new();
    internal readonly Dictionary<(uint Offset, bool Module), ReadOnlyCollection<MetadataAttributePayload>> ScopePayloads = new();
    internal readonly List<MetadataProjectionDiagnostic> Diagnostics = new();
    private readonly HashSet<(uint Handle, string Projection)> failedProjections = new();
    private readonly HashSet<uint> forwardedRecords = new();
    internal SignatureBuilder SignatureBuilder { get; }
    internal Signatures PublishedSignatures => SignatureBuilder.Publish();
    internal readonly Dictionary<uint, int> SignatureIndex = new();
    internal readonly Dictionary<uint, int> MethodSignatureIndex = new();
    private readonly Dictionary<uint, (string Name, uint Scope)> referenceNames = new();
    private readonly Dictionary<uint, MetadataScopeReference> referencedScopes = new();
    internal IEnumerable<MetadataScopeReference> ReferencedScopes => referencedScopes.Values;
    internal IEnumerable<KeyValuePair<uint, int>> TypeSignatureHandles => SignatureIndex;

    internal MetadataMembersBuilder MembersBuilder { get; }

    internal MetadataBuilder(ReadOnlyMemory<byte> data, int handleBits, bool legacyConstants = false)
        : this(data.ToArray(), new MetadataEncoding(handleBits, legacyConstants), default) {
    }

    internal MetadataBuilder(ReadOnlyMemory<byte> data, int handleBits, bool legacyConstants, bool takeOwnership)
        : this(takeOwnership ? data : data.ToArray(), new MetadataEncoding(handleBits, legacyConstants)) {
    }

    internal MetadataBuilder(ReadOnlyMemory<byte> data, MetadataEncoding encoding,
        CancellationToken cancellationToken = default, MetadataFacts.Builder? sourceFacts = null) {
        encoding.Validate();
        cancellationToken.ThrowIfCancellationRequested();
        Data = data;
        Encoding = encoding;
        constructionCancellation = cancellationToken;
        facts = sourceFacts ?? new(Data, encoding, MetadataReadLimits.Default, cancellationToken);
        SignatureBuilder = new(1, 0, 1);
        MembersBuilder = new(this);
    }

    internal static MetadataBuilder FromImage(PeImage image, ReadyToRun header, CancellationToken cancellationToken = default) {
        header = header.ValidateSource(image);
        var section = header.Find(RtrSectionId.EmbeddedMetadata);
        ReadOnlyMemory<byte> data = section.Length == 0
            ? default
            : image.FileMemory(section.Start, checked((int)section.Length)).ToArray();
        return new(data, new MetadataEncoding(header.MetadataHandleBits, header.Format.LegacyMetadataConstants,
            header.Format.CombinedMetadataTypeOwnership), cancellationToken);
    }

    internal Metadata Publish(CancellationToken cancellationToken = default) {
        EnsureMutable();
        cancellationToken.ThrowIfCancellationRequested();
        ReadDefinitions(cancellationToken);
        MaterializeRemaining(cancellationToken);
        MembersBuilder.ReadAll(cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        var sourceFacts = facts.Build();
        var signatures = SignatureBuilder.Publish();
        var members = MembersBuilder.Publish(signatures);
        cancellationToken.ThrowIfCancellationRequested();
        var snapshot = new Metadata(this, sourceFacts, signatures, members);
        published = true;
        return snapshot;
    }

    private void EnsureMutable() {
        if (published)
            throw new InvalidOperationException("Metadata construction has already been published.");
        constructionCancellation.ThrowIfCancellationRequested();
    }

    internal NativeReader Reader(uint offset) {
        EnsureMutable();
        if (offset == 0 || offset >= Data.Length)
            throw new InvalidDataException($"Metadata record offset 0x{offset:X} is outside the blob.");
        return new(Data.Span, (int)offset);
    }

    internal void AddRoot(MetadataRecordId id) {
        EnsureMutable();
        facts.AddRoot(id);
        facts.ReadRoots();
    }

    internal MetadataDecodedField RecordField(MetadataRecordId id, MetadataFieldName name) {
        AddRoot(id);
        return facts.Field(id, name);
    }

    internal MetadataFact<string> RecordName(MetadataNameId id) {
        AddRoot(id.Record);
        return facts.Name(id);
    }

    internal string String(uint offset) {
        if (offset == 0)
            return "";
        if (Strings.TryGetValue(offset, out string? name))
            return name;
        if (offset > 0x01FFFFFF || offset >= Data.Length)
            throw new InvalidDataException($"Metadata string offset 0x{offset:X} is outside the blob.");
        var value = RecordName(new(offset));
        if (!value.IsAvailable)
            throw new InvalidDataException($"Metadata string at 0x{offset:X} is unavailable ({value.Status}).");
        Strings.Add(offset, value.Value);
        return value.Value;
    }

    internal IEnumerable<MetadataRecordId> ReadRecordIds() => facts.ReadRecordIds();

    private MetadataRecordId Id(MetadataRecordKind kind, uint offset) {
        if (offset > 0x01FFFFFF)
            throw new InvalidDataException($"Metadata record offset 0x{offset:X} exceeds its encoded range.");
        return new(kind, offset);
    }

    private MetadataRecordId Decode(uint raw) {
        uint kind = raw & ((1U << HandleBits) - 1);
        if (kind > 63 || (kind == 0 && raw >> HandleBits != 0))
            throw new InvalidDataException($"Metadata handle 0x{raw:X} has an invalid record kind.");
        return Encoding.DecodeHandle(raw);
    }
    private uint Raw(MetadataRecordId id) => Encoding.EncodeHandle(id);

    internal uint UInt(MetadataRecordId id, MetadataFieldName name) => Required(RecordField(id, name).UInt32, id, name);
    internal int Int(MetadataRecordId id, MetadataFieldName name) => Required(RecordField(id, name).Int32, id, name);
    internal MetadataRecordId Reference(MetadataRecordId id, MetadataFieldName name) => Required(RecordField(id, name).Reference, id, name);
    internal uint Handle(MetadataRecordId id, MetadataFieldName name) => Raw(Reference(id, name));
    internal uint Offset(MetadataRecordId id, MetadataFieldName name) => Reference(id, name).Offset;

    private static T Required<T>(MetadataFact<T> fact, MetadataRecordId id, MetadataFieldName name) {
        if (!fact.IsAvailable)
            throw new InvalidDataException($"Metadata {id.Kind}.{name} at 0x{id.Offset:X} is unavailable ({fact.Status}).");
        return fact.Value;
    }

    internal string Name(MetadataRecordId id, MetadataFieldName field = MetadataFieldName.Name) {
        try {
            return String(Offset(id, field));
        } catch (InvalidDataException error) {
            RecordFailure(Raw(id), field.ToString(), error);
            return "";
        }
    }

    private uint AvailableUInt(MetadataRecordId id, MetadataFieldName field, out MetadataFactStatus status) {
        var value = RecordField(id, field).UInt32;
        status = value.Status;
        if (value.IsAvailable && value.Source.IsAvailable)
            return value.Value;
        RecordFailure(Raw(id), field.ToString(), new InvalidDataException($"Metadata {field} is unavailable ({status})."));
        return 0;
    }

    internal uint AvailableHandle(MetadataRecordId id, MetadataFieldName field, out MetadataFactStatus status) {
        var value = RecordField(id, field);
        var reference = value.Reference;
        status = reference.Status;
        const MetadataFactStatus undecoded = MetadataFactStatus.Truncated | MetadataFactStatus.InvalidEncoding
            | MetadataFactStatus.LimitExceeded | MetadataFactStatus.Absent;
        bool decoded = value.Source.IsAvailable && (value.Status & undecoded) == 0;
        if (status != MetadataFactStatus.Valid || !decoded)
            RecordFailure(Raw(id), field.ToString(), new InvalidDataException($"Metadata {field} is unavailable ({status})."));
        return decoded ? unchecked((uint)value.Bits) : 0;
    }

    internal void RecordFailure(uint handle, string projection, Exception error) {
        if (failedProjections.Add((handle, projection)))
            Diagnostics.Add(new(handle, projection, error.Message));
    }

    internal void Recover(MetadataRecordId id, string projection, Action read) {
        try {
            read();
        } catch (Exception error) when (error is InvalidDataException or OverflowException or NotSupportedException) {
            RecordFailure(Raw(id), projection, error);
        }
    }

    private IndexRange Collection(MetadataRecordId id, MetadataFieldName name, bool offsets = true) {
        var items = RecordField(id, name).Items;
        int start = Handles.Count;
        foreach (var item in items) {
            var reference = item.Reference;
            if (!reference.IsAvailable || reference.Value.IsNil) {
                RecordFailure(Raw(id), name.ToString(), new InvalidDataException($"Collection item is unavailable ({reference.Status})."));
                continue;
            }
            Handles.Add(offsets ? reference.Value.Offset : Raw(reference.Value));
        }
        if (items.Status != MetadataFactStatus.Valid)
            RecordFailure(Raw(id), name.ToString(), new InvalidDataException($"Collection is partial ({items.Status})."));
        return new(start, Handles.Count - start);
    }

    internal void ReadDefinitions(CancellationToken cancellationToken = default) {
        EnsureMutable();
        cancellationToken.ThrowIfCancellationRequested();
        if (definitionsRead)
            return;
        facts.ReadRoots();
        var records = facts.ReadRecordIds().ToArray();
        foreach (var id in records) {
            cancellationToken.ThrowIfCancellationRequested();
            if (id.Kind == MetadataRecordKind.ScopeDefinition)
                Recover(id, "scope", () => ReadScope(id));
        }
        foreach (var id in records) {
            cancellationToken.ThrowIfCancellationRequested();
            if (id.Kind == MetadataRecordKind.NamespaceDefinition)
                Recover(id, "namespace", () => NamespaceName(id.Offset, 0));
            else if (id.Kind == MetadataRecordKind.TypeDefinition)
                Recover(id, "type", () => ReadType(id));
            else if (id.Kind == MetadataRecordKind.Method)
                Recover(id, "method", () => ReadMethod(id.Offset));
            else if (id.Kind == MetadataRecordKind.Field)
                Recover(id, "field", () => ReadField(id.Offset));
            else if (id.Kind == MetadataRecordKind.ScopeReference)
                Recover(id, "scope reference", () => ReadScopeReference(id.Offset));
        }
        var collisions = Types.GroupBy(type => type.Name, StringComparer.Ordinal)
            .Where(group => group.Select(type => type.Scope).Distinct().Skip(1).Any())
            .Select(group => group.Key).ToHashSet(StringComparer.Ordinal);
        for (int i = 0; i < Types.Count; i++) {
            var type = Types[i];
            if (collisions.Contains(type.Name) && scopeIndex.TryGetValue(type.Scope, out int scope)) {
                type.Name = $"[{Scopes[scope].Name}@scope_{type.Scope:X}]{type.Name}";
                Types[i] = type;
                DefinitionNames[type.Offset] = type.Name;
            }
            for (int p = type.Methods.Start; p < type.Methods.End; p++) {
                if (!MethodIndex.TryGetValue(Handles[p], out int methodIndex))
                    continue;
                var method = Methods[methodIndex];
                if (method.UniqueOwner == 0)
                    method.UniqueOwner = type.Offset;
                else if (method.UniqueOwner != type.Offset)
                    method.Shared = true;
                Methods[methodIndex] = method;
            }
            Recover(Id(MetadataRecordKind.TypeDefinition, type.Offset), "attributes", () => ReadAttributes(type.Attributes, type.Offset, 0));
            for (int p = type.Methods.Start; p < type.Methods.End; p++) {
                if (MethodIndex.TryGetValue(Handles[p], out int methodIndex)) {
                    var method = Methods[methodIndex];
                    Recover(Id(MetadataRecordKind.Method, method.Offset), "attributes", () => ReadAttributes(method.Attributes, type.Offset, method.Offset));
                }
            }
        }
        foreach (var id in records) {
            cancellationToken.ThrowIfCancellationRequested();
            if (id.Kind != MetadataRecordKind.NamespaceDefinition || !namespaces.TryGetValue(id.Offset, out var owner))
                continue;
            var forwarders = RecordField(id, MetadataFieldName.TypeForwarders).Items;
            for (int i = 0; i < forwarders.Count; i++) {
                var forwarder = forwarders[i].Reference;
                if (forwarder.IsAvailable)
                    Recover(forwarder.Value, "type forwarder", () => ReadForwarder(forwarder.Value,
                        owner.Name.Length == 0 ? "" : owner.Name + ".", owner.Scope, new HashSet<uint>()));
            }
        }
        definitionsRead = true;
    }

    internal uint AvailableOffset(MetadataRecordId id, MetadataFieldName field) {
        uint offset = 0;
        Recover(id, field.ToString(), () => {
            offset = Offset(id, field);
            if (offset == 0)
                throw new InvalidDataException("Metadata signature reference is absent.");
        });
        return offset;
    }

    private void ReadScope(MetadataRecordId id) {
        if (scopeIndex.ContainsKey(id.Offset))
            return;
        var key = RecordField(id, MetadataFieldName.PublicKey).Items;
        byte[] bytes = new byte[key.Count];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = checked((byte)key[i].UInt32.Value);
        MetadataScope scope = new() {
            Offset = id.Offset,
            Flags = UInt(id, MetadataFieldName.Flags),
            Name = Name(id),
            Major = checked((ushort)UInt(id, MetadataFieldName.MajorVersion)),
            Minor = checked((ushort)UInt(id, MetadataFieldName.MinorVersion)),
            Build = checked((ushort)UInt(id, MetadataFieldName.BuildNumber)),
            Revision = checked((ushort)UInt(id, MetadataFieldName.RevisionNumber)),
            PublicKey = bytes,
            Culture = Name(id, MetadataFieldName.Culture),
            RootNamespace = Offset(id, MetadataFieldName.RootNamespaceDefinition)
        };
        scopeIndex.Add(id.Offset, Scopes.Count);
        Scopes.Add(scope);
    }

    private (uint Namespace, uint Enclosing) TypeOwnership(MetadataRecordId id) {
        AddRoot(id);
        var owner = Required(facts.TypeOwner(id), id, MetadataFieldName.NamespaceOrEnclosingType);
        return owner.Kind switch {
            MetadataRecordKind.NamespaceDefinition => (owner.Offset, 0),
            MetadataRecordKind.TypeDefinition => (0, owner.Offset),
            _ when owner.IsNil => (0, 0),
            _ => throw new InvalidDataException("Type definition has an invalid owner kind.")
        };
    }

    private MetadataRecordId ReferenceOwner(MetadataRecordId id) {
        AddRoot(id);
        return Required(facts.ReferenceOwner(id), id, MetadataFieldName.NamespaceOrEnclosingType);
    }

    private void ReadType(MetadataRecordId id) {
        if (TypeIndex.ContainsKey(id.Offset))
            return;
        var owner = TypeOwnership(id);
        MetadataType type = new() {
            Offset = id.Offset,
            Flags = UInt(id, MetadataFieldName.Flags),
            Scope = DefinitionScope(id.Offset),
            Name = DefinitionName(id.Offset),
            BaseType = Handle(id, MetadataFieldName.BaseType),
            Namespace = DefinitionNamespace(id.Offset),
            EnclosingType = owner.Enclosing,
            Size = UInt(id, MetadataFieldName.Size),
            Packing = UInt(id, MetadataFieldName.PackingSize),
            NestedTypes = Collection(id, MetadataFieldName.NestedTypes),
            Methods = Collection(id, MetadataFieldName.Methods),
            Fields = Collection(id, MetadataFieldName.Fields),
            Properties = Collection(id, MetadataFieldName.Properties),
            Events = Collection(id, MetadataFieldName.Events),
            GenericParameters = Collection(id, MetadataFieldName.GenericParameters),
            Interfaces = Collection(id, MetadataFieldName.Interfaces, offsets: false),
            Attributes = Collection(id, MetadataFieldName.CustomAttributes)
        };
        TypeIndex.Add(id.Offset, Types.Count);
        Types.Add(type);
    }

    internal MetadataMethod ReadMethodDefinition(uint offset) => Methods[ReadMethod(offset)];
    internal MetadataField ReadFieldDefinition(uint offset) => Fields[ReadField(offset)];

    internal int ReadMethod(uint offset) {
        if (MethodIndex.TryGetValue(offset, out int index))
            return index;
        var id = Id(MetadataRecordKind.Method, offset);
        MetadataMethod method = new() {
            Offset = offset,
            Flags = UInt(id, MetadataFieldName.Flags),
            ImplementationFlags = UInt(id, MetadataFieldName.ImplFlags),
            Name = Name(id),
            SignatureOffset = AvailableOffset(id, MetadataFieldName.Signature),
            Parameters = Collection(id, MetadataFieldName.Parameters),
            GenericParameters = Collection(id, MetadataFieldName.GenericParameters),
            Attributes = Collection(id, MetadataFieldName.CustomAttributes)
        };
        if (method.Flags > ushort.MaxValue || method.ImplementationFlags > ushort.MaxValue)
            throw new InvalidDataException("Method flags exceed their runtime field width.");
        index = Methods.Count;
        MethodIndex.Add(offset, index);
        Methods.Add(method);
        return index;
    }

    internal int ReadField(uint offset) {
        if (FieldIndex.TryGetValue(offset, out int index))
            return index;
        var id = Id(MetadataRecordKind.Field, offset);
        if (!RecordField(id, MetadataFieldName.Flags).Source.IsAvailable)
            throw new InvalidDataException($"Metadata field record at 0x{offset:X} is unavailable.");
        uint flags = AvailableUInt(id, MetadataFieldName.Flags, out var flagsStatus);
        if (flags > ushort.MaxValue) {
            flagsStatus |= MetadataFactStatus.InvalidNumeric;
            RecordFailure(Raw(id), "Flags", new InvalidDataException("Field flags exceed their runtime field width."));
        }
        uint defaultValue = AvailableHandle(id, MetadataFieldName.DefaultValue, out var defaultStatus);
        uint explicitOffset = AvailableUInt(id, MetadataFieldName.Offset, out var offsetStatus);
        MetadataField field = new() {
            Offset = offset,
            Flags = flags,
            FlagsStatus = flagsStatus,
            Name = Name(id),
            SignatureOffset = AvailableOffset(id, MetadataFieldName.Signature),
            DefaultValue = defaultValue,
            DefaultValueStatus = defaultStatus,
            ExplicitOffset = explicitOffset,
            ExplicitOffsetStatus = offsetStatus,
            Attributes = Collection(id, MetadataFieldName.CustomAttributes)
        };
        index = Fields.Count;
        FieldIndex.Add(offset, index);
        Fields.Add(field);
        return index;
    }

    private void ReadAttributes(IndexRange range, uint ownerType, uint ownerMethod) {
        for (int i = range.Start; i < range.End; i++) {
            var id = Id(MetadataRecordKind.CustomAttribute, Handles[i]);
            Recover(id, "attribute type", () => {
                uint constructor = Handle(id, MetadataFieldName.Constructor);
                uint type = AttributeOwner(constructor);
                Attributes.Add(new(ownerType, ownerMethod, id.Offset, constructor, TypeSignature(type)));
            });
        }
    }

    private uint AttributeOwner(uint constructor) {
        var id = Decode(constructor);
        return id.Kind switch {
            MetadataRecordKind.QualifiedMethod => Handle(id, MetadataFieldName.EnclosingType),
            MetadataRecordKind.MemberReference => Handle(id, MetadataFieldName.Parent),
            _ => throw new InvalidDataException("Invalid custom attribute constructor kind.")
        };
    }

    private void MaterializeRemaining(CancellationToken cancellationToken) {
        facts.ReadRoots();
        var records = facts.ReadRecordIds().ToArray();
        foreach (var id in records) {
            cancellationToken.ThrowIfCancellationRequested();
            if (id.Kind == MetadataRecordKind.ScopeDefinition)
                Recover(id, "scope", () => ReadScope(id));
            else if (id.Kind == MetadataRecordKind.TypeDefinition)
                Recover(id, "type", () => ReadType(id));
            else if (id.Kind == MetadataRecordKind.Method)
                Recover(id, "method", () => ReadMethod(id.Offset));
            else if (id.Kind == MetadataRecordKind.Field)
                Recover(id, "field", () => ReadField(id.Offset));
            else if (id.Kind == MetadataRecordKind.ScopeReference)
                Recover(id, "scope reference", () => ReadScopeReference(id.Offset));
        }
        foreach (var id in records) {
            cancellationToken.ThrowIfCancellationRequested();
            if (IsTypeSignature(id.Kind)) {
                Recover(id, "type signature", () => {
                    uint handle = Raw(id);
                    int signature = TypeSignature(handle);
                    if (id.Kind is MetadataRecordKind.TypeDefinition or MetadataRecordKind.TypeInstantiationSignature
                        or MetadataRecordKind.TypeReference or MetadataRecordKind.TypeSpecification) {
                        var value = new MetadataValue(handle, "type", SignatureBuilder.RenderType(signature));
                        Constants.TryAdd(handle, new(value, 1, 1));
                    }
                });
            }
            else if (id.Kind == MetadataRecordKind.MethodSignature)
                Recover(id, "method signature", () => MethodSignature(id.Offset));
            else if (id.Kind == MetadataRecordKind.CustomAttribute)
                Recover(id, "attribute payload", () => AttributePayload(id.Offset, cancellationToken));
            else if (id.Kind is >= MetadataRecordKind.ConstantBooleanArray and <= MetadataRecordKind.ConstantUInt64Value)
                Recover(id, "constant", () => Constant(Raw(id), cancellationToken));
            else if (id.Kind == MetadataRecordKind.TypeForwarder && !forwardedRecords.Contains(id.Offset))
                Recover(id, "type forwarder", () => ReadForwarder(id, "", 0, new HashSet<uint>()));
            else if (id.Kind == MetadataRecordKind.ScopeDefinition) {
                Recover(id, "scope attributes", () => ScopeAttributePayloads(id.Offset, false, cancellationToken));
                Recover(id, "module attributes", () => ScopeAttributePayloads(id.Offset, true, cancellationToken));
            }
        }
        for (int i = 0; i < Methods.Count; i++) {
            var method = Methods[i];
            if (MethodSignatureIndex.TryGetValue(method.SignatureOffset, out int signature)) {
                method.Signature = signature;
                Methods[i] = method;
            }
        }
        ReadFieldSignatures(cancellationToken);
    }

    internal void ReadFieldSignatures(CancellationToken cancellationToken = default) {
        ReadDefinitions(cancellationToken);
        for (int i = 0; i < Fields.Count; i++) {
            cancellationToken.ThrowIfCancellationRequested();
            var field = Fields[i];
            if (field.Signature != 0)
                continue;
            Recover(Id(MetadataRecordKind.Field, field.Offset), "field signature", () => {
                field.Signature = TypeSignature(Handle(Id(MetadataRecordKind.FieldSignature, field.SignatureOffset), MetadataFieldName.Type));
            });
            Fields[i] = field;
        }
    }

    private static bool IsTypeSignature(MetadataRecordKind kind) => kind is
        MetadataRecordKind.ArraySignature or MetadataRecordKind.ByReferenceSignature or
        MetadataRecordKind.FunctionPointerSignature or MetadataRecordKind.MethodTypeVariableSignature or
        MetadataRecordKind.ModifiedType or MetadataRecordKind.PointerSignature or MetadataRecordKind.SZArraySignature or
        MetadataRecordKind.TypeDefinition or MetadataRecordKind.TypeInstantiationSignature or
        MetadataRecordKind.TypeReference or MetadataRecordKind.TypeSpecification or MetadataRecordKind.TypeVariableSignature;

    private void ReadForwarder(MetadataRecordId id, string prefix, uint sourceScope, HashSet<uint> active) {
        if (Forwarders.Count >= ValueLimit)
            throw new InvalidDataException("Metadata forwarders exceed one million declaration occurrences.");
        if (active.Count >= 256)
            throw new InvalidDataException("Metadata forwarder nesting exceeds 256 records.");
        if (!active.Add(id.Value))
            throw new InvalidDataException("Cyclic metadata forwarders.");
        try {
            uint scope = Offset(id, MetadataFieldName.Scope);
            ReadScopeReference(scope);
            string name = prefix + Name(id);
            Forwarders.Add(new(id.Offset, sourceScope, name, referencedScopes[scope].Name));
            forwardedRecords.Add(id.Offset);
            foreach (var nested in RecordField(id, MetadataFieldName.NestedTypes).Items)
                ReadForwarder(nested.Reference.Value, name + "+", sourceScope, active);
        } finally {
            active.Remove(id.Value);
        }
    }
}
