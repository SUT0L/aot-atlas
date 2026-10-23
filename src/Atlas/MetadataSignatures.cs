namespace Atlas;

internal sealed partial class MetadataBuilder {
    private readonly HashSet<uint> activeNames = new();
    private readonly HashSet<uint> activeTypeSignatures = new();
    private readonly HashSet<uint> activeMethodSignatures = new();
    private readonly List<(bool Method, uint Value)> addedSignatures = new();
    private readonly Dictionary<uint, string> failedMethodSignatures = new();
    private bool readingSignatures;

    internal MetadataFactStatus TypeNameStatus(MetadataRecordId id) => id.Kind switch {
        MetadataRecordKind.TypeDefinition => DefinitionNameStatus(id.Offset, 0),
        MetadataRecordKind.TypeReference => ReferenceNameStatus(id, 0),
        _ => MetadataFactStatus.Unresolved
    };

    private MetadataFactStatus DefinitionNameStatus(uint offset, int depth) {
        if (depth > 256)
            return MetadataFactStatus.Incomplete;

        var id = Id(MetadataRecordKind.TypeDefinition, offset);
        var owner = TypeOwnership(id);
        var status = NamePartStatus(id, MetadataFieldName.Name, allowEmpty: false);
        if (owner.Enclosing != 0)
            status |= DefinitionNameStatus(owner.Enclosing, depth + 1);
        else if (owner.Namespace != 0)
            status |= NamespaceNameStatus(owner.Namespace, depth + 1);
        return status;
    }

    private MetadataFactStatus NamespaceNameStatus(uint offset, int depth) {
        if (depth > 256)
            return MetadataFactStatus.Incomplete;

        var id = Id(MetadataRecordKind.NamespaceDefinition, offset);
        var parent = Reference(id, MetadataFieldName.ParentScopeOrNamespace);
        var status = NamePartStatus(id, MetadataFieldName.Name, allowEmpty: true);
        if (parent.Kind == MetadataRecordKind.NamespaceDefinition)
            status |= NamespaceNameStatus(parent.Offset, depth + 1);
        return status;
    }

    private MetadataFactStatus ReferenceNameStatus(MetadataRecordId id, int depth) {
        if (depth > 256)
            return MetadataFactStatus.Incomplete;

        var parent = id.Kind == MetadataRecordKind.NamespaceReference
            ? Reference(id, MetadataFieldName.ParentScopeOrNamespace)
            : ReferenceOwner(id);
        var status = NamePartStatus(id, id.Kind == MetadataRecordKind.TypeReference
            ? MetadataFieldName.TypeName : MetadataFieldName.Name,
            allowEmpty: id.Kind == MetadataRecordKind.NamespaceReference);
        if (parent.Kind is MetadataRecordKind.TypeReference or MetadataRecordKind.NamespaceReference)
            status |= ReferenceNameStatus(parent, depth + 1);
        return status;
    }

    private MetadataFactStatus NamePartStatus(MetadataRecordId id, MetadataFieldName field, bool allowEmpty) {
        var reference = RecordField(id, field);
        var offset = reference.UInt32;
        if (!offset.IsAvailable || offset.Value > 0x01FFFFFF)
            return offset.Status | reference.NameStatus | MetadataFactStatus.Unresolved;
        if (offset.Value == 0)
            return offset.Status | reference.NameStatus
                | (allowEmpty ? MetadataFactStatus.Valid : MetadataFactStatus.InvalidName);

        var name = RecordName(new(offset.Value));
        var nameField = RecordField(new(MetadataRecordKind.ConstantStringValue, offset.Value), MetadataFieldName.Value);
        return offset.Status | reference.NameStatus | name.Status | nameField.NameStatus
            | (!allowEmpty && name.Value.Length == 0 ? MetadataFactStatus.InvalidName : MetadataFactStatus.Valid);
    }

    internal string DefinitionName(uint offset, int depth = 0) {
        if (DefinitionNames.TryGetValue(offset, out string? cached))
            return cached;
        var id = Id(MetadataRecordKind.TypeDefinition, offset);
        if (depth > 256 || !activeNames.Add(id.Value))
            throw new InvalidDataException("Cyclic or excessively nested type definition.");
        try {
            var owner = TypeOwnership(id);
            string name = Name(id);
            string prefix = owner.Enclosing != 0
                ? DefinitionName(owner.Enclosing, depth + 1)
                : NamespaceName(owner.Namespace, depth + 1);
            string result = prefix.Length == 0 ? name : prefix + (owner.Enclosing != 0 ? "+" : ".") + name;
            if (name.Length == 0)
                throw new InvalidDataException("Type definition has no available name.");
            DefinitionNames.Add(offset, result);
            return result;
        } finally {
            activeNames.Remove(id.Value);
        }
    }

    private string NamespaceName(uint offset, int depth) {
        if (offset == 0)
            return "";
        if (namespaces.TryGetValue(offset, out var known))
            return known.Name;
        var id = Id(MetadataRecordKind.NamespaceDefinition, offset);
        if (depth > 256 || !activeNames.Add(id.Value))
            throw new InvalidDataException("Cyclic or excessively nested namespace definition.");
        try {
            var parent = Reference(id, MetadataFieldName.ParentScopeOrNamespace);
            if (parent.IsNil) {
                throw new InvalidDataException("Namespace has a nil parent.");
            }

            string name = String(Offset(id, MetadataFieldName.Name));
            string prefix;
            uint scope;
            if (parent.Kind == MetadataRecordKind.ScopeDefinition) {
                prefix = "";
                scope = parent.Offset;
            } else if (parent.Kind == MetadataRecordKind.NamespaceDefinition) {
                prefix = NamespaceName(parent.Offset, depth + 1);
                scope = namespaces[parent.Offset].Scope;
            } else
                throw new InvalidDataException("Namespace has an invalid parent kind.");
            string full = prefix.Length != 0 && name.Length != 0 ? prefix + "." + name : prefix + name;
            namespaces.Add(offset, (scope, full));
            return full;
        } finally {
            activeNames.Remove(id.Value);
        }
    }

    private (string Name, uint Scope) ReferenceIdentity(uint raw, int depth) {
        if (referenceNames.TryGetValue(raw, out var known))
            return known;
        var id = Decode(raw);
        if (depth > 256 || !activeNames.Add(id.Value))
            throw new InvalidDataException("Cyclic or excessively nested metadata reference.");
        try {
            var parent = id.Kind == MetadataRecordKind.NamespaceReference
                ? Reference(id, MetadataFieldName.ParentScopeOrNamespace)
                : ReferenceOwner(id);
            string part = String(Offset(id, id.Kind == MetadataRecordKind.TypeReference
                ? MetadataFieldName.TypeName : MetadataFieldName.Name));
            if (id.Kind == MetadataRecordKind.TypeReference && part.Length == 0) {
                throw new InvalidDataException("Type reference has no available name.");
            }

            string prefix;
            uint scope;
            if (id.Kind == MetadataRecordKind.NamespaceReference && parent.Kind == MetadataRecordKind.ScopeReference) {
                ReadScopeReference(parent.Offset);
                prefix = "";
                scope = Raw(parent);
            } else if ((id.Kind == MetadataRecordKind.NamespaceReference && parent.Kind == MetadataRecordKind.NamespaceReference)
                || (id.Kind == MetadataRecordKind.TypeReference && parent.Kind is MetadataRecordKind.NamespaceReference or MetadataRecordKind.TypeReference)) {
                var owner = ReferenceIdentity(Raw(parent), depth + 1);
                prefix = owner.Name;
                scope = owner.Scope;
            } else
                throw new InvalidDataException($"Invalid metadata reference parent {parent.Kind} for {id.Kind}.");
            string name = prefix.Length == 0 ? part : part.Length == 0 ? prefix
                : prefix + (parent.Kind == MetadataRecordKind.TypeReference ? "+" : ".") + part;
            referenceNames.Add(raw, (name, scope));
            return (name, scope);
        } finally {
            activeNames.Remove(id.Value);
        }
    }

    private IndexRange SignatureCollection(MetadataRecordId id, MetadataFieldName field, int depth, bool dimensions = false) {
        var items = RecordField(id, field).Items;
        if (items.Status != MetadataFactStatus.Valid)
            throw new InvalidDataException($"Signature {field} collection is partial ({items.Status}).");
        int start = SignatureBuilder.Edges.Length;
        SignatureBuilder.ReserveEdges(items.Count);
        for (int i = 0; i < items.Count; i++) {
            int value = dimensions ? Required(items[i].Int32, id, field)
                : TypeSignature(Raw(Required(items[i].Reference, id, field)), depth + 1);
            SignatureBuilder.SetEdge(start + i, value);
        }
        return new(start, items.Count);
    }

    internal int TypeSignature(uint raw, int depth = 0) => ReadSignature(raw, depth, false);
    internal int MethodSignature(uint offset, int depth = 0) => ReadSignature(offset, depth, true);
    internal bool TryMethodSignature(uint offset, out int signature) {
        signature = 0;
        if (offset == 0 || failedMethodSignatures.ContainsKey(offset))
            return false;
        try {
            signature = MethodSignature(offset);
            return true;
        } catch (Exception error) when (error is InvalidDataException or OverflowException or NotSupportedException) {
            return false;
        }
    }
    internal SignatureType ReadTypeSignature(uint handle) {
        int index = TypeSignature(handle);
        return SignatureBuilder.Publish().Types[index];
    }
    internal SignatureMethod ReadMethodSignature(uint offset) {
        int index = MethodSignature(offset);
        return SignatureBuilder.Publish().MethodSignatures[index];
    }

    private int ReadSignature(uint value, int depth, bool method) {
        EnsureMutable();
        if (method ? value == 0 : value >> HandleBits == 0)
            return 0;
        if (depth > 256)
            throw new InvalidDataException("Signature nesting exceeds 256 records.");
        var cache = method ? MethodSignatureIndex : SignatureIndex;
        if (cache.TryGetValue(value, out int cached))
            return cached;
        if (method && failedMethodSignatures.TryGetValue(value, out string? failure))
            throw new InvalidDataException(failure);
        if (readingSignatures) {
            return ProjectSignature(value, depth, method);
        }

        var signatureStart = SignatureBuilder.BeginRead();
        readingSignatures = true;
        bool complete = false;
        try {
            int index = ProjectSignature(value, depth, method);
            complete = true;
            return index;
        } catch (Exception error) when (error is InvalidDataException or OverflowException or NotSupportedException) {
            if (method && depth == 0) {
                failedMethodSignatures.TryAdd(value, error.Message);
                if (value <= 0x01FFFFFF)
                    RecordFailure(Raw(Id(MetadataRecordKind.MethodSignature, value)), "method signature", error);
            }
            throw;
        } finally {
            if (complete) {
                SignatureBuilder.CompleteRead(signatureStart);
            } else {
                SignatureBuilder.RollbackRead(signatureStart);
                foreach (var added in addedSignatures) {
                    (added.Method ? MethodSignatureIndex : SignatureIndex).Remove(added.Value);
                }
            }
            addedSignatures.Clear();
            readingSignatures = false;
        }
    }

    private int ProjectSignature(uint value, int depth, bool method) {
        var active = method ? activeMethodSignatures : activeTypeSignatures;
        if (!active.Add(value)) {
            throw new InvalidDataException(method ? "Cyclic method signature." : "Cyclic type signature.");
        }

        try {
            int index = method ? ProjectMethodSignature(value, depth) : ProjectTypeSignature(value, depth);
            addedSignatures.Add((method, value));
            (method ? MethodSignatureIndex : SignatureIndex).Add(value, index);
            return index;
        } finally {
            active.Remove(value);
        }
    }

    private int ProjectTypeSignature(uint raw, int depth) {
        var id = Decode(raw);
        AddRoot(id);
        SignatureNode node = new();
        switch (id.Kind) {
            case MetadataRecordKind.TypeDefinition:
                node.Kind = SignatureKind.Named;
                node.Name = DefinitionName(id.Offset);
                uint scope = DefinitionScope(id.Offset);
                node.MetadataScope = scope == 0 ? 0 : Raw(Id(MetadataRecordKind.ScopeDefinition, scope));
                break;
            case MetadataRecordKind.TypeReference:
                if (ReferenceOwner(id).IsNil) {
                    node.Kind = SignatureKind.ParameterName;
                    node.Name = Name(id, MetadataFieldName.TypeName);
                    if (node.Name.Length == 0)
                        throw new InvalidDataException("Parentless type reference has no parameter name.");
                } else {
                    var identity = ReferenceIdentity(raw, depth);
                    node.Kind = SignatureKind.Named;
                    node.Name = identity.Name;
                    node.MetadataScope = identity.Scope;
                }
                break;
            case MetadataRecordKind.TypeVariableSignature:
            case MetadataRecordKind.MethodTypeVariableSignature:
                node.Kind = id.Kind == MetadataRecordKind.TypeVariableSignature ? SignatureKind.TypeVariable : SignatureKind.MethodVariable;
                node.Value = Int(id, MetadataFieldName.Number);
                if (node.Value < 0)
                    throw new InvalidDataException("Negative generic variable index.");
                break;
            case MetadataRecordKind.ArraySignature:
                node.Kind = SignatureKind.Array;
                node.Element = TypeSignature(Handle(id, MetadataFieldName.ElementType), depth + 1);
                node.Value = Int(id, MetadataFieldName.Rank);
                if (node.Value is < 1 or > 32)
                    throw new InvalidDataException("Array rank exceeds the runtime range 1..32.");
                node.Sizes = SignatureCollection(id, MetadataFieldName.Sizes, depth, true);
                node.LowerBounds = SignatureCollection(id, MetadataFieldName.LowerBounds, depth, true);
                if (node.Sizes.Count > node.Value || node.LowerBounds.Count > node.Value)
                    throw new InvalidDataException("Array dimensions exceed its rank.");
                break;
            case MetadataRecordKind.SZArraySignature:
            case MetadataRecordKind.PointerSignature:
            case MetadataRecordKind.ByReferenceSignature:
                node.Kind = id.Kind == MetadataRecordKind.SZArraySignature ? SignatureKind.SzArray
                    : id.Kind == MetadataRecordKind.PointerSignature ? SignatureKind.Pointer : SignatureKind.ByReference;
                node.Element = TypeSignature(Handle(id, id.Kind == MetadataRecordKind.SZArraySignature ? MetadataFieldName.ElementType : MetadataFieldName.Type), depth + 1);
                break;
            case MetadataRecordKind.TypeInstantiationSignature:
                node.Kind = SignatureKind.Instantiation;
                node.Element = TypeSignature(Handle(id, MetadataFieldName.GenericType), depth + 1);
                node.Arguments = SignatureCollection(id, MetadataFieldName.GenericTypeArguments, depth);
                break;
            case MetadataRecordKind.TypeSpecification:
                return TypeSignature(Handle(id, MetadataFieldName.Signature), depth + 1);
            case MetadataRecordKind.ModifiedType:
                node.Kind = SignatureKind.Modified;
                node.Optional = Required(RecordField(id, MetadataFieldName.IsOptional).Boolean, id, MetadataFieldName.IsOptional);
                node.Value = TypeSignature(Handle(id, MetadataFieldName.ModifierType), depth + 1);
                node.Element = TypeSignature(Handle(id, MetadataFieldName.Type), depth + 1);
                break;
            case MetadataRecordKind.FunctionPointerSignature:
                int signatureId = MethodSignature(Offset(id, MetadataFieldName.Signature), depth + 1);
                var signature = SignatureBuilder.Methods[signatureId];
                node.Kind = SignatureKind.FunctionPointer;
                node.Element = signature.ReturnType;
                node.Arguments = signature.Parameters;
                node.Varargs = signature.Varargs;
                node.Value = checked((int)signature.CallingConvention);
                break;
            default:
                throw new InvalidDataException($"Metadata record {id.Kind} is not a type signature.");
        }
        return SignatureBuilder.AddNode(node);
    }

    private int ProjectMethodSignature(uint offset, int depth) {
        var id = Id(MetadataRecordKind.MethodSignature, offset);
        MethodSignature signature = new() {
            Offset = offset,
            CallingConvention = UInt(id, MetadataFieldName.CallingConvention),
            GenericParameterCount = Int(id, MetadataFieldName.GenericParameterCount),
            ReturnType = TypeSignature(Handle(id, MetadataFieldName.ReturnType), depth + 1),
            Parameters = SignatureCollection(id, MetadataFieldName.Parameters, depth),
            Varargs = SignatureCollection(id, MetadataFieldName.VarArgParameters, depth)
        };
        if (signature.GenericParameterCount < 0)
            throw new InvalidDataException("Negative generic parameter count.");
        return SignatureBuilder.AddMethod(signature);
    }
}
