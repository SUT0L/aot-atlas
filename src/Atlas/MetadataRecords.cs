namespace Atlas;

// Typed views resolve only the fields a caller reads, retaining their source owner.
public readonly struct MetadataMethodFacts {
    private readonly MetadataFacts facts;
    public MetadataMethodId Id { get; }
    public MetadataFact<uint> Flags => facts.Field(Id.Record, MetadataFieldName.Flags).UInt32;
    public MetadataFact<uint> ImplementationFlags => facts.Field(Id.Record, MetadataFieldName.ImplFlags).UInt32;
    public MetadataFact<MetadataNameId> Name => facts.NameReference(Id.Record, MetadataFieldName.Name);
    public MetadataFact<MetadataRecordId> Signature => facts.Field(Id.Record, MetadataFieldName.Signature).Reference;
    public MetadataReferences Parameters => facts.References(Id.Record, MetadataFieldName.Parameters);
    public MetadataReferences GenericParameters => facts.References(Id.Record, MetadataFieldName.GenericParameters);
    public MetadataReferences CustomAttributes => facts.References(Id.Record, MetadataFieldName.CustomAttributes);

    internal MetadataMethodFacts(MetadataFacts facts, MetadataMethodId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataTypeFacts {
    private readonly MetadataFacts facts;
    public MetadataTypeId Id { get; }
    public MetadataFact<uint> Flags => facts.Field(Id.Record, MetadataFieldName.Flags).UInt32;
    public MetadataFact<MetadataRecordId> BaseType => facts.Field(Id.Record, MetadataFieldName.BaseType).Reference;
    public MetadataFact<MetadataRecordId> Owner => facts.Owner(Id.Record);
    public MetadataFact<MetadataNameId> Name => facts.NameReference(Id.Record, MetadataFieldName.Name);
    public MetadataFact<uint> Size => facts.Field(Id.Record, MetadataFieldName.Size).UInt32;
    public MetadataFact<uint> PackingSize => facts.Field(Id.Record, MetadataFieldName.PackingSize).UInt32;
    public MetadataReferences NestedTypes => facts.References(Id.Record, MetadataFieldName.NestedTypes);
    public MetadataReferences Methods => facts.References(Id.Record, MetadataFieldName.Methods);
    public MetadataReferences Fields => facts.References(Id.Record, MetadataFieldName.Fields);
    public MetadataReferences Properties => facts.References(Id.Record, MetadataFieldName.Properties);
    public MetadataReferences Events => facts.References(Id.Record, MetadataFieldName.Events);
    public MetadataReferences GenericParameters => facts.References(Id.Record, MetadataFieldName.GenericParameters);
    public MetadataReferences Interfaces => facts.References(Id.Record, MetadataFieldName.Interfaces);
    public MetadataReferences CustomAttributes => facts.References(Id.Record, MetadataFieldName.CustomAttributes);

    internal MetadataTypeFacts(MetadataFacts facts, MetadataTypeId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataFieldFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<uint> Flags => facts.Field(Id, MetadataFieldName.Flags).UInt32;
    public MetadataFact<MetadataNameId> Name => facts.NameReference(Id, MetadataFieldName.Name);
    public MetadataFact<MetadataRecordId> Signature => facts.Field(Id, MetadataFieldName.Signature).Reference;
    public MetadataFact<MetadataRecordId> DefaultValue => facts.Field(Id, MetadataFieldName.DefaultValue).Reference;
    public MetadataFact<uint> ExplicitOffset => facts.Field(Id, MetadataFieldName.Offset).UInt32;
    public MetadataReferences CustomAttributes => facts.References(Id, MetadataFieldName.CustomAttributes);

    internal MetadataFieldFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataScopeFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<uint> Flags => facts.Field(Id, MetadataFieldName.Flags).UInt32;
    public MetadataFact<MetadataNameId> Name => facts.NameReference(Id, MetadataFieldName.Name);
    public MetadataFact<uint> HashAlgorithm => facts.Field(Id, MetadataFieldName.HashAlgorithm).UInt32;
    public MetadataFact<uint> MajorVersion => facts.Field(Id, MetadataFieldName.MajorVersion).UInt32;
    public MetadataFact<uint> MinorVersion => facts.Field(Id, MetadataFieldName.MinorVersion).UInt32;
    public MetadataFact<uint> BuildNumber => facts.Field(Id, MetadataFieldName.BuildNumber).UInt32;
    public MetadataFact<uint> RevisionNumber => facts.Field(Id, MetadataFieldName.RevisionNumber).UInt32;
    public MetadataFieldItems PublicKey => facts.Field(Id, MetadataFieldName.PublicKey).Items;
    public MetadataFact<MetadataNameId> Culture => facts.NameReference(Id, MetadataFieldName.Culture);
    public MetadataFact<MetadataRecordId> RootNamespace => facts.Field(Id, MetadataFieldName.RootNamespaceDefinition).Reference;
    public MetadataFact<MetadataRecordId> EntryPoint => facts.Field(Id, MetadataFieldName.EntryPoint).Reference;
    public MetadataFact<MetadataRecordId> GlobalModuleType => facts.Field(Id, MetadataFieldName.GlobalModuleType).Reference;
    public MetadataReferences CustomAttributes => facts.References(Id, MetadataFieldName.CustomAttributes);
    public MetadataFact<MetadataNameId> ModuleName => facts.NameReference(Id, MetadataFieldName.ModuleName);
    public MetadataFieldItems ModuleVersionId => facts.Field(Id, MetadataFieldName.Mvid).Items;
    public MetadataReferences ModuleCustomAttributes => facts.References(Id, MetadataFieldName.ModuleCustomAttributes);

    internal MetadataScopeFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataNamespaceFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<MetadataRecordId> Parent => facts.Field(Id, MetadataFieldName.ParentScopeOrNamespace).Reference;
    public MetadataFact<MetadataNameId> Name => facts.NameReference(Id, MetadataFieldName.Name);
    public MetadataReferences Types => facts.References(Id, MetadataFieldName.TypeDefinitions);
    public MetadataReferences TypeForwarders => facts.References(Id, MetadataFieldName.TypeForwarders);
    public MetadataReferences Namespaces => facts.References(Id, MetadataFieldName.NamespaceDefinitions);

    internal MetadataNamespaceFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataGenericParameterFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<uint> Number => facts.Field(Id, MetadataFieldName.Number).UInt32;
    public MetadataFact<uint> Flags => facts.Field(Id, MetadataFieldName.Flags).UInt32;
    public MetadataFact<uint> Kind => facts.Field(Id, MetadataFieldName.Kind).UInt32;
    public MetadataFact<MetadataNameId> Name => facts.NameReference(Id, MetadataFieldName.Name);
    public MetadataReferences Constraints => facts.References(Id, MetadataFieldName.Constraints);
    public MetadataReferences CustomAttributes => facts.References(Id, MetadataFieldName.CustomAttributes);

    internal MetadataGenericParameterFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataMethodSignatureFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<uint> CallingConvention => facts.Field(Id, MetadataFieldName.CallingConvention).UInt32;
    public MetadataFact<int> GenericParameterCount => facts.Field(Id, MetadataFieldName.GenericParameterCount).Int32;
    public MetadataFact<MetadataRecordId> ReturnType => facts.Field(Id, MetadataFieldName.ReturnType).Reference;
    public MetadataReferences Parameters => facts.References(Id, MetadataFieldName.Parameters);
    public MetadataReferences VarArgParameters => facts.References(Id, MetadataFieldName.VarArgParameters);

    internal MetadataMethodSignatureFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataCustomAttributeFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<MetadataRecordId> Constructor => facts.Field(Id, MetadataFieldName.Constructor).Reference;
    public MetadataReferences FixedArguments => facts.References(Id, MetadataFieldName.FixedArguments);
    public MetadataReferences NamedArguments => facts.References(Id, MetadataFieldName.NamedArguments);

    internal MetadataCustomAttributeFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataEventFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<uint> Flags => facts.Field(Id, MetadataFieldName.Flags).UInt32;
    public MetadataFact<MetadataNameId> Name => facts.NameReference(Id, MetadataFieldName.Name);
    public MetadataFact<MetadataRecordId> Type => facts.Field(Id, MetadataFieldName.Type).Reference;
    public MetadataReferences MethodSemantics => facts.References(Id, MetadataFieldName.MethodSemantics);
    public MetadataReferences CustomAttributes => facts.References(Id, MetadataFieldName.CustomAttributes);

    internal MetadataEventFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataMemberReferenceFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<MetadataRecordId> Parent => facts.Field(Id, MetadataFieldName.Parent).Reference;
    public MetadataFact<MetadataNameId> Name => facts.NameReference(Id, MetadataFieldName.Name);
    public MetadataFact<MetadataRecordId> Signature => facts.Field(Id, MetadataFieldName.Signature).Reference;

    internal MetadataMemberReferenceFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataMethodInstantiationFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<MetadataRecordId> Method => facts.Field(Id, MetadataFieldName.Method).Reference;
    public MetadataReferences GenericTypeArguments => facts.References(Id, MetadataFieldName.GenericTypeArguments);

    internal MetadataMethodInstantiationFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataMethodSemanticsFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<uint> Attributes => facts.Field(Id, MetadataFieldName.Attributes).UInt32;
    public MetadataFact<MetadataRecordId> Method => facts.Field(Id, MetadataFieldName.Method).Reference;

    internal MetadataMethodSemanticsFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataNamedArgumentFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<uint> Flags => facts.Field(Id, MetadataFieldName.Flags).UInt32;
    public MetadataFact<MetadataNameId> Name => facts.NameReference(Id, MetadataFieldName.Name);
    public MetadataFact<MetadataRecordId> Type => facts.Field(Id, MetadataFieldName.Type).Reference;
    public MetadataFact<MetadataRecordId> Value => facts.Field(Id, MetadataFieldName.Value).Reference;

    internal MetadataNamedArgumentFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataNamespaceReferenceFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<MetadataRecordId> ParentScopeOrNamespace => facts.Field(Id, MetadataFieldName.ParentScopeOrNamespace).Reference;
    public MetadataFact<MetadataNameId> Name => facts.NameReference(Id, MetadataFieldName.Name);

    internal MetadataNamespaceReferenceFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataParameterFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<uint> Flags => facts.Field(Id, MetadataFieldName.Flags).UInt32;
    public MetadataFact<uint> Sequence => facts.Field(Id, MetadataFieldName.Sequence).UInt32;
    public MetadataFact<MetadataNameId> Name => facts.NameReference(Id, MetadataFieldName.Name);
    public MetadataFact<MetadataRecordId> DefaultValue => facts.Field(Id, MetadataFieldName.DefaultValue).Reference;
    public MetadataReferences CustomAttributes => facts.References(Id, MetadataFieldName.CustomAttributes);

    internal MetadataParameterFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataPropertyFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<uint> Flags => facts.Field(Id, MetadataFieldName.Flags).UInt32;
    public MetadataFact<MetadataNameId> Name => facts.NameReference(Id, MetadataFieldName.Name);
    public MetadataFact<MetadataRecordId> Signature => facts.Field(Id, MetadataFieldName.Signature).Reference;
    public MetadataReferences MethodSemantics => facts.References(Id, MetadataFieldName.MethodSemantics);
    public MetadataFact<MetadataRecordId> DefaultValue => facts.Field(Id, MetadataFieldName.DefaultValue).Reference;
    public MetadataReferences CustomAttributes => facts.References(Id, MetadataFieldName.CustomAttributes);

    internal MetadataPropertyFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataQualifiedFieldFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<MetadataRecordId> Field => facts.Field(Id, MetadataFieldName.Field).Reference;
    public MetadataFact<MetadataRecordId> EnclosingType => facts.Field(Id, MetadataFieldName.EnclosingType).Reference;

    internal MetadataQualifiedFieldFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataQualifiedMethodFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<MetadataRecordId> Method => facts.Field(Id, MetadataFieldName.Method).Reference;
    public MetadataFact<MetadataRecordId> EnclosingType => facts.Field(Id, MetadataFieldName.EnclosingType).Reference;

    internal MetadataQualifiedMethodFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataScopeReferenceFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<uint> Flags => facts.Field(Id, MetadataFieldName.Flags).UInt32;
    public MetadataFact<MetadataNameId> Name => facts.NameReference(Id, MetadataFieldName.Name);
    public MetadataFact<uint> MajorVersion => facts.Field(Id, MetadataFieldName.MajorVersion).UInt32;
    public MetadataFact<uint> MinorVersion => facts.Field(Id, MetadataFieldName.MinorVersion).UInt32;
    public MetadataFact<uint> BuildNumber => facts.Field(Id, MetadataFieldName.BuildNumber).UInt32;
    public MetadataFact<uint> RevisionNumber => facts.Field(Id, MetadataFieldName.RevisionNumber).UInt32;
    public MetadataFieldItems PublicKeyOrToken => facts.Field(Id, MetadataFieldName.PublicKeyOrToken).Items;
    public MetadataFact<MetadataNameId> Culture => facts.NameReference(Id, MetadataFieldName.Culture);

    internal MetadataScopeReferenceFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataTypeForwarderFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<MetadataRecordId> Scope => facts.Field(Id, MetadataFieldName.Scope).Reference;
    public MetadataFact<MetadataNameId> Name => facts.NameReference(Id, MetadataFieldName.Name);
    public MetadataReferences NestedTypes => facts.References(Id, MetadataFieldName.NestedTypes);

    internal MetadataTypeForwarderFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataTypeSpecificationFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<MetadataRecordId> Signature => facts.Field(Id, MetadataFieldName.Signature).Reference;

    internal MetadataTypeSpecificationFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataTypeReferenceFacts {
    private readonly MetadataFacts facts;
    public MetadataRecordId Id { get; }
    public MetadataFact<MetadataRecordId> Owner => facts.Owner(Id);
    public MetadataFact<MetadataNameId> Name => facts.NameReference(Id, MetadataFieldName.TypeName);

    internal MetadataTypeReferenceFacts(MetadataFacts facts, MetadataRecordId id) {
        this.facts = facts;
        Id = id;
    }
}

public readonly struct MetadataReferences {
    private readonly MetadataFieldItems _items;
    public int Count => _items.Count;
    public bool IsAvailable => _items.IsAvailable;
    public ulong DeclaredCount => _items.DeclaredCount;
    public MetadataFactStatus Status => _items.Status;
    public MetadataSourceRange Source => _items.Source;
    public MetadataFact<MetadataRecordId> this[int index] => _items[index].Reference;

    internal MetadataReferences(MetadataFieldItems items) {
        _items = items;
    }

    public Enumerator GetEnumerator() => new(this);

    public struct Enumerator {
        private readonly MetadataReferences _references;
        private int _position;
        public MetadataFact<MetadataRecordId> Current => _references[_position];

        internal Enumerator(MetadataReferences references) {
            _references = references;
            _position = -1;
        }

        public bool MoveNext() => ++_position < _references.Count;
    }
}

public sealed partial class MetadataFacts {
    public MetadataMethodFacts Method(MetadataMethodId id) => new(this, id);

    public MetadataTypeFacts Type(MetadataTypeId id) => new(this, id);

    public MetadataFieldFacts FieldDefinition(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.Field);
        return new(this, id);
    }

    public MetadataScopeFacts Scope(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.ScopeDefinition);
        return new(this, id);
    }

    public MetadataNamespaceFacts Namespace(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.NamespaceDefinition);
        return new(this, id);
    }

    public MetadataGenericParameterFacts GenericParameter(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.GenericParameter);
        return new(this, id);
    }

    public MetadataMethodSignatureFacts MethodSignature(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.MethodSignature);
        return new(this, id);
    }

    public MetadataCustomAttributeFacts CustomAttribute(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.CustomAttribute);
        return new(this, id);
    }

    public MetadataEventFacts Event(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.Event);
        return new(this, id);
    }

    public MetadataMemberReferenceFacts MemberReference(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.MemberReference);
        return new(this, id);
    }

    public MetadataMethodInstantiationFacts MethodInstantiation(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.MethodInstantiation);
        return new(this, id);
    }

    public MetadataMethodSemanticsFacts MethodSemantics(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.MethodSemantics);
        return new(this, id);
    }

    public MetadataNamedArgumentFacts NamedArgument(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.NamedArgument);
        return new(this, id);
    }

    public MetadataNamespaceReferenceFacts NamespaceReference(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.NamespaceReference);
        return new(this, id);
    }

    public MetadataParameterFacts Parameter(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.Parameter);
        return new(this, id);
    }

    public MetadataPropertyFacts Property(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.Property);
        return new(this, id);
    }

    public MetadataQualifiedFieldFacts QualifiedField(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.QualifiedField);
        return new(this, id);
    }

    public MetadataQualifiedMethodFacts QualifiedMethod(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.QualifiedMethod);
        return new(this, id);
    }

    public MetadataScopeReferenceFacts ScopeReference(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.ScopeReference);
        return new(this, id);
    }

    public MetadataTypeForwarderFacts TypeForwarder(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.TypeForwarder);
        return new(this, id);
    }

    public MetadataTypeSpecificationFacts TypeSpecification(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.TypeSpecification);
        return new(this, id);
    }

    public MetadataTypeReferenceFacts TypeReference(MetadataRecordId id) {
        RequireKind(id, MetadataRecordKind.TypeReference);
        return new(this, id);
    }

    internal MetadataFact<MetadataRecordId> Owner(MetadataRecordId id) {
        var fields = MetadataSchema.OwnerFields(Encoding, id.Kind);
        var owner = Field(id, fields.Primary).Reference;
        if (owner.IsAvailable && owner.Value.IsNil && fields.Fallback is MetadataFieldName fallback) {
            return Field(id, fallback).Reference;
        }
        return owner;
    }

    internal MetadataReferences References(MetadataRecordId id, MetadataFieldName field) {
        return new(Field(id, field).Items);
    }

    internal MetadataFact<MetadataNameId> NameReference(MetadataRecordId id, MetadataFieldName field) {
        var reference = Field(id, field).Reference;
        return new(new(reference.Value.Offset), reference.Status, reference.Source);
    }

    private static void RequireKind(MetadataRecordId id, MetadataRecordKind expected) {
        if (id.Kind != expected) {
            throw new ArgumentException($"Expected {expected}, found {id.Kind}.", nameof(id));
        }
    }
}
