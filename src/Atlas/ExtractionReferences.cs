namespace Atlas;

public sealed partial class Extraction {
    public RuntimeTypeReference RuntimeTypeAt(int position) =>
        RuntimeType(Types.Types[position].Address);

    public RuntimeTypeReference GcLayoutTypeAt(int position) =>
        RuntimeTypeAt(Gc.Layouts[position].TypeIndex);

    public RuntimeTypeReference InheritedGcTypeAt(int position) =>
        RuntimeTypeAt(Gc.Inherited[position].TypeIndex);

    public RuntimeTypeReference InheritedGcBaseTypeAt(int position) =>
        RuntimeTypeAt(Gc.Inherited[position].BaseTypeIndex);

    public RuntimeTypeReference UnprovenGcTypeAt(int position) =>
        RuntimeTypeAt(Gc.Unproven[position]);

    public RuntimeTypeReference FrozenObjectTypeAt(int position) =>
        RuntimeTypeAt(Frozen.Objects[position].TypeIndex);

    public RuntimeTypeReference FrozenRuntimeTypeAt(int position) =>
        RuntimeTypeAt(Frozen.RuntimeTypes[position].TypeIndex);

    public RuntimeTypeReference NativeStructTypeAt(int position) =>
        RuntimeTypeAt(Marshalling.Structs[position].TypeIndex);

    public RuntimeTypeReference NativeDelegateTypeAt(int position) =>
        RuntimeTypeAt(Marshalling.Delegates[position].TypeIndex);

    public RuntimeTypeReference ExternalMapGroupTypeAt(int position) =>
        RuntimeType(TypeMaps.External.Groups[position].GroupType);

    public RuntimeTypeReference ExternalMapTargetTypeAt(int position) =>
        RuntimeType(TypeMaps.External.Entries[position].TargetType);

    public RuntimeTypeReference ProxyMapGroupTypeAt(int position) =>
        RuntimeType(TypeMaps.Proxy.Groups[position].GroupType);

    public RuntimeTypeReference ProxyMapSourceTypeAt(int position) =>
        RuntimeType(TypeMaps.Proxy.Entries[position].SourceType);

    public RuntimeTypeReference ProxyMapTargetTypeAt(int position) =>
        RuntimeType(TypeMaps.Proxy.Entries[position].TargetType);

    public RuntimeTypeReference DispatchOwnerAt(int position) =>
        RuntimeTypeAt(Dispatch.Targets[position].OwnerType);

    public RuntimeTypeReference DispatchInterfaceAt(int position) =>
        RuntimeTypeAt(Dispatch.Targets[position].InterfaceType);

    public RuntimeTypeReference UnresolvedDispatchOwnerAt(int position) =>
        RuntimeTypeAt(Dispatch.Unresolved[position].OwnerType);

    public DispatchMap? DispatchMapForType(int runtimeTypePosition) {
        int map = Dispatch.TypeMaps[runtimeTypePosition];
        return map == 0 ? null : Dispatch.Maps[map - 1];
    }

    public RuntimeTypeReference ExceptionTypeAt(int position) {
        var clause = Managed.Clauses[position];
        return clause.Kind == ExceptionClauseKind.Typed
            ? RuntimeType(Image.ImageBase + clause.Type)
            : default;
    }

    public RuntimeTypeReference LayoutBaseTypeAt(int runtimeTypePosition) {
        return BoundType(Fields.Layouts[runtimeTypePosition].BaseType);
    }

    public RuntimeTypeReference FieldOwnerAt(int position) =>
        BoundType(Fields.FieldTypes[position].Owner);

    public RuntimeTypeReference FieldRuntimeTypeAt(int position) =>
        BoundType(Fields.FieldTypes[position].Binding);

    public SignatureType FieldTypeAt(int position) =>
        Fields.Bindings.Signatures.Types[Fields.FieldTypes[position].Signature];

    public SignatureType EnumTypeAt(int position) =>
        Signatures.Types[Enums.Definitions[position].Signature];

    public SignatureType EnumBaseTypeAt(int position) =>
        Signatures.Types[Enums.Definitions[position].BaseSignature];

    public SignatureType EnumValueTypeAt(int position) =>
        Signatures.Types[Enums.Definitions[position].ValueSignature];

    public EnumDefinition? EnumForRuntimeType(int position) {
        int definition = Enums.RuntimeIndices[position];
        return definition == 0 ? null : Enums.Definitions[definition - 1];
    }

    public SignatureMethod GenericMethodSignatureAt(int position) =>
        Signatures.MethodSignatures[Generics.Methods[position].Signature];

    public SignatureMethod VirtualMethodSignatureAt(int position) =>
        Signatures.MethodSignatures[Virtuals.Entries[position].Identity.Signature];

    public RuntimeTypeReference CanonicalTypeAt(int runtimeTypePosition) =>
        RuntimeTypeAt(Fields.Canonical.Groups[runtimeTypePosition] - 1);

    public SignatureType TraceDeclaringTypeAt(int position) =>
        Signatures.Types[Traces.Methods[position].DeclaringType];

    public SignatureMethod TraceMethodSignatureAt(int position) =>
        Signatures.MethodSignatures[Traces.Methods[position].Signature];

    public SignatureType MethodTemplateDeclaringTypeAt(int position) =>
        Signatures.Types[Templates.Methods[position].Method.DeclaringType];

    public SignatureMethod MethodTemplateSignatureAt(int position) =>
        Signatures.MethodSignatures[Templates.Methods[position].Method.Identity.Signature];

    public SignatureTypes MethodTemplateArgumentsAt(int position) =>
        new(Signatures, Templates.Methods[position].Method.Arguments);

    public SignatureType TypeTemplateBaseTypeAt(int position) =>
        Signatures.Types[Templates.Types[position].BaseType.Signature];

    public SignatureType TypeTemplateInterfaceTypeAt(int templatePosition, int interfacePosition) {
        var range = Templates.Types[templatePosition].Interfaces;
        ArgumentOutOfRangeException.ThrowIfNegative(interfacePosition);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(interfacePosition, range.Count);

        return Signatures.Types[Templates.Interfaces[range.Start + interfacePosition].Signature];
    }

    public SignatureType GvmInterfaceTypeAt(int position) =>
        Signatures.Types[Gvms.Signatures[position].Signature];

    public SignatureMethod GvmClassCallingSignatureAt(int position) =>
        Signatures.MethodSignatures[Gvms.Classes[position].Calling.Identity.Signature];

    public SignatureMethod GvmClassTargetSignatureAt(int position) =>
        Signatures.MethodSignatures[Gvms.Classes[position].Target.Identity.Signature];

    public SignatureMethod GvmInterfaceCallingSignatureAt(int position) =>
        Signatures.MethodSignatures[Gvms.Interfaces[position].Calling.Identity.Signature];

    public SignatureMethod GvmImplementationSignatureAt(int position) =>
        Signatures.MethodSignatures[Gvms.Implementations[position].Target.Identity.Signature];

    public SignatureType DictionaryRecipeTypeAt(int position) =>
        Signatures.Types[Dictionaries.Recipes[position].Type];

    public SignatureType DictionaryRecipeSecondTypeAt(int position) =>
        Signatures.Types[Dictionaries.Recipes[position].SecondType];

    public SignatureType DictionaryRecipeDeclaringTypeAt(int position) =>
        Signatures.Types[Dictionaries.Recipes[position].Method.DeclaringType];

    public SignatureMethod DictionaryRecipeMethodAt(int position) =>
        Signatures.MethodSignatures[Dictionaries.Recipes[position].Method.Identity.Signature];

    public SignatureMethod DictionaryRecipeConverterSignatureAt(int position) =>
        Signatures.MethodSignatures[Dictionaries.Recipes[position].ConverterSignature];

    public SignatureTypes DictionaryRecipeArgumentsAt(int position) =>
        new(Signatures, Dictionaries.Recipes[position].Method.Arguments);

    public RuntimeTypeReference DictionarySlotTypeAt(int position) =>
        BoundType(Dictionaries.Slots[position].Type);

    public RuntimeTypeReference DictionaryInterfaceTypeAt(int position) =>
        RuntimeTypeAt(Dictionaries.InterfaceCells[position].InterfaceType);

    public DictionaryLayout? MethodTemplateDictionaryAt(int position) {
        int layout = Dictionaries.MethodLayouts[position];
        return layout == 0 ? null : Dictionaries.Layouts[layout - 1];
    }

    public DictionaryLayout? TypeTemplateDictionaryAt(int position) {
        int layout = Dictionaries.TypeLayouts[position];
        return layout == 0 ? null : Dictionaries.Layouts[layout - 1];
    }

    private RuntimeTypeReference BoundType(int binding) =>
        binding == 0 ? default : RuntimeTypeAt(binding - 1);

    private RuntimeTypeReference RuntimeType(ulong address) {
        var runtime = RuntimeIndex;
        return new(runtime, runtime.Binding(address));
    }
}
