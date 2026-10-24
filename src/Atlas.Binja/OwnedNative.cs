using System.Runtime.InteropServices;

namespace Atlas.Binja;

[StructLayout(LayoutKind.Sequential)]
internal struct TagReference {
    internal byte Kind;
    internal byte Auto;
    internal nint Tag;
    internal nint Architecture;
    internal nint Function;
    internal ulong Address;
}

[StructLayout(LayoutKind.Sequential)]
internal struct QualifiedNameAndType {
    internal QualifiedName Name;
    internal nint Type;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeStructureMember {
    internal nint Type;
    internal byte* Name;
    internal ulong Offset;
    internal byte Confidence;
    internal byte Access;
    internal byte Scope;
    internal byte BitPosition;
    internal byte BitWidth;
}

[StructLayout(LayoutKind.Sequential)]
internal struct TypeFieldReference {
    internal nint Function;
    internal nint Architecture;
    internal ulong Address;
    internal nuint Size;
    internal TypeConfidence Type;
}

[StructLayout(LayoutKind.Sequential)]
internal struct TypeReferenceSource {
    internal QualifiedName Name;
    internal ulong Offset;
    internal byte Kind;
}

[StructLayout(LayoutKind.Sequential)]
internal struct ReferenceSource {
    internal nint Function;
    internal nint Architecture;
    internal ulong Address;
}

internal static unsafe partial class Core {
    [LibraryImport(Library)]
    internal static partial byte* BNTagTypeGetId(nint tagType);
    [LibraryImport(Library)]
    internal static partial byte* BNTagTypeGetName(nint tagType);
    internal static QualifiedName BNDefineAnalysisType(nint view, byte* id, QualifiedName* name, nint type) =>
        AnnotationReconciliation.Current is { } owned && owned.View == view
            ? owned.DefineType(id, name, type) : DefineType(view, id, name, type);

    internal static nint BNCreateNamedTypeReferenceFromTypeAndId(byte* id, QualifiedName* name, nint type) =>
        AnnotationReconciliation.Current is { } owned
            ? owned.CreateTypeReference(id, name, type) : CreateTypeReference(id, name, type);

    internal static void BNDefineUserSymbol(nint view, nint symbol) {
        if (AnnotationReconciliation.Current is { } owned && owned.View == view)
            owned.DefineSymbol(symbol);
        else
            DefineSymbol(view, symbol);
    }

    internal static void BNDefineUserDataVariable(nint view, ulong address, TypeConfidence* type) {
        if (AnnotationReconciliation.Current is { } owned && owned.View == view)
            owned.DefineVariable(address, type);
        else
            DefineVariable(view, address, type);
    }

    internal static void BNAddUserDataReference(nint view, ulong from, ulong to) {
        if (AnnotationReconciliation.Current is { } owned && owned.View == view)
            owned.AddReference(from, to);
        else
            AddReference(view, from, to);
    }

    internal static nint BNGetAnalysisFunction(nint view, nint platform, ulong address) {
        nint function = GetFunction(view, platform, address);
        if (AnnotationReconciliation.Current is { } owned && owned.View == view && function != 0)
            owned.VisitFunction(address);
        return function;
    }

    internal static nint BNAddFunctionForAnalysis(nint view, nint platform, ulong address, byte auto, nint type) =>
        AnnotationReconciliation.Current is { } owned && owned.View == view
            ? owned.AddFunction(platform, address, auto, type) : AddFunction(view, platform, address, auto, type);

    internal static void BNApplyAutoDiscoveredFunctionType(nint function, nint type) {
        if (AnnotationReconciliation.Current is { } owned)
            owned.ApplyFunctionType(function, type);
        else
            ApplyFunctionType(function, type);
    }

    internal static bool BNCanApplyAutoDiscoveredFunctionType(nint function) =>
        AnnotationReconciliation.Current is { } owned
            ? owned.CanApplyFunctionType(function)
            : BNFunctionHasUserType(function) == 0;

    internal static void BNTagSetData(nint tag, byte* text) {
        if (AnnotationReconciliation.Current is { } owned)
            owned.SetTagData(tag, text);
        else
            SetTagData(tag, text);
    }

    internal static void BNRemoveTag(nint view, nint tag, byte user) {
        if (AnnotationReconciliation.Current is { } owned && owned.View == view)
            owned.RetireTag(tag);
        else
            RemoveTag(view, tag, user);
    }

    internal static void BNAddUserFunctionTag(nint function, nint tag) {
        AddFunctionTag(function, tag);
    }

    internal static void BNAddUserDataTag(nint view, ulong address, nint tag) {
        AddDataTag(view, address, tag);
    }

    internal static void BNBinaryViewStoreMetadata(nint view, byte* key, nint value, byte flags) {
        if (AnnotationReconciliation.Current is { } owned && owned.View == view)
            owned.StoreMetadata(key, value, flags);
        else
            StoreMetadataRaw(view, key, value, flags);
    }

    internal static void BNAddUserTypeFieldReference(nint function, nint architecture, ulong address,
        QualifiedName* name, ulong offset, nuint size) {
        if (AnnotationReconciliation.Current is { } owned)
            owned.AddFieldReference(function, architecture, address, name, offset, size);
        else
            AddFieldReference(function, architecture, address, name, offset, size);
    }

    [LibraryImport(Library)]
    internal static partial byte BNTypesEqual(nint first, nint second);
    [LibraryImport(Library)]
    internal static partial byte BNGetDataVariableAtAddress(nint view, ulong address, DataVariable* variable);
    [LibraryImport(Library)]
    internal static partial void BNFreeDataVariable(DataVariable* variable);
    [LibraryImport(Library)]
    internal static partial void BNUndefineUserDataVariable(nint view, ulong address);
    [LibraryImport(Library)]
    internal static partial void BNUndefineUserSymbol(nint view, nint symbol);
    [LibraryImport(Library)]
    internal static partial ulong* BNGetDataReferencesFrom(nint view, ulong address, nuint* count);
    [LibraryImport(Library)]
    internal static partial void BNFreeDataReferences(ulong* references);
    [LibraryImport(Library)]
    internal static partial void BNRemoveUserDataReference(nint view, ulong from, ulong to);
    [LibraryImport(Library)]
    internal static partial nint BNGetFunctionType(nint function);
    [LibraryImport(Library)]
    internal static partial ulong BNGetFunctionStart(nint function);
    [LibraryImport(Library)]
    internal static partial byte BNFunctionHasUserAnnotations(nint function);
    [LibraryImport(Library)]
    internal static partial void BNRemoveAnalysisFunction(nint view, nint function, byte updateReferences);
    [LibraryImport(Library)]
    internal static partial void BNSetFunctionAutoType(nint function, nint type);
    [LibraryImport(Library)]
    internal static partial void BNUndefineAnalysisType(nint view, byte* id);
    [LibraryImport(Library)]
    internal static partial nint BNGetTag(nint view, byte* id);
    [LibraryImport(Library)]
    internal static partial nint BNTagGetType(nint tag);
    [LibraryImport(Library)]
    internal static partial nint BNNewTagReference(nint tag);
    [LibraryImport(Library)]
    internal static partial TagReference* BNGetAllTagReferences(nint view, nuint* count);
    [LibraryImport(Library)]
    internal static partial void BNRemoveTagReference(nint view, TagReference reference);
    [LibraryImport(Library)]
    internal static partial void BNFreeTagReferences(TagReference* references, nuint count);
    [LibraryImport(Library)]
    internal static partial void BNBinaryViewRemoveMetadata(nint view, byte* key);
    [LibraryImport(Library)]
    internal static partial QualifiedNameAndType* BNGetAnalysisTypeList(nint view, nuint* count);
    [LibraryImport(Library)]
    internal static partial byte* BNGetAnalysisTypeId(nint view, QualifiedName* name);
    [LibraryImport(Library)]
    internal static partial void BNFreeTypeAndNameList(QualifiedNameAndType* types, nuint count);
    [LibraryImport(Library)]
    internal static partial nint BNNewTypeLibrary(nint architecture, byte* name);
    [LibraryImport(Library)]
    internal static partial void BNBinaryViewExportTypeToTypeLibrary(nint view, nint library, QualifiedName* name, nint type);
    [LibraryImport(Library)]
    internal static partial void BNAddTypeLibraryNamedType(nint library, QualifiedName* name, nint type);
    [LibraryImport(Library)]
    internal static partial QualifiedNameAndType* BNGetTypeLibraryNamedTypes(nint library, nuint* count);
    [LibraryImport(Library)]
    internal static partial TypeConfidence BNGetChildType(nint type);
    [LibraryImport(Library)]
    internal static partial nint BNGetTypeStructure(nint type);
    [LibraryImport(Library)]
    internal static partial NativeStructureMember* BNGetStructureMembers(nint structure, nuint* count);
    [LibraryImport(Library)]
    internal static partial void BNFreeStructureMemberList(NativeStructureMember* members, nuint count);
    [LibraryImport(Library)]
    internal static partial BaseStructure* BNGetBaseStructuresForStructure(nint structure, nuint* count);
    [LibraryImport(Library)]
    internal static partial void BNFreeBaseStructureList(BaseStructure* bases, nuint count);
    [LibraryImport(Library)]
    internal static partial nint BNGetTypeLibraryNamedType(nint library, QualifiedName* name);
    [LibraryImport(Library)]
    internal static partial byte BNFinalizeTypeLibrary(nint library);
    [LibraryImport(Library)]
    internal static partial byte BNWriteTypeLibraryToFile(nint library, byte* path);
    [LibraryImport(Library)]
    internal static partial nint BNLoadTypeLibraryFromFile(byte* path);
    [LibraryImport(Library)]
    internal static partial void BNFreeTypeLibrary(nint library);
    [LibraryImport(Library)]
    internal static partial byte* BNAllocString(byte* text);
    [LibraryImport(Library)]
    internal static partial byte** BNAllocStringList(byte** text, nuint count);
    [LibraryImport(Library)]
    internal static partial TypeFieldReference* BNGetCodeReferencesForTypeField(nint view,
        QualifiedName* name, ulong offset, nuint* count, byte limit, nuint maximum);
    [LibraryImport(Library)]
    internal static partial void BNFreeTypeFieldReferences(TypeFieldReference* references, nuint count);
    [LibraryImport(Library)]
    internal static partial void BNRemoveUserTypeFieldReference(nint function, nint architecture, ulong address,
        QualifiedName* name, ulong offset, nuint size);
    [LibraryImport(Library)]
    internal static partial ReferenceSource* BNGetCodeReferencesForType(nint view,
        QualifiedName* name, nuint* count, byte limit, nuint maximum);
    [LibraryImport(Library)]
    internal static partial ulong* BNGetDataReferencesForType(nint view,
        QualifiedName* name, nuint* count, byte limit, nuint maximum);
    [LibraryImport(Library)]
    internal static partial TypeReferenceSource* BNGetTypeReferencesForType(nint view,
        QualifiedName* name, nuint* count, byte limit, nuint maximum);
    [LibraryImport(Library)]
    internal static partial void BNFreeCodeReferences(ReferenceSource* references, nuint count);
    [LibraryImport(Library)]
    internal static partial void BNFreeTypeReferences(TypeReferenceSource* references, nuint count);
    [LibraryImport(Library)]
    internal static partial byte BNGetSymbolBinding(nint symbol);
    [LibraryImport(Library)]
    internal static partial ulong BNGetSymbolOrdinal(nint symbol);
    [LibraryImport(Library)]
    internal static partial QualifiedName BNGetSymbolNameSpace(nint symbol);
    [LibraryImport(Library)]
    internal static partial void BNFreeNameSpace(QualifiedName* name);
    [LibraryImport(Library)]
    internal static partial ReturnValue BNGetTypeReturnValue(nint type);
    [LibraryImport(Library)]
    internal static partial FunctionParameter* BNGetTypeParameters(nint type, nuint* count);
    [LibraryImport(Library)]
    internal static partial void BNFreeTypeParameterList(FunctionParameter* parameters, nuint count);
    [LibraryImport(Library)]
    internal static partial void BNFreeValueLocation(ValueLocation* location);
    [LibraryImport(Library)]
    internal static partial CallingConventionConfidence BNGetTypeCallingConvention(nint type);
    [LibraryImport(Library)]
    internal static partial OffsetConfidence BNGetTypeStackAdjustment(nint type);
    [LibraryImport(Library)]
    internal static partial BoolConfidence BNTypeHasVariableArguments(nint type);
    [LibraryImport(Library)]
    internal static partial BoolConfidence BNFunctionTypeCanReturn(nint type);
    [LibraryImport(Library)]
    internal static partial BoolConfidence BNIsTypePure(nint type);
    [LibraryImport(Library)]
    internal static partial byte* BNGetCallingConventionName(nint convention);
}
