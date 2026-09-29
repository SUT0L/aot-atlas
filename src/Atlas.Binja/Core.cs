using System.Runtime.InteropServices;

namespace Atlas.Binja;

[StructLayout(LayoutKind.Sequential)]
internal struct TypeConfidence(nint type) {
    internal nint Type = type;
    internal byte Confidence = 255;
}

[StructLayout(LayoutKind.Sequential)]
internal struct DataVariable {
    internal ulong Address;
    internal nint Type;
    internal byte AutoDiscovered, Confidence;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BoolConfidence {
    internal byte Value, Confidence;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct QualifiedName {
    internal byte** Names;
    internal byte* Join;
    internal nuint Count;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BaseStructure {
    internal nint Type;
    internal ulong Offset, Width;
}

[StructLayout(LayoutKind.Sequential)]
internal struct Variable {
    internal byte Source;
    internal uint Index;
    internal long Storage;
}

[StructLayout(LayoutKind.Sequential)]
internal struct ValueLocationComponent {
    internal Variable Variable;
    internal long Offset;
    internal byte SizeValid;
    internal ulong Size;
}

[StructLayout(LayoutKind.Sequential)]
internal struct ValueLocation {
    internal nuint Count;
    internal nint Components;
    internal byte Indirect, ReturnedPointerValid;
    internal Variable ReturnedPointer;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct FunctionParameter {
    internal byte* Name;
    internal nint Type;
    internal byte TypeConfidence, LocationSource;
    internal ValueLocation Location;
}

[StructLayout(LayoutKind.Sequential)]
internal struct ReturnValue {
    internal nint Type;
    internal byte TypeConfidence, DefaultLocation;
    internal ValueLocation Location;
    internal byte LocationConfidence;
}

[StructLayout(LayoutKind.Sequential)]
internal struct CallingConventionConfidence {
    internal nint Convention;
    internal byte Confidence;
}

[StructLayout(LayoutKind.Sequential)]
internal struct OffsetConfidence {
    internal long Value;
    internal byte Confidence;
}

// ABI 187: binaryninja-api commit 2ddf304b3275aa184e95570404539cbc4beb64c6
// Enums and C bools are one byte; opaque handles retain the cores ownership rules
internal static unsafe partial class Core {
    [LibraryImport("binaryninjacore")] internal static partial nint BNNewTypeReference(nint type);
    [LibraryImport("binaryninjacore")] internal static partial ulong BNGetTypeWidth(nint type);
    private const string Library = "binaryninjacore";

    [LibraryImport(Library)] internal static partial uint BNGetCurrentCoreABIVersion();
    [LibraryImport(Library)]
    internal static partial void BNRegisterPluginCommand(byte* name, byte* description,
        delegate* unmanaged[Cdecl]<nint, nint, void> action, delegate* unmanaged[Cdecl]<nint, nint, byte> valid, nint context);
    [LibraryImport(Library)] internal static partial void BNRegisterBinaryViewEvent(byte type,
        delegate* unmanaged[Cdecl]<nint, nint, void> callback, nint context);
    [LibraryImport(Library)] internal static partial nint BNBeginBackgroundTask(byte* text, byte cancelable);
    [LibraryImport(Library)] internal static partial void BNSetBackgroundTaskProgressText(nint task, byte* text);
    [LibraryImport(Library)] internal static partial byte BNIsBackgroundTaskCancelled(nint task);
    [LibraryImport(Library)] internal static partial void BNFinishBackgroundTask(nint task);
    [LibraryImport(Library)] internal static partial void BNFreeBackgroundTask(nint task);
    [LibraryImport(Library)] internal static partial void BNLogString(ulong session, byte level, byte* logger, ulong thread, byte* text);

    [LibraryImport(Library)] internal static partial nint BNNewViewReference(nint view);
    [LibraryImport(Library)] internal static partial void BNFreeBinaryView(nint view);
    [LibraryImport(Library)] internal static partial nint BNGetFileForView(nint view);
    [LibraryImport(Library)] internal static partial void BNFreeFileMetadata(nint file);
    [LibraryImport(Library)] internal static partial ulong BNFileMetadataGetSessionId(nint file);
    [LibraryImport(Library)] internal static partial nint BNGetFileViewOfType(nint file, byte* name);
    [LibraryImport(Library)] internal static partial byte* BNGetViewType(nint view);
    [LibraryImport(Library)] internal static partial void BNFreeString(byte* text);
    [LibraryImport(Library)] internal static partial ulong BNGetImageBase(nint view);
    [LibraryImport(Library)] internal static partial ulong BNGetViewLength(nint view);
    [LibraryImport(Library)] internal static partial nint BNReadViewBuffer(nint view, ulong offset, ulong length);
    [LibraryImport(Library)] internal static partial void* BNGetDataBufferContents(nint buffer);
    [LibraryImport(Library)] internal static partial ulong BNGetDataBufferLength(nint buffer);
    [LibraryImport(Library)] internal static partial void BNFreeDataBuffer(nint buffer);

    [LibraryImport(Library)] internal static partial nint BNCreateMetadataRawData(byte* data, nuint size);
    [LibraryImport(Library)] internal static partial byte BNMetadataIsRaw(nint metadata);
    [LibraryImport(Library)] internal static partial byte* BNMetadataGetRaw(nint metadata, nuint* size);
    [LibraryImport(Library)] internal static partial void BNFreeMetadataRaw(byte* data);
    [LibraryImport(Library)] internal static partial void BNFreeMetadata(nint metadata);
    [LibraryImport(Library)] internal static partial nint BNBinaryViewQueryMetadata(nint view, byte* key);
    [LibraryImport(Library)] internal static partial void BNBinaryViewStoreMetadata(nint view, byte* key, nint metadata, byte flags);
    [LibraryImport(Library)] internal static partial nint BNGetAnalysisTypeById(nint view, byte* id);
    [LibraryImport(Library)] internal static partial byte BNIsAnalysisTypeAutoDefined(nint view, QualifiedName* name);
    [LibraryImport(Library)] internal static partial byte BNGetTypeClass(nint type);
    [LibraryImport(Library)] internal static partial BoolConfidence BNIsTypeSigned(nint type);
    [LibraryImport(Library)] internal static partial nint BNCreateTypeBuilderFromType(nint type);
    [LibraryImport(Library)] internal static partial void BNTypeBuilderSetSigned(nint type, BoolConfidence* signed);
    [LibraryImport(Library)] internal static partial nint BNFinalizeTypeBuilder(nint type);
    [LibraryImport(Library)] internal static partial void BNFreeTypeBuilder(nint type);

    [LibraryImport(Library)]
    internal static partial nint BNCreateSymbol(byte kind, byte* shortName, byte* fullName,
        byte* rawName, ulong address, byte binding, nint nameSpace, ulong ordinal);
    [LibraryImport(Library)] internal static partial nint BNGetSymbolByAddress(nint view, ulong address, nint nameSpace);
    [LibraryImport(Library)] internal static partial byte* BNGetSymbolRawName(nint symbol);
    [LibraryImport(Library)] internal static partial byte* BNGetSymbolFullName(nint symbol);
    [LibraryImport(Library)] internal static partial byte* BNGetSymbolShortName(nint symbol);
    [LibraryImport(Library)] internal static partial nint* BNGetSymbols(nint view, nuint* count, nint nameSpace);
    [LibraryImport(Library)] internal static partial ulong BNGetSymbolAddress(nint symbol);
    [LibraryImport(Library)] internal static partial byte BNGetSymbolType(nint symbol);
    [LibraryImport(Library)] internal static partial void BNFreeSymbolList(nint* symbols, nuint count);
    [LibraryImport(Library)] internal static partial byte BNIsSymbolAutoDefined(nint symbol);
    [LibraryImport(Library)] internal static partial void BNDefineUserSymbol(nint view, nint symbol);
    [LibraryImport(Library)] internal static partial void BNFreeSymbol(nint symbol);
    [LibraryImport(Library)] internal static partial void BNBeginBulkModifySymbols(nint view);
    [LibraryImport(Library)] internal static partial void BNEndBulkModifySymbols(nint view);
    [LibraryImport(Library)] internal static partial void BNAddUserDataReference(nint view, ulong from, ulong to);
    [LibraryImport(Library)] internal static partial void BNDefineUserDataVariable(nint view, ulong address, TypeConfidence* type);
    [LibraryImport(Library)] internal static partial DataVariable* BNGetDataVariables(nint view, nuint* count);
    [LibraryImport(Library)] internal static partial void BNFreeDataVariables(DataVariable* variables, nuint count);

    [LibraryImport(Library)] internal static partial nint BNGetDefaultPlatform(nint view);
    [LibraryImport(Library)] internal static partial void BNFreePlatform(nint platform);
    [LibraryImport(Library)] internal static partial nint BNGetPlatformArchitecture(nint platform);
    [LibraryImport(Library)] internal static partial uint BNGetArchitectureRegisterByName(nint architecture, byte* name);
    [LibraryImport(Library)] internal static partial nint BNGetArchitectureCallingConventionByName(nint architecture, byte* name);
    [LibraryImport(Library)] internal static partial void BNFreeCallingConvention(nint convention);
    [LibraryImport(Library)] internal static partial nint BNGetAnalysisFunction(nint view, nint platform, ulong address);
    [LibraryImport(Library)] internal static partial nint BNAddFunctionForAnalysis(nint view, nint platform, ulong address, byte autoDiscovered, nint type);
    [LibraryImport(Library)] internal static partial void BNFreeFunction(nint function);
    [LibraryImport(Library)] internal static partial void BNApplyAutoDiscoveredFunctionType(nint function, nint type);
    [LibraryImport(Library)] internal static partial void BNUpdateAnalysis(nint view);
    [LibraryImport(Library)] internal static partial void BNUpdateAnalysisAndWait(nint view);
    [LibraryImport(Library)] internal static partial byte BNGetAnalysisState(nint view);
    [LibraryImport(Library)] internal static partial nint BNGetFunctionBasicBlockAtAddress(nint function, nint architecture, ulong address);
    [LibraryImport(Library)] internal static partial void BNFreeBasicBlock(nint block);
    [LibraryImport(Library)] internal static partial QualifiedName BNGetAnalysisTypeNameById(nint view, byte* id);
    [LibraryImport(Library)] internal static partial void BNAddUserTypeFieldReference(nint function, nint architecture,
        ulong address, QualifiedName* name, ulong offset, nuint size);
    [LibraryImport(Library)] internal static partial byte BNFunctionHasUserType(nint function);
    [LibraryImport(Library)] internal static partial nint BNGetTagType(nint view, byte* name);
    [LibraryImport(Library)] internal static partial nint BNCreateTagType(nint view);
    [LibraryImport(Library)] internal static partial void BNTagTypeSetName(nint type, byte* name);
    [LibraryImport(Library)] internal static partial void BNTagTypeSetIcon(nint type, byte* icon);
    [LibraryImport(Library)] internal static partial void BNAddTagType(nint view, nint type);
    [LibraryImport(Library)] internal static partial void BNFreeTagType(nint type);
    [LibraryImport(Library)] internal static partial nint BNCreateTag(nint type, byte* data);
    [LibraryImport(Library)] internal static partial byte* BNTagGetData(nint tag);
    [LibraryImport(Library)] internal static partial byte* BNTagGetId(nint tag);
    [LibraryImport(Library)] internal static partial void BNTagSetData(nint tag, byte* data);
    [LibraryImport(Library)] internal static partial void BNAddTag(nint view, nint tag, byte user);
    [LibraryImport(Library)] internal static partial void BNRemoveTag(nint view, nint tag, byte user);
    [LibraryImport(Library)] internal static partial void BNFreeTag(nint tag);
    [LibraryImport(Library)] internal static partial nint* BNGetUserFunctionTagsOfType(nint function, nint type, nuint* count);
    [LibraryImport(Library)] internal static partial void BNFreeTagList(nint* tags, nuint count);
    [LibraryImport(Library)] internal static partial void BNAddUserFunctionTag(nint function, nint tag);
    [LibraryImport(Library)] internal static partial void BNRemoveUserFunctionTag(nint function, nint tag);
    [LibraryImport(Library)] internal static partial nint* BNGetUserDataTagsOfType(nint view, ulong address, nint type, nuint* count);
    [LibraryImport(Library)] internal static partial void BNAddUserDataTag(nint view, ulong address, nint tag);
    [LibraryImport(Library)] internal static partial void BNRemoveUserDataTag(nint view, ulong address, nint tag);

    [LibraryImport(Library)] internal static partial nint BNCreateIntegerType(nuint width, BoolConfidence* signed, byte* name);
    [LibraryImport(Library)] internal static partial nint BNCreateEnumerationBuilder();
    [LibraryImport(Library)] internal static partial void BNAddEnumerationBuilderMemberWithValue(nint builder, byte* name, ulong value);
    [LibraryImport(Library)] internal static partial nint BNFinalizeEnumerationBuilder(nint builder);
    [LibraryImport(Library)] internal static partial nint BNCreateEnumerationTypeOfWidth(nint enumeration, nuint width, BoolConfidence* signed);
    [LibraryImport(Library)] internal static partial void BNFreeEnumeration(nint enumeration);
    [LibraryImport(Library)] internal static partial void BNFreeEnumerationBuilder(nint builder);
    [LibraryImport(Library)] internal static partial nint BNCreateVoidType();
    [LibraryImport(Library)] internal static partial nint BNCreateBoolType();
    [LibraryImport(Library)] internal static partial nint BNCreateFloatType(nuint width, byte* name);
    [LibraryImport(Library)] internal static partial nint BNCreateWideCharType(nuint width, byte* name);
    [LibraryImport(Library)]
    internal static partial nint BNCreatePointerTypeOfWidth(nuint width, TypeConfidence* type,
        BoolConfidence* constant, BoolConfidence* volatileValue, byte referenceType);
    [LibraryImport(Library)] internal static partial nint BNCreateArrayType(TypeConfidence* type, ulong count);
    [LibraryImport(Library)]
    internal static partial nint BNCreateFunctionType(ReturnValue* result, CallingConventionConfidence* convention,
        FunctionParameter* parameters, nuint count, BoolConfidence* varArgs, BoolConfidence* canReturn,
        OffsetConfidence* stackAdjust, uint* registerStackRegisters, OffsetConfidence* registerStackValues,
        nuint registerStackCount, byte nameType, BoolConfidence* pure);
    [LibraryImport(Library)] internal static partial nint BNGetTypeNamedTypeReference(nint type);
    [LibraryImport(Library)] internal static partial byte* BNGetTypeReferenceId(nint reference);
    [LibraryImport(Library)] internal static partial QualifiedName BNGetTypeReferenceName(nint reference);
    [LibraryImport(Library)] internal static partial nint BNCreateNamedType(byte kind, byte* id, QualifiedName* name);
    [LibraryImport(Library)] internal static partial nint BNCreateNamedTypeReference(nint reference, nuint width, nuint alignment, BoolConfidence* constant, BoolConfidence* volatileValue);
    [LibraryImport(Library)] internal static partial void BNFreeNamedTypeReference(nint reference);
    [LibraryImport(Library)] internal static partial void BNFreeType(nint type);
    [LibraryImport(Library)] internal static partial nint BNCreateStructureBuilder();
    [LibraryImport(Library)]
    internal static partial void BNAddStructureBuilderMemberAtOffset(nint builder, TypeConfidence* type,
        byte* name, ulong offset, byte overwrite, byte access, byte scope, byte bitPosition, byte bitWidth);
    [LibraryImport(Library)] internal static partial void BNSetStructureBuilderWidth(nint builder, ulong width);
    [LibraryImport(Library)] internal static partial void BNSetStructureBuilderPacked(nint builder, byte packed);
    [LibraryImport(Library)] internal static partial void BNSetBaseStructuresForStructureBuilder(nint builder, BaseStructure* bases, nuint count);
    [LibraryImport(Library)] internal static partial nint BNFinalizeStructureBuilder(nint builder);
    [LibraryImport(Library)] internal static partial void BNFreeStructureBuilder(nint builder);
    [LibraryImport(Library)] internal static partial nint BNCreateStructureType(nint structure);
    [LibraryImport(Library)] internal static partial void BNFreeStructure(nint structure);
    [LibraryImport(Library)] internal static partial QualifiedName BNDefineAnalysisType(nint view, byte* id, QualifiedName* name, nint type);
    [LibraryImport(Library)] internal static partial nint BNCreateNamedTypeReferenceFromTypeAndId(byte* id, QualifiedName* name, nint type);
    [LibraryImport(Library)] internal static partial void BNFreeQualifiedName(QualifiedName* name);
}
