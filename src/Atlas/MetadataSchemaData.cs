// NativeAOT metadata record schemas. Kind and field identities are canonical across source encodings.
namespace Atlas;

internal static class MetadataSchema {
    internal static RecordSpec Get(MetadataEncoding encoding, byte kind) {
        if (!encoding.CombinedTypeOwnership) {
            if (kind == 58) {
                return LegacyTypeDefinition;
            }
            if (kind == 61) {
                return LegacyTypeReference;
            }
        }
        return Current[kind];
    }

    internal static (MetadataFieldName Primary, MetadataFieldName? Fallback) OwnerFields(
        MetadataEncoding encoding, MetadataRecordKind kind) {
        return kind switch {
            MetadataRecordKind.TypeDefinition when !encoding.CombinedTypeOwnership =>
                (MetadataFieldName.EnclosingType, MetadataFieldName.NamespaceDefinition),
            MetadataRecordKind.TypeDefinition => (MetadataFieldName.NamespaceOrEnclosingType, null),
            MetadataRecordKind.TypeReference when !encoding.CombinedTypeOwnership =>
                (MetadataFieldName.ParentNamespaceOrType, null),
            MetadataRecordKind.TypeReference => (MetadataFieldName.NamespaceOrEnclosingType, null),
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };
    }

    internal static readonly RecordSpec[] Current = [
        new(0, "Root", [new(MetadataFieldName.ScopeDefinitions, "ScopeDefinition", WireKind.TypedHandle, 56, 1UL << 56, true, true, false)]),
        new(1, "ArraySignature", [
            new(MetadataFieldName.ElementType, "Handle", WireKind.Handle, 0, 0x6400200000000000UL, false, false, false),
            new(MetadataFieldName.Rank, "int", WireKind.Int32, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.Sizes, "Int32", WireKind.Int32, 0, 0x0UL, true, false, false),
            new(MetadataFieldName.LowerBounds, "Int32", WireKind.Int32, 0, 0x0UL, true, false, false),
        ]),
        new(2, "ByReferenceSignature", [
            new(MetadataFieldName.Type, "Handle", WireKind.Handle, 0, 0x6400200000000000UL, false, false, false),
        ]),
        new(3, "ConstantBooleanArray", [
            new(MetadataFieldName.Value, "Boolean", WireKind.Boolean, 0, 0x0UL, true, false, false),
        ]),
        new(4, "ConstantBooleanValue", [
            new(MetadataFieldName.Value, "bool", WireKind.Boolean, 0, 0x0UL, false, false, false),
        ]),
        new(5, "ConstantByteArray", [
            new(MetadataFieldName.Value, "Byte", WireKind.Byte, 0, 0x0UL, true, false, false),
        ]),
        new(6, "ConstantByteValue", [
            new(MetadataFieldName.Value, "byte", WireKind.Byte, 0, 0x0UL, false, false, false),
        ]),
        new(7, "ConstantCharArray", [
            new(MetadataFieldName.Value, "Char", WireKind.Char, 0, 0x0UL, true, false, false),
        ]),
        new(8, "ConstantCharValue", [
            new(MetadataFieldName.Value, "char", WireKind.Char, 0, 0x0UL, false, false, false),
        ]),
        new(9, "ConstantDoubleArray", [
            new(MetadataFieldName.Value, "Double", WireKind.Double, 0, 0x0UL, true, false, false),
        ]),
        new(10, "ConstantDoubleValue", [
            new(MetadataFieldName.Value, "double", WireKind.Double, 0, 0x0UL, false, false, false),
        ]),
        new(11, "ConstantEnumArray", [
            new(MetadataFieldName.ElementType, "Handle", WireKind.Handle, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.Value, "Handle", WireKind.Handle, 0, 0x0UL, false, false, false),
        ]),
        new(12, "ConstantEnumValue", [
            new(MetadataFieldName.Value, "Handle", WireKind.Handle, 0, 0x0UL, false, true, false),
            new(MetadataFieldName.Type, "Handle", WireKind.Handle, 0, 0x0UL, false, false, false),
        ]),
        new(13, "ConstantHandleArray", [
            new(MetadataFieldName.Value, "Handle", WireKind.Handle, 0, 0x0UL, true, false, false),
        ]),
        new(14, "ConstantInt16Array", [
            new(MetadataFieldName.Value, "Int16", WireKind.Int16, 0, 0x0UL, true, false, false),
        ]),
        new(15, "ConstantInt16Value", [
            new(MetadataFieldName.Value, "short", WireKind.Int16, 0, 0x0UL, false, false, false),
        ]),
        new(16, "ConstantInt32Array", [
            new(MetadataFieldName.Value, "Int32", WireKind.Int32, 0, 0x0UL, true, false, false),
        ]),
        new(17, "ConstantInt32Value", [
            new(MetadataFieldName.Value, "int", WireKind.Int32, 0, 0x0UL, false, false, false),
        ]),
        new(18, "ConstantInt64Array", [
            new(MetadataFieldName.Value, "Int64", WireKind.Int64, 0, 0x0UL, true, false, false),
        ]),
        new(19, "ConstantInt64Value", [
            new(MetadataFieldName.Value, "long", WireKind.Int64, 0, 0x0UL, false, false, false),
        ]),
        new(20, "ConstantReferenceValue", [
        ]),
        new(21, "ConstantSByteArray", [
            new(MetadataFieldName.Value, "SByte", WireKind.SByte, 0, 0x0UL, true, false, false),
        ]),
        new(22, "ConstantSByteValue", [
            new(MetadataFieldName.Value, "sbyte", WireKind.SByte, 0, 0x0UL, false, false, false),
        ]),
        new(23, "ConstantSingleArray", [
            new(MetadataFieldName.Value, "Single", WireKind.Single, 0, 0x0UL, true, false, false),
        ]),
        new(24, "ConstantSingleValue", [
            new(MetadataFieldName.Value, "float", WireKind.Single, 0, 0x0UL, false, false, false),
        ]),
        new(25, "ConstantStringArray", [
            new(MetadataFieldName.Value, "Handle", WireKind.Handle, 0, 0x4100000UL, true, false, false),
        ]),
        new(26, "ConstantStringValue", [
            new(MetadataFieldName.Value, "string", WireKind.String, 0, 0x0UL, false, false, false),
        ]),
        new(27, "ConstantUInt16Array", [
            new(MetadataFieldName.Value, "UInt16", WireKind.UInt16, 0, 0x0UL, true, false, false),
        ]),
        new(28, "ConstantUInt16Value", [
            new(MetadataFieldName.Value, "ushort", WireKind.UInt16, 0, 0x0UL, false, false, false),
        ]),
        new(29, "ConstantUInt32Array", [
            new(MetadataFieldName.Value, "UInt32", WireKind.UInt32, 0, 0x0UL, true, false, false),
        ]),
        new(30, "ConstantUInt32Value", [
            new(MetadataFieldName.Value, "uint", WireKind.UInt32, 0, 0x0UL, false, false, false),
        ]),
        new(31, "ConstantUInt64Array", [
            new(MetadataFieldName.Value, "UInt64", WireKind.UInt64, 0, 0x0UL, true, false, false),
        ]),
        new(32, "ConstantUInt64Value", [
            new(MetadataFieldName.Value, "ulong", WireKind.UInt64, 0, 0x0UL, false, false, false),
        ]),
        new(33, "CustomAttribute", [
            new(MetadataFieldName.Constructor, "Handle", WireKind.Handle, 0, 0x40008000000000UL, false, false, false),
            new(MetadataFieldName.FixedArguments, "Handle", WireKind.Handle, 0, 0x64000001FFFFFFF8UL, true, false, false),
            new(MetadataFieldName.NamedArguments, "NamedArgument", WireKind.TypedHandle, 46, 0x400000000000UL, true, true, false),
        ]),
        new(34, "Event", [
            new(MetadataFieldName.Flags, "EventAttributes", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.Name, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
            new(MetadataFieldName.Type, "Handle", WireKind.Handle, 0, 0x6400000000000000UL, false, false, false),
            new(MetadataFieldName.MethodSemantics, "MethodSemantics", WireKind.TypedHandle, 42, 0x40000000000UL, true, true, false),
            new(MetadataFieldName.CustomAttributes, "CustomAttribute", WireKind.TypedHandle, 33, 0x200000000UL, true, true, false),
        ]),
        new(35, "Field", [
            new(MetadataFieldName.Flags, "FieldAttributes", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.Name, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
            new(MetadataFieldName.Signature, "FieldSignature", WireKind.TypedHandle, 36, 0x1000000000UL, false, true, false),
            new(MetadataFieldName.DefaultValue, "Handle", WireKind.Handle, 0, 0x64000001FFFFFFF8UL, false, false, false),
            new(MetadataFieldName.Offset, "uint", WireKind.UInt32, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.CustomAttributes, "CustomAttribute", WireKind.TypedHandle, 33, 0x200000000UL, true, true, false),
        ]),
        new(36, "FieldSignature", [
            new(MetadataFieldName.Type, "Handle", WireKind.Handle, 0, 0x6400200000000000UL, false, false, false),
        ]),
        new(37, "FunctionPointerSignature", [
            new(MetadataFieldName.Signature, "MethodSignature", WireKind.TypedHandle, 43, 0x80000000000UL, false, false, false),
        ]),
        new(38, "GenericParameter", [
            new(MetadataFieldName.Number, "ushort", WireKind.UInt16, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.Flags, "GenericParameterAttributes", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.Kind, "GenericParameterKind", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.Name, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
            new(MetadataFieldName.Constraints, "Handle", WireKind.Handle, 0, 0x6400200000000000UL, true, false, false),
            new(MetadataFieldName.CustomAttributes, "CustomAttribute", WireKind.TypedHandle, 33, 0x200000000UL, true, true, false),
        ]),
        new(39, "MemberReference", [
            new(MetadataFieldName.Parent, "Handle", WireKind.Handle, 0, 0x6400000000000000UL, false, false, false),
            new(MetadataFieldName.Name, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
            new(MetadataFieldName.Signature, "Handle", WireKind.Handle, 0, 0x81000000000UL, false, true, false),
        ]),
        new(40, "Method", [
            new(MetadataFieldName.Flags, "MethodAttributes", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.ImplFlags, "MethodImplAttributes", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.Name, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
            new(MetadataFieldName.Signature, "MethodSignature", WireKind.TypedHandle, 43, 0x80000000000UL, false, true, false),
            new(MetadataFieldName.Parameters, "Parameter", WireKind.TypedHandle, 49, 0x2000000000000UL, true, true, false),
            new(MetadataFieldName.GenericParameters, "GenericParameter", WireKind.TypedHandle, 38, 0x4000000000UL, true, true, false),
            new(MetadataFieldName.CustomAttributes, "CustomAttribute", WireKind.TypedHandle, 33, 0x200000000UL, true, true, false),
        ]),
        new(41, "MethodInstantiation", [
            new(MetadataFieldName.Method, "Handle", WireKind.Handle, 0, 0x40008000000000UL, false, false, false),
            new(MetadataFieldName.GenericTypeArguments, "Handle", WireKind.Handle, 0, 0x6400200000000000UL, true, false, false),
        ]),
        new(42, "MethodSemantics", [
            new(MetadataFieldName.Attributes, "MethodSemanticsAttributes", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.Method, "Method", WireKind.TypedHandle, 40, 0x10000000000UL, false, false, false),
        ]),
        new(43, "MethodSignature", [
            new(MetadataFieldName.CallingConvention, "SignatureCallingConvention", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.GenericParameterCount, "int", WireKind.Int32, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.ReturnType, "Handle", WireKind.Handle, 0, 0x6400200000000000UL, false, false, false),
            new(MetadataFieldName.Parameters, "Handle", WireKind.Handle, 0, 0x6400200000000000UL, true, false, false),
            new(MetadataFieldName.VarArgParameters, "Handle", WireKind.Handle, 0, 0x6400200000000000UL, true, false, false),
        ]),
        new(44, "MethodTypeVariableSignature", [
            new(MetadataFieldName.Number, "int", WireKind.Int32, 0, 0x0UL, false, false, false),
        ]),
        new(45, "ModifiedType", [
            new(MetadataFieldName.IsOptional, "bool", WireKind.Boolean, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.ModifierType, "Handle", WireKind.Handle, 0, 0x6400000000000000UL, false, false, false),
            new(MetadataFieldName.Type, "Handle", WireKind.Handle, 0, 0x6400200000000000UL, false, false, false),
        ]),
        new(46, "NamedArgument", [
            new(MetadataFieldName.Flags, "NamedArgumentMemberKind", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.Name, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
            new(MetadataFieldName.Type, "Handle", WireKind.Handle, 0, 0x6400000000000000UL, false, false, false),
            new(MetadataFieldName.Value, "Handle", WireKind.Handle, 0, 0x64000001FFFFFFF8UL, false, false, false),
        ]),
        new(47, "NamespaceDefinition", [
            new(MetadataFieldName.ParentScopeOrNamespace, "Handle", WireKind.Handle, 0, 0x100800000000000UL, false, false, false),
            new(MetadataFieldName.Name, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
            new(MetadataFieldName.TypeDefinitions, "TypeDefinition", WireKind.TypedHandle, 58, 0x400000000000000UL, true, true, false),
            new(MetadataFieldName.TypeForwarders, "TypeForwarder", WireKind.TypedHandle, 59, 0x800000000000000UL, true, true, false),
            new(MetadataFieldName.NamespaceDefinitions, "NamespaceDefinition", WireKind.TypedHandle, 47, 0x800000000000UL, true, true, false),
        ]),
        new(48, "NamespaceReference", [
            new(MetadataFieldName.ParentScopeOrNamespace, "Handle", WireKind.Handle, 0, 0x201000000000000UL, false, false, false),
            new(MetadataFieldName.Name, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
        ]),
        new(49, "Parameter", [
            new(MetadataFieldName.Flags, "ParameterAttributes", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.Sequence, "ushort", WireKind.UInt16, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.Name, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
            new(MetadataFieldName.DefaultValue, "Handle", WireKind.Handle, 0, 0x64000001FFFFFFF8UL, false, false, false),
            new(MetadataFieldName.CustomAttributes, "CustomAttribute", WireKind.TypedHandle, 33, 0x200000000UL, true, true, false),
        ]),
        new(50, "PointerSignature", [
            new(MetadataFieldName.Type, "Handle", WireKind.Handle, 0, 0x6400200000000000UL, false, false, false),
        ]),
        new(51, "Property", [
            new(MetadataFieldName.Flags, "PropertyAttributes", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.Name, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
            new(MetadataFieldName.Signature, "PropertySignature", WireKind.TypedHandle, 52, 0x10000000000000UL, false, true, false),
            new(MetadataFieldName.MethodSemantics, "MethodSemantics", WireKind.TypedHandle, 42, 0x40000000000UL, true, true, false),
            new(MetadataFieldName.DefaultValue, "Handle", WireKind.Handle, 0, 0x64000001FFFFFFF8UL, false, false, false),
            new(MetadataFieldName.CustomAttributes, "CustomAttribute", WireKind.TypedHandle, 33, 0x200000000UL, true, true, false),
        ]),
        new(52, "PropertySignature", [
            new(MetadataFieldName.CallingConvention, "CallingConventions", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.Type, "Handle", WireKind.Handle, 0, 0x6400200000000000UL, false, false, false),
            new(MetadataFieldName.Parameters, "Handle", WireKind.Handle, 0, 0x6400200000000000UL, true, false, false),
        ]),
        new(53, "QualifiedField", [
            new(MetadataFieldName.Field, "Field", WireKind.TypedHandle, 35, 0x800000000UL, false, false, false),
            new(MetadataFieldName.EnclosingType, "TypeDefinition", WireKind.TypedHandle, 58, 0x400000000000000UL, false, false, false),
        ]),
        new(54, "QualifiedMethod", [
            new(MetadataFieldName.Method, "Method", WireKind.TypedHandle, 40, 0x10000000000UL, false, false, false),
            new(MetadataFieldName.EnclosingType, "TypeDefinition", WireKind.TypedHandle, 58, 0x400000000000000UL, false, false, false),
        ]),
        new(55, "SZArraySignature", [
            new(MetadataFieldName.ElementType, "Handle", WireKind.Handle, 0, 0x6400200000000000UL, false, false, false),
        ]),
        new(56, "ScopeDefinition", [
            new(MetadataFieldName.Flags, "AssemblyFlags", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.Name, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
            new(MetadataFieldName.HashAlgorithm, "AssemblyHashAlgorithm", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.MajorVersion, "ushort", WireKind.UInt16, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.MinorVersion, "ushort", WireKind.UInt16, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.BuildNumber, "ushort", WireKind.UInt16, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.RevisionNumber, "ushort", WireKind.UInt16, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.PublicKey, "Byte", WireKind.Byte, 0, 0x0UL, true, false, false),
            new(MetadataFieldName.Culture, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
            new(MetadataFieldName.RootNamespaceDefinition, "NamespaceDefinition", WireKind.TypedHandle, 47, 0x800000000000UL, false, true, false),
            new(MetadataFieldName.EntryPoint, "QualifiedMethod", WireKind.TypedHandle, 54, 0x40000000000000UL, false, false, false),
            new(MetadataFieldName.GlobalModuleType, "TypeDefinition", WireKind.TypedHandle, 58, 0x400000000000000UL, false, false, false),
            new(MetadataFieldName.CustomAttributes, "CustomAttribute", WireKind.TypedHandle, 33, 0x200000000UL, true, true, false),
            new(MetadataFieldName.ModuleName, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
            new(MetadataFieldName.Mvid, "Byte", WireKind.Byte, 0, 0x0UL, true, false, false),
            new(MetadataFieldName.ModuleCustomAttributes, "CustomAttribute", WireKind.TypedHandle, 33, 0x200000000UL, true, true, false),
        ]),
        new(57, "ScopeReference", [
            new(MetadataFieldName.Flags, "AssemblyFlags", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.Name, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
            new(MetadataFieldName.MajorVersion, "ushort", WireKind.UInt16, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.MinorVersion, "ushort", WireKind.UInt16, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.BuildNumber, "ushort", WireKind.UInt16, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.RevisionNumber, "ushort", WireKind.UInt16, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.PublicKeyOrToken, "Byte", WireKind.Byte, 0, 0x0UL, true, false, false),
            new(MetadataFieldName.Culture, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
        ]),
        new(58, "TypeDefinition", [
            new(MetadataFieldName.Flags, "TypeAttributes", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.BaseType, "Handle", WireKind.Handle, 0, 0x6400000000000000UL, false, false, false),
            new(MetadataFieldName.NamespaceOrEnclosingType, "Handle", WireKind.Handle, 0, 0x400800000000000UL, false, false, false),
            new(MetadataFieldName.Name, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
            new(MetadataFieldName.Size, "uint", WireKind.UInt32, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.PackingSize, "ushort", WireKind.UInt16, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.NestedTypes, "TypeDefinition", WireKind.TypedHandle, 58, 0x400000000000000UL, true, true, false),
            new(MetadataFieldName.Methods, "Method", WireKind.TypedHandle, 40, 0x10000000000UL, true, true, false),
            new(MetadataFieldName.Fields, "Field", WireKind.TypedHandle, 35, 0x800000000UL, true, true, false),
            new(MetadataFieldName.Properties, "Property", WireKind.TypedHandle, 51, 0x8000000000000UL, true, true, false),
            new(MetadataFieldName.Events, "Event", WireKind.TypedHandle, 34, 0x400000000UL, true, true, false),
            new(MetadataFieldName.GenericParameters, "GenericParameter", WireKind.TypedHandle, 38, 0x4000000000UL, true, true, false),
            new(MetadataFieldName.Interfaces, "Handle", WireKind.Handle, 0, 0x6400000000000000UL, true, false, false),
            new(MetadataFieldName.CustomAttributes, "CustomAttribute", WireKind.TypedHandle, 33, 0x200000000UL, true, true, false),
        ]),
        new(59, "TypeForwarder", [
            new(MetadataFieldName.Scope, "ScopeReference", WireKind.TypedHandle, 57, 0x200000000000000UL, false, false, false),
            new(MetadataFieldName.Name, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
            new(MetadataFieldName.NestedTypes, "TypeForwarder", WireKind.TypedHandle, 59, 0x800000000000000UL, true, true, false),
        ]),
        new(60, "TypeInstantiationSignature", [
            new(MetadataFieldName.GenericType, "Handle", WireKind.Handle, 0, 0x6400000000000000UL, false, false, false),
            new(MetadataFieldName.GenericTypeArguments, "Handle", WireKind.Handle, 0, 0x6400200000000000UL, true, false, false),
        ]),
        new(61, "TypeReference", [
            new(MetadataFieldName.NamespaceOrEnclosingType, "Handle", WireKind.Handle, 0, 0x2001000000000000UL, false, false, false),
            new(MetadataFieldName.TypeName, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
        ]),
        new(62, "TypeSpecification", [
            new(MetadataFieldName.Signature, "Handle", WireKind.Handle, 0, 0xB484102000000006UL, false, true, false),
        ]),
        new(63, "TypeVariableSignature", [
            new(MetadataFieldName.Number, "int", WireKind.Int32, 0, 0x0UL, false, false, false),
        ]),
    ];
    internal static readonly RecordSpec LegacyTypeDefinition = new(58, "TypeDefinition", [
            new(MetadataFieldName.Flags, "TypeAttributes", WireKind.Enum, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.BaseType, "Handle", WireKind.Handle, 0, 0x6400000000000000UL, false, false, false),
            new(MetadataFieldName.NamespaceDefinition, "NamespaceDefinition", WireKind.TypedHandle, 47, 0x800000000000UL, false, false, false),
            new(MetadataFieldName.Name, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
            new(MetadataFieldName.Size, "uint", WireKind.UInt32, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.PackingSize, "ushort", WireKind.UInt16, 0, 0x0UL, false, false, false),
            new(MetadataFieldName.EnclosingType, "TypeDefinition", WireKind.TypedHandle, 58, 0x400000000000000UL, false, false, false),
            new(MetadataFieldName.NestedTypes, "TypeDefinition", WireKind.TypedHandle, 58, 0x400000000000000UL, true, true, false),
            new(MetadataFieldName.Methods, "Method", WireKind.TypedHandle, 40, 0x10000000000UL, true, true, false),
            new(MetadataFieldName.Fields, "Field", WireKind.TypedHandle, 35, 0x800000000UL, true, true, false),
            new(MetadataFieldName.Properties, "Property", WireKind.TypedHandle, 51, 0x8000000000000UL, true, true, false),
            new(MetadataFieldName.Events, "Event", WireKind.TypedHandle, 34, 0x400000000UL, true, true, false),
            new(MetadataFieldName.GenericParameters, "GenericParameter", WireKind.TypedHandle, 38, 0x4000000000UL, true, true, false),
            new(MetadataFieldName.Interfaces, "Handle", WireKind.Handle, 0, 0x6400000000000000UL, true, false, false),
            new(MetadataFieldName.CustomAttributes, "CustomAttribute", WireKind.TypedHandle, 33, 0x200000000UL, true, true, false),
    ]);
    internal static readonly RecordSpec LegacyTypeReference = new(61, "TypeReference", [
            new(MetadataFieldName.ParentNamespaceOrType, "Handle", WireKind.Handle, 0, 0x2001000000000000UL, false, false, false),
            new(MetadataFieldName.TypeName, "ConstantStringValue", WireKind.TypedHandle, 26, 0x4000000UL, false, true, true),
    ]);
}

internal enum WireKind : byte {
    Boolean,
    Byte,
    SByte,
    Char,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Single,
    Double,
    Enum,
    String,
    Handle,
    TypedHandle
}

internal readonly record struct FieldSpec(
    MetadataFieldName Name,
    string ValueType,
    WireKind Wire,
    byte TargetKind,
    ulong AllowedKinds,
    bool Collection,
    bool Child,
    bool NameValue);

internal readonly record struct RecordSpec(byte Kind, string Name, FieldSpec[] Fields);



