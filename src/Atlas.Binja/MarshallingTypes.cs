using System.Buffers;
using System.Buffers.Text;
using System.Runtime.InteropServices;
using System.Text;

namespace Atlas.Binja;

internal struct StubPrototype {
    internal nint Type;
    internal byte Shape;
}

internal sealed unsafe class MarshallingTypes {
    internal StubPrototype[] Prototypes = [];
    private readonly List<nint> owned = new();
    private readonly Dictionary<int, nint> managedPointers = new();
    private nint convention;

    internal void Build(nint view, nint platform, Extraction extraction, ReadOnlySpan<nint> runtimeTypes, nint voidType, nint voidPointer) {
        var structs = CollectionsMarshal.AsSpan(extraction.Marshalling.Structs);
        var delegates = CollectionsMarshal.AsSpan(extraction.Marshalling.Delegates);
        if (structs.IsEmpty && delegates.IsEmpty)
            return;

        fixed (byte* name = "win64\0"u8)
            convention = Core.BNGetArchitectureCallingConventionByName(Core.BNGetPlatformArchitecture(platform), name);
        if (convention == 0)
            throw new NotSupportedException("Binary Ninja has no win64 calling convention for the NativeAOT PE view.");

        Prototypes = new StubPrototype[checked(4 + 3 * structs.Length + delegates.Length)];
        owned.EnsureCapacity(checked(10 + 6 * structs.Length + 2 * delegates.Length));
        Prototypes[1] = new StubPrototype { Type = Function(voidType, voidPointer, 0, "native\0"u8), Shape = 1 };
        Prototypes[2] = new StubPrototype { Type = Function(voidType, voidPointer, voidPointer, "arg1\0arg2\0"u8), Shape = 2 };
        Prototypes[3] = new StubPrototype { Type = Function(voidPointer, voidPointer, 0, "function_pointer\0"u8), Shape = 3 };

        var fields = CollectionsMarshal.AsSpan(extraction.Marshalling.Fields);
        var fieldData = extraction.Marshalling.StructData.Span;
        int maxName = 0;
        foreach (ref readonly var entry in structs)
            maxName = Math.Max(maxName, Encoding.UTF8.GetByteCount(extraction.Names.Values[entry.TypeIndex]));
        foreach (ref readonly var field in fields) {
            if (fieldData.Slice(field.Name.Start, field.Name.Count).Contains((byte)0))
                throw new InvalidDataException("A native field name contains a NUL and cant be represented by a Binary Ninja type.");
            maxName = Math.Max(maxName, field.Name.Count);
        }

        byte[] nameBuffer = new byte[maxName + 1];
        Span<byte> identifier = stackalloc byte[40];
        ReadOnlySpan<byte> idPrefix = "aot-atlas:native-type:v1:"u8;
        idPrefix.CopyTo(identifier);
        identifier[idPrefix.Length + 8] = 0;
        BoolConfidence qualifier = default;
        fixed (byte* atlas = "atlas\0"u8)
        fixed (byte* native = "native\0"u8)
        fixed (byte* join = "::\0"u8)
        fixed (byte* unknown = "unknown_native_field\0"u8)
        fixed (byte* unknownId = "aot-atlas:unknown-native-field:v1\0"u8)
        fixed (byte* text = nameBuffer)
        fixed (byte* id = identifier) {
            byte** parts = stackalloc byte*[3] { atlas, native, unknown };
            QualifiedName name = new() { Names = parts, Join = join, Count = 3 };
            nint unknownReference = Core.BNCreateNamedType(0, unknownId, &name);
            nint unknownType = Core.BNCreateNamedTypeReference(unknownReference, 0, 1, &qualifier, &qualifier);
            Core.BNFreeNamedTypeReference(unknownReference);
            owned.Add(unknownType);
            var fieldType = new TypeConfidence(unknownType);
            parts[2] = text;

            for (int i = 0; i < structs.Length; ++i) {
                ref readonly var entry = ref structs[i];
                if (entry.InvalidLayout)
                    continue;

                uint rva = checked((uint)(extraction.Types.Types[entry.TypeIndex].Address - extraction.Image.ImageBase));
                Utf8Formatter.TryFormat(rva, identifier[idPrefix.Length..], out _, new StandardFormat('X', 8));
                int bytes = Encoding.UTF8.GetBytes(extraction.Names.Values[entry.TypeIndex], nameBuffer);
                nameBuffer[bytes] = 0;
                nint reference;
                if (!entry.HasLayoutSize) {
                    nint named = Core.BNCreateNamedType(3, id, &name);
                    reference = Core.BNCreateNamedTypeReference(named, 0, 1, &qualifier, &qualifier);
                    Core.BNFreeNamedTypeReference(named);
                } else {
                    nint builder = Core.BNCreateStructureBuilder();
                    try {
                        Core.BNSetStructureBuilderPacked(builder, 1);
                        Core.BNSetStructureBuilderWidth(builder, entry.Size);
                        // The map proves offsets, but says nothing about each native fields type or extent
                        // Zero-width members preserve that distinction
                        for (int j = entry.Fields.Start; j < entry.Fields.End; ++j) {
                            ref readonly var field = ref fields[j];
                            fieldData.Slice(field.Name.Start, field.Name.Count).CopyTo(nameBuffer);
                            nameBuffer[field.Name.Count] = 0;
                            Core.BNAddStructureBuilderMemberAtOffset(builder, &fieldType, text, field.Offset, 0, 0, 0, 0, 0);
                        }

                        bytes = Encoding.UTF8.GetBytes(extraction.Names.Values[entry.TypeIndex], nameBuffer);
                        nameBuffer[bytes] = 0;
                        nint structure = Core.BNFinalizeStructureBuilder(builder);
                        nint type = Core.BNCreateStructureType(structure);
                        Core.BNFreeStructure(structure);
                        var actual = Core.BNDefineAnalysisType(view, id, &name, type);
                        reference = Core.BNCreateNamedTypeReferenceFromTypeAndId(id, &actual, type);
                        Core.BNFreeQualifiedName(&actual);
                        Core.BNFreeType(type);
                    } finally {
                        Core.BNFreeStructureBuilder(builder);
                    }
                }

                owned.Add(reference);
                if (entry.ToNative == 0 && entry.ToManaged == 0 && entry.Cleanup == 0)
                    continue;

                var target = new TypeConfidence(reference);
                nint nativePointer = Core.BNCreatePointerTypeOfWidth(8, &target, &qualifier, &qualifier, 0);
                owned.Add(nativePointer);
                nint managedPointer = ManagedPointer(entry.TypeIndex, runtimeTypes);
                int first = 4 + 3 * i;
                Prototypes[first] = new StubPrototype { Type = Function(voidType, managedPointer, nativePointer, "managed\0native\0"u8), Shape = 2 };
                Prototypes[first + 1] = new StubPrototype { Type = Function(voidType, nativePointer, managedPointer, "native\0managed\0"u8), Shape = 2 };
                Prototypes[first + 2] = new StubPrototype { Type = Function(voidType, nativePointer, 0, "native\0"u8), Shape = 1 };
            }
        }

        for (int i = 0; i < delegates.Length; ++i) {
            nint result = ManagedPointer(delegates[i].TypeIndex, runtimeTypes);
            Prototypes[4 + 3 * structs.Length + i] = new StubPrototype {
                Type = Function(result, voidPointer, 0, "function_pointer\0"u8),
                Shape = 3
            };
        }
    }

    private nint ManagedPointer(int index, ReadOnlySpan<nint> runtimeTypes) {
        if (managedPointers.TryGetValue(index, out nint pointer))
            return pointer;

        BoolConfidence qualifier = default;
        var target = new TypeConfidence(runtimeTypes[index]);
        pointer = Core.BNCreatePointerTypeOfWidth(8, &target, &qualifier, &qualifier, 0);
        owned.Add(pointer);
        managedPointers.Add(index, pointer);
        return pointer;
    }

    private nint Function(nint result, nint first, nint second, ReadOnlySpan<byte> names) {
        ReturnValue returnValue = new() { Type = result, TypeConfidence = 255, DefaultLocation = 1 };
        CallingConventionConfidence callingConvention = new() { Convention = convention, Confidence = 255 };
        BoolConfidence varArgs = new() { Confidence = 255 }, canReturn = new() { Value = 1 }, pure = default;
        OffsetConfidence stackAdjust = default;
        FunctionParameter* parameters = stackalloc FunctionParameter[2];
        parameters[0] = new FunctionParameter { Type = first, TypeConfidence = 255 };
        parameters[1] = new FunctionParameter { Type = second, TypeConfidence = 255 };
        fixed (byte* text = names) {
            parameters[0].Name = text;
            parameters[1].Name = second == 0 ? text : text + names.IndexOf((byte)0) + 1;
            nint type = Core.BNCreateFunctionType(&returnValue, &callingConvention, parameters, second == 0 ? 1U : 2U,
                &varArgs, &canReturn, &stackAdjust, null, null, 0, 0, &pure);
            owned.Add(type);
            return type;
        }
    }

    internal void Free() {
        foreach (nint type in owned)
            Core.BNFreeType(type);
        if (convention != 0)
            Core.BNFreeCallingConvention(convention);
    }
}
