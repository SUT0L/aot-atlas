using System.Buffers.Text;
using System.Runtime.InteropServices;

namespace Atlas.Binja;

internal sealed unsafe class ManagedTypes {
    private readonly List<nint> owned = new();
    private readonly Dictionary<nint, nint> pointers = new();
    private readonly Dictionary<int, nint> boxes = new();
    private readonly uint[] registers = new uint[9];
    private FunctionParameter[] parameters = [];
    private ValueLocationComponent[] components = [];
    private byte[] names = [];
    private nint convention, unknown;
    private byte[] traceName = new byte[1024];

    internal void DefineTrace(nint view, uint witness, ReadOnlySpan<byte> name, nint type) {
        Span<byte> identifier = stackalloc byte[48];
        ReadOnlySpan<byte> prefix = "aot-atlas:trace-signature:v1:"u8;
        prefix.CopyTo(identifier);
        Utf8Formatter.TryFormat(witness, identifier[prefix.Length..], out _, new System.Buffers.StandardFormat('X', 8));
        identifier[prefix.Length + 8] = 0;
        if (traceName.Length < name.Length + 11) {
            Array.Resize(ref traceName, Math.Max(traceName.Length * 2, name.Length + 11));
        }

        name.CopyTo(traceName);
        "::"u8.CopyTo(traceName.AsSpan(name.Length));
        identifier.Slice(prefix.Length, 8).CopyTo(traceName.AsSpan(name.Length + 2));
        traceName[name.Length + 10] = 0;
        fixed (byte* id = identifier)
        fixed (byte* label = traceName)
        fixed (byte* atlas = "atlas\0"u8)
        fixed (byte* join = "::\0"u8) {
            byte** parts = stackalloc byte*[2] { atlas, label };
            QualifiedName qualified = new() { Names = parts, Join = join, Count = 2 };
            var actual = Core.BNDefineAnalysisType(view, id, &qualified, type);
            Core.BNFreeQualifiedName(&actual);
        }
    }

    internal nint Constructor(nint voidType) {
        ReturnValue result = new() { Type = voidType, TypeConfidence = 255, DefaultLocation = 1, LocationConfidence = 255 };
        CallingConventionConfidence callingConvention = new() { Convention = convention, Confidence = 255 };
        BoolConfidence varArgs = new() { Confidence = 255 }, canReturn = new() { Value = 1 }, pure = default;
        OffsetConfidence stackAdjust = default;
        // BN6 requires a parameter-list pointer even when its count is zero
        FunctionParameter empty = default;
        return Core.BNCreateFunctionType(&result, &callingConvention, &empty, 0,
            &varArgs, &canReturn, &stackAdjust, null, null, 0, 0, &pure);
    }

    internal void Initialize(nint platform, ManagedAbi abi) {
        nint architecture = Core.BNGetPlatformArchitecture(platform);
        fixed (byte* name = "win64\0"u8)
            convention = Core.BNGetArchitectureCallingConventionByName(architecture, name);
        if (convention == 0)
            throw new NotSupportedException("Binary Ninja has no win64 calling convention for the NativeAOT PE view.");

        ReadOnlySpan<byte> registerNames = "rcx\0rdx\0r8\0r9\0xmm0\0xmm1\0xmm2\0xmm3\0rax\0"u8;
        fixed (byte* text = registerNames) {
            int offset = 0;
            for (int i = 0; i < registers.Length; ++i) {
                registers[i] = Core.BNGetArchitectureRegisterByName(architecture, text + offset);
                if (registers[i] == uint.MaxValue)
                    throw new NotSupportedException("Binary Ninja's architecture does not expose the Windows x64 argument registers.");
                offset += registerNames[offset..].IndexOf((byte)0) + 1;
            }
        }

        int maximum = 0;
        foreach (ref readonly var method in abi.Methods.AsSpan())
            maximum = Math.Max(maximum, method.Parameters.Count);
        parameters = new FunctionParameter[maximum];
        components = new ValueLocationComponent[maximum + 1];
        names = new byte[checked(maximum * 24)];

        BoolConfidence qualifier = default;
        fixed (byte* id = "aot-atlas:unknown-managed-type:v1\0"u8)
        fixed (byte* text = "unknown_managed_type\0"u8) {
            QualifiedName name = new() { Names = &text, Count = 1 };
            nint reference = Core.BNCreateNamedType(0, id, &name);
            unknown = Core.BNCreateNamedTypeReference(reference, 0, 1, &qualifier, &qualifier);
            Core.BNFreeNamedTypeReference(reference);
            owned.Add(unknown);
        }
    }

    internal nint Function(nint view, Extraction extraction, ManagedAbi abi, int index,
        ReadOnlySpan<nint> runtimeTypes, nint headerType, nint voidType, nint voidPointer, bool unboxed) {
        ref readonly var method = ref abi.Methods[index];
        int owner = abi.Owners[index];
        var typeArguments = ManagedAbi.Arguments(extraction, index);
        var arguments = abi.Parameters.AsSpan(method.Parameters.Start, method.Parameters.Count);
        ReturnValue result = new() {
            Type = Type(view, extraction, method.Return, owner, typeArguments, runtimeTypes, headerType, voidType, voidPointer),
            TypeConfidence = 255,
            DefaultLocation = (byte)(method.Return.Kind == AbiKind.Void ? 1 : 0),
            LocationConfidence = 255
        };

        fixed (FunctionParameter* native = parameters)
        fixed (ValueLocationComponent* locations = components)
        fixed (byte* text = names) {
            if (method.Return.Kind != AbiKind.Void) {
                Variable storage = method.Return.Indirect ? ArgumentLocation(method.ReturnSlot, false)
                    : new Variable { Source = 1, Storage = registers[method.Return.Kind == AbiKind.Float ? 4 : 8] };
                locations[0] = new ValueLocationComponent {
                    Variable = storage,
                    SizeValid = (byte)(method.Return.Indirect ? 0 : 1),
                    Size = method.Return.Indirect ? 0 : method.Return.Size
                };
                result.Location = new ValueLocation {
                    Count = 1,
                    Components = (nint)locations,
                    Indirect = (byte)(method.Return.Indirect ? 1 : 0),
                    ReturnedPointerValid = (byte)(method.Return.Indirect ? 1 : 0),
                    ReturnedPointer = new Variable { Source = 1, Storage = registers[8] }
                };
            }

            int formal = 0;
            for (int i = 0; i < arguments.Length; ++i) {
                ref readonly var argument = ref arguments[i];
                var name = names.AsSpan(i * 24, 24);
                if (argument.Role == AbiRole.This)
                    "this\0"u8.CopyTo(name);
                else if (argument.Role == AbiRole.GenericContext)
                    "generic_context\0"u8.CopyTo(name);
                else {
                    "arg"u8.CopyTo(name);
                    Utf8Formatter.TryFormat(++formal, name[3..], out int bytes);
                    name[3 + bytes] = 0;
                }

                locations[i + 1] = new ValueLocationComponent {
                    Variable = ArgumentLocation(argument.Slot, argument.Value.Kind == AbiKind.Float),
                    SizeValid = (byte)(argument.Value.Indirect ? 0 : 1),
                    Size = argument.Value.Indirect ? 0 : argument.Value.Size
                };
                native[i] = new FunctionParameter {
                    Name = text + i * 24,
                    Type = unboxed && argument.Role == AbiRole.This ? Pointer(runtimeTypes[argument.Value.Binding - 1])
                        : Type(view, extraction, argument.Value, owner, typeArguments, runtimeTypes, headerType, voidType, voidPointer),
                    TypeConfidence = 255,
                    LocationSource = 3,
                    Location = new ValueLocation {
                        Count = 1,
                        Components = (nint)(locations + i + 1),
                        Indirect = (byte)(argument.Value.Indirect ? 1 : 0)
                    }
                };
            }

            CallingConventionConfidence callingConvention = new() { Convention = convention, Confidence = 255 };
            BoolConfidence varArgs = new() { Confidence = 255 }, canReturn = new() { Value = 1 }, pure = default;
            OffsetConfidence stackAdjust = default;
            return Core.BNCreateFunctionType(&result, &callingConvention, native, (nuint)arguments.Length,
                &varArgs, &canReturn, &stackAdjust, null, null, 0, 0, &pure);
        }
    }

    private Variable ArgumentLocation(int slot, bool floating) => slot >= 4
        ? new Variable { Storage = 8L + 8L * slot }
        : new Variable { Source = 1, Storage = registers[(floating ? 4 : 0) + slot] };

    private nint Type(nint view, Extraction extraction, in AbiValue value, int owner, ReadOnlySpan<ulong> arguments,
        ReadOnlySpan<nint> runtimeTypes, nint headerType, nint voidType, nint voidPointer) {
        if (value.Kind == AbiKind.Void)
            return voidType;
        if (value.Kind == AbiKind.Context)
            return voidPointer;
        if (value.Binding != 0) {
            nint runtime = runtimeTypes[value.Binding - 1];
            if (value.Kind is AbiKind.Reference or AbiKind.UnboxedReference)
                return Pointer(runtime);
            if (value.Kind != AbiKind.BoxedReference)
                return runtime;
            if (boxes.TryGetValue(value.Binding, out nint box))
                return box;

            var table = extraction.Types.Types[value.Binding - 1];
            uint rva = checked((uint)(table.Address - extraction.Image.ImageBase));
            nint reference = ObjectTypes.DefineBox(view, rva, table.BaseSize - 8, runtime, Pointer(headerType));
            owned.Add(reference);
            box = Pointer(reference);
            boxes.Add(value.Binding, box);
            return box;
        }

        if (value.Kind is AbiKind.Pointer or AbiKind.ByReference) {
            var nodes = CollectionsMarshal.AsSpan(extraction.Metadata.Signatures.Nodes);
            int signature = value.Signature;
            while (nodes[signature].Kind == SignatureKind.Modified)
                signature = nodes[signature].Element;
            var element = ManagedAbi.Resolve(extraction, nodes[signature].Element,
                owner, arguments);
            return Pointer(Type(view, extraction, element, owner, arguments, runtimeTypes, headerType, voidType, voidPointer));
        }

        // An array or function-pointer signature proves pointer storage even when its target identity or callable ABI cant be reconstructed
        return value.Kind is AbiKind.Reference or AbiKind.FunctionPointer ? Pointer(unknown) : unknown;
    }

    private nint Pointer(nint target) {
        if (pointers.TryGetValue(target, out nint pointer))
            return pointer;

        var type = new TypeConfidence(target);
        BoolConfidence qualifier = default;
        pointer = Core.BNCreatePointerTypeOfWidth(8, &type, &qualifier, &qualifier, 0);
        pointers.Add(target, pointer);
        owned.Add(pointer);
        return pointer;
    }

    internal void Free() {
        foreach (nint type in owned)
            Core.BNFreeType(type);
        if (convention != 0)
            Core.BNFreeCallingConvention(convention);
    }
}
