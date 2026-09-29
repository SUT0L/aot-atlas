using System.Text;

namespace Atlas.Binja;

internal static unsafe class PropertyFunctionAnnotations {
    internal static int Apply(Symbols symbols, nint view, Extraction extraction, PropertyProjections properties,
        ReadOnlySpan<nint> runtimeTypes, nint voidType, ref ApplyStats stats, nint task) {
        if (properties.Functions.Length == 0) {
            return 0;
        }
        nint platform = Core.BNGetDefaultPlatform(view);
        nint architecture = Core.BNGetPlatformArchitecture(platform);
        nint convention;
        uint receiverRegister, valueRegister, returnRegister;
        fixed (byte* win64 = "win64\0"u8)
        fixed (byte* rcx = "rcx\0"u8)
        fixed (byte* rdx = "rdx\0"u8)
        fixed (byte* rax = "rax\0"u8) {
            convention = Core.BNGetArchitectureCallingConventionByName(architecture, win64);
            receiverRegister = Core.BNGetArchitectureRegisterByName(architecture, rcx);
            valueRegister = Core.BNGetArchitectureRegisterByName(architecture, rdx);
            returnRegister = Core.BNGetArchitectureRegisterByName(architecture, rax);
        }
        if (convention == 0 || receiverRegister == uint.MaxValue || valueRegister == uint.MaxValue || returnRegister == uint.MaxValue) {
            if (convention != 0) {
                Core.BNFreeCallingConvention(convention);
            }
            Core.BNFreePlatform(platform);
            throw new NotSupportedException("Binary Ninja does not expose the Windows x64 property accessor calling convention.");
        }

        var pointers = new Dictionary<nint, nint>();
        var names = new StringBuilder();
        byte[] nameBuffer = new byte[Encoding.UTF8.GetMaxByteCount(1024) + 1];
        char[] nameCharacters = new char[1024];
        BoolConfidence qualifier = default;
        FunctionParameter* parameters = stackalloc FunctionParameter[2];
        ValueLocationComponent* locations = stackalloc ValueLocationComponent[3];
        int applied = 0;
        try {
            fixed (byte* thisName = "this\0"u8)
            fixed (byte* valueName = "arg1\0"u8) {
                foreach (var entry in properties.Functions) {
                    if (task != 0 && Core.BNIsBackgroundTaskCancelled(task) != 0) {
                        throw new OperationCanceledException();
                    }
                    var projection = properties.Projections[entry.Projection];
                    nint receiver = runtimeTypes[projection.Owner];
                    if (!pointers.TryGetValue(receiver, out nint receiverPointer)) {
                        var confidence = new TypeConfidence(receiver);
                        receiverPointer = Core.BNCreatePointerTypeOfWidth(8, &confidence, &qualifier, &qualifier, 0);
                        pointers.Add(receiver, receiverPointer);
                    }
                    nint value = runtimeTypes[projection.Storage.Binding - 1];
                    if (projection.Storage.Kind == AbiKind.Reference) {
                        if (!pointers.TryGetValue(value, out nint valuePointer)) {
                            var confidence = new TypeConfidence(value);
                            valuePointer = Core.BNCreatePointerTypeOfWidth(8, &confidence, &qualifier, &qualifier, 0);
                            pointers.Add(value, valuePointer);
                        }
                        value = valuePointer;
                    }

                    locations[0] = new ValueLocationComponent {
                        Variable = new Variable { Source = 1, Storage = receiverRegister }, SizeValid = 1, Size = 8
                    };
                    locations[1] = new ValueLocationComponent {
                        Variable = new Variable { Source = 1, Storage = valueRegister }, SizeValid = 1, Size = projection.Size
                    };
                    locations[2] = new ValueLocationComponent {
                        Variable = new Variable { Source = 1, Storage = returnRegister }, SizeValid = 1, Size = projection.Size
                    };
                    parameters[0] = new FunctionParameter {
                        Name = thisName, Type = receiverPointer, TypeConfidence = 255, LocationSource = 3,
                        Location = new ValueLocation { Count = 1, Components = (nint)locations }
                    };
                    parameters[1] = new FunctionParameter {
                        Name = valueName, Type = value, TypeConfidence = 255, LocationSource = 3,
                        Location = new ValueLocation { Count = 1, Components = (nint)(locations + 1) }
                    };
                    ReturnValue result = new() {
                        Type = entry.Setter ? voidType : value, TypeConfidence = 255,
                        DefaultLocation = (byte)(entry.Setter ? 1 : 0), LocationConfidence = 255,
                        Location = entry.Setter ? default : new ValueLocation { Count = 1, Components = (nint)(locations + 2) }
                    };
                    CallingConventionConfidence callingConvention = new() { Convention = convention, Confidence = 255 };
                    BoolConfidence varargs = new() { Confidence = 255 }, canReturn = new() { Value = 1 }, pure = default;
                    OffsetConfidence stackAdjust = default;
                    nint type = Core.BNCreateFunctionType(&result, &callingConvention, parameters, entry.Setter ? 2U : 1U,
                        &varargs, &canReturn, &stackAdjust, null, null, 0, 0, &pure);
                    ulong address = stats.ImageBase + entry.Address - extraction.Image.ImageBase;
                    nint function = Core.BNGetAnalysisFunction(view, platform, address);
                    if (function == 0) {
                        function = Core.BNAddFunctionForAnalysis(view, platform, address, 0, 0);
                    }
                    if (function == 0) {
                        Core.BNFreeType(type);
                        throw new InvalidDataException($"Binary Ninja rejected the metadata-proven property accessor at 0x{address:X}.");
                    }
                    try {
                        if (Core.BNFunctionHasUserType(function) == 0) {
                            Core.BNApplyAutoDiscoveredFunctionType(function, type);
                            ++applied;
                        }
                        names.Clear();
                        names.Append(projection.Origin == PropertyOrigin.Interface ? "interface_property::" : "base_property::")
                            .Append(extraction.Names.Values[projection.Owner]).Append("::")
                            .Append(extraction.Names.Values[projection.Contract]).Append("::")
                            .Append(properties.Members.Properties[projection.Property].Name).Append(entry.Setter ? "::set" : "::get");
                        if (nameCharacters.Length < names.Length) {
                            Array.Resize(ref nameCharacters, names.Length);
                            Array.Resize(ref nameBuffer, Encoding.UTF8.GetMaxByteCount(names.Length) + 1);
                        }
                        names.CopyTo(0, nameCharacters, 0, names.Length);
                        int bytes = Encoding.UTF8.GetBytes(nameCharacters.AsSpan(0, names.Length), nameBuffer);
                        nameBuffer[bytes] = 0;
                        fixed (byte* name = nameBuffer) {
                            symbols.Define(address, 0, name);
                        }
                        ++stats.Symbols;
                    } finally {
                        Core.BNFreeType(type);
                        Core.BNFreeFunction(function);
                    }
                }
            }
        } finally {
            foreach (nint pointer in pointers.Values) {
                Core.BNFreeType(pointer);
            }
            Core.BNFreeCallingConvention(convention);
            Core.BNFreePlatform(platform);
        }
        return applied;
    }
}
