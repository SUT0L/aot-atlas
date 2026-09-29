using System.Diagnostics;
using System.Runtime.InteropServices;
using Atlas.Binja;

internal static unsafe class Program {
    private static void Main(string[] args) {
        SymbolNameChecks.Run();
        nint library = NativeLibrary.Load(Path.GetFullPath(args[0]));
        NativeLibrary.SetDllImportResolver(typeof(Core).Assembly, (name, assembly, path) => library);
        Assert(Core.BNGetCurrentCoreABIVersion() == 187);
        Assert(sizeof(Variable) == 16 && sizeof(ValueLocationComponent) == 40 && sizeof(ValueLocation) == 40);
        Assert(sizeof(FunctionParameter) == 64 && sizeof(ReturnValue) == 64);
        Assert(Marshal.OffsetOf<ValueLocationComponent>("Size").ToInt32() == 32);
        Assert(Marshal.OffsetOf<FunctionParameter>("Location").ToInt32() == 24);

        Guid module = typeof(Core).Module.ModuleVersionId;
        Assert(module != Guid.Empty);
        Console.WriteLine($"Module identity: {module:D}");

        byte[] payload = new byte[73];
        for (int i = 0; i < payload.Length; ++i)
            payload[i] = (byte)(i * 37);

        nint metadata;
        fixed (byte* bytes = payload)
            metadata = Core.BNCreateMetadataRawData(bytes, (nuint)payload.Length);
        payload.AsSpan().Clear();
        Assert(Core.BNMetadataIsRaw(metadata) != 0);
        nuint storedLength = 0;
        byte* stored = Core.BNMetadataGetRaw(metadata, &storedLength);
        Assert(storedLength == 73);
        for (int i = 0; i < (int)storedLength; ++i)
            Assert(stored[i] == (byte)(i * 37));

        Core.BNFreeMetadataRaw(stored);

        const int copies = 100_000;
        long started = Stopwatch.GetTimestamp();
        for (int i = 0; i < copies; ++i) {
            stored = Core.BNMetadataGetRaw(metadata, &storedLength);
            Assert(storedLength == 73);
            Core.BNFreeMetadataRaw(stored);
        }
        double nanoseconds = Stopwatch.GetElapsedTime(started).TotalNanoseconds / copies;
        Console.WriteLine($"BN6 raw metadata copy/free: {copies} copies of 73 bytes, {nanoseconds:F1} ns/copy.");

        Core.BNFreeMetadata(metadata);
        Console.WriteLine("BN6 metadata: raw bytes survive release of the borrowed source buffer.");

        nint voidType = Core.BNCreateVoidType();
        var target = new TypeConfidence(voidType);
        BoolConfidence qualifier = default;
        nint pointer = Core.BNCreatePointerTypeOfWidth(8, &target, &qualifier, &qualifier, 0);
        target = new TypeConfidence(pointer);
        nint aggregate = Core.BNCreateArrayType(&target, 3);
        CallingConventionConfidence convention = default;
        BoolConfidence varArgs = new() { Confidence = 255 }, canReturn = new() { Value = 1 }, pure = default;
        OffsetConfidence stackAdjust = default;

        ReturnValue emptyResult = new() { Type = voidType, TypeConfidence = 255, DefaultLocation = 1, LocationConfidence = 255 };
        FunctionParameter emptyParameter = default;
        nint emptyWithStorage = Core.BNCreateFunctionType(&emptyResult, &convention, &emptyParameter, 0,
            &varArgs, &canReturn, &stackAdjust, null, null, 0, 0, &pure);
        Assert(emptyWithStorage != 0);
        Core.BNFreeType(emptyWithStorage);
        Console.WriteLine("BN6 function types: a zero-parameter void function retains a valid native type.");

        ValueLocationComponent* components = stackalloc ValueLocationComponent[3];
        components[0] = new ValueLocationComponent { Variable = new Variable { Source = 1, Storage = 17 } };
        components[1] = new ValueLocationComponent { Variable = new Variable { Source = 1, Storage = 23 }, SizeValid = 1, Size = 8 };
        components[2] = new ValueLocationComponent { Variable = new Variable { Storage = 40 } };
        FunctionParameter* parameters = stackalloc FunctionParameter[2];
        fixed (byte* names = "this\0arg1\0"u8) {
            parameters[0] = new FunctionParameter {
                Name = names,
                Type = pointer,
                TypeConfidence = 255,
                LocationSource = 3,
                Location = new ValueLocation { Count = 1, Components = (nint)(components + 1) }
            };
            parameters[1] = new FunctionParameter {
                Name = names + 5,
                Type = aggregate,
                TypeConfidence = 255,
                LocationSource = 3,
                Location = new ValueLocation { Count = 1, Components = (nint)(components + 2), Indirect = 1 }
            };
            ReturnValue result = new() {
                Type = aggregate,
                TypeConfidence = 255,
                LocationConfidence = 255,
                Location = new ValueLocation {
                    Count = 1,
                    Components = (nint)components,
                    Indirect = 1,
                    ReturnedPointerValid = 1,
                    ReturnedPointer = new Variable { Source = 1, Storage = 29 }
                }
            };

            // The core must copy these borrowed arrays; no managed buffer may remain pinned for the lifetime of an applied function type
            nint function = Core.BNCreateFunctionType(&result, &convention, parameters, 2,
                &varArgs, &canReturn, &stackAdjust, null, null, 0, 0, &pure);
            new Span<ValueLocationComponent>(components, 3).Clear();
            new Span<FunctionParameter>(parameters, 2).Clear();

            nuint count = 0;
            var actual = Inspect.BNGetTypeParameters(function, &count);
            Assert(count == 2);
            for (int i = 0; i < 2; ++i) {
                Assert(Marshal.PtrToStringUTF8((nint)actual[i].Name) == (i == 0 ? "this" : "arg1"));
                Assert(actual[i].TypeConfidence == 255 && actual[i].LocationSource == 3);
                Assert(Inspect.BNGetTypeWidth(actual[i].Type) == (i == 0 ? 8U : 24U));
                ValueLocation location = actual[i].Location;
                Assert(location.Count == 1 && location.Indirect == i && location.ReturnedPointerValid == 0);
                var component = *(ValueLocationComponent*)location.Components;
                Assert(component.Variable.Source == (i == 0 ? 1 : 0) && component.Variable.Storage == (i == 0 ? 23 : 40));
                Assert(component.Offset == 0 && component.SizeValid == (i == 0 ? 1 : 0));
                if (i == 0)
                    Assert(component.Size == 8);
            }
            Inspect.BNFreeTypeParameterList(actual, count);

            var returned = Inspect.BNGetTypeReturnValueLocation(function);
            Assert(returned.Confidence == 255 && returned.Location.Count == 1 && returned.Location.Indirect == 1);
            Assert(returned.Location.ReturnedPointerValid == 1 && returned.Location.ReturnedPointer.Storage == 29);
            var returnComponent = *(ValueLocationComponent*)returned.Location.Components;
            Assert(returnComponent.Variable.Source == 1 && returnComponent.Variable.Storage == 17);
            Assert(returnComponent.SizeValid == 0 && returnComponent.Offset == 0);
            Inspect.BNFreeValueLocation(&returned.Location);
            Core.BNFreeType(function);
        }

        Core.BNFreeType(aggregate);
        Core.BNFreeType(pointer);
        Core.BNFreeType(voidType);
        Console.WriteLine("BN6 native ABI: structure sizes, copied components, indirect return and stack parameter passed.");

        FrozenTypeChecks.Run(args.AsSpan(1));
        DispatchChecks.Run(args.AsSpan(1));
        StaticChecks.Run(args.AsSpan(1));
        EnumChecks.Run(args.AsSpan(1));
        UnwindTypeChecks.Run(args.AsSpan(1));
        ExceptionChecks.Run(args.AsSpan(1));
        PInvokeChecks.Run();
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Binary Ninja core ABI round trip disagrees with the supplied type.");
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct LocationConfidence {
    internal ValueLocation Location;
    internal byte Confidence;
}

internal static unsafe partial class Inspect {
    [LibraryImport("binaryninjacore")] internal static partial FunctionParameter* BNGetTypeParameters(nint type, nuint* count);
    [LibraryImport("binaryninjacore")] internal static partial void BNFreeTypeParameterList(FunctionParameter* types, nuint count);
    [LibraryImport("binaryninjacore")] internal static partial ulong BNGetTypeWidth(nint type);
    [LibraryImport("binaryninjacore")] internal static partial LocationConfidence BNGetTypeReturnValueLocation(nint type);
    [LibraryImport("binaryninjacore")] internal static partial void BNFreeValueLocation(ValueLocation* location);
}
