using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

internal static partial class Program {
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Plain))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Generic<string>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Generic<object>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Generic<int>))]
    private static unsafe void Main(string[] args) {
        Type[] types = [typeof(Plain), typeof(Generic<string>), typeof(Generic<object>), typeof(Generic<int>)];
        nint image = GetModuleHandleW(0);
        if (args.Length == 0) {
            for (int i = 0; i < types.Length; ++i)
                Console.WriteLine($"{i}|{types[i].TypeHandle.Value - image:X}");
            Assert(Counter.Value == 0);
            return;
        }

        using var reader = new BinaryReader(File.OpenRead(args[0]));
        Assert(reader.ReadBytes(32).AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(Environment.ProcessPath!))));
        for (int i = 0; i < types.Length; ++i) {
            uint contextRva = reader.ReadUInt32(), pointerRva = reader.ReadUInt32();
            uint entrypointRva = reader.ReadUInt32(), argumentRva = reader.ReadUInt32();
            nint* context = (nint*)(image + contextRva);
            Assert(*context == image + pointerRva);
            if ((pointerRva & 2) != 0) {
                nint* descriptor = (nint*)(image + pointerRva - 2);
                Assert(descriptor[0] == image + entrypointRva && descriptor[1] == image + argumentRva);
            } else {
                Assert(pointerRva == entrypointRva && argumentRva == 0);
            }

            for (int run = 0; run < 2; ++run) {
                switch (i) {
                    case 0: RuntimeHelpers.RunClassConstructor(typeof(Plain).TypeHandle); break;
                    case 1: RuntimeHelpers.RunClassConstructor(typeof(Generic<string>).TypeHandle); break;
                    case 2: RuntimeHelpers.RunClassConstructor(typeof(Generic<object>).TypeHandle); break;
                    case 3: RuntimeHelpers.RunClassConstructor(typeof(Generic<int>).TypeHandle); break;
                }
                Assert(*context == 0 && Counter.Value == i + 1);
            }
            Console.WriteLine($"{i}|PASS");
        }
        Assert(reader.BaseStream.Position == reader.BaseStream.Length);
        Assert(Plain.Value == 19);
        Assert(Generic<string>.Value == typeof(string) && Generic<object>.Value == typeof(object) && Generic<int>.Value == typeof(int));
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("The constructor context disagrees with live execution.");
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW(nint name);
}

internal static class Counter {
    internal static int Value;
}

public static class Plain {
    public static int Value;

    static Plain() {
        ++Counter.Value;
        Value = 19;
    }
}

public static class Generic<T> {
    public static Type Value;

    static Generic() {
        ++Counter.Value;
        Value = typeof(T);
    }
}
