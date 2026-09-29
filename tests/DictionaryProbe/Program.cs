using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

internal static partial class Program {
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(DictionaryFunctions))]
    private static unsafe void Main(string[] args) {
        Emit<string>();
        Emit<object>();
        Emit<DictionaryValue<string>>();
        Emit<DictionaryValue<object>>();
        if (args.Length == 0)
            return;

        nint image = GetModuleHandleW(0);
        using var reader = new BinaryReader(File.OpenRead(args[0]));
        Assert(reader.ReadBytes(32).AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(Environment.ProcessPath!))));
        int count = reader.ReadInt32();
        for (int i = 0; i < count; ++i) {
            nint address = image + (nint)reader.ReadUInt32();
            nint target = image + (nint)reader.ReadUInt32();
            Assert(*(nint*)address == target);
        }
        for (int i = 0; i < 4; ++i) {
            nint type = image + (nint)reader.ReadUInt32();
            nint nonGc = image + (nint)reader.ReadUInt32();
            nint gc = image + (nint)reader.ReadUInt32();
            if (type == typeof(DictionaryStorage<string>).TypeHandle.Value)
                CheckStorage<string>(nonGc, gc);
            else if (type == typeof(DictionaryStorage<object>).TypeHandle.Value)
                CheckStorage<object>(nonGc, gc);
            else if (type == typeof(DictionaryStorage<DictionaryValue<string>>).TypeHandle.Value)
                CheckStorage<DictionaryValue<string>>(nonGc, gc);
            else {
                Assert(type == typeof(DictionaryStorage<DictionaryValue<object>>).TypeHandle.Value);
                CheckStorage<DictionaryValue<object>>(nonGc, gc);
            }
        }
        Assert(reader.BaseStream.Position == reader.BaseStream.Length);
        Console.WriteLine($"verified|{count}|4");
    }

    private static unsafe void Emit<T>() {
        DictionaryStorage<T>.Number = 73;
        DictionaryStorage<T>.Reference = new object();
        nint expected = typeof(T).TypeHandle.Value;
        Assert(DictionaryFunctions.Inner<T>() == expected && DictionaryFunctions.Outer<T>() == expected);
        Assert(DictionaryFunctions.NonGc<T>() == (nint)Unsafe.AsPointer(ref DictionaryStorage<T>.Number));
        Assert(Unsafe.AreSame(ref DictionaryFunctions.Gc<T>(), ref DictionaryStorage<T>.Reference));
        Assert(DictionaryFunctions.Interface<T>(new T[3]) == 3);
        Print("Inner", (nint)(delegate*<nint>)&DictionaryFunctions.Inner<T>, expected, typeof(DictionaryStorage<T>));
        Print("Outer", (nint)(delegate*<nint>)&DictionaryFunctions.Outer<T>, expected, typeof(DictionaryStorage<T>));
        Print("NonGc", (nint)(delegate*<nint>)&DictionaryFunctions.NonGc<T>, expected, typeof(DictionaryStorage<T>));
        Print("Gc", (nint)(delegate*<ref object?>)&DictionaryFunctions.Gc<T>, expected, typeof(DictionaryStorage<T>));
        Print("Interface", (nint)(delegate*<IReadOnlyCollection<T>, int>)&DictionaryFunctions.Interface<T>,
            expected, typeof(DictionaryStorage<T>), typeof(IReadOnlyCollection<T>));
    }

    private static unsafe void CheckStorage<T>(nint nonGc, nint gc) {
        Assert((nint)Unsafe.AsPointer(ref DictionaryStorage<T>.Number) == nonGc);
        fixed (byte* field = &Unsafe.As<object?, byte>(ref DictionaryStorage<T>.Reference)) {
            Assert(*(nint*)gc + sizeof(nint) == (nint)field);
        }
    }

    private static unsafe void Print(string name, nint callable, nint argument, Type storage, Type? contract = null) {
        Assert((callable & 2) != 0);
        nint image = GetModuleHandleW(0);
        nint* descriptor = (nint*)(callable - 2);
        Console.Write($"{name}|{argument - image:X}|{descriptor[1] - image:X}|{descriptor[0] - image:X}|{storage.TypeHandle.Value - image:X}");
        if (contract != null)
            Console.Write($"|{contract.TypeHandle.Value - image:X}");
        Console.WriteLine();
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("A live dictionary relationship disagrees with its runtime identity.");
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW(nint name);
}

public struct DictionaryValue<T> { public T Item; }

public static class DictionaryStorage<T> {
    public static long Number;
    public static object? Reference;
}

public static class DictionaryFunctions {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static nint Inner<T>() => typeof(T).TypeHandle.Value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static nint Outer<T>() => Inner<T>();

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static unsafe nint NonGc<T>() => (nint)Unsafe.AsPointer(ref DictionaryStorage<T>.Number);

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static ref object? Gc<T>() => ref DictionaryStorage<T>.Reference;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int Interface<T>(IReadOnlyCollection<T> values) => values.Count;
}
