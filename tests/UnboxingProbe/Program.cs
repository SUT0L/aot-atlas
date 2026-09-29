using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Program {
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.PublicFields, typeof(Counter))]
    private static unsafe void Main(string[] args) {
        nint image = GetModuleHandleW(0);
        if (args.Length == 0) {
            Console.WriteLine($"{typeof(Counter).TypeHandle.Value - image:X}");
            return;
        }

        int verified = 0;
        foreach (string line in File.ReadLines(args[0])) {
            string[] parts = line.Split('|');
            nint boxedEntry = image + nint.Parse(parts[1], NumberStyles.HexNumber);
            nint unboxedEntry = image + nint.Parse(parts[2], NumberStyles.HexNumber);
            Counter value = new() { Value = 31 }, expected = value;
            object boxed = value;
            if (parts[0] == "Add") {
                int answer = expected.Add(11);
                Assert(((delegate*<object, int, int>)boxedEntry)(boxed, 11) == answer);
                Assert(((delegate*<Counter*, int, int>)unboxedEntry)(&value, 11) == answer);
            } else if (parts[0] == "Bump") {
                Large answer = expected.Bump(11), boxedResult = default, unboxedResult = default;
                Large* boxedPointer = ((delegate*<object, Large*, int, Large*>)boxedEntry)(boxed, &boxedResult, 11);
                Large* unboxedPointer = ((delegate*<Counter*, Large*, int, Large*>)unboxedEntry)(&value, &unboxedResult, 11);
                Assert(boxedPointer == &boxedResult && unboxedPointer == &unboxedResult);
                Assert(boxedResult.A == answer.A && boxedResult.B == answer.B && boxedResult.C == answer.C);
                Assert(unboxedResult.A == answer.A && unboxedResult.B == answer.B && unboxedResult.C == answer.C);
                Assert(value.Value == expected.Value && Unsafe.Unbox<Counter>(boxed).Value == expected.Value);
            } else {
                throw new InvalidDataException(parts[0]);
            }
            ++verified;
        }

        Assert(verified == 2);
        Console.WriteLine("2 boxed entrypoints and unboxed bodies agree with direct managed calls.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("The physical call disagrees with the managed call.");
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW(nint name);
}

public struct Large { public long A, B, C; }

public struct Counter {
    public int Value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public int Add(int amount) => Value + amount;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public Large Bump(int amount) {
        Value += amount;
        return new Large { A = Value, B = amount, C = Value + amount };
    }
}
