using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Program {
    private static unsafe void Main(string[] args) {
        nint image = GetModuleHandleW(0);
        var owner = new TraceOwner { Value = 19 };
        var counter = new TraceCounter { Value = 31 };
        Large input = new() { A = 5, B = 17, C = 29 };
        int value = 7;

        Console.WriteLine(TraceFunctions.Signed(-7));
        Console.WriteLine(TraceFunctions.Mix(3, 1.5f, 7, 2.25, 13));
        Console.WriteLine(TraceFunctions.Large(input).C);
        Console.WriteLine(TraceFunctions.ByRef(ref value));
        Console.WriteLine(owner.Large(7).C);
        Console.WriteLine(counter.Add(11));
        Console.WriteLine(TraceFunctions.Generic("generic"));
        Console.WriteLine(GenericOwner<string>.Scalar(7));
        delegate* unmanaged<int, int> callback = &TraceFunctions.Callback;
        Console.WriteLine(callback(5));
        Console.WriteLine(TraceFunctions.IntZero());
        Console.WriteLine(TraceFunctions.NullObject() is null);
        Console.WriteLine($"F|IntZero|{(nint)(delegate*<int>)&TraceFunctions.IntZero - image:X}");
        Console.WriteLine($"F|NullObject|{(nint)(delegate*<object?>)&TraceFunctions.NullObject - image:X}");

        foreach (Type type in new[] { typeof(TraceFunctions), typeof(TraceOwner), typeof(TraceCounter),
            typeof(Large), typeof(int), typeof(long), typeof(float), typeof(double), typeof(void), typeof(GenericOwner<>) }) {
            Console.WriteLine($"T|{type.FullName}|{type.TypeHandle.Value - image:X}");
        }

        if (args.Length == 0) {
            return;
        }

        int verified = 0;
        foreach (string line in File.ReadLines(args[0])) {
            string[] parts = line.Split('|');
            nint code = image + nint.Parse(parts[1], NumberStyles.HexNumber);
            switch (parts[0]) {
                case "Signed":
                    Assert(((delegate*<int, int>)code)(-7) == TraceFunctions.Signed(-7));
                    break;
                case "Mix":
                    Assert(((delegate*<int, float, long, double, int, double>)code)(3, 1.5f, 7, 2.25, 13)
                        == TraceFunctions.Mix(3, 1.5f, 7, 2.25, 13));
                    break;
                case "Large": {
                    Large result = default;
                    Large* returned = ((delegate*<Large*, Large*, Large*>)code)(&result, &input);
                    Large expected = TraceFunctions.Large(input);
                    Assert(returned == &result && result.A == expected.A && result.B == expected.B && result.C == expected.C);
                    break;
                }
                case "ByRef": {
                    int direct = 7, physical = 7;
                    Assert(((delegate*<ref int, int>)code)(ref physical) == TraceFunctions.ByRef(ref direct) && physical == direct);
                    break;
                }
                case "OwnerLarge": {
                    Large result = default;
                    Large* returned = ((delegate*<TraceOwner, Large*, int, Large*>)code)(owner, &result, 7);
                    Large expected = owner.Large(7);
                    Assert(returned == &result && result.A == expected.A && result.B == expected.B && result.C == expected.C);
                    break;
                }
                case "Add":
                    Assert(((delegate*<TraceCounter*, int, int>)code)(&counter, 11) == counter.Add(11));
                    break;
                default:
                    throw new InvalidDataException(parts[0]);
            }
            ++verified;
        }

        Assert(verified == 6);
        Console.WriteLine("PASS: six trace entrypoints agree with direct managed calls.");
    }

    private static void Assert(bool condition) {
        if (!condition) {
            throw new InvalidDataException("Trace ABI call disagrees with the managed call.");
        }
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW(nint name);
}

public struct Large { public long A, B, C; }

public struct TraceCounter {
    public int Value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public int Add(int value) => Value + value;
}

public sealed class TraceOwner {
    public int Value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public Large Large(int value) => new() { A = Value, B = value, C = Value + value };
}

public static class TraceFunctions {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int Signed(int value) => value * 3 - 19;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static double Mix(int a, float b, long c, double d, int e) => a + b * 2 + c * 3 + d * 4 + e * 5;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Large Large(Large value) => new() { A = value.A + 1, B = value.B + 3, C = value.C + 7 };

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int ByRef(ref int value) => ++value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int Generic<T>(T value) => value!.ToString()!.Length;

    [UnmanagedCallersOnly]
    public static int Callback(int value) => value + 19;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int IntZero() => 0;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static object? NullObject() => null;
}

public static class GenericOwner<T> {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int Scalar(int value) => value + typeof(T).Name.Length;
}
