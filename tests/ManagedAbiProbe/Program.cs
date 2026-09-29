using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

internal static partial class Program {
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(Functions))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(Owner))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(Counter))]
    private static unsafe void Main(string[] args) {
        var owner = new Owner { Value = 19 };
        var counter = new Counter { Value = 31 };
        string text = "hello";
        Assert(Functions.Generic(text, 7).C == 23);
        Assert(owner.Generic(text, 7).C == 23);
        Assert(counter.Add(11) == 42);

        nint image = GetModuleHandleW(0);
        Assert(typeof(double).TypeHandle.Value > image);
        if (args.Length == 0) {
            foreach (string name in new[] { "Mix", "Small", "Packed", "Large", "FloatStruct", "Vector128", "Vector256", "Reference", "Pointer", "Signed" })
                Console.WriteLine($"{name}|{typeof(Functions).TypeHandle.Value - image:X}|");

            Console.WriteLine($"Generic|{typeof(Functions).TypeHandle.Value - image:X}|{typeof(string).TypeHandle.Value - image:X}");
            Console.WriteLine($"Mix|{typeof(Owner).TypeHandle.Value - image:X}|");
            Console.WriteLine($"Large|{typeof(Owner).TypeHandle.Value - image:X}|");
            Console.WriteLine($"Generic|{typeof(Owner).TypeHandle.Value - image:X}|{typeof(string).TypeHandle.Value - image:X}");
            Console.WriteLine($"Add|{typeof(Counter).TypeHandle.Value - image:X}|");
            return;
        }

        int verified = 0;
        foreach (string line in File.ReadLines(args[0])) {
            string[] parts = line.Split('|');
            string name = parts[0];
            nint ownerType = image + nint.Parse(parts[1], System.Globalization.NumberStyles.HexNumber);
            nint code = image + nint.Parse(parts[2], System.Globalization.NumberStyles.HexNumber);
            nint context = parts[3] == "0" ? 0 : image + nint.Parse(parts[3], System.Globalization.NumberStyles.HexNumber);

            if (ownerType == typeof(Counter).TypeHandle.Value) {
                object boxed = counter;
                Assert(((delegate*<object, int, int>)code)(boxed, 11) == counter.Add(11));
            } else if (ownerType == typeof(Owner).TypeHandle.Value) {
                if (name == "Mix")
                    Assert(((delegate*<Owner, float, long, double, int, double>)code)(owner, 1.5f, 7, 2.25, 13) == owner.Mix(1.5f, 7, 2.25, 13));
                else {
                    Large result = default;
                    Large* returned;
                    Large expected;
                    if (name == "Generic") {
                        Assert(context != 0);
                        returned = ((delegate*<Owner, Large*, nint, string, long, Large*>)code)(owner, &result, context, text, 7);
                        expected = owner.Generic(text, 7);
                    } else {
                        returned = ((delegate*<Owner, Large*, int, Large*>)code)(owner, &result, 7);
                        expected = owner.Large(7);
                    }

                    Assert(returned == &result && result.A == expected.A && result.B == expected.B && result.C == expected.C);
                }
            } else {
                Assert(ownerType == typeof(Functions).TypeHandle.Value);
                switch (name) {
                    case "Mix":
                        Assert(((delegate*<int, float, long, double, int, double>)code)(3, 1.5f, 7, 2.25, 13) == Functions.Mix(3, 1.5f, 7, 2.25, 13));
                        break;
                    case "Small":
                        Small small = new() { Value = 41 };
                        Assert(((delegate*<ulong, ulong>)code)(small.Value) == Functions.Small(small).Value);
                        break;
                    case "FloatStruct":
                        FloatStruct floating = new() { Value = 1.25f };
                        uint bits = BitConverter.SingleToUInt32Bits(floating.Value);
                        Assert(((delegate*<uint, uint>)code)(bits) == BitConverter.SingleToUInt32Bits(Functions.FloatStruct(floating).Value));
                        break;
                    case "Packed":
                        Packed packed = new() { A = 7, B = 31 }, packedResult = default;
                        Packed* packedPointer = ((delegate*<Packed*, Packed*, Packed*>)code)(&packedResult, &packed);
                        Packed packedExpected = Functions.Packed(packed);
                        Assert(packedPointer == &packedResult && packedResult.A == packedExpected.A && packedResult.B == packedExpected.B);
                        break;
                    case "Large":
                        Large large = new() { A = 5, B = 17, C = 29 }, largeResult = default;
                        Large* largePointer = ((delegate*<Large*, Large*, Large*>)code)(&largeResult, &large);
                        Large largeExpected = Functions.Large(large);
                        Assert(largePointer == &largeResult && largeResult.A == largeExpected.A && largeResult.B == largeExpected.B && largeResult.C == largeExpected.C);
                        break;
                    case "Vector128":
                        Vector128<uint> vector128 = Vector128.Create(1U, 2U, 3U, 4U), result128 = default;
                        Vector128<uint>* pointer128 = ((delegate*<Vector128<uint>*, Vector128<uint>*, Vector128<uint>*>)code)(&result128, &vector128);
                        Assert(pointer128 == &result128 && Vector128.EqualsAll(result128, Functions.Vector128(vector128)));
                        break;
                    case "Vector256":
                        Vector256<uint> vector256 = Vector256.Create(1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U), result256 = default;
                        Vector256<uint>* pointer256 = ((delegate*<Vector256<uint>*, Vector256<uint>*, Vector256<uint>*>)code)(&result256, &vector256);
                        Assert(pointer256 == &result256 && Vector256.EqualsAll(result256, Functions.Vector256(vector256)));
                        break;
                    case "Generic":
                        Assert(context != 0);
                        Large genericResult = default;
                        Large* genericPointer = ((delegate*<Large*, nint, string, long, Large*>)code)(&genericResult, context, text, 7);
                        Large genericExpected = Functions.Generic(text, 7);
                        Assert(genericPointer == &genericResult && genericResult.A == genericExpected.A && genericResult.B == genericExpected.B && genericResult.C == genericExpected.C);
                        break;
                    case "Reference":
                        Assert(((delegate*<ref string, int>)code)(ref text) == Functions.Reference(ref text));
                        break;
                    case "Pointer":
                        int value = 42;
                        Assert(((delegate*<int*, int>)code)(&value) == Functions.Pointer(&value));
                        break;
                    case "Signed":
                        Assert(((delegate*<int, int>)code)(-7) == Functions.Signed(-7));
                        break;
                    default:
                        throw new InvalidDataException(name);
                }
            }

            ++verified;
        }

        Assert(verified == 15);
        Console.WriteLine($"{verified} metadata entrypoints agree with direct managed calls.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("The physical call disagrees with the managed call.");
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW(nint name);
}

public struct Small { public ulong Value; }
public struct FloatStruct { public float Value; }
public struct Large { public long A, B, C; }

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct Packed { public byte A; public int B; }

public struct Counter {
    public int Value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public int Add(int value) => Value + value;
}

public sealed class Owner {
    public int Value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public double Mix(float a, long b, double c, int d) => Value + a + 2 * b + 3 * c + 4 * d;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public Large Large(int value) => new() { A = Value, B = value, C = Value + value };

    [MethodImpl(MethodImplOptions.NoInlining)]
    public Large Generic<T>(T value, long number) => new() { A = Value + number, B = value!.ToString()!.Length, C = typeof(T) == typeof(string) ? 23 : 37 };
}

public static class Functions {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static double Mix(int a, float b, long c, double d, int e) => a + 2 * b + 3 * c + 4 * d + 5 * e;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Small Small(Small value) => new() { Value = value.Value + 1 };

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static FloatStruct FloatStruct(FloatStruct value) => new() { Value = value.Value * 2 };

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Packed Packed(Packed value) => new() { A = (byte)(value.A + 1), B = value.B + 2 };

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Large Large(Large value) => new() { A = value.A + 1, B = value.B + 2, C = value.C + 3 };

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Vector128<uint> Vector128(Vector128<uint> value) => value ^ System.Runtime.Intrinsics.Vector128.Create(0xA5A5U);

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Vector256<uint> Vector256(Vector256<uint> value) => value ^ System.Runtime.Intrinsics.Vector256.Create(0xA5A5U);

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Large Generic<T>(T value, long number) => new() { A = number, B = value!.ToString()!.Length, C = typeof(T) == typeof(string) ? 23 : 37 };

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int Reference(ref string value) => value.Length;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static unsafe int Pointer(int* value) => *value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static sbyte Signed(sbyte value) => (sbyte)(value - 1);
}
