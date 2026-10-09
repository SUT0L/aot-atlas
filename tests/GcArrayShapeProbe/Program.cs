using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

public struct PointerPair {
    public object? First;
    public object? Second;
}

public struct PointerScalar {
    public object? Reference;
    public long Scalar;
}

[StructLayout(LayoutKind.Explicit, Size = 24)]
public struct PointerGap {
    [FieldOffset(0)] public object? First;
    [FieldOffset(8)] public long Scalar;
    [FieldOffset(16)] public object? Second;
}

public struct PointerTail {
    public object? Reference;
    public byte Scalar;
}

public struct ConstructedPair {
    public object? First;
    public object? Second;
}

[StructLayout(LayoutKind.Explicit, Size = 24)]
public struct ConstructedGap {
    [FieldOffset(0)] public object? First;
    [FieldOffset(8)] public long Scalar;
    [FieldOffset(16)] public object? Second;
}

public struct ConstructedTail {
    public object? Reference;
    public byte Scalar;
}

internal static class Program {
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static object[] CreateBoxes() => [
        new PointerPair { First = new object(), Second = new object() },
        new PointerScalar { Reference = new object(), Scalar = 42 },
        new PointerGap { First = new object(), Scalar = 42, Second = new object() },
        new PointerTail { Reference = new object(), Scalar = 42 }
    ];

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static PointerPair[] CastPair(object value) => (PointerPair[])value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static PointerScalar[,] CastScalar(object value) => (PointerScalar[,])value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static PointerGap[] CastGap(object value) => (PointerGap[])value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static PointerTail[] CastTail(object value) => (PointerTail[])value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static object[] CreateConstructedArrays() => [
        new ConstructedPair[2], new ConstructedGap[2], new ConstructedTail[2]
    ];

    private static void Main() {
        object[] boxes = CreateBoxes();
        try {
            Console.WriteLine(CastPair(boxes).Length);
        } catch (InvalidCastException) {
        }
        try {
            Console.WriteLine(CastScalar(boxes).Length);
        } catch (InvalidCastException) {
        }
        try {
            Console.WriteLine(CastGap(boxes).Length);
        } catch (InvalidCastException) {
        }
        try {
            Console.WriteLine(CastTail(boxes).Length);
        } catch (InvalidCastException) {
        }
        Console.WriteLine(boxes.Length);
        Console.WriteLine(CreateConstructedArrays().Length);
    }
}
