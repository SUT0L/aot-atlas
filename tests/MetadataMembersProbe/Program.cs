using System.Diagnostics.CodeAnalysis;

internal static class Program {
    [DynamicDependency(DynamicallyAccessedMemberTypes.All, typeof(Model<>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.All, typeof(Packet))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.All, typeof(Contract))]
    private static void Main() {
    }
}

public class Model<T> where T : class, IDisposable, new() {
    public T Value { get; private set; } = new();

    public static long Global { get; set; }

    public string this[int row, string column] => row + column;

    public event Action? Changed;

    public void Raise() => Changed?.Invoke();

    public int Optional(int count = 7, string? label = null, SampleMode mode = SampleMode.Second) =>
        count + (label?.Length ?? 0) + (int)mode;

    public U Echo<U>(T input, U seed) where U : unmanaged {
        input.Dispose();

        return seed;
    }
}

public enum SampleMode : byte {
    First = 1,
    Second = 2
}

public enum RichMode : uint {
    Large = 0xFEDCBA98
}

[AttributeUsage(AttributeTargets.Class)]
public sealed class RichAttribute : Attribute {
    public RichAttribute(int[] numbers, string?[] names, Type type, RichMode mode,
        byte number, char character, double fraction, long signed, ulong unsigned, object[] mixed) {
    }
}

[Rich(new[] { -1, 7, 123456 }, new string?[] { "alpha", null }, typeof(Packet),
    RichMode.Large, 255, 'Ω', 3.25, long.MinValue, ulong.MaxValue,
    new object[] { false, (short)-2, 1.5f })]
public sealed class Packet {
    public const int WireId = 0x1234;
}

[AttributeUsage(AttributeTargets.Class)]
public sealed class TypesAttribute : Attribute {
    public TypesAttribute(Type vector, Type[] shapes) {
    }

    public Type? Named { get; set; }
}

public class Outer<T> {
    public class Inner<U> {
    }
}

[Types(typeof(int[]), new[] {
    typeof(Dictionary<string, int>), typeof(int[,]), typeof(int*), typeof(Outer<int>.Inner<string>)
}, Named = typeof(List<int[]>))]
public unsafe sealed class Contract {
}
