using System.Diagnostics.CodeAnalysis;

internal static class Program {
    [DynamicDependency(DynamicallyAccessedMemberTypes.All, typeof(Model<>))]
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
