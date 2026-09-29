using System.Runtime.InteropServices;

Print(typeof(int));
Print(typeof(int[]));
Print(typeof(int[][]));
Print(typeof(int[,]));
Print(typeof(int[,,]));
Print(typeof(Pair<int, long>));
Print(typeof(Pair<int, Pair<long, byte>>));
Print(typeof(Pair<int, long>.Nested<byte>));
Print(typeof(Pair<int, long>[]));
Print(typeof(Pair<int, long>.Nested<byte>[,]));
Print(typeof(int?));

unsafe {
    Print(typeof(int*));
    Print(typeof(delegate*<ref int, void>));
}

foreach (var field in typeof(Indirect).GetFields())
    Print(field.FieldType);

static void Print(Type type) {
    nint imageBase = Native.GetModuleHandleW(0);
    Console.WriteLine($"{type.TypeHandle.Value - imageBase:X}|{type}");
}

public struct Pair<T, U> {
    public T First;
    public U Second;

    public struct Nested<V> {
        public Pair<T, U> Outer;
        public V Inner;
    }
}

public unsafe ref struct Indirect {
    public int* Pointer;
    public ref int Reference;
    public delegate*<int, void> Managed;
    public delegate* unmanaged[Cdecl]<long, int> Unmanaged;
    public delegate*<void> NoArguments;
}

internal static partial class Native {
    [LibraryImport("kernel32.dll")]
    internal static partial nint GetModuleHandleW(nint name);
}
