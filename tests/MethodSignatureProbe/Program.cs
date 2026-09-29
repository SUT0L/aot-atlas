using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Program {
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(Functions))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(Owner<int>))]
    private static unsafe void Main() {
        delegate*<Envelope<int>, Envelope<int>> integer = &Functions.Echo<int>;
        delegate*<Envelope<string>, Envelope<string>> text = &Functions.Echo<string>;
        delegate*<int[], int[]> integerArray = &Functions.Array<int>;
        delegate*<string[], string[]> textArray = &Functions.Array<string>;
        delegate*<int[,], int[,]> matrix = &Functions.Matrix<int>;
        delegate*<Pair<int, string>, Pair<int, string>> mixed = &Owner<int>.Echo<string>;
        delegate*<int*, int*> pointer = &Functions.Pointer;

        Assert(integer(new Envelope<int> { Value = 42 }).Value == 42);
        Assert(text(new Envelope<string> { Value = "value" }).Value == "value");
        Assert(integerArray([10, 20])[1] == 20);
        Assert(textArray(["a", "b"])[1] == "b");
        Assert(matrix(new int[,] { { 1, 2 }, { 3, 4 } })[1, 0] == 3);
        Assert(mixed(new Pair<int, string> { First = 42, Second = "mixed" }).Second == "mixed");
        int value = 123;
        Assert(pointer(&value) == &value);

        Print("integer", (nint)integer, typeof(Functions), [typeof(int)], typeof(Envelope<int>));
        Print("text", (nint)text, typeof(Functions), [typeof(string)], typeof(Envelope<string>));
        Print("integer_array", (nint)integerArray, typeof(Functions), [typeof(int)], typeof(int[]));
        Print("text_array", (nint)textArray, typeof(Functions), [typeof(string)], typeof(string[]));
        Print("matrix", (nint)matrix, typeof(Functions), [typeof(int)], typeof(int[,]));
        Print("mixed", (nint)mixed, typeof(Owner<int>), [typeof(string)], typeof(Pair<int, string>));
        Print("pointer", (nint)pointer, typeof(Functions), [], typeof(int*));
    }

    private static unsafe void Print(string label, nint pointer, Type owner, Type[] arguments, Type signatureType) {
        nint image = GetModuleHandleW(0);
        nint code = pointer, dictionary = 0;
        if ((pointer & 2) != 0) {
            nint* descriptor = (nint*)(pointer - 2);
            code = descriptor[0];
            dictionary = descriptor[1];
        }

        Console.Write($"{label}|{owner.TypeHandle.Value - image:X}|{code - image:X}|{(dictionary == 0 ? 0 : dictionary - image):X}|{signatureType.TypeHandle.Value - image:X}|");
        for (int i = 0; i < arguments.Length; ++i) {
            if (i != 0)
                Console.Write(',');
            Console.Write($"{arguments[i].TypeHandle.Value - image:X}");
        }
        Console.WriteLine();
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Method signature fixture returned an unexpected value.");
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW(nint name);
}

public struct Envelope<T> { public T Value; }
public struct Pair<T, U> { public T First; public U Second; }

public static class Functions {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Envelope<T> Echo<T>(Envelope<T> value) => value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static T[] Array<T>(T[] value) => value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static T[,] Matrix<T>(T[,] value) => value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static unsafe int* Pointer(int* value) => value;
}

public static class Owner<T> {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Pair<T, U> Echo<U>(Pair<T, U> value) => value;
}
