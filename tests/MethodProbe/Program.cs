using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Program {
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(Functions))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(Owner<int>))]
    private static unsafe void Main() {
        delegate*<int, int> integer = &Functions.Identity<int>;
        delegate*<string, string> text = &Functions.Identity<string>;
        delegate*<object, object> reference = &Functions.Identity<object>;
        delegate*<int, string, string> nested = &Owner<int>.Echo<string>;

        Print("integer", (nint)integer, typeof(Functions), typeof(int), integer(42).ToString());
        Print("text", (nint)text, typeof(Functions), typeof(string), text("value"));
        Print("reference", (nint)reference, typeof(Functions), typeof(object), reference("reference").ToString()!);
        Print("nested", (nint)nested, typeof(Owner<int>), typeof(string), nested(42, "nested"));
    }

    private static unsafe void Print(string label, nint pointer, Type owner, Type argument, string result) {
        nint image = Native.GetModuleHandleW(0);
        nint code = pointer, dictionary = 0;
        if ((pointer & 2) != 0) {
            nint* descriptor = (nint*)(pointer - 2);
            code = descriptor[0];
            dictionary = descriptor[1];
        }

        Console.WriteLine($"{label}|{owner.TypeHandle.Value - image:X}|{argument.TypeHandle.Value - image:X}|{code - image:X}|{(dictionary == 0 ? 0 : dictionary - image):X}|{result}");
    }
}

public static class Functions {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static T Identity<T>(T value) => value;
}

public static class Owner<T> {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static U Echo<U>(T owner, U value) => value;
}

internal static partial class Native {
    [LibraryImport("kernel32.dll")]
    internal static partial nint GetModuleHandleW(nint name);
}
