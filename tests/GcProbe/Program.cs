using System.Runtime.InteropServices;

Print("mixed", new Mixed { Reference = "value", Number = 42 });
Print("references", new References { First = "first", Second = "second" });
Print("mixed_array", new Mixed[3]);
Print("references_array", new References[3]);
Print("objects", new object[3]);
Print("mixed_matrix", new Mixed[2, 3]);

static unsafe void Print(string label, object value) {
    byte* table = (byte*)value.GetType().TypeHandle.Value;
    nint imageBase = Native.GetModuleHandleW(0);
    long series = *(long*)(table - 8);
    int count = checked((int)Math.Abs(series));
    int length = checked(series < 0 ? 16 + count * 8 : 8 + count * 16);

    string header = Convert.ToHexString(new ReadOnlySpan<byte>(table, 24));
    string descriptor = Convert.ToHexString(new ReadOnlySpan<byte>(table - length, length));
    Console.WriteLine($"{label}|{(long)table - imageBase:X}|{imageBase:X}|{header}|{descriptor}");
    GC.KeepAlive(value);
}

public struct Mixed {
    public object Reference;
    public long Number;
}

public struct References {
    public object First;
    public object Second;
}

internal static partial class Native {
    [LibraryImport("kernel32.dll")]
    internal static partial nint GetModuleHandleW(nint name);
}
