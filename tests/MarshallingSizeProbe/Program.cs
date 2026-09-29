using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Program {
    private static void Main() {
        var automatic = new Automatic { First = true, Second = true, Third = true };
        var packed = new Packed { First = 1, Second = 2, Third = 3 };
        nint image = GetModuleHandleW(0);
        Console.WriteLine($"S|0|{typeof(Automatic).TypeHandle.Value - image:X}|{Unsafe.SizeOf<Automatic>()}|{Marshal.SizeOf<Automatic>()}");
        Field(0, nameof(Automatic.First), ref automatic, ref automatic.First);
        Field(0, nameof(Automatic.Second), ref automatic, ref automatic.Second);
        Field(0, nameof(Automatic.Third), ref automatic, ref automatic.Third);
        Console.WriteLine($"S|1|{typeof(Packed).TypeHandle.Value - image:X}|{Unsafe.SizeOf<Packed>()}|{Marshal.SizeOf<Packed>()}");
        Field(1, nameof(Packed.First), ref packed, ref packed.First);
        Field(1, nameof(Packed.Second), ref packed, ref packed.Second);
        Field(1, nameof(Packed.Third), ref packed, ref packed.Third);
    }

    private static void Field<T, TField>(int type, string name, ref T owner, ref TField field) {
        long managed = (long)Unsafe.ByteOffset(ref Unsafe.As<T, byte>(ref owner), ref Unsafe.As<TField, byte>(ref field));
        Console.WriteLine($"F|{type}|{name}|{managed}|{Marshal.OffsetOf<T>(name)}");
    }

    [LibraryImport("kernel32", EntryPoint = "GetModuleHandleW")]
    private static partial nint GetModuleHandleW(nint name);
}

[StructLayout(LayoutKind.Auto)]
public struct Automatic {
    public bool First;
    public bool Second;
    public bool Third;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct Packed {
    public byte First;
    public long Second;
    public short Third;
}
