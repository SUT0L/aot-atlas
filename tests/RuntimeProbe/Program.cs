using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

Print<byte>();
Print<int>();
Print<TwelveBytes>();
Print<PackedFiveBytes>();
Print<WithReference>();
Print<ByteEnum>();
Print<int?>();
Print<PackedFiveBytes?>();
Print<TwelveBytes?>();

static unsafe void Print<T>() {
    byte* mt = (byte*)typeof(T).TypeHandle.Value;
    nint imageBase = Native.GetModuleHandleW(0);
    long rva = (long)mt - imageBase;
    Console.WriteLine($"{typeof(T)}|{rva:X}|{Unsafe.SizeOf<T>()}|{Convert.ToHexString(new ReadOnlySpan<byte>(mt, 24))}|{imageBase:X}");
}

public struct TwelveBytes { public int A, B, C; }
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct PackedFiveBytes { public byte A; public int B; }
public struct WithReference { public object A; public int B; }
public enum ByteEnum : byte { A = 1, B = 255 }

internal static partial class Native {
    [LibraryImport("kernel32.dll")]
    internal static partial nint GetModuleHandleW(nint name);
}
