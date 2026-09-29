using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

unsafe {
    delegate*<int, string, string> capture = &Frames<int>.Capture<string>;
    nint pointer = (nint)capture;
    if ((pointer & 2) != 0)
        pointer = *(nint*)(pointer - 2);

    Console.WriteLine($"P|{pointer - Native.GetModuleHandleW(0):X}");
    Console.WriteLine(capture(42, "value"));
}

internal static class Frames<TOwner> {
    [MethodImpl(MethodImplOptions.NoInlining)]
    internal static string Capture<T>(TOwner first, T second) {
        GC.KeepAlive(first);
        GC.KeepAlive(second);
#line 120 "AtlasTraceFixture.cs"
        return new StackTrace(0, true).ToString();
#line default
    }
}

internal static partial class Native {
    [LibraryImport("kernel32.dll")]
    internal static partial nint GetModuleHandleW(nint name);
}
