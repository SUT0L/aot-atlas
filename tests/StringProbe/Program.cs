using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Program {
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static ReadOnlySpan<byte> Narrow() => "Atlas native ASCII candidate\0"u8;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static ReadOnlySpan<byte> Controls() => "Atlas \"quote\" \\ slash\tline\n\0"u8;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static ReadOnlySpan<ushort> Wide() => ['A', 't', 'l', 'a', 's', ' ', 'w', 'i', 'd', 'e', ' ', 't', 'e', 'x', 't', 0];

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static ReadOnlySpan<ushort> Overlap() => [0x6100, 0x6362, 0x0064, 0x0065, 0x0066, 0x0067, 0];

    private static unsafe void Main() {
        nint image = GetModuleHandleW(0);
        for (int index = 0; index < 4; ++index) {
            ReadOnlySpan<byte> data = index == 0 ? Narrow() : index == 1 ? Controls() : index == 2 ? MemoryMarshal.AsBytes(Wide()) : MemoryMarshal.AsBytes(Overlap());
            fixed (byte* address = data)
                Console.WriteLine($"{index}|{(nint)address - image:X}|{Convert.ToHexString(data)}");
        }
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW(nint name);
}
