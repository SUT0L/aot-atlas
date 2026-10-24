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

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static ReadOnlySpan<byte> BinaryMagic() => [0x41, 0x42, 0x43, 0x44, 0];

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static ReadOnlySpan<ushort> BinaryWords() => [0x0041, 0x0042, 0x0043, 0x0044, 0];

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static ReadOnlySpan<byte> ShortAscii() => "OK\0"u8;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static ReadOnlySpan<ushort> ShortWide() => ['Y', 'e', 's', 0];

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static ReadOnlySpan<byte> Noise() => [0xFF, 0x03, 0xFE, 0];

    private static unsafe void Main() {
        nint image = GetModuleHandleW(0);

        for (int index = 0; index < 9; ++index) {
            ReadOnlySpan<byte> data = index switch {
                0 => Narrow(),
                1 => Controls(),
                2 => MemoryMarshal.AsBytes(Wide()),
                3 => MemoryMarshal.AsBytes(Overlap()),
                4 => BinaryMagic(),
                5 => MemoryMarshal.AsBytes(BinaryWords()),
                6 => ShortAscii(),
                7 => MemoryMarshal.AsBytes(ShortWide()),
                8 => Noise(),
                _ => throw new InvalidOperationException()
            };

            fixed (byte* address = data)
                Console.WriteLine($"{index}|{(nint)address - image:X}|{Convert.ToHexString(data)}");
        }
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW(nint name);
}
