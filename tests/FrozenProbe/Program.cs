using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

internal static class Program {
    private static nint image;
    private static readonly Dictionary<uint, int> Sizes = new();

    private static unsafe void Main(string[] args) {
        image = Native.GetModuleHandleW(0);
        using var reader = new BinaryReader(File.OpenRead(args[0]));
        Assert(reader.ReadBytes(32).AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(Environment.ProcessPath!))));
        int count = reader.ReadInt32();
        int strings = 0, references = 0;
        for (int i = 0; i < count; ++i) {
            uint rva = reader.ReadUInt32();
            uint methodTable = reader.ReadUInt32();
            int size = reader.ReadInt32();
            byte kind = reader.ReadByte();
            int length = reader.ReadInt32();
            byte* pointer = (byte*)image + rva;
            Assert(*(nint*)pointer == image + methodTable);
            byte* type = (byte*)image + methodTable;
            long actualSize = *(uint*)(type + 4);
            if ((*(uint*)type & 0x80000000) != 0) {
                Assert(*(int*)(pointer + 8) == length);
                actualSize += length * (long)*(ushort*)type;
            }
            Assert(((actualSize + 7) & ~7L) == size);
            Sizes.Add(rva, size);

            if (kind == 3) {
                byte[] utf16 = reader.ReadBytes(length * 2);
                Assert(new ReadOnlySpan<byte>(pointer + 12, utf16.Length).SequenceEqual(utf16));
                Assert(*(ushort*)(pointer + 12 + utf16.Length) == 0);
                ++strings;
            }

            int targets = reader.ReadInt32();
            for (int j = 0; j < targets; ++j) {
                uint offset = reader.ReadUInt32(), target = reader.ReadUInt32();
                Assert(*(nint*)(pointer + offset) == image + target);
            }
            references += targets;
        }
        Assert(reader.BaseStream.Position == reader.BaseStream.Length);
        Console.WriteLine($"A|{count}");
        Console.WriteLine($"S|{strings}");
        Console.WriteLine($"R|{references}");

        Print("empty", "");
        Print("nul", "A\0B");
        Print("high", "\uD800");
        Print("low", "\uDFFF");
        Print("pair", "A\uD83D\uDE00Z");
        Print("numbers", Values.Numbers);
        Print("longs", Values.Longs);
        Print("special", Values.Special);
        Print("box", Values.Box);
        Print("nan_box", Values.NaNBox);
        Print("packed_box", Values.PackedBox);
        Print("node", Values.Head);
        Print("refs", Values.References);
        Print("slots", Values.Slots);
        Print("words", Values.Words);
        Print("delegate", Values.Callback);
        Assert(Values.Callback() == 42);
    }

    private static unsafe void Print(string name, object value) {
        nint pointer = Unsafe.As<object, nint>(ref value);
        long rva = pointer - image;
        Assert(rva >= 0 && rva <= uint.MaxValue && Sizes.ContainsKey((uint)rva));
        int size = Sizes[(uint)rva];
        Console.WriteLine($"F|{name}|{rva:X}|{image:X}|{Convert.ToHexString(new ReadOnlySpan<byte>((void*)(pointer + 8), size - 16))}");
        GC.KeepAlive(value);
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Live frozen storage differs from its extraction.");
    }
}

internal static class Values {
    internal static readonly int[] Numbers = [10, -20, 30, int.MaxValue];
    internal static readonly long[] Longs = [long.MinValue, 0, long.MaxValue];
    internal static readonly double[] Special = [double.NaN, double.NegativeInfinity, double.PositiveInfinity, -0.0, 1.25];
    internal static readonly object Box = 123;
    internal static readonly object NaNBox = double.NaN;
    internal static readonly object PackedBox = new Packed { Byte = 7, Number = 0x12345678 };
    internal static readonly Node Head = new();
    internal static readonly object?[] References = [];
    internal static readonly Slot[] Slots = [];
    internal static readonly Word[] Words = [new() { Value = 0x140000000 }, new() { Value = ulong.MaxValue }];
    internal static readonly Func<int> Callback = FortyTwo;

    internal static int FortyTwo() => 42;
}

internal sealed class Node {
    internal readonly long Number;

    internal Node() {
        Number = 41;
    }
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct Packed {
    internal byte Byte;
    internal int Number;
}

public struct Slot {
    public object? Value;
    public long Number;
}

internal struct Word {
    internal ulong Value;
}

internal static partial class Native {
    [LibraryImport("kernel32.dll")]
    internal static partial nint GetModuleHandleW(nint name);
}
