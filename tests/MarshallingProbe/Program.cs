using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace MarshallingFixture;

internal static partial class Program {
    private static nint image;
    private static readonly Dictionary<nint, (nint ToNative, nint ToManaged, nint Cleanup)> Stubs = new();

    private static unsafe void Main(string[] args) {
        image = GetModuleHandleW(0);
        nint creation = 0;

        if (args.Length != 0) {
            using var reader = new BinaryReader(File.OpenRead(args[0]));
            Assert(reader.ReadBytes(32).AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(Environment.ProcessPath!))));
            int records = reader.ReadInt32();
            for (int i = 0; i < records; ++i) {
                uint rva = reader.ReadUInt32();
                int length = reader.ReadInt32();
                uint expected = reader.ReadUInt32();
                uint hash = 2166136261;
                foreach (byte value in new ReadOnlySpan<byte>((byte*)image + rva, length))
                    hash = (hash ^ value) * 16777619;
                Assert(hash == expected);
            }
            Console.WriteLine($"A|{records}");

            int count = reader.ReadInt32();
            for (int i = 0; i < count; ++i) {
                uint type = reader.ReadUInt32();
                uint toNative = reader.ReadUInt32(), toManaged = reader.ReadUInt32(), cleanup = reader.ReadUInt32();
                Stubs.Add(image + (nint)type, (image + (nint)toNative, image + (nint)toManaged, image + (nint)cleanup));
            }

            creation = image + (nint)reader.ReadUInt32();
            Assert(reader.BaseStream.Position == reader.BaseStream.Length);
        }

        Layout<Blittable>(nameof(Blittable.Tag), nameof(Blittable.Value));
        Layout<NativeBool>(nameof(NativeBool.Tag), nameof(NativeBool.Enabled), nameof(NativeBool.Code));
        Layout<Inline>(nameof(Inline.Code), nameof(Inline.Text), nameof(Inline.Samples));
        Layout<Owned>(nameof(Owned.Text), nameof(Owned.Number));
        Layout<LayoutClass>(nameof(LayoutClass.Tag), nameof(LayoutClass.Enabled), nameof(LayoutClass.Code));

        bool invalid = false;
        byte* invalidStorage = stackalloc byte[64];
        try {
            InvalidOffset(nameof(InvalidLayout.Value));
            Marshal.DestroyStructure<InvalidLayout>((nint)invalidStorage);
        } catch (ArgumentException) {
            invalid = true;
        }

        Assert(invalid);
        Console.WriteLine($"I|{typeof(InvalidLayout).TypeHandle.Value - image:X}");

        Callback open = Add;
        Callback closed = new Adder(7).Apply;
        nint openPointer = Marshal.GetFunctionPointerForDelegate(open);
        nint closedPointer = Marshal.GetFunctionPointerForDelegate(closed);
        Assert(((delegate* unmanaged[Cdecl]<int, int, int>)openPointer)(10, 20) == 30);
        Assert(((delegate* unmanaged[Cdecl]<int, int, int>)closedPointer)(10, 20) == 37);
        nint nativePointer = (nint)(delegate* unmanaged[Cdecl]<int, int, int>)&Subtract;
        Callback wrapped = Marshal.GetDelegateForFunctionPointer<Callback>(nativePointer);
        Assert(wrapped(42, 19) == 23);
        GC.KeepAlive(open);
        GC.KeepAlive(closed);
        Console.WriteLine($"D|{typeof(Callback).TypeHandle.Value - image:X}");

        if (args.Length == 0)
            return;

        var boolean = RoundTrip(new NativeBool { Tag = 3, Enabled = true, Code = -1234 }, false);
        Assert(boolean.Tag == 3 && boolean.Enabled && boolean.Code == -1234);
        var inline = RoundTrip(new Inline { Code = 27, Text = "AΩ😀", Samples = [1, -2, 300] }, false);
        Assert(inline.Code == 27 && inline.Text == "AΩ😀" && inline.Samples.AsSpan().SequenceEqual(new short[] { 1, -2, 300 }));
        var owned = RoundTrip(new Owned { Text = "native Ω 😀", Number = 987 }, true);
        Assert(owned.Text == "native Ω 😀" && owned.Number == 987);

        var record = new LayoutClass { Tag = 4, Enabled = true, Code = -4321 };
        var result = new LayoutClass();
        var stubs = Stubs[typeof(LayoutClass).TypeHandle.Value];
        int size = Marshal.SizeOf<LayoutClass>();
        byte* reference = (byte*)NativeMemory.AllocZeroed((nuint)size);
        byte* direct = (byte*)NativeMemory.AllocZeroed((nuint)size);
        Marshal.StructureToPtr(record, (nint)reference, false);
        ((delegate*<object, ref byte, void>)stubs.ToNative)(record, ref *direct);
        Assert(new ReadOnlySpan<byte>(reference, size).SequenceEqual(new ReadOnlySpan<byte>(direct, size)));
        ((delegate*<ref byte, object, void>)stubs.ToManaged)(ref *direct, result);
        Assert(result.Tag == 4 && result.Enabled && result.Code == -4321);
        ((delegate*<ref byte, void>)stubs.Cleanup)(ref *direct);
        Marshal.DestroyStructure<LayoutClass>((nint)reference);
        NativeMemory.Free(reference);
        NativeMemory.Free(direct);

        Callback created = (Callback)((delegate*<nint, Delegate>)creation)(nativePointer);
        Assert(created(42, 19) == 23);
        Console.WriteLine("T|13");
    }

    private static unsafe T RoundTrip<T>(T value, bool ownedString) where T : struct {
        var stubs = Stubs[typeof(T).TypeHandle.Value];
        int size = Marshal.SizeOf<T>();
        byte* reference = (byte*)NativeMemory.AllocZeroed((nuint)size);
        byte* direct = (byte*)NativeMemory.AllocZeroed((nuint)size);
        Marshal.StructureToPtr(value, (nint)reference, false);
        ((delegate*<ref byte, ref byte, void>)stubs.ToNative)(ref Unsafe.As<T, byte>(ref value), ref *direct);
        if (ownedString) {
            Assert(Marshal.PtrToStringUni(*(nint*)reference) == "native Ω 😀");
            Assert(Marshal.PtrToStringUni(*(nint*)direct) == "native Ω 😀");
            Assert(new ReadOnlySpan<byte>(reference + 8, size - 8).SequenceEqual(new ReadOnlySpan<byte>(direct + 8, size - 8)));
        } else {
            Assert(new ReadOnlySpan<byte>(reference, size).SequenceEqual(new ReadOnlySpan<byte>(direct, size)));
        }

        T result = default;
        ((delegate*<ref byte, ref byte, void>)stubs.ToManaged)(ref *direct, ref Unsafe.As<T, byte>(ref result));
        ((delegate*<ref byte, void>)stubs.Cleanup)(ref *direct);
        Marshal.DestroyStructure<T>((nint)reference);
        NativeMemory.Free(reference);
        NativeMemory.Free(direct);
        return result;
    }

    private static void Layout<T>(params string[] fields) {
        Console.WriteLine($"S|{typeof(T).TypeHandle.Value - image:X}|{Marshal.SizeOf<T>()}");
        foreach (string field in fields)
            Console.WriteLine($"F|{typeof(T).TypeHandle.Value - image:X}|{field}|{Marshal.OffsetOf<T>(field)}");
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static nint InvalidOffset(string field) => Marshal.OffsetOf<InvalidLayout>(field);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Subtract(int left, int right) => left - right;

    private static int Add(int left, int right) => left + right;

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Assertion failed.");
    }

    [LibraryImport("kernel32", EntryPoint = "GetModuleHandleW")]
    private static partial nint GetModuleHandleW(nint name);
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct Blittable {
    public byte Tag;
    public long Value;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct NativeBool {
    public byte Tag;
    [MarshalAs(UnmanagedType.Bool)] public bool Enabled;
    public short Code;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
public struct Inline {
    public short Code;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 6)] public string Text;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3, ArraySubType = UnmanagedType.I2)] public short[] Samples;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct Owned {
    [MarshalAs(UnmanagedType.LPWStr)] public string Text;
    public int Number;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public sealed class LayoutClass {
    public byte Tag;
    [MarshalAs(UnmanagedType.Bool)] public bool Enabled;
    public short Code;
}

[StructLayout(LayoutKind.Sequential)]
public struct InvalidLayout {
    public int[,] Value;
}

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate int Callback(int left, int right);

public sealed class Adder(int amount) {
    public int Apply(int left, int right) => left + right + amount;
}
