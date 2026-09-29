using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

internal static class Program {
    private static readonly Dictionary<(uint Type, string Field), Binding> Fields = new();
    private static nint image;

    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(StaticsFixture))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Preinitialized))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(GenericStatics<int>))]
    private static unsafe void Main(string[] args) {
        image = Native.GetModuleHandleW(0);
        using var reader = new BinaryReader(File.OpenRead(args[0]));
        Assert(reader.ReadBytes(32).AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(Environment.ProcessPath!))));
        int count = reader.ReadInt32();

        for (int i = 0; i < count; ++i) {
            uint rva = reader.ReadUInt32();
            uint flags = reader.ReadUInt32();
            uint size = reader.ReadUInt32();
            uint related = reader.ReadUInt32();
            int length = reader.ReadInt32();
            byte[] descriptor = reader.ReadBytes(length);
            byte* pointer = (byte*)image + rva;
            Assert(*(uint*)pointer == flags && *(uint*)(pointer + 4) == size);
            Assert(*(nint*)(pointer + 8) == image + related);
            Assert(new ReadOnlySpan<byte>(pointer - length, length).SequenceEqual(descriptor));
        }

        Console.WriteLine($"A|{count}");
        uint threadRegion = reader.ReadUInt32();
        int threadCount = reader.ReadInt32();
        for (int i = 0; i < threadCount; ++i)
            Assert(*(nint*)(image + threadRegion + i * 8) == image + reader.ReadUInt32());

        Console.WriteLine($"T|{threadCount}");
        int indices = reader.ReadInt32();
        for (int i = 0; i < indices; ++i) {
            uint address = reader.ReadUInt32();
            uint module = reader.ReadUInt32();
            long index = reader.ReadInt64();
            Assert(*(nint*)(image + address) == image + module);
            Assert(*(long*)(image + address + 8) == index);
        }

        Console.WriteLine($"I|{indices}");
        int fields = reader.ReadInt32();
        for (int i = 0; i < fields; ++i) {
            uint type = reader.ReadUInt32();
            string name = reader.ReadString();
            Fields.Add((type, name), new Binding {
                Location = reader.ReadByte(),
                Address = reader.ReadUInt32(),
                Offset = reader.ReadUInt32(),
                Descriptor = reader.ReadUInt32()
            });
        }
        Assert(reader.BaseStream.Position == reader.BaseStream.Length);

        StaticsFixture.Number = 17;
        StaticsFixture.ThreadNumber = 41;
        StaticsFixture.ThreadReference = "thread";
        GenericStatics<int>.Value = 61;
        GenericStatics<int>.ThreadValue = 73;

        Check(typeof(StaticsFixture), nameof(StaticsFixture.Number), ref StaticsFixture.Number);
        Check(typeof(StaticsFixture), nameof(StaticsFixture.Reference), ref StaticsFixture.Reference);
        Check(typeof(StaticsFixture), nameof(StaticsFixture.ThreadNumber), ref StaticsFixture.ThreadNumber);
        Check(typeof(StaticsFixture), nameof(StaticsFixture.ThreadReference), ref StaticsFixture.ThreadReference);
        Check(typeof(Preinitialized), nameof(Preinitialized.Text), ref Unsafe.AsRef(in Preinitialized.Text));
        Check(typeof(Preinitialized), nameof(Preinitialized.Values), ref Unsafe.AsRef(in Preinitialized.Values));
        Check(typeof(GenericStatics<int>), nameof(GenericStatics<int>.Number), ref GenericStatics<int>.Number);
        Check(typeof(GenericStatics<int>), nameof(GenericStatics<int>.Value), ref GenericStatics<int>.Value);
        Check(typeof(GenericStatics<int>), nameof(GenericStatics<int>.Text), ref GenericStatics<int>.Text);
        Check(typeof(GenericStatics<int>), nameof(GenericStatics<int>.ThreadValue), ref GenericStatics<int>.ThreadValue);
    }

    private static unsafe void Check<T>(Type owner, string name, ref T field) {
        uint type = checked((uint)(owner.TypeHandle.Value - image));
        Binding expected = Fields[(type, name)];
        fixed (byte* pointer = &Unsafe.As<T, byte>(ref field)) {
            if (expected.Location == 1) {
                Assert((nint)pointer == image + expected.Address);
            } else {
                byte* objectStart = pointer - expected.Offset;
                Assert(*(nint*)objectStart == image + expected.Descriptor);
                if (expected.Location == 2)
                    Assert(*(nint*)(image + expected.Address) == (nint)objectStart);
                else
                    Assert(expected.Location == 3);
            }
        }

        Console.WriteLine($"F|{type:X}|{name}|{expected.Location}");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Live static storage differs from the extraction.");
    }
}

internal struct Binding {
    internal byte Location;
    internal uint Address, Offset, Descriptor;
}

public static class StaticsFixture {
    public static int Number;
    public static object Reference;
    [ThreadStatic] public static int ThreadNumber;
    [ThreadStatic] public static object? ThreadReference;

    static StaticsFixture() {
        Number = Environment.TickCount;
        Reference = new object();
    }
}

public static class Preinitialized {
    public static readonly string Text = "preinit";
    public static readonly int[] Values = [1, 2, 3];
}

public static class GenericStatics<T> {
    public static int Number = 23;
    public static T? Value;
    public static string Text = "generic";
    [ThreadStatic] public static T? ThreadValue;
}

internal static partial class Native {
    [LibraryImport("kernel32.dll")]
    internal static partial nint GetModuleHandleW(nint name);
}
