using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

Assert(Call<Variant, int>(new Variant()) == 44);
Assert(Call<GenericVariant<string>, string>(new GenericVariant<string>()) == 92);
Assert(Call<OverrideVariant, int>(new OverrideVariant()) == 264);
Print(typeof(Variant), typeof(IVariant<int>));
Print(typeof(GenericVariant<string>), typeof(IVariant<string>));
Print(typeof(OverrideVariant), typeof(IVariant<int>));
if (args.Length == 1)
    Audit(args[0]);

[MethodImpl(MethodImplOptions.NoInlining)]
static int Call<TImplementation, TValue>(TImplementation value) where TImplementation : IVariant<TValue> {
    return value.Instance(1) + value.Default(1) + TImplementation.Static(1) + TImplementation.StaticDefault(1);
}

static void Print([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] Type owner,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] Type contract) {
    nint image = Native.GetModuleHandleW(0);
    GC.KeepAlive(owner.GetMethods());
    GC.KeepAlive(contract.GetMethods());
    Console.WriteLine($"T|{owner.TypeHandle.Value - image:X}|{contract.TypeHandle.Value - image:X}");
}

static unsafe void Audit(string path) {
    using var reader = new BinaryReader(File.OpenRead(path));
    Assert(reader.ReadBytes(32).AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(Environment.ProcessPath!))));
    nint image = Native.GetModuleHandleW(0);
    byte* bytes = (byte*)image;
    uint imageSize = *(uint*)(bytes + *(int*)(bytes + 0x3C) + 24 + 56);
    int records = reader.ReadInt32();
    for (int i = 0; i < records; ++i) {
        uint rva = reader.ReadUInt32(), length = reader.ReadUInt32(), expected = reader.ReadUInt32();
        Assert(rva < imageSize && length <= imageSize - rva);
        uint hash = 2166136261;
        for (uint offset = 0; offset < length; ++offset)
            hash = unchecked((hash ^ bytes[rva + offset]) * 16777619);
        Assert(hash == expected);
    }
    Console.WriteLine($"A|{records}");
    int count = reader.ReadInt32();
    for (int i = 0; i < count; ++i) {
        uint owner = reader.ReadUInt32(), contract = reader.ReadUInt32();
        Assert(owner < imageSize && contract < imageSize);
        ushort slot = reader.ReadUInt16();
        bool isStatic = reader.ReadBoolean();
        nint context = 0;
#if NET8_0
        nint target = Native.Resolve(image + (nint)owner, image + (nint)contract, slot, isStatic ? &context : null);
#else
        nint target = isStatic ? Native.ResolveStatic(image + (nint)owner, image + (nint)contract, slot, &context)
            : Native.Resolve(image + (nint)owner, image + (nint)contract, slot);
#endif
        Assert(target != 0);
        Console.WriteLine($"Q|{owner:X}|{contract:X}|{slot}|{(isStatic ? 1 : 0)}|{target - image:X}|{(context == 0 ? 0 : context - image):X}");
    }
    Assert(reader.BaseStream.Position == reader.BaseStream.Length);
}

static void Assert(bool condition) {
    if (!condition)
        throw new InvalidDataException("Dispatch variants do not match the fixture contract.");
}

public interface IVariant<T> {
    int Instance(int value);
    int Default(int value) => value + typeof(T).Name.Length;
    static abstract int Static(int value);
    static virtual int StaticDefault(int value) => value + typeof(T).Name.Length;
}

public sealed class Variant : IVariant<int> {
    public int Instance(int value) => value + 10;
    public static int Static(int value) => value + 20;
}

public sealed class GenericVariant<T> : IVariant<T> {
    public int Instance(int value) => value + 30;
    public static int Static(int value) => value + 40 + typeof(T).Name.Length;
}

public sealed class OverrideVariant : IVariant<int> {
    public int Instance(int value) => value + 50;
    public int Default(int value) => value + 60;
    public static int Static(int value) => value + 70;
    public static int StaticDefault(int value) => value + 80;
}

internal static partial class Native {
    [LibraryImport("kernel32.dll")]
    internal static partial nint GetModuleHandleW(nint name);

    [LibraryImport("__Internal", EntryPoint = "RhResolveDispatchOnType")]
#if NET8_0
    internal static unsafe partial nint Resolve(nint owner, nint contract, ushort slot, nint* context);
#else
    internal static partial nint Resolve(nint owner, nint contract, ushort slot);

    [LibraryImport("__Internal", EntryPoint = "RhResolveStaticDispatchOnType")]
    internal static unsafe partial nint ResolveStatic(nint owner, nint contract, ushort slot, nint* context);
#endif
}
