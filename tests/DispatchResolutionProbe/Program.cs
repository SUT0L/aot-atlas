using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

Assert(Read(new Base()) == "base");
Assert(Read(new Derived()) == "derived");
Assert(Read(new Variant()) == "variant");
Assert(Read(new Exact()) == "exact");
Query(typeof(Base), typeof(IRead<object>), true);
Query(typeof(Derived), typeof(IRead<object>), true);
Query(typeof(Variant), typeof(IRead<object>), true);
Query(typeof(Exact), typeof(IRead<object>), true);
Query(typeof(Reader<string>), typeof(IRead<object>), new Reader<string>() is IRead<object>);
Query(typeof(Reader<int>), typeof(IRead<object>), (object)new Reader<int>() is IRead<object>);
Query(typeof(Reader<int[]>), typeof(IRead<uint[]>), (object)new Reader<int[]>() is IRead<uint[]>);
Query(typeof(Reader<PairA[]>), typeof(IRead<PairB[]>), (object)new Reader<PairA[]>() is IRead<PairB[]>);
Query(typeof(Reader<bool[]>), typeof(IRead<byte[]>), (object)new Reader<bool[]>() is IRead<byte[]>);
Query(typeof(Reader<char[]>), typeof(IRead<ushort[]>), (object)new Reader<char[]>() is IRead<ushort[]>);
Query(typeof(Reader<string[,]>), typeof(IRead<object[,]>), (object)new Reader<string[,]>() is IRead<object[,]>);
Query(typeof(Reader<string[,]>), typeof(IRead<object[]>), (object)new Reader<string[,]>() is IRead<object[]>);
Query(typeof(Reader<IRead<string>>), typeof(IRead<IRead<object>>), (object)new Reader<IRead<string>>() is IRead<IRead<object>>);
Query(typeof(Writer<object>), typeof(IWrite<string>), (object)new Writer<object>() is IWrite<string>);
Query(typeof(DefaultBase), typeof(IDefault<object>), true);
Query(typeof(DefaultDerived), typeof(IDefault<object>), true);
Query(typeof(DefaultDerived), typeof(IDefault<DefaultBase>), true);
Query(typeof(SpecificDefaultDerived), typeof(IDefault<object>), true);
Console.WriteLine($"V|{Describe(new DefaultDerived())}");
Console.WriteLine($"V|{Describe(new SpecificDefaultDerived())}");
ArrayQuery(typeof(string[]), typeof(IEnumerable<object>), true);
ArrayQuery(typeof(int[]), typeof(IEnumerable<uint>), (object)new int[1] is IEnumerable<uint>);
ArrayQuery(typeof(PairA[]), typeof(IEnumerable<PairB>), (object)new PairA[1] is IEnumerable<PairB>);
ArrayQuery(typeof(string[]), typeof(System.Collections.IEnumerable), true);
if (args.Length == 1)
    AuditCells(args[0]);

[MethodImpl(MethodImplOptions.NoInlining)]
static string Read(IRead<object> value) => (string)value.Read();

[MethodImpl(MethodImplOptions.NoInlining)]
static string Describe(IDefault<object> value) => value.Describe();

static void Query([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] Type owner,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] Type contract, bool compatible) {
    GC.KeepAlive(owner.GetMethods());
    GC.KeepAlive(contract.GetMethods());
    Resolve(owner, contract, compatible);
}

static void ArrayQuery(Type owner, [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] Type contract, bool compatible) {
    GC.KeepAlive(contract.GetMethods());
    Resolve(owner, contract, compatible);
}

static unsafe void Resolve(Type owner, Type contract, bool compatible) {
    nint image = Native.GetModuleHandleW(0);
    nint result;
    // Each generic contract has its dictionary slot before its sole method
    ushort slot = contract.IsGenericType ? (ushort)1 : (ushort)0;
#if NET8_0
    result = Native.Resolve(owner.TypeHandle.Value, contract.TypeHandle.Value, slot, null);
#else
    result = Native.Resolve(owner.TypeHandle.Value, contract.TypeHandle.Value, slot);
#endif
    Console.WriteLine($"Q|{owner.TypeHandle.Value - image:X}|{contract.TypeHandle.Value - image:X}|{slot}|{(compatible ? 1 : 0)}|{(result == 0 ? 0 : result - image):X}|{owner}|{contract}");
}

static unsafe void AuditCells(string path) {
    using var reader = new BinaryReader(File.OpenRead(path));
    Assert(reader.ReadBytes(32).AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(Environment.ProcessPath!))));
    byte* image = (byte*)Native.GetModuleHandleW(0);
    uint imageSize = *(uint*)(image + *(int*)(image + 60) + 24 + 56);
    int count = reader.ReadInt32(), initial = 0, cached = 0, optimized = 0;
    for (int i = 0; i < count; ++i) {
        uint cell = reader.ReadUInt32(), contract = reader.ReadUInt32(), terminator = reader.ReadUInt32();
        ushort slot = reader.ReadUInt16();
        Assert(cell < imageSize - 16 && contract < imageSize && terminator < imageSize - 16);
        Assert(*(nuint*)(image + terminator) == 0 && *(nuint*)(image + terminator + 8) == slot);
        nuint value = *(nuint*)(image + cell + 8);
        nuint actual;
        if ((value & 3) == 0) {
            if (value < 4096) {
                ++optimized;
                continue;
            }
            actual = *(nuint*)value;
            Assert(*(uint*)(value + 8) == (uint)slot * 4);
            ++cached;
        } else {
            if ((value & 3) == 1) {
                actual = value & ~(nuint)3;
            } else {
                actual = ((nuint)(image + cell + 8) + unchecked((nuint)(nint)(int)value)) & ~(nuint)3;
                if ((value & 3) == 2)
                    actual = *(nuint*)actual;
            }
            ++initial;
        }
        Assert(actual == (nuint)(image + contract));
    }
    Assert(reader.BaseStream.Position == reader.BaseStream.Length);
    Console.WriteLine($"C|{count}|{initial}|{cached}|{optimized}");
}

static void Assert(bool condition) {
    if (!condition)
        throw new InvalidDataException("Live dispatch fixture disagrees.");
}

public interface IRead<out T> { T Read(); }
public interface IWrite<in T> { int Write(T value); }
public class Base : IRead<object> { public virtual object Read() => "base"; }
public class Derived : Base { public override object Read() => "derived"; }
public class Variant : Base, IRead<string> { string IRead<string>.Read() => "variant"; }
public class Exact : Variant, IRead<object> { object IRead<object>.Read() => "exact"; }
public class Reader<T> : IRead<T> { public T Read() => default!; }
public class Writer<T> : IWrite<T> { public int Write(T value) => 17; }
public struct PairA { public long A, B; }
public struct PairB { public long A, B; }
public interface IDefault<out T> { string Describe() => typeof(T).Name; }
public interface IMore<out T> : IDefault<T> { string IDefault<T>.Describe() => typeof(List<T>).Name; }
public class DefaultBase : IMore<DefaultBase> { }
public class DefaultDerived : DefaultBase, IMore<DefaultDerived> { }
public class SpecificDefaultBase : IDefault<object> { }
public class SpecificDefaultDerived : SpecificDefaultBase, IDefault<string> { }

internal static partial class Native {
    [LibraryImport("kernel32.dll")]
    internal static partial nint GetModuleHandleW(nint name);

    [LibraryImport("__Internal", EntryPoint = "RhResolveDispatchOnType")]
#if NET8_0
    internal static unsafe partial nint Resolve(nint owner, nint contract, ushort slot, nint* context);
#else
    internal static partial nint Resolve(nint owner, nint contract, ushort slot);
#endif
}
