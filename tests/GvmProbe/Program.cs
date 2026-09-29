using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace GvmFixture;

internal static partial class Program {
    private static nint image;

    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(Base<int>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(Base<List<int>>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(Derived<int>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.NonPublicMethods, typeof(Explicit<int>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(Value<int>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(IDefault<int>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.NonPublicMethods, typeof(IDefaultOverride<int>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(Multi))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(StaticProvider))]
    private static unsafe void Main(string[] args) {
        image = GetModuleHandleW(0);
        byte[] digest = SHA256.HashData(File.ReadAllBytes(Environment.ProcessPath!));
        int records = 0;
        if (args.Length != 0) {
            using var reader = new BinaryReader(File.OpenRead(args[0]));
            Assert(reader.ReadBytes(32).AsSpan().SequenceEqual(digest));
            records = reader.ReadInt32();
            for (int i = 0; i < records; ++i) {
                uint rva = reader.ReadUInt32();
                int length = reader.ReadInt32();
                uint expected = reader.ReadUInt32();
                uint hash = 2166136261;
                foreach (byte value in new ReadOnlySpan<byte>((byte*)image + rva, length))
                    hash = (hash ^ value) * 16777619;
                Assert(hash == expected);
            }
            Assert(reader.BaseStream.Position == reader.BaseStream.Length);
        }

        using var json = new Utf8JsonWriter(Console.OpenStandardOutput());
        json.WriteStartObject();
        json.WriteString("input_sha256", Convert.ToHexString(digest).ToLowerInvariant());
        json.WriteNumber("matched_records", records);
        json.WriteStartArray("calls");
        Class(json, "base", new Base<int>());
        Class(json, "override", new Derived<int>());
        Class(json, "inherited", new Inherited<int>());
        Interface(json, "interface_base", new Base<int>());
        Interface(json, "interface_override", new Derived<int>());
        Interface(json, "interface_explicit", new Explicit<int>());
        Interface(json, "interface_value", new Value<int>());
        Interface<List<int>>(json, "interface_inherited", new Inherited<int>());
        Default<int>(json, "default", new Default<int>());
        Default<int>(json, "default_override", new DefaultOverride<int>());
        Key<int>(json, "multi_integer", new Multi());
        Key<string>(json, "multi_string", new Multi());
        Static<StaticProvider>(json);
        json.WriteEndArray();
        json.WriteEndObject();
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Class<T>(Utf8JsonWriter json, string label, Base<T> value) {
        Func<T, string, string> call = value.Map<string>;
        Print(json, label, typeof(Base<T>), value.GetType(), call, call(default!, "input"));
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Interface<T>(Utf8JsonWriter json, string label, IMap<T> value) {
        Func<T, string, string> call = value.Map<string>;
        Print(json, label, typeof(IMap<T>), value.GetType(), call, call(default!, "input"));
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Default<T>(Utf8JsonWriter json, string label, IDefault<T> value) {
        Func<string, string> call = value.Map<string>;
        Print(json, label, typeof(IDefault<T>), value.GetType(), call, call("input"));
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Key<T>(Utf8JsonWriter json, string label, IKey<T> value) {
        Func<string, string> call = value.Read<string>;
        Print(json, label, typeof(IKey<T>), value.GetType(), call, call("input"));
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Static<T>(Utf8JsonWriter json) where T : IStatic<T> {
        Func<int, string, string> call = T.Make<int, string>;
        Print(json, "static", typeof(IStatic<T>), typeof(T), call, call(42, "input"));
    }

    private static void Print(Utf8JsonWriter json, string label, Type caller, Type instance, Delegate call, string result) {
        Type owner = call.Method.DeclaringType!;
        json.WriteStartObject();
        json.WriteString("label", label);
        json.WriteNumber("calling_type", (caller.IsGenericType ? caller.GetGenericTypeDefinition() : caller).TypeHandle.Value - image);
        json.WriteNumber("instance_type", (instance.IsGenericType ? instance.GetGenericTypeDefinition() : instance).TypeHandle.Value - image);
        json.WriteNumber("target_type", (owner.IsGenericType ? owner.GetGenericTypeDefinition() : owner).TypeHandle.Value - image);
        json.WriteString("target_name", call.Method.Name);
        json.WriteNumber("generic_arity", call.Method.GetGenericArguments().Length);
        json.WriteBoolean("static", call.Method.IsStatic);
        json.WriteString("result", result);
        json.WriteStartArray("hierarchy");
        for (Type? current = instance; current != null; current = current.BaseType)
            json.WriteNumberValue((current.IsGenericType ? current.GetGenericTypeDefinition() : current).TypeHandle.Value - image);
        json.WriteEndArray();
        json.WriteEndObject();
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Assertion failed.");
    }

    [LibraryImport("kernel32", EntryPoint = "GetModuleHandleW")]
    private static partial nint GetModuleHandleW(nint name);
}

public interface IMap<T> {
    string Map<U>(T first, U second);
}

public class Base<T> : IMap<T> {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public virtual string Map<U>(T first, U second) => "base";
}

public sealed class Derived<T> : Base<T> {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public override string Map<U>(T first, U second) => "override";
}

public sealed class Inherited<T> : Base<List<T>> {
}

public sealed class Explicit<T> : IMap<T> {
    [MethodImpl(MethodImplOptions.NoInlining)]
    string IMap<T>.Map<U>(T first, U second) => "explicit";
}

public struct Value<T> : IMap<T> {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public string Map<U>(T first, U second) => "value";
}

public interface IDefault<T> {
    [MethodImpl(MethodImplOptions.NoInlining)]
    string Map<U>(U value) => "default";
}

public sealed class Default<T> : IDefault<T> {
}

public interface IDefaultOverride<T> : IDefault<T> {
    [MethodImpl(MethodImplOptions.NoInlining)]
    string IDefault<T>.Map<U>(U value) => "default_override";
}

public sealed class DefaultOverride<T> : IDefaultOverride<T> {
}

public interface IKey<T> {
    string Read<U>(U value);
}

public sealed class Multi : IKey<int>, IKey<string> {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public string Read<U>(U value) => "multi";
}

public interface IStatic<T> where T : IStatic<T> {
    static abstract string Make<U, V>(U first, V second);
}

public sealed class StaticProvider : IStatic<StaticProvider> {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static string Make<U, V>(U first, V second) => "static";
}
