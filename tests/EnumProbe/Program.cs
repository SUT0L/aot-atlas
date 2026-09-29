using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

internal static partial class Program {
    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW(nint name);

    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.PublicMethods, typeof(EnumHolder))]
    private static void Main() {
        using var json = new Utf8JsonWriter(Console.OpenStandardOutput(), new JsonWriterOptions { Indented = true });
        json.WriteStartObject();
        json.WriteString("input_sha256", Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Environment.ProcessPath!))).ToLowerInvariant());
        json.WriteStartArray("types");
        Check(typeof(SignedByte), json);
        Check(typeof(UnsignedByte), json);
        Check(typeof(SignedShort), json);
        Check(typeof(UnsignedShort), json);
        Check(typeof(SignedInt), json);
        Check(typeof(UnsignedInt), json);
        Check(typeof(SignedLong), json);
        Check(typeof(UnsignedLong), json);
        Check(typeof(Empty), json);
        Check(typeof(Outer<>.Choice), json);
        Check(typeof(Outer<int>.Choice), json);
        Check(typeof(Outer<string>.Choice), json);
        json.WriteEndArray();
        json.WriteEndObject();
    }

    private static unsafe void Check([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields)] Type type, Utf8JsonWriter json) {
        Type storage = Enum.GetUnderlyingType(type);
        int width = Type.GetTypeCode(storage) switch {
            TypeCode.SByte or TypeCode.Byte => 1,
            TypeCode.Int16 or TypeCode.UInt16 => 2,
            TypeCode.Int32 or TypeCode.UInt32 => 4,
            TypeCode.Int64 or TypeCode.UInt64 => 8,
            _ => throw new InvalidDataException("Unexpected enum storage.")
        };
        bool signed = storage == typeof(sbyte) || storage == typeof(short) || storage == typeof(int) || storage == typeof(long);
        uint flags = *(uint*)type.TypeHandle.Value;
        byte element = (byte)((flags >> 26) & 31);
        if (width != 1 << ((element - 4) / 2) || signed != ((element & 1) == 0))
            throw new InvalidDataException("Live enum storage disagrees with reflection.");

        json.WriteStartObject();
        json.WriteString("name", type.FullName);
        json.WriteNumber("rva", (long)(type.TypeHandle.Value - GetModuleHandleW(0)));
        json.WriteNumber("width", width);
        json.WriteBoolean("signed", signed);
        json.WriteBoolean("flags", type.IsDefined(typeof(FlagsAttribute), false));
        json.WriteStartObject("members");
        ulong mask = ulong.MaxValue >> (64 - width * 8);
        foreach (FieldInfo field in type.GetFields(BindingFlags.Public | BindingFlags.Static)) {
            object value = field.GetRawConstantValue()!;
            ulong bits = signed ? unchecked((ulong)Convert.ToInt64(value)) : Convert.ToUInt64(value);
            json.WriteNumber(field.Name, bits & mask);
        }
        json.WriteEndObject();
        json.WriteEndObject();
    }
}

public enum SignedByte : sbyte { Min = sbyte.MinValue, Negative = -1, Zero = 0, Alias = 0, Max = sbyte.MaxValue }
public enum UnsignedByte : byte { Zero = 0, High = 128, Max = byte.MaxValue }
public enum SignedShort : short { Min = short.MinValue, Negative = -1, Zero = 0, Max = short.MaxValue }
public enum UnsignedShort : ushort { Zero = 0, High = 32768, Max = ushort.MaxValue }
public enum SignedInt : int { Min = int.MinValue, Negative = -1, Zero = 0, Max = int.MaxValue }
public enum UnsignedInt : uint { Zero = 0, High = 0x80000000, Max = uint.MaxValue }
public enum SignedLong : long { Min = long.MinValue, Negative = -1, Zero = 0, Max = long.MaxValue }
[Flags]
public enum UnsignedLong : ulong { Zero = 0, First = 1, High = 0x8000000000000000, Max = ulong.MaxValue, Ω = ulong.MaxValue }
public enum Empty : ushort { }

public static class Outer<T> {
    public enum Choice : short { Min = short.MinValue, Zero = 0, Max = short.MaxValue }
}

public class EnumHolder {
    public SignedByte Small;
    public UnsignedLong Large;
    public Outer<int>.Choice Generic;

    public SignedByte Convert(UnsignedLong value) => unchecked((SignedByte)value);
}
