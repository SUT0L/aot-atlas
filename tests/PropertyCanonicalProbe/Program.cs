using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

public struct Nested<T> {
    public T Item;
    public long Marker;
    public override string ToString() => Marker.ToString();
}

public struct TwoLongs {
    public long First, Second;
}

public struct OtherTwoLongs {
    public long First, Second;
}

public sealed class Box<T> {
    public int Prefix = 0x12345678;
    public T fValue = default!;
    public long Suffix = 0x102030405060708;
    public T Value {
        [MethodImpl(MethodImplOptions.NoInlining)] get => fValue;
        [MethodImpl(MethodImplOptions.NoInlining)] set => fValue = value;
    }
}

internal static partial class Program {
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(Box<string>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(Box<object>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(Box<string[]>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(Box<Nested<string>>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(Box<Nested<object>>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(Box<Nested<int>>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(Box<TwoLongs>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(Box<OtherTwoLongs>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(Box<long>))]
    private static void Main() {
        var text = new Box<string> { Value = "value" };
        Assert(text.Value == "value");
        Emit(text);

        object marker = new();
        var reference = new Box<object> { Value = marker };
        Assert(ReferenceEquals(reference.Value, marker));
        Emit(reference);

        string[] content = ["one", "two"];
        var array = new Box<string[]> { Value = content };
        Assert(ReferenceEquals(array.Value, content));
        Emit(array);

        var nestedText = new Box<Nested<string>> { Value = new() { Item = "nested", Marker = 123 } };
        Assert(nestedText.Value.Item == "nested" && nestedText.Value.Marker == 123);
        Emit(nestedText);

        var nestedReference = new Box<Nested<object>> { Value = new() { Item = marker, Marker = 456 } };
        Assert(ReferenceEquals(nestedReference.Value.Item, marker) && nestedReference.Value.Marker == 456);
        Emit(nestedReference);

        var nestedInteger = new Box<Nested<int>> { Value = new() { Item = -77, Marker = 789 } };
        Assert(nestedInteger.Value.Item == -77 && nestedInteger.Value.Marker == 789);
        Emit(nestedInteger);
        Assert(((object)nestedText.Value).ToString() == "123" && ((object)nestedReference.Value).ToString() == "456");

        var pair = new Box<TwoLongs> { Value = new() { First = 11, Second = 22 } };
        Assert(pair.Value.First == 11 && pair.Value.Second == 22);
        Emit(pair);

        var other = new Box<OtherTwoLongs> { Value = new() { First = 33, Second = 44 } };
        Assert(other.Value.First == 33 && other.Value.Second == 44);
        Emit(other);

        var integer = new Box<long> { Value = long.MinValue + 77 };
        Assert(integer.Value == long.MinValue + 77);
        Emit(integer);
        Console.WriteLine("assertions|passed");
    }

    private static unsafe void Emit<T>(Box<T> value) {
        object owner = value;
        nint offset = (nint)Unsafe.AsPointer(ref value.fValue) - Unsafe.As<object, nint>(ref owner);
        nint image = GetModuleHandleW(0);
        var property = typeof(Box<T>).GetProperty("Value")!;
        nint code = property.GetMethod!.MethodHandle.GetFunctionPointer();
        if ((code & 2) != 0) {
            code = *(nint*)(code - 2);
        }
        Console.WriteLine($"owner|{typeof(Box<T>)}|{typeof(Box<T>).TypeHandle.Value - image:X}|{offset}|{Unsafe.SizeOf<T>()}|{typeof(T).TypeHandle.Value - image:X}|{code - image:X}");
        Assert(value.Prefix == 0x12345678 && value.Suffix == 0x102030405060708);
    }

    private static void Assert(bool condition) {
        if (!condition) {
            throw new InvalidDataException("Canonical fixture assertion failed.");
        }
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW(nint name);
}
