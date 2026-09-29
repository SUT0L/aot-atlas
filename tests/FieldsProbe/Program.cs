using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Program {
    private static nint image;

    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Holder))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Packed))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(ThreeInts))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(References))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Overlap))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Cell<string>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Cell<Packed>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Cell<Cell<Packed>>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Cell<Cell<string>>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Cell<int[]>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Base))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Derived))]
    private static void Main() {
        image = Native.GetModuleHandleW(0);
        Holder holder = new();
        Field(ref holder, nameof(Holder.Small), ref holder.Small);
        Field(ref holder, nameof(Holder.Wide), ref holder.Wide);
        Field(ref holder, nameof(Holder.Embedded), ref holder.Embedded);
        Field(ref holder, nameof(Holder.Maybe), ref holder.Maybe);
        Field(ref holder, nameof(Holder.Count), ref holder.Count);
        Field(ref holder, nameof(Holder.Nested), ref holder.Nested);
        Field(ref holder, nameof(Holder.Reference), ref holder.Reference);
        Field(ref holder, nameof(Holder.Numbers), ref holder.Numbers);
        Field(ref holder, nameof(Holder.Matrix), ref holder.Matrix);
        Field(ref holder, nameof(Holder.Tail), ref holder.Tail);
        Field(ref holder, nameof(Holder.Choice), ref holder.Choice);

        Packed packed = default;
        Field(ref packed, nameof(Packed.A), ref packed.A);
        Field(ref packed, nameof(Packed.B), ref packed.B);
        ThreeInts wide = default;
        Field(ref wide, nameof(ThreeInts.A), ref wide.A);
        Field(ref wide, nameof(ThreeInts.B), ref wide.B);
        Field(ref wide, nameof(ThreeInts.C), ref wide.C);
        References embedded = default;
        Field(ref embedded, nameof(References.Reference), ref embedded.Reference);
        Field(ref embedded, nameof(References.Number), ref embedded.Number);

        Overlap overlap = default;
        Field(ref overlap, nameof(Overlap.Whole), ref overlap.Whole);
        Field(ref overlap, nameof(Overlap.High), ref overlap.High);
        Cell<string> text = default;
        Field(ref text, nameof(Cell<string>.Item), ref text.Item);
        Field(ref text, nameof(Cell<string>.Tag), ref text.Tag);
        Cell<Packed> value = default;
        Field(ref value, nameof(Cell<Packed>.Item), ref value.Item);
        Field(ref value, nameof(Cell<Packed>.Tag), ref value.Tag);
        Cell<Cell<Packed>> nested = default;
        Field(ref nested, nameof(Cell<Cell<Packed>>.Item), ref nested.Item);
        Field(ref nested, nameof(Cell<Cell<Packed>>.Tag), ref nested.Tag);
        Cell<Cell<string>> nestedText = default;
        Field(ref nestedText, nameof(Cell<Cell<string>>.Item), ref nestedText.Item);
        Field(ref nestedText, nameof(Cell<Cell<string>>.Tag), ref nestedText.Tag);
        Cell<int[]> array = default;
        Field(ref array, nameof(Cell<int[]>.Item), ref array.Item);
        Field(ref array, nameof(Cell<int[]>.Tag), ref array.Tag);

        Derived derived = new();
        Base parent = derived;
        Field(ref parent, nameof(Base.Number), ref parent.Number);
        Field(ref parent, nameof(Base.Reference), ref parent.Reference);
        Field(ref derived, nameof(Derived.Small), ref derived.Small);
        Field(ref derived, nameof(Derived.Last), ref derived.Last);

        Size<Packed>();
        Size<ThreeInts>();
        Size<References>();
        Size<Overlap>();
        Size<Packed?>();
        Size<int?>();
        Size<Cell<string>>();
        Size<Cell<Packed>>();
        Size<Cell<Cell<Packed>>>();
        Size<Cell<Cell<string>>>();
        Size<Cell<int[]>>();
        Size<ByteChoice>();
    }

    private static unsafe void Field<T, F>(ref T owner, string name, ref F field) {
        fixed (byte* value = &Unsafe.As<F, byte>(ref field))
        fixed (byte* container = &Unsafe.As<T, byte>(ref owner)) {
            byte* start = typeof(T).IsValueType ? container : (byte*)Unsafe.As<T, nint>(ref owner);
            Console.WriteLine($"F|{typeof(T).TypeHandle.Value - image:X}|{name}|{value - start}|{Unsafe.SizeOf<F>()}|{typeof(F).TypeHandle.Value - image:X}");
        }
    }

    private static void Size<T>() {
        Console.WriteLine($"S|{typeof(T).TypeHandle.Value - image:X}|{Unsafe.SizeOf<T>()}");
    }
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct Packed {
    public byte A;
    public int B;
}

[StructLayout(LayoutKind.Sequential)]
public struct ThreeInts {
    public int A, B, C;
}

public struct References {
    public object? Reference;
    public int Number;
}

[StructLayout(LayoutKind.Explicit, Size = 8)]
public struct Overlap {
    [FieldOffset(0)] public long Whole;
    [FieldOffset(4)] public int High;
}

public struct Cell<T> {
    public T? Item;
    public byte Tag;
}

public enum ByteChoice : byte {
    Zero, One
}

public sealed class Holder {
    public Packed Small;
    public ThreeInts Wide;
    public References Embedded;
    public Packed? Maybe;
    public int? Count;
    public Cell<Cell<Packed>> Nested;
    public object? Reference;
    public int[]? Numbers;
    public int[,]? Matrix;
    public byte Tail;
    public ByteChoice Choice;
}

public class Base {
    public int Number;
    public object? Reference;
}

public sealed class Derived : Base {
    public Packed Small;
    public long Last;
}

internal static partial class Native {
    [LibraryImport("kernel32.dll")]
    internal static partial nint GetModuleHandleW(nint name);
}
