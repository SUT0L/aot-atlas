using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Program {
    private static nint image;

    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Words))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(Nested))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(CutWords))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(CutNested))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(References))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(NestedReferences))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields, typeof(CutReferences))]
    private static void Main() {
        image = Native.GetModuleHandleW(0);
        Words words = default;
        Field(ref words, nameof(Words.A), ref words.A);
        Field(ref words, nameof(Words.B), ref words.B);
        Nested nested = default;
        Field(ref nested, nameof(Nested.Value), ref nested.Value);
        CutWords cut = default;
        Field(ref cut, nameof(CutWords.Value), ref cut.Value);
        Field(ref cut, nameof(CutWords.Tail), ref cut.Tail);
        CutNested cutNested = default;
        Field(ref cutNested, nameof(CutNested.Value), ref cutNested.Value);
        Field(ref cutNested, nameof(CutNested.Tail), ref cutNested.Tail);

        References references = default;
        Field(ref references, nameof(References.Reference), ref references.Reference);
        Field(ref references, nameof(References.Number), ref references.Number);
        NestedReferences nestedReferences = default;
        Field(ref nestedReferences, nameof(NestedReferences.Value), ref nestedReferences.Value);
        CutReferences cutReferences = default;
        Field(ref cutReferences, nameof(CutReferences.Value), ref cutReferences.Value);
        Field(ref cutReferences, nameof(CutReferences.Tail), ref cutReferences.Tail);

        Size<Words>();
        Size<Nested>();
        Size<CutWords>();
        Size<CutNested>();
        Size<References>();
        Size<NestedReferences>();
        Size<CutReferences>();
    }

    private static unsafe void Field<T, F>(ref T owner, string name, ref F field) {
        fixed (byte* value = &Unsafe.As<F, byte>(ref field))
        fixed (byte* start = &Unsafe.As<T, byte>(ref owner)) {
            Console.WriteLine($"F|{typeof(T).TypeHandle.Value - image:X}|{name}|{value - start}|{Unsafe.SizeOf<F>()}|{typeof(F).TypeHandle.Value - image:X}");
        }
    }

    private static void Size<T>() {
        Console.WriteLine($"S|{typeof(T).TypeHandle.Value - image:X}|{Unsafe.SizeOf<T>()}");
    }
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct Words {
    public byte A;
    public int B;
}

public struct Nested {
    public Words Value;
}

[StructLayout(LayoutKind.Explicit, Size = 5)]
public struct CutWords {
    [FieldOffset(0)] public Words Value;
    [FieldOffset(3)] public short Tail;
}

[StructLayout(LayoutKind.Explicit, Size = 5)]
public struct CutNested {
    [FieldOffset(0)] public Nested Value;
    [FieldOffset(3)] public short Tail;
}

public struct References {
    public object? Reference;
    public int Number;
}

public struct NestedReferences {
    public References Value;
}

[StructLayout(LayoutKind.Explicit, Size = 16)]
public struct CutReferences {
    [FieldOffset(0)] public NestedReferences Value;
    [FieldOffset(12)] public int Tail;
}

internal static partial class Native {
    [LibraryImport("kernel32.dll")]
    internal static partial nint GetModuleHandleW(nint name);
}
