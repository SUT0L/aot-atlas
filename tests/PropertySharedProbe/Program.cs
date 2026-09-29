using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

public static class Program {
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(IPublished))]
#if KEEP_UNBOXED
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(UnboxedCollision))]
#endif
    public static void Main() {
        var published = new Published();
        var unrelated = new Unrelated();
        if (ReadPublished(published) != "published" || ReadUnrelated(unrelated) != 73
            || ReadUnrelated(new OtherUnrelated()) != 73 || ReadExtra(published) != "published" || ReadExtra(new OtherExtra()) != "other") {
            throw new InvalidDataException("Shared-body fixture results differ from their initialized storage.");
        }
        published.Audit();
        unrelated.Audit();
        Console.WriteLine($"shared-contract|{typeof(IUnrelated).Name}");
#if KEEP_UNBOXED
        UnboxedCollision numeric = new() { Padding = 11, Value = 37 };
        if (ReadBoxed(numeric) != 37) {
            throw new InvalidDataException("The boxed getter differs from its initialized storage.");
        }
        Console.WriteLine($"shared-unboxed|{Unsafe.ByteOffset(ref Unsafe.As<UnboxedCollision, byte>(ref numeric), ref Unsafe.As<int?, byte>(ref numeric.Value))}|{Unsafe.SizeOf<int?>()}");
#endif
        Console.WriteLine("shared-property-bodies-executed");
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string ReadPublished(IPublished value) => value.Name;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static long ReadUnrelated(IUnrelated value) => value.Read(19, 23);

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string ReadExtra(IExtra value) => value.Read(19);

#if KEEP_UNBOXED
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int? ReadBoxed(IBoxed value) => value.Number;
#endif

    public static void Audit<T>(object owner, ref T value, string name) {
        long offset = (long)Unsafe.ByteOffset(ref Unsafe.As<RawData>(owner).Data, ref Unsafe.As<T, byte>(ref value)) + IntPtr.Size;
        Console.WriteLine($"shared-layout|{name}|{offset}|{Unsafe.SizeOf<T>()}");
        GC.KeepAlive(owner);
    }
}

public sealed class RawData {
    public byte Data;
}

public interface IPublished {
    string Name { get; }
}

public sealed class Published : IPublished, IExtra {
    private string value = "published";

    public string Name {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => value;
    }

    public void Audit() => Program.Audit(this, ref value, "Published");

    [MethodImpl(MethodImplOptions.NoInlining)]
    public string Read(int unused) => value;
}

public interface IUnrelated {
    long Read(int unused, long alsoUnused);
}

public sealed class Unrelated : IUnrelated {
    private long value = 73;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public long Read(int unused, long alsoUnused) => value;

    public void Audit() => Program.Audit(this, ref value, "Unrelated");
}

public interface IBoxed {
    int? Number { get; }
}

public interface IExtra {
    string Read(int unused);
}

public sealed class OtherExtra : IExtra {
    private string value = "other";

    [MethodImpl(MethodImplOptions.NoInlining)]
    public string Read(int unused) => value;
}

public sealed class OtherUnrelated : IUnrelated {
    private long value = 74;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public long Read(int unused, long alsoUnused) => value - 1;
}

public struct UnboxedCollision : IBoxed {
    public long Padding;
    public int? Value;

    public int? Number {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => Value;
    }
}
