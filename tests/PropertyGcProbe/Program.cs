using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

public static unsafe class Program {
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(NumericHolder))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(ReferenceHolder))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(CorrectHolder))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(PartialHolder))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(NecessaryHolder))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(NecessaryValueOwner))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(ComputedHolder))]
    public static void Main() {
        var numeric = new NumericHolder();
        ref var projected = ref numeric.FalseGcValue;
        if (!Unsafe.AreSame(ref Unsafe.As<PairWithReference, RawPair>(ref projected), ref numeric.Raw)) {
            throw new Exception("Ref projection did not alias the raw storage.");
        }

        var reference = new ReferenceHolder { Reference = new object() };
        if (reference.FalseFunctionPointer == null) {
            throw new Exception("Function-pointer projection did not read the reference bits.");
        }

        ref var hidden = ref reference.HidesGcValue;
        if (!Unsafe.AreSame(ref Unsafe.As<RawPair, object?>(ref hidden), ref reference.Reference)) {
            throw new Exception("Raw value projection did not alias the reference storage.");
        }

        var correct = new CorrectHolder();
        if (!Unsafe.AreSame(ref correct.ReferenceView, ref correct.ReferencePair)
            || !Unsafe.AreSame(ref correct.NumericView, ref correct.NumericPair)) {
            throw new Exception("Positive projection did not alias its real field.");
        }

        var partial = new PartialHolder { Reference = new object() };
        ref byte expectedPartial = ref Unsafe.AddByteOffset(ref Unsafe.As<object?, byte>(ref partial.Reference), 4);
        if (!Unsafe.AreSame(ref Unsafe.As<RawPair, byte>(ref partial.CutsGcSlot), ref expectedPartial)) {
            throw new Exception("Partial projection did not cut the reference slot.");
        }

        Console.WriteLine($"necessary-type|{typeof(NecessaryHolder).TypeHandle.Value}");
        var valueOwner = new NecessaryValueOwner { Reference = new object() };
        if (!Unsafe.AreSame(ref Unsafe.As<RawPair, object?>(ref valueOwner.HidesUnknownGc), ref valueOwner.Reference)) {
            throw new Exception("Value owner projection did not alias the reference storage.");
        }
        Console.WriteLine($"necessary-value-type|{typeof(NecessaryValueOwner).TypeHandle.Value}");
        Console.WriteLine($"pair-size|{Unsafe.SizeOf<PairWithReference>()}");
        Console.WriteLine($"pair-type|{typeof(PairWithReference).TypeHandle.Value}");
        Console.WriteLine($"raw-type|{typeof(RawPair).TypeHandle.Value}");
        var computed = new ComputedHolder { ComputedRead = 21 };
        if (computed.ComputedRead != 42) {
            throw new Exception("The computed getter did not differ from the stored input.");
        }
        computed.Audit();
        Console.WriteLine("counterexamples-executed");
        GC.KeepAlive(reference);
        GC.KeepAlive(numeric);
        GC.KeepAlive(correct);
        GC.KeepAlive(partial);
    }
}

public sealed class ComputedHolder {
    private int stored;

    public int ComputedRead {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => stored * 2;
        [MethodImpl(MethodImplOptions.NoInlining)]
        set => stored = value;
    }

    public void Audit() {
        ref byte payload = ref Unsafe.As<RawObject>(this).Data;
        long offset = (long)Unsafe.ByteOffset(ref payload, ref Unsafe.As<int, byte>(ref stored)) + IntPtr.Size;
        Console.WriteLine($"store-only|{offset}|{Unsafe.SizeOf<int>()}|{stored}|{ComputedRead}");
        GC.KeepAlive(this);
    }
}

public sealed class RawObject {
    public byte Data = 0;
}

public sealed class CorrectHolder {
    public PairWithReference ReferencePair;
    public RawPair NumericPair;

    public ref PairWithReference ReferenceView {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => ref ReferencePair;
    }

    public ref RawPair NumericView {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => ref NumericPair;
    }
}

public sealed class PartialHolder {
    public object? Reference;
    public long Tail;
    public long More;

    public ref RawPair CutsGcSlot {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => ref Unsafe.As<byte, RawPair>(ref Unsafe.AddByteOffset(ref Unsafe.As<object?, byte>(ref Reference), 4));
    }
}

public sealed class NecessaryHolder {
    public object? Reference;
    public long Tail;

    public ref RawPair HidesUnknownGc {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => ref Unsafe.As<object?, RawPair>(ref Reference);
    }
}

[StructLayout(LayoutKind.Sequential)]
public struct NecessaryValueOwner {
    public long Prefix;
    public object? Reference;
    public long Tail;

    public ref RawPair HidesUnknownGc {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => ref Unsafe.As<object?, RawPair>(ref Unsafe.AsRef(in Reference));
    }
}

[StructLayout(LayoutKind.Sequential)]
public struct RawPair {
    public long First;
    public long Second;
}

[StructLayout(LayoutKind.Sequential)]
public struct PairWithReference {
    public object? Reference;
    public long Second;
}

public sealed class NumericHolder {
    public RawPair Raw;

    public ref PairWithReference FalseGcValue {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => ref Unsafe.As<RawPair, PairWithReference>(ref Raw);
    }
}

public sealed unsafe class ReferenceHolder {
    public object? Reference;
    public long Tail;

    public ref RawPair HidesGcValue {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => ref Unsafe.As<object?, RawPair>(ref Reference);
    }

    public delegate* unmanaged<void> FalseFunctionPointer {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => (delegate* unmanaged<void>)Unsafe.As<object?, nint>(ref Reference);
    }
}
