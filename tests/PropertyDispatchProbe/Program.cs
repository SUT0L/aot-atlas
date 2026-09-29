using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

public static class Program {
#if KEEP_CONTRACTS
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(IFields))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(IDefault))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(IValue<>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(IOut<>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicProperties, typeof(AbstractBase))]
#endif
    public static void Main() {
        var ordinary = new Ordinary();
        Verify(ordinary, 13, "ordinary");
        ordinary.Audit();

        var explicitItem = new Explicit();
        Verify(explicitItem, 17, "explicit");
        explicitItem.Audit();

        var defaultItem = new UsesDefault();
        VerifyDefault(defaultItem, 23);
        defaultItem.Audit();

        var integer = new Value<int>(29);
        VerifyValue(integer, 29);
        integer.Audit("Value`1<System.Int32>");

        var text = new Value<string>("generic");
        VerifyValue(text, "generic");
        text.Audit("Value`1<System.String>");

        var variant = new Covariant("variance");
        VerifyVariance(variant);
        variant.Audit();

        var derived = new AbstractDerived();
        VerifyAbstract(derived, 31);
        derived.Audit();

        var indirect = new IndirectDerived();
        VerifyAbstract(indirect, 37);
        indirect.Audit();

        Console.WriteLine("interface-projections-executed");
    }

    public static void Audit<T>(object owner, ref T field, string type, string property) {
        ref byte payload = ref Unsafe.As<RawData>(owner).Data;
        long offset = (long)Unsafe.ByteOffset(ref payload, ref Unsafe.As<T, byte>(ref field)) + IntPtr.Size;
        Console.WriteLine($"layout|{type}|{property}|{offset}|{Unsafe.SizeOf<T>()}");
        GC.KeepAlive(owner);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Verify(IFields item, int count, string label) {
        if (item.Count != count || item.Label != label) {
            throw new Exception("Interface getter result mismatch.");
        }

        item.Count = count + 1;
        if (item.Count != count + 1) {
            throw new Exception("Interface setter result mismatch.");
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void VerifyDefault(IDefault item, int expected) {
        if (item.Raw != expected || item.Next != expected + 1) {
            throw new Exception("Default interface result mismatch.");
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void VerifyValue<T>(IValue<T> item, T expected) {
        if (!EqualityComparer<T>.Default.Equals(item.Item, expected)) {
            throw new Exception("Generic interface result mismatch.");
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void VerifyVariance(IOut<object> item) {
        if (!Equals(item.Item, "variance")) {
            throw new Exception("Variant interface result mismatch.");
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void VerifyAbstract(AbstractBase item, int expected) {
        if (item.Amount != expected) {
            throw new Exception("Abstract property result mismatch.");
        }
    }
}

public sealed class RawData {
    public byte Data = 0;
}

public interface IFields {
    int Count { get; set; }
    string Label { get; }
}

public sealed class Ordinary : IFields {
    private int count = 13;
    private string label = "ordinary";

    public void Audit() {
        Program.Audit(this, ref count, "Ordinary", "Count");
        Program.Audit(this, ref label, "Ordinary", "Label");
    }

    public int Count {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => count;
        [MethodImpl(MethodImplOptions.NoInlining)]
        set => count = value;
    }

    public string Label {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => label;
    }
}

public sealed class Explicit : IFields {
    private int count = 17;
    private string label = "explicit";

    public void Audit() {
        Program.Audit(this, ref count, "Explicit", "Count");
        Program.Audit(this, ref label, "Explicit", "Label");
    }

    int IFields.Count {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => count;
        [MethodImpl(MethodImplOptions.NoInlining)]
        set => count = value;
    }

    string IFields.Label {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => label;
    }
}

public interface IDefault {
    int Raw { get; }
    int Next => Raw + 1;
}

public sealed class UsesDefault : IDefault {
    private int raw = 23;

    public void Audit() => Program.Audit(this, ref raw, "UsesDefault", "Raw");

    public int Raw {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => raw;
    }
}

public interface IValue<T> {
    T Item { get; }
}

public sealed class Value<T>(T item) : IValue<T> {
    public void Audit(string name) => Program.Audit(this, ref item, name, "Item");

    T IValue<T>.Item {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => item;
    }
}

public interface IOut<out T> {
    T Item { get; }
}

public sealed class Covariant(string item) : IOut<string> {
    public void Audit() => Program.Audit(this, ref item, "Covariant", "Item");

    public string Item {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => item;
    }
}

public abstract class AbstractBase {
    public abstract int Amount { get; }
}

public sealed class AbstractDerived : AbstractBase {
    private int amount = 31;

    public void Audit() => Program.Audit(this, ref amount, "AbstractDerived", "Amount");

    public override int Amount {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => amount;
    }
}

public abstract class AbstractMiddle : AbstractBase {
}

public sealed class IndirectDerived : AbstractMiddle {
    private object padding = new();
    private int amount = 37;

    public void Audit() => Program.Audit(this, ref amount, "IndirectDerived", "Amount");

    public override int Amount {
        [MethodImpl(MethodImplOptions.NoInlining)]
        get => amount;
    }
}
