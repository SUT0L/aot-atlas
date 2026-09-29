using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Program {
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(Functions))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(Owner<string>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(Owner<int>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(InstanceOwner))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(ValueOwner))]
    private static unsafe void Main(string[] args) {
        bool extended = args.Length != 0 && args[^1] == "--abi";
        delegate*<nint> text = &Functions.Handle<string>;
        delegate*<nint> reference = &Functions.Handle<object>;
        delegate*<nint> integer = &Functions.Handle<int>;
        delegate*<int, nint> intOverload = &Functions.Handle<string>;
        delegate*<float, nint> floatOverload = &Functions.Handle<string>;
        delegate*<TypePair> pair = &Functions.Handles<string, object>;
        delegate*<TypePair> reversed = &Functions.Handles<object, string>;
        delegate*<TypePair> nested = &Functions.Handles<Value<string>, object>;
        delegate*<TypePair> nestedReference = &Functions.Handles<Value<object>, string>;
        delegate*<nint> owner = &Owner<string>.Handle<object>;
        delegate*<nint> valueOwner = &Owner<int>.Handle<string>;
        Type functions = typeof(Functions);
        nint stringType = typeof(string).TypeHandle.Value;
        nint objectType = typeof(object).TypeHandle.Value;
        nint intType = typeof(int).TypeHandle.Value;
        Assert(typeof(float).Name == "Single");
        var instanceOwner = new DerivedOwner { Marker = 41 };
        var structOwner = new ValueOwner { Marker = 73 };
        Func<long, TypePair> instance = instanceOwner.Handle<string>;
        Func<long, TypePair> valueInstance = structOwner.Handle<object>;

        Assert(text() == stringType && reference() == objectType && integer() == intType);
        Assert(intOverload(7) == stringType + 7 && floatOverload(7) == stringType + 8);
        var result = pair();
        Assert(result.First == stringType && result.Second == objectType && result.Marker == 0x12345678);
        result = reversed();
        Assert(result.First == objectType && result.Second == stringType && result.Marker == 0x12345678);
        result = nested();
        Assert(result.First == typeof(Value<string>).TypeHandle.Value && result.Second == objectType);
        result = nestedReference();
        Assert(result.First == typeof(Value<object>).TypeHandle.Value && result.Second == stringType);
        Assert(owner() == (stringType ^ objectType) && valueOwner() == (intType ^ stringType));
        Assert(Functions.Handle<int[,]>() == typeof(int[,]).TypeHandle.Value);
        Assert(instance(7).Second == 48 && valueInstance(11).Second == 84);
        Assert(instanceOwner.Direct(7).Second == 48 && structOwner.Handle<object>(11).Second == 84);

        if (args.Length != 0 && args[0] != "--abi") {
            nint image = GetModuleHandleW(0);
            nint* descriptor = stackalloc nint[2];
            int verified = 0;
            foreach (string line in File.ReadLines(args[0])) {
                string[] parts = line.Split('|');
                descriptor[0] = image + nint.Parse(parts[2], System.Globalization.NumberStyles.HexNumber);
                descriptor[1] = image + nint.Parse(parts[3], System.Globalization.NumberStyles.HexNumber);
                nint argument = image + nint.Parse(parts[4], System.Globalization.NumberStyles.HexNumber);
                nint callable = (nint)descriptor + 2;
                switch (parts[0]) {
                    case "type":
                        Assert(((delegate*<nint>)callable)() == argument);
                        break;
                    case "int-overload":
                        Assert(((delegate*<int, nint>)callable)(7) == argument + 7);
                        break;
                    case "float-overload":
                        Assert(((delegate*<float, nint>)callable)(7) == argument + 8);
                        break;
                    case "pair":
                        result = ((delegate*<TypePair>)callable)();
                        nint second = image + nint.Parse(parts[5], System.Globalization.NumberStyles.HexNumber);
                        Assert(result.First == argument && result.Second == second && result.Marker == 0x12345678);
                        break;
                    case "owner":
                        nint ownerType = image + nint.Parse(parts[1], System.Globalization.NumberStyles.HexNumber);
                        nint first = ownerType == typeof(Owner<string>).TypeHandle.Value ? stringType : intType;
                        Assert(ownerType == typeof(Owner<string>).TypeHandle.Value || ownerType == typeof(Owner<int>).TypeHandle.Value);
                        Assert(((delegate*<nint>)callable)() == (first ^ argument));
                        break;
                    case "instance":
                        TypePair* classReturned = ((delegate*<InstanceOwner, TypePair*, nint, long, TypePair*>)descriptor[0])(
                            instanceOwner, &result, descriptor[1], 7);
                        Assert(classReturned == &result && result.First == stringType && result.Second == 48
                            && result.Marker == 0x12345678);
                        break;
                    case "value-instance":
                        object boxed = structOwner;
                        TypePair* valueReturned = ((delegate*<object, TypePair*, nint, long, TypePair*>)descriptor[0])(
                            boxed, &result, descriptor[1], 11);
                        Assert(valueReturned == &result && result.First == objectType && result.Second == 84
                            && result.Marker == 0x12345678);
                        break;
                    default:
                        throw new InvalidDataException("Unknown shared-call fixture case.");
                }
                ++verified;
            }

            Assert(verified == (extended ? 12 : 10));
            Console.WriteLine($"{verified} callable templates validated.");
            return;
        }

        Print("type", (nint)text, functions, [stringType]);
        Print("type", (nint)reference, functions, [objectType]);
        Print("type", (nint)integer, functions, [intType]);
        Print("int-overload", (nint)intOverload, functions, [stringType]);
        Print("float-overload", (nint)floatOverload, functions, [stringType]);
        Print("pair", (nint)pair, functions, [stringType, objectType]);
        Print("pair", (nint)reversed, functions, [objectType, stringType]);
        Print("pair", (nint)nested, functions, [typeof(Value<string>).TypeHandle.Value, objectType]);
        Print("pair", (nint)nestedReference, functions, [typeof(Value<object>).TypeHandle.Value, stringType]);
        Print("owner", (nint)owner, typeof(Owner<string>), [objectType]);
        Print("owner", (nint)valueOwner, typeof(Owner<int>), [stringType]);
        if (extended) {
            Assert((ExtraFunctionPointer(instance) & 2) != 0 && (ExtraFunctionPointer(valueInstance) & 2) != 0);
            Print("instance", ExtraFunctionPointer(instance), typeof(InstanceOwner), [stringType]);
            Print("value-instance", ExtraFunctionPointer(valueInstance), typeof(ValueOwner), [objectType]);
        }
    }

#if NET8_0
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "m_extraFunctionPointerOrData")]
#else
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_extraFunctionPointerOrData")]
#endif
    private static extern ref nint ExtraFunctionPointer(Delegate value);

    private static unsafe void Print(string label, nint pointer, Type owner, ReadOnlySpan<nint> arguments) {
        nint image = GetModuleHandleW(0);
        nint code = pointer, dictionary = 0;
        if ((pointer & 2) != 0) {
            nint* descriptor = (nint*)(pointer - 2);
            code = descriptor[0];
            dictionary = descriptor[1];
        }

        Console.Write($"{label}|{owner.TypeHandle.Value - image:X}|{code - image:X}|{(dictionary == 0 ? 0 : dictionary - image):X}");
        foreach (nint argument in arguments)
            Console.Write($"|{argument - image:X}");
        Console.WriteLine();
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Shared generic call returned an incorrect runtime identity.");
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW(nint name);
}

public struct Value<T> { public T Item; }
public struct TypePair { public nint First, Second, Marker; }

public class InstanceOwner {
    public long Marker;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public virtual TypePair Handle<T>(long value) => new() {
        First = typeof(T).TypeHandle.Value,
        Second = (nint)(Marker + value),
        Marker = 0x12345678
    };
}

public sealed class DerivedOwner : InstanceOwner {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public TypePair Direct(long value) => base.Handle<string>(value);
}

public interface IValueOwner { TypePair Handle<T>(long value); }

public struct ValueOwner : IValueOwner {
    public long Marker;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public TypePair Handle<T>(long value) => new() {
        First = typeof(T).TypeHandle.Value,
        Second = (nint)(Marker + value),
        Marker = 0x12345678
    };
}

public static class Functions {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static nint Handle<T>() => typeof(T).TypeHandle.Value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static nint Handle<T>(int value) => typeof(T).TypeHandle.Value + value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static nint Handle<T>(float value) => typeof(T).TypeHandle.Value + (int)value + 1;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static TypePair Handles<T, U>() => new() {
        First = typeof(T).TypeHandle.Value,
        Second = typeof(U).TypeHandle.Value,
        Marker = 0x12345678
    };
}

public static class Owner<T> {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static nint Handle<U>() => typeof(T).TypeHandle.Value ^ typeof(U).TypeHandle.Value;
}
