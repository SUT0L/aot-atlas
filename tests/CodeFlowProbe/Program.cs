using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Program {
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.PublicFields, typeof(Holder))]
    private static unsafe void Main(string[] args) {
        var holder = new Holder { Value = 17, Other = 29 };
        Assert(holder.Read() == 17);
        holder.Write(31);
        Assert(holder.Read() == 31 && holder.Pair().Second == 29);
        holder.Reference() = 43;
        Assert(holder.Value == 43);

        nint image = GetModuleHandleW(0);
        fixed (int* field = &holder.Value, other = &holder.Other) {
            nint address = Unsafe.As<Holder, nint>(ref holder);
            Console.WriteLine($"{typeof(Holder).TypeHandle.Value - image:X}|{(nint)field - address:X}|{(nint)other - address:X}");
        }

        if (args.Length == 0)
            return;
        foreach (string line in File.ReadLines(args[0])) {
            string[] parts = line.Split('|');
            nint code = image + nint.Parse(parts[1], System.Globalization.NumberStyles.HexNumber);
            switch (parts[0]) {
                case "Read":
                    Assert(((delegate*<Holder, int>)code)(holder) == holder.Value);
                    break;
                case "Write":
                    ((delegate*<Holder, int, void>)code)(holder, 59);
                    Assert(holder.Value == 59);
                    break;
                case "Reference":
                    ((delegate*<Holder, ref int>)code)(holder) = 71;
                    Assert(holder.Value == 71);
                    break;
                case "Pair":
                    Pair pair = default;
                    Pair* returned = ((delegate*<Holder, Pair*, Pair*>)code)(holder, &pair);
                    Assert(returned == &pair && pair.First == holder.Value && pair.Second == holder.Other);
                    break;
                default:
                    throw new Exception("Unexpected fixture method.");
            }
            Console.WriteLine(parts[0] + "|PASS");
        }
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Code flow fixture assertion failed.");
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW(nint name);
}

public class BaseHolder {
    public int Other;
}

public sealed class Holder : BaseHolder {
    public int Value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public int Read() => Value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public void Write(int value) { Value = value; }

    [MethodImpl(MethodImplOptions.NoInlining)]
    public ref int Reference() => ref Value;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public Pair Pair() => new() { First = Value, Second = Other };
}

public struct Pair {
    public long First, Second;
}
