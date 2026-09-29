using System.Text;

namespace Atlas;

public enum SignatureKind : byte {
    Unknown, Named, TypeVariable, MethodVariable, Array, SzArray, Pointer, ByReference,
    Instantiation, FunctionPointer, Modified, RuntimeType, ParameterName
}

public struct SignatureNode {
    public SignatureKind Kind;
    public int Element, Value;
    public string Name;
    public ulong TypeAddress;
    public IndexRange Arguments, Varargs, Sizes, LowerBounds;
    public bool Optional, NativeConvention;
}

public struct MethodSignature {
    public uint Offset, CallingConvention;
    public int GenericParameterCount, ReturnType;
    public IndexRange Parameters, Varargs;
    public bool NativeConvention;
}

public sealed class Signatures {
    public readonly List<SignatureNode> Nodes = new(32768) { default };
    public readonly List<int> Edges = new(65536);
    public readonly List<MethodSignature> Methods = new(16384) { default };

    public string RenderType(int index, ReadOnlySpan<string> typeArguments = default, ReadOnlySpan<string> methodArguments = default) {
        var builder = new StringBuilder();
        AppendType(builder, index, typeArguments, methodArguments);
        return builder.ToString();
    }

    public string RenderMethod(string name, int index, ReadOnlySpan<string> typeArguments = default, ReadOnlySpan<string> methodArguments = default) {
        var builder = new StringBuilder(name);
        AppendMethod(builder, index, typeArguments, methodArguments);
        return builder.ToString();
    }

    public void AppendMethod(StringBuilder builder, int index, ReadOnlySpan<string> typeArguments = default, ReadOnlySpan<string> methodArguments = default) {
        var signature = Methods[index];
        builder.Append('(');
        AppendParameters(builder, signature.Parameters, signature.Varargs, signature.NativeConvention ? 0 : signature.CallingConvention, ", ", typeArguments, methodArguments);
        builder.Append(") -> ");
        AppendType(builder, signature.ReturnType, typeArguments, methodArguments);
        if (signature.NativeConvention)
            builder.Append($" [native_cc=0x{signature.CallingConvention:X}]");
        else if ((signature.CallingConvention & ~0x20U) != 0)
            builder.Append($" [cc=0x{signature.CallingConvention:X}]");
    }

    private void AppendParameters(StringBuilder builder, IndexRange args, IndexRange varargs, uint cc, string separator,
        ReadOnlySpan<string> typeArguments, ReadOnlySpan<string> methodArguments) {
        for (int i = args.Start; i < args.End; ++i) {
            if (i != args.Start)
                builder.Append(separator);
            AppendType(builder, Edges[i], typeArguments, methodArguments);
        }

        if (varargs.Count != 0 || (cc & 15) == 5) {
            if (args.Count != 0)
                builder.Append(separator);
            builder.Append("...");
            for (int i = varargs.Start; i < varargs.End; ++i) {
                builder.Append(separator);
                AppendType(builder, Edges[i], typeArguments, methodArguments);
            }
        }
    }

    public void AppendType(StringBuilder builder, int index, ReadOnlySpan<string> typeArguments = default, ReadOnlySpan<string> methodArguments = default) {
        var node = Nodes[index];
        switch (node.Kind) {
            case SignatureKind.Unknown:
                builder.Append("??");
                break;
            case SignatureKind.Named:
            case SignatureKind.ParameterName:
                builder.Append(node.Name);
                break;
            case SignatureKind.RuntimeType:
                builder.Append("mt_ref_").Append(node.TypeAddress.ToString("X"));
                break;
            case SignatureKind.TypeVariable:
            case SignatureKind.MethodVariable:
                var arguments = node.Kind == SignatureKind.MethodVariable ? methodArguments : typeArguments;
                if ((uint)node.Value < (uint)arguments.Length && !string.IsNullOrEmpty(arguments[node.Value]))
                    builder.Append(arguments[node.Value]);
                else {
                    builder.Append(node.Kind == SignatureKind.MethodVariable ? "TM" : "T");
                    if (node.Value != 0)
                        builder.Append(node.Value);
                }
                break;
            case SignatureKind.FunctionPointer:
                builder.Append("delegate*");
                if (node.NativeConvention) {
                    if ((node.Value & 4) != 0)
                        builder.Append(" unmanaged");
                } else if (node.Value != 0)
                    builder.Append("[cc=0x").Append(node.Value.ToString("X")).Append(']');
                builder.Append('<');
                AppendParameters(builder, node.Arguments, node.Varargs, node.NativeConvention ? 0 : (uint)node.Value, ",", typeArguments, methodArguments);
                if (node.Arguments.Count != 0 || node.Varargs.Count != 0 || (!node.NativeConvention && (node.Value & 15) == 5))
                    builder.Append(',');
                AppendType(builder, node.Element, typeArguments, methodArguments);
                builder.Append('>');
                break;
            default:
                AppendType(builder, node.Element, typeArguments, methodArguments);
                switch (node.Kind) {
                    case SignatureKind.SzArray:
                        builder.Append("[]");
                        break;
                    case SignatureKind.Array:
                        builder.Append('[');
                        if (node.Value == 1)
                            builder.Append('*');
                        else
                            builder.Append(',', node.Value - 1);
                        builder.Append(']');
                        break;
                    case SignatureKind.Pointer:
                        builder.Append('*');
                        break;
                    case SignatureKind.ByReference:
                        builder.Append('&');
                        break;
                    case SignatureKind.Instantiation:
                        if (node.Arguments.Count == 0)
                            break;
                        builder.Append('<');
                        AppendParameters(builder, node.Arguments, default, 0, ",", typeArguments, methodArguments);
                        builder.Append('>');
                        break;
                    case SignatureKind.Modified:
                        builder.Append(node.Optional ? " modopt(" : " modreq(");
                        AppendType(builder, node.Value, typeArguments, methodArguments);
                        builder.Append(')');
                        break;
                }
                break;
        }
    }
}
