using Atlas;
using System.Text;

internal static class SignatureRenderChecks {
    internal static void Run() {
        var signatures = new SignatureBuilder();
        int generic = Add(signatures, new SignatureNode { Kind = SignatureKind.Named, Name = "G" });
        int leaf = Add(signatures, new SignatureNode { Kind = SignatureKind.Named, Name = "Seed" });
        int first = Instance(signatures, generic, leaf, leaf);
        int root = Instance(signatures, generic, first, first);

        Assert(signatures.RenderType(root) == "G<G<Seed,Seed>,G<Seed,Seed>>" && !signatures.HasAbbreviatedReferences,
            "Ordinary signature changed.");

        for (int i = 0; i < 30; ++i)
            root = Instance(signatures, generic, root, root);

        var prefix = new StringBuilder("preserved:");
        signatures.Publish().AppendType(prefix, root);

        Assert(prefix.ToString() == $"preserved:sig_ref_{root}" && signatures.HasAbbreviatedReferences,
            "Shared signature graph did not remain bounded.");
        Assert(signatures.RenderType(leaf) == "Seed" && signatures.HasAbbreviatedReferences,
            "Abbreviation history was reset.");

        int variable = Add(signatures, new SignatureNode { Kind = SignatureKind.TypeVariable, Value = 1 });
        int methodVariable = Add(signatures, new SignatureNode { Kind = SignatureKind.MethodVariable, Value = 0 });

        Assert(signatures.RenderType(variable, ["A", "B"]) == "B", "Type substitution changed.");
        Assert(signatures.RenderType(methodVariable, methodArguments: ["M"]) == "M", "Method substitution changed.");
        Assert(signatures.RenderType(variable) == "T1" && signatures.RenderType(methodVariable) == "TM",
            "Open variable spelling changed.");

        int exact = Add(signatures, new SignatureNode { Kind = SignatureKind.Named, Name = new string('S', 4096) });
        Assert(signatures.RenderType(exact).Length == 4096, "Exact name budget changed.");

        int tooLong = Add(signatures, new SignatureNode { Kind = SignatureKind.Named, Name = new string('S', 4097) });
        Assert(signatures.RenderType(tooLong) == $"sig_ref_{tooLong}",
            "Oversized name did not reference its exact graph node.");
        Assert(signatures.RenderType(variable, ["A", new string('S', 4097)]) == $"sig_ref_{variable}",
            "Borrowed substitution bypassed output bound.");

        int array = Add(signatures, new SignatureNode { Kind = SignatureKind.Array, Element = leaf, Value = 1 });
        int pointer = Add(signatures, new SignatureNode { Kind = SignatureKind.Pointer, Element = array });
        int modifier = Add(signatures, new SignatureNode { Kind = SignatureKind.Modified, Element = pointer, Value = generic });

        Assert(signatures.RenderType(modifier) == "Seed[*]* modreq(G)", "Array, pointer or modifier spelling changed.");

        int start = signatures.Edges.Length;
        signatures.AddEdge(variable);
        signatures.AddEdge(methodVariable);
        int function = Add(signatures, new SignatureNode {
            Kind = SignatureKind.FunctionPointer,
            Element = leaf,
            Arguments = new IndexRange(start, 1),
            Varargs = new IndexRange(start + 1, 1),
            Value = 5
        });

        Assert(signatures.RenderType(function) == "delegate*[cc=0x5]<T1,...,TM,Seed>",
            "Managed varargs function-pointer convention changed.");

        int native = Add(signatures, new SignatureNode {
            Kind = SignatureKind.FunctionPointer,
            Element = leaf,
            Arguments = new IndexRange(start, 1),
            Value = 4,
            NativeConvention = true
        });

        Assert(signatures.RenderType(native) == "delegate* unmanaged<T1,Seed>",
            "Native function-pointer convention changed.");

        signatures.AddMethod(new MethodSignature {
            ReturnType = leaf,
            Parameters = new IndexRange(start, 1),
            Varargs = new IndexRange(start + 1, 1),
            CallingConvention = 5
        });

        Assert(signatures.RenderMethod("M", 1) == "M(T1, ..., TM) -> Seed [cc=0x5]", "Method convention changed.");

        signatures.AddMethod(new MethodSignature {
            ReturnType = root,
            Parameters = new IndexRange(start, 1),
            CallingConvention = 1,
            NativeConvention = true
        });
        prefix.Clear().Append("Owner.M");

        signatures.Publish().AppendMethod(prefix, 2);
        Assert(prefix.ToString() == "Owner.M [method_sig_ref_2]", "Method abbreviation changed the caller's prefix.");

        int cycle = Add(signatures, new SignatureNode { Kind = SignatureKind.Pointer });
        var cyclic = signatures.Nodes[cycle];
        cyclic.Element = cycle;
        signatures.SetNode(cycle, cyclic);
        prefix.Clear().Append("preserved:");

        try {
            signatures.Publish().AppendType(prefix, cycle);
            throw new InvalidOperationException("Cyclic signature was accepted.");
        } catch (InvalidDataException) {
        }

        Assert(prefix.ToString() == "preserved:", "Cycle failure changed the caller's builder.");

        int deep = leaf;

        for (int i = 0; i < 4096; ++i)
            deep = Add(signatures, new SignatureNode { Kind = SignatureKind.Pointer, Element = deep });

        Assert(signatures.RenderType(deep) == $"sig_ref_{deep}", "Deep signature did not remain stack bounded.");

        Console.WriteLine("Signature rendering: bounded shared DAGs/deep paths, cycle rollback, exact budget, substitutions, function pointers, modifiers, varargs, calling conventions and caller prefixes passed.");
    }

    private static int Add(SignatureBuilder signatures, SignatureNode node) {
        int index = signatures.Nodes.Length;
        signatures.AddNode(node);

        return index;
    }

    private static int Instance(SignatureBuilder signatures, int definition, int left, int right) {
        int start = signatures.Edges.Length;
        signatures.AddEdge(left);
        signatures.AddEdge(right);

        return Add(signatures, new SignatureNode {
            Kind = SignatureKind.Instantiation,
            Element = definition,
            Arguments = new IndexRange(start, 2)
        });
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
