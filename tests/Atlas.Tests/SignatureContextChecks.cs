using Atlas;
using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

internal static class SignatureContextChecks {
    internal static void Run() {
        ScopedAliases();

        var signatures = new SignatureBuilder();
        int left = Add(new() { Kind = SignatureKind.Named, Name = "Collision.Packet", MetadataScope = 1 });
        int right = Add(new() { Kind = SignatureKind.Named, Name = "Collision.Packet", MetadataScope = 2 });
        int variable = Add(new() { Kind = SignatureKind.TypeVariable, Value = 1 });
        int methodVariable = Add(new() { Kind = SignatureKind.MethodVariable });
        int generic = Add(new() { Kind = SignatureKind.Named, Name = "G" });

        var types = new[] {
            SignatureArgument.RuntimeType(0x1234, "A"),
            SignatureArgument.TypeSignature(left, "Collision.Packet")
        };
        var methods = new[] { SignatureArgument.TypeSignature(right, "Collision.Packet") };
        var context = new SignatureContext(types, methods);
        string[] typeDisplays = types.Select(a => a.Display).ToArray();
        string[] methodDisplays = methods.Select(a => a.Display).ToArray();
        var builder = new StringBuilder("prefix:");

        Assert(signatures.Publish().AppendTypeWithStatus(builder, variable, typeDisplays, methodDisplays)
            && builder.ToString() == "prefix:Collision.Packet", "Typed substitution changed text.");

        builder.Clear();
        Assert(signatures.Publish().AppendTypeWithStatus(builder, methodVariable, typeDisplays, methodDisplays)
            && builder.ToString() == "Collision.Packet", "Method argument lost its order.");

        int array = Add(new() { Kind = SignatureKind.Array, Element = variable, Value = 2 });
        int pointer = Add(new() { Kind = SignatureKind.Pointer, Element = array });
        int modifier = Add(new() {
            Kind = SignatureKind.Modified,
            Element = pointer,
            Value = right,
            Optional = true
        });
        int start = signatures.Edges.Length;
        signatures.AddEdge(modifier);
        signatures.AddEdge(methodVariable);
        int function = Add(new() {
            Kind = SignatureKind.FunctionPointer,
            Element = variable,
            NativeConvention = true,
            Value = 4,
            Arguments = new(start, 1),
            Varargs = new(start + 1, 1)
        });
        builder.Clear();

        Assert(signatures.Publish().AppendTypeWithStatus(builder, function, typeDisplays, methodDisplays),
            "Ordinary function pointer abbreviated.");
        Assert(builder.ToString() == "delegate* unmanaged<Collision.Packet[,]* modopt(Collision.Packet),...,Collision.Packet,Collision.Packet>",
            "Composite substitution changed text.");

        int root = function;

        for (int i = 0; i < 30; ++i) {
            start = signatures.Edges.Length;
            signatures.AddEdge(root);
            signatures.AddEdge(root);
            root = Add(new() { Kind = SignatureKind.Instantiation, Element = generic, Arguments = new(start, 2) });
        }

        int nodes = signatures.Nodes.Length;
        int edges = signatures.Edges.Length;
        builder.Clear();

        Assert(!signatures.Publish().AppendTypeWithStatus(builder, root, typeDisplays, methodDisplays)
            && builder.ToString() == $"sig_ref_{root}", "Deep shared graph did not abbreviate.");

        builder.Clear();
        Assert(signatures.Publish().AppendTypeWithStatus(builder, variable, typeDisplays, methodDisplays),
            "Owner history was mistaken for per-use completion.");

        string first = Publish(root, false, context);
        string repeat = Publish(root, false, context);
        Assert(first == repeat, "Repeated publication changed its bytes.");

        types[1] = SignatureArgument.TypeSignature(right, "Collision.Packet");
        string second = Publish(root, false, context);

        Assert(first != second && signatures.Nodes.Length == nodes && signatures.Edges.Length == edges,
            "Context was merged by display or materialized into the declaration graph.");

        using (var json = JsonDocument.Parse(first)) {
            var use = json.RootElement.GetProperty("signature_context");
            Assert(use.GetProperty("type_signature_id").GetInt32() == root, "Declaration root changed.");

            var typeArguments = use.GetProperty("type_arguments");
            Assert(typeArguments[0].GetProperty("type_address").GetUInt64() == 0x1234,
                "Runtime address was not preserved.");
            Assert(typeArguments[1].GetProperty("type_signature_id").GetInt32() == left,
                "Previously published borrowed arguments changed.");
            Assert(use.GetProperty("method_arguments")[0].GetProperty("type_signature_id").GetInt32() == right,
                "Method argument identity was guessed from its display.");
        }

        signatures.AddMethod(new() {
            ReturnType = root,
            Parameters = new(start, 2),
            NativeConvention = true,
            CallingConvention = 4
        });
        builder.Clear();

        Assert(!signatures.Publish().AppendMethodWithStatus(builder, 1, typeDisplays, methodDisplays)
            && builder.ToString() == " [method_sig_ref_1]", "Deep method bound changed.");
        Assert(Publish(1, true, context).Contains("\"method_signature_id\":1"),
            "Method and type identity spaces were conflated.");

        var unresolved = new SignatureContext(
            [default, SignatureArgument.ParameterName("T")], [SignatureArgument.ParameterName("")]);
        string open = Publish(1, true, unresolved);
        Assert(open.Contains("Unresolved") && open.Contains("ParameterName"),
            "Unknown and named formal substitutions were conflated.");

        string empty = Publish(root, false, default);
        Assert(empty.Contains("\"type_arguments\":[]") && empty.Contains("\"method_arguments\":[]"),
            "Absent substitutions were not explicit.");
        Assert(signatures.Nodes.Length == nodes && signatures.Edges.Length == edges && signatures.Methods.Length == 2,
            "Publication mutated signature identity.");

        int Add(SignatureNode node) {
            signatures.AddNode(node);

            return signatures.Nodes.Length - 1;
        }
    }

    private static void ScopedAliases() {
        foreach (int bits in new[] { 7, 8 }) {
            byte[] data = new byte[1024];
            uint H(int offset, uint kind) => ((uint)offset << bits) | kind;

            void Put(int offset, params uint[] values) {
                foreach (uint value in values) {
                    data[offset++] = 15;
                    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), value);
                    offset += 4;
                }
            }

            void Text(int offset, string text) {
                Put(offset, (uint)Encoding.UTF8.GetByteCount(text));
                Encoding.UTF8.GetBytes(text, data.AsSpan(offset + 5));
            }

            Text(32, "Collision");
            Text(64, "Packet");
            Text(96, "Left");
            Text(128, "Right");

            Put(256, H(320, 0x30), 64);
            Put(288, H(352, 0x30), 64);
            Put(320, H(400, 0x39), 32);
            Put(352, H(480, 0x39), 32);
            Put(400, 0, 96, 1, 0, 0, 0, 0, 0);
            Put(480, 0, 128, 1, 0, 0, 0, 0, 0);
            Put(560, H(288, 0x3d));

            var metadata = new MetadataBuilder(data, bits);
            int left = metadata.TypeSignature(H(256, 0x3d));
            int alias = metadata.TypeSignature(H(560, 0x3e));

            Assert(alias == metadata.TypeSignature(H(288, 0x3d)) && left != alias,
                "Scoped aliases lost declared identity.");

            var arguments = new[] {
                SignatureArgument.TypeSignature(left, "Collision.Packet"),
                SignatureArgument.TypeSignature(alias, "Collision.Packet")
            };
            var context = new SignatureContext(arguments);
            int count = metadata.SignatureBuilder.Nodes.Length;

            using var stream = new MemoryStream();

            using (var json = new Utf8JsonWriter(stream)) {
                json.WriteStartObject();
                MetadataIdentityOutput.WriteContext(json, left, false, context);
                MetadataIdentityOutput.Write(json, metadata.Publish());
                json.WriteEndObject();
            }

            using var result = JsonDocument.Parse(stream.ToArray());
            var graph = result.RootElement.GetProperty("signature_graph");
            var scopes = graph.GetProperty("scope_references").EnumerateArray()
                .Select(s => s.GetProperty("handle").GetUInt32()).ToHashSet();
            var nodes = graph.GetProperty("types").EnumerateArray()
                .ToDictionary(n => n.GetProperty("id").GetInt32());

            Assert(nodes[left].GetProperty("scope").GetUInt32() == H(400, 0x39)
                && nodes[alias].GetProperty("scope").GetUInt32() == H(480, 0x39),
                "Equal argument displays conflated assembly scopes.");
            Assert(scopes.Contains(H(400, 0x39)) && scopes.Contains(H(480, 0x39)),
                "Context scope closure was incomplete.");
            Assert(graph.GetProperty("handles").GetProperty(H(560, 0x3e).ToString()).GetInt32() == alias,
                "Forwarder handle did not resolve its context argument.");
            Assert(metadata.SignatureBuilder.Nodes.Length == count && nodes.Count == count - 1,
                "Publishing context added or lost graph nodes.");
        }
    }

    private static string Publish(int signature, bool method, scoped SignatureContext context) {
        using var stream = new MemoryStream();

        using (var json = new Utf8JsonWriter(stream)) {
            json.WriteStartObject();
            MetadataIdentityOutput.WriteContext(json, signature, method, context);
            json.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
