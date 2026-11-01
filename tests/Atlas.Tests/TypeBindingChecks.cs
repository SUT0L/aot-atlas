using Atlas;

internal static class TypeBindingChecks {
    internal static void Run() {
        const int count = 4096;
        var random = new Random(0x4649454C);

        var tables = new MethodTables();
        var signatures = new SignatureBuilder();
        var maps = new ReflectionMaps();

        var nodes = new int[count];

        var expectedCanonical = new string[count];
        var exact = new Dictionary<string, int>();

        for (int i = 0; i < count; ++i) {
            ulong address = 0x140000000UL + (uint)i * 64;
            int element = i < 8
                ? (i & 1) == 0 ? 0x10 : 0x14
                : (i & 2) == 0 ? 0x10 : 0x14;

            MethodTable type = new() {
                Address = address,
                Flags = (uint)element << 26,
                BaseSize = 24
            };
            SignatureNode node = new() {
                Kind = SignatureKind.Named,
                Name = "SameName"
            };

            if (i is >= 4 and < 8) {
                type.Flags |= 3U << 16;
                type.GenericArity = (ushort)(i - 3);
            }

            if (i < 8) {
                expectedCanonical[i] = address.ToString();
            } else {
                int definition = 4 + (element == 0x10 ? 0 : 1) + (random.Next(2) * 2);
                int arity = definition - 3;

                type.Flags |= 0x02000000;
                type.GenericDefinition = tables.Types[definition].Address;
                type.Arguments = new IndexRange(tables.Pointers.Count, arity);

                node.Kind = SignatureKind.Instantiation;
                node.Element = nodes[definition];
                node.Arguments = new IndexRange(signatures.Edges.Length, arity);

                string key = type.GenericDefinition + "<";
                string canonical = key;

                for (int j = 0; j < arity; ++j) {
                    int argument = random.Next(i - 4);
                    if (argument >= 4)
                        argument += 4;

                    var child = tables.Types[argument];
                    tables.Pointers.Add(child.Address);
                    signatures.AddEdge(nodes[argument]);
                    key += child.Address + ",";
                    canonical += (child.IsValueType ? expectedCanonical[argument] : "R") + ",";
                }

                key += ">";
                expectedCanonical[i] = canonical + ">";
                exact[key] = exact.ContainsKey(key) ? 0 : i + 1;
            }

            tables.Index.Add(address, i);
            tables.Types.Add(type);

            nodes[i] = signatures.Nodes.Length;
            signatures.AddNode(node);
            if (i < 8)
                maps.Types.Add(new TypeMapEntry {
                    MethodTable = address,
                    Signature = nodes[i],
                    Name = "SameName"
                });
        }

        int variable = signatures.Nodes.Length;
        signatures.AddNode(new SignatureNode {
            Kind = SignatureKind.TypeVariable,
            Value = 0
        });

        int methodVariable = signatures.Nodes.Length;

        for (int i = 0; i < 5; ++i)
            signatures.AddNode(new SignatureNode {
                Kind = SignatureKind.MethodVariable,
                Value = i
            });

        int[] methodCompositions = new int[4];

        for (int arity = 1; arity <= 4; ++arity) {
            methodCompositions[arity - 1] = signatures.Nodes.Length;
            signatures.AddNode(new SignatureNode {
                Kind = SignatureKind.Instantiation,
                Element = nodes[arity + 3],
                Arguments = new IndexRange(signatures.Edges.Length, arity)
            });

            for (int i = 0; i < arity; ++i)
                signatures.AddEdge(methodVariable + i);
        }

        var bindings = new TypeBindings(tables, maps, signatures.Publish());
        var canonicalTypes = new CanonicalTypes(tables);

        var canonicalGroups = new Dictionary<string, int>();
        var shapeByGroup = new Dictionary<int, string>();
        var expectedBindings = new int[count];
        for (int i = 0; i < count; ++i) {
            if (i < 8) {
                expectedBindings[i] = i + 1;
                continue;
            }
            var type = tables.Types[i];
            string key = type.GenericDefinition + "<";
            bool ambiguousChild = false;
            for (int j = type.Arguments.Start; j < type.Arguments.End; ++j) {
                key += tables.Pointers[j] + ",";
                ambiguousChild |= expectedBindings[tables.Index[tables.Pointers[j]]] == 0;
            }
            expectedBindings[i] = ambiguousChild ? 0 : exact[key + ">"];
        }

        for (int i = 0; i < count; ++i) {
            int group = canonicalTypes.Groups[i];
            if (canonicalGroups.TryGetValue(expectedCanonical[i], out int expectedGroup))
                Assert(group == expectedGroup);
            else
                canonicalGroups.Add(expectedCanonical[i], group);

            if (shapeByGroup.TryGetValue(group, out string? shape))
                Assert(shape == expectedCanonical[i]);
            else
                shapeByGroup.Add(group, expectedCanonical[i]);

            int actual = bindings.Resolve(nodes[i]);
            Assert(actual == expectedBindings[i]);
            if (i < 8) {
                Assert(actual == i + 1);
                Assert(bindings.Resolve(variable, i + 1) == 0);
                continue;
            }

            var type = tables.Types[i];
            Assert(bindings.Resolve(variable, i + 1) == tables.Index[tables.Pointers[type.Arguments.Start]] + 1);
        }

        Console.WriteLine("Type bindings: 4096 declared compositions match independent identities and a bijection of canonical shapes.");

        Span<ulong> methodArguments = stackalloc ulong[4];

        for (int i = 0; i < 20_000; ++i) {
            int index = random.Next(8, count);
            var type = tables.Types[index];
            int arity = type.Arguments.Count;
            string key = type.GenericDefinition + "<";

            for (int j = 0; j < arity; ++j) {
                methodArguments[j] = tables.Pointers[type.Arguments.Start + j];
                key += methodArguments[j] + ",";
            }

            int signature = methodCompositions[arity - 1];
            var arguments = methodArguments[..arity];
            int owner = random.Next(count) + 1;

            Assert(bindings.Resolve(signature, owner) == 0);
            Assert(bindings.Resolve(signature, owner, arguments) == exact[key + ">"]);
            Assert(bindings.Resolve(signature, owner, arguments[..^1]) == 0);
            Assert(bindings.Resolve(signature, owner, arguments) == exact[key + ">"]);
            Assert(bindings.Resolve(methodVariable, owner, arguments) == tables.Index[arguments[0]] + 1);
            Assert(bindings.Resolve(methodVariable + 4, owner, arguments) == 0);
        }

        Console.WriteLine("Method bindings: 20000 seeded context changes preserve exact runtime identities and reject incomplete arguments.");

    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Type binding differs from the reference model.");
    }
}
