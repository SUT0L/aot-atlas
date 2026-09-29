using Atlas;

internal static class TypeBindingChecks {
    internal static void Run() {
        const int count = 4096;
        var random = new Random(0x4649454C);
        var tables = new MethodTables();
        var signatures = new Signatures();
        var maps = new ReflectionMaps();
        var nodes = new int[count];
        var expectedCanonical = new string[count];
        var exact = new Dictionary<string, int>();

        for (int i = 0; i < count; ++i) {
            ulong address = 0x140000000UL + (uint)i * 64;
            int element = i < 8 ? (i & 1) == 0 ? 0x10 : 0x14 : (i & 2) == 0 ? 0x10 : 0x14;
            MethodTable type = new() { Address = address, Flags = (uint)element << 26, BaseSize = 24 };
            SignatureNode node = new() { Kind = SignatureKind.Named, Name = "SameName" };
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
                node.Arguments = new IndexRange(signatures.Edges.Count, arity);
                string key = type.GenericDefinition + "<";
                string canonical = key;

                for (int j = 0; j < arity; ++j) {
                    int argument = random.Next(i - 4);
                    if (argument >= 4)
                        argument += 4;

                    var child = tables.Types[argument];
                    tables.Pointers.Add(child.Address);
                    signatures.Edges.Add(nodes[argument]);
                    key += child.Address + ",";
                    canonical += (child.IsValueType ? expectedCanonical[argument] : "R") + ",";
                }

                key += ">";
                expectedCanonical[i] = canonical + ">";
                exact[key] = exact.ContainsKey(key) ? 0 : i + 1;
            }

            tables.Index.Add(address, i);
            tables.Types.Add(type);
            nodes[i] = signatures.Nodes.Count;
            signatures.Nodes.Add(node);
            if (i < 8)
                maps.Types.Add(new TypeMapEntry { MethodTable = address, Signature = nodes[i], Name = "SameName" });
        }

        int variable = signatures.Nodes.Count;
        signatures.Nodes.Add(new SignatureNode { Kind = SignatureKind.TypeVariable, Value = 0 });
        int methodVariable = signatures.Nodes.Count;
        for (int i = 0; i < 5; ++i)
            signatures.Nodes.Add(new SignatureNode { Kind = SignatureKind.MethodVariable, Value = i });

        int[] methodCompositions = new int[4];
        for (int arity = 1; arity <= 4; ++arity) {
            methodCompositions[arity - 1] = signatures.Nodes.Count;
            signatures.Nodes.Add(new SignatureNode {
                Kind = SignatureKind.Instantiation,
                Element = nodes[arity + 3],
                Arguments = new IndexRange(signatures.Edges.Count, arity)
            });
            for (int i = 0; i < arity; ++i)
                signatures.Edges.Add(methodVariable + i);
        }

        var bindings = new TypeBindings(tables, maps, signatures);
        var canonicalTypes = new CanonicalTypes(tables);
        var canonicalGroups = new Dictionary<string, int>();
        for (int i = 0; i < count; ++i) {
            int group = canonicalTypes.Groups[i];
            if (canonicalGroups.TryGetValue(expectedCanonical[i], out int expectedGroup))
                Assert(group == expectedGroup);
            else
                canonicalGroups.Add(expectedCanonical[i], group);

            int actual = bindings.Resolve(nodes[i]);
            if (i < 8) {
                Assert(actual == i + 1);
                Assert(bindings.Resolve(variable, i + 1) == 0);
                continue;
            }

            var type = tables.Types[i];
            string key = type.GenericDefinition + "<";
            bool ambiguousChild = false;
            for (int j = type.Arguments.Start; j < type.Arguments.End; ++j) {
                int child = tables.Index[tables.Pointers[j]];
                key += tables.Pointers[j] + ",";
                ambiguousChild |= bindings.Resolve(nodes[child]) == 0;
            }

            Assert(actual == (ambiguousChild ? 0 : exact[key + ">"]));
            Assert(bindings.Resolve(variable, i + 1) == tables.Index[tables.Pointers[type.Arguments.Start]] + 1);
        }

        for (int i = 0; i < 20_000; ++i) {
            int left = random.Next(count), right = random.Next(count);
            Assert((canonicalTypes.Groups[left] == canonicalTypes.Groups[right]) == (expectedCanonical[left] == expectedCanonical[right]));
        }

        Console.WriteLine("Type bindings: 4096 seeded compositions and 20000 canonical comparisons match the structural reference.");

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

        var metadata = new Metadata(default, 7);
        tables = new MethodTables();
        maps = new ReflectionMaps();
        uint[] flags = [0x14U << 26, 5U << 26, 8U << 26, 0x10U << 26, (0x12U << 26) | (3U << 16)];
        uint[] padding = [0, 7, 4, 3, 0];
        for (int i = 0; i < flags.Length; ++i) {
            ulong address = 0x140000000UL + (uint)i * 64;
            tables.Index.Add(address, i);
            tables.Types.Add(new MethodTable {
                Address = address,
                Flags = flags[i],
                BaseSize = i == 0 ? 96U : 24U,
                ValuePadding = padding[i],
                GenericArity = i == 4 ? (ushort)1 : (ushort)0
            });
            metadata.Signatures.Nodes.Add(new SignatureNode { Kind = SignatureKind.Named, Name = "SameName" });
            maps.Types.Add(new TypeMapEntry { MethodTable = address, Signature = i + 1 });
        }

        for (int i = 0; i < 7; ++i) {
            SignatureNode node = i < 3
                ? new SignatureNode { Kind = SignatureKind.Instantiation, Element = 5, Arguments = new IndexRange(metadata.Signatures.Edges.Count, 1) }
                : new SignatureNode { Kind = i == 3 ? SignatureKind.Pointer : i == 4 ? SignatureKind.SzArray : i == 5 ? SignatureKind.ByReference : SignatureKind.Unknown };
            if (i < 3)
                metadata.Signatures.Edges.Add(i + 2);

            int signature = metadata.Signatures.Nodes.Count;
            metadata.Signatures.Nodes.Add(node);
            maps.Fields.Add(new FieldMapEntry {
                DeclaringType = tables.Types[0].Address,
                Name = "F" + i,
                Signature = signature,
                Location = FieldLocation.Offset,
                Value = 8U + (uint)i * 8
            });
        }

        var layouts = new FieldLayouts(metadata, maps, tables);
        uint[] expectedSizes = [2, 8, 0, 8, 8, 8, 0];
        FieldStorageKind[] expectedStorage = [FieldStorageKind.Value, FieldStorageKind.Value, FieldStorageKind.Unknown,
            FieldStorageKind.Pointer, FieldStorageKind.Reference, FieldStorageKind.ByReference, FieldStorageKind.Unknown];
        for (int i = 0; i < expectedSizes.Length; ++i) {
            Assert(layouts.FieldTypes[i].Size == expectedSizes[i]);
            Assert(layouts.FieldTypes[i].Storage == expectedStorage[i]);
            Assert(layouts.FieldTypes[i].Binding == 0);
        }

        Console.WriteLine("Field sizes: primitive nullable alignment, unresolved struct alignment, and signature-defined pointer widths passed.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Type binding differs from the reference model.");
    }
}
