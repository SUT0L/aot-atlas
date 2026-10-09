using Atlas;
using System.Text.RegularExpressions;

internal static class RuntimeNameChecks {
    private const uint Class = 0x14U << 26;

    private static ulong Address(int index) => 0x140002000UL + (uint)index * 64;

    internal static void Run() {
        var (tables, maps) = Source("G", "Seed");
        int first = Generic(tables, [1, 1]);
        int second = Generic(tables, [first, first]);
        var names = new RuntimeNames(tables, maps);

        Assert(names.Values[second] == "G<G<Seed,Seed>,G<Seed,Seed>>", "Ordinary names changed.");
        Assert(names.Complete[second], "Known ordinary name became incomplete.");

        // This closure represents G<G<...>,G<...>>. Its graph has linear size,
        // while spelling the complete type doubles each level.
        for (int i = 0; i < 256; ++i)
            second = Generic(tables, [second, second]);

        names = new RuntimeNames(tables, maps);
        Assert(names.Values.All(value => value.Length <= 4096), "Shared identity graph amplified name storage.");
        Assert(names.Complete.Any(value => !value), "Abbreviated identity was marked complete.");

        foreach (string name in names.Values) {
            foreach (Match reference in Regex.Matches(name, "mt_ref_([0-9A-F]+)")) {
                Assert(tables.Index.ContainsKey(Convert.ToUInt64(reference.Groups[1].Value, 16)),
                    "Name contains an unresolvable EEType reference.");
            }
        }

        Assert(names.Values.SequenceEqual(new RuntimeNames(tables, maps).Values), "Repeat rendering changed references.");

        (tables, maps) = Source("G", new string('S', 2046));
        int exact = Generic(tables, [1, 1]);
        names = new RuntimeNames(tables, maps);

        Assert(names.Values[exact].Length == 4096 && names.Complete[exact], "Exact budget name changed.");

        int longer = Add(tables, new MethodTable { Flags = Class, BaseSize = 24 });
        maps.Types.Add(new TypeMapEntry { MethodTable = Address(longer), Name = new string('T', 2047) });
        int exceeds = Generic(tables, [1, longer]);
        names = new RuntimeNames(tables, maps);

        Assert(names.Values[exceeds] == $"mt_ref_{Address(0):X}<mt_ref_{Address(1):X},mt_ref_{Address(longer):X}>"
            && !names.Complete[exceeds], "Oversized identity did not retain resolvable generic shape.");

        (tables, maps) = Source("G", "Seed");
        int function = Add(tables, new MethodTable {
            Flags = 0x10000,
            BaseSize = 0x80000001,
            RelatedType = Address(1),
            Arguments = new IndexRange(0, 1)
        });
        tables.Pointers.Add(Address(1));
        int array = Add(tables, new MethodTable {
            Flags = (0x17U << 26) | 0x20000 | 0x80000008,
            BaseSize = 32,
            RelatedType = Address(1)
        });
        names = new RuntimeNames(tables, maps);

        Assert(names.Values[function] == "delegate* unmanaged<Seed,Seed>", "Function pointer spelling changed.");
        Assert(names.Values[array] == "Seed[*]", "Nonvector rank-one spelling changed.");

        maps.Types[1] = new TypeMapEntry { MethodTable = Address(1), Name = new string('S', 17) };

        foreach (int arity in new[] { 256, ushort.MaxValue }) {
            int wideDefinition = Add(tables, new MethodTable {
                Flags = Class | 0x30000,
                GenericArity = checked((ushort)arity)
            });
            int wide = Generic(tables, Enumerable.Repeat(1, arity).ToArray());
            var wideType = tables.Types[wide];
            wideType.GenericDefinition = Address(wideDefinition);
            tables.Types[wide] = wideType;

            names = new RuntimeNames(tables, maps);
            Assert(names.Values[wide] == $"mt_ref_{Address(wide):X}" && !names.Complete[wide],
                "Very wide identity did not remain bounded.");
        }

        Console.WriteLine("Runtime names: exact 4096-character boundary, generic DAG amplification, 256 levels, wide identity, resolvable references, and ordinary spelling passed.");
    }

    private static (MethodTables, ReflectionMaps) Source(string definition, string leaf) {
        var tables = new MethodTables();
        Add(tables, new MethodTable { Flags = Class | 0x30000, GenericArity = 2 });
        Add(tables, new MethodTable { Flags = Class, BaseSize = 24 });

        var maps = new ReflectionMaps();
        maps.Types.Add(new TypeMapEntry { MethodTable = Address(0), Name = definition });
        maps.Types.Add(new TypeMapEntry { MethodTable = Address(1), Name = leaf });

        return (tables, maps);
    }

    private static int Generic(MethodTables tables, int[] arguments) {
        int start = tables.Pointers.Count;

        foreach (int argument in arguments)
            tables.Pointers.Add(Address(argument));

        return Add(tables, new MethodTable {
            Flags = Class | 0x02000000,
            BaseSize = 24,
            GenericDefinition = Address(0),
            GenericArity = checked((ushort)arguments.Length),
            Arguments = new IndexRange(start, arguments.Length)
        });
    }

    private static int Add(MethodTables tables, MethodTable type) {
        int index = tables.Types.Count;
        type.Address = Address(index);
        tables.Add(type.Address, TypeEvidence.TypeMap);
        tables.Types[index] = type;

        return index;
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
