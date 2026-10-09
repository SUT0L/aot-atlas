using System.Buffers.Binary;
using Atlas;

internal static class DictionaryContextRelationChecks {
    internal static void Run(string binary, string linkerMap) {
        PeImage image = new(File.ReadAllBytes(binary));
        ReadyToRun header = ReadyToRun.Read(image);
        RuntimeMemory memory = new(image, Hydration.Read(image, header));
        UnwindAnalysis analysis = new(image, header, memory);
        UnwindTables unwind = analysis.RequireUnwind();
        MethodGcMap gc = new(image, header, unwind, analysis.RequireManaged());
        Dictionary<string, ulong> symbols = new(StringComparer.Ordinal);

        foreach (string line in File.ReadLines(linkerMap)) {
            string[] columns = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (columns.Length >= 4 && columns[0].Contains(':') && columns[3] == "Probe.obj")
                symbols[columns[1]] = Convert.ToUInt64(columns[2], 16);
        }

        KeyValuePair<string, ulong> outer = symbols.Single(symbol => symbol.Key ==
            "Probe_DictionaryFunctions__Outer<Probe_DictionaryValue_1<System___Canon>>");
        ulong target = symbols[outer.Key.Replace("__Outer<", "__Inner<", StringComparison.Ordinal)];
        DictionarySlotConsumers result = new(image, memory, unwind, gc, []);
        DictionaryContextRelation relation = result.Relations.Single(relation => relation.Owner == outer.Value && relation.Target == target);
        Assert(relation.Kind == DictionaryContextRelationKind.LoadedSlot && relation.SlotOffset == 0
            && relation.ParameterRegister == 1 && relation.TargetRegister == 1
            && relation.ParameterStore == outer.Value + 4 && relation.Load == outer.Value + 9
            && relation.Instruction == outer.Value + 12,
            "Outer<T>'s linker-bound Inner<T> call has a different dictionary relationship.");
        Assert(image.FileSpan(relation.Load, 3).SequenceEqual(new byte[] { 0x48, 0x8B, 0x09 })
            && image.FileSpan(relation.Instruction, 1)[0] == 0xE8
            && unchecked(relation.Instruction + 5 + (ulong)BinaryPrimitives.ReadInt32LittleEndian(
                image.FileSpan(relation.Instruction + 1, 4))) == target,
            "Independent machine bytes disagree with the RCX slot-zero load and direct call.");
        Assert(result.ContextTransfers.All(transfer => transfer.Owner != outer.Value),
            "Producer no longer exercises a context relationship without an image dictionary seed.");

        int index = Array.FindIndex(gc.Methods, method => image.ImageBase + method.Begin == outer.Value);
        MethodGcEntry method = gc.Methods[index];
        int offset = image.FileRange(outer.Value).Start;
        int cases = 0;

        Case([0x48, 0x8B, 0x09], 1, 1);
        Case([], 1, 0);
        Case([0x48, 0x89, 0xCB, 0x48, 0x8B, 0x0B], 1, 1);
        Case([0x48, 0x8B, 0x0A], 0, 0);
        Case([0x48, 0x8B, 0x09, 0xB1, 1], 0, 1);
        Case([0x84, 0xC0, 0x75, 3, 0x48, 0x8B, 0x09], 0, 1);
        Case([0x48, 0x8B, 0x09], 0, 0, sourceRole: 0x10);

        Console.WriteLine($"Dictionary context producer: {result.Relations.Count} symbolic relations, {result.SlotAccesses.Count} slot accesses; Outer<T>→Inner<T> retains exact slot-zero provenance without a static address; {cases} alias, role, overwrite and join cases passed.");

        void Case(byte[] body, int expectedRelations, int expectedAccesses, ushort sourceRole = 0x20) {
            byte[] bytes = (byte[])image.FileData.Clone();
            Span<byte> code = bytes.AsSpan(offset, 23);
            code[9..].Fill(0x90);
            body.CopyTo(code[9..]);
            int call = 9 + body.Length;
            code[call] = 0xE8;
            BinaryPrimitives.WriteInt32LittleEndian(code[(call + 1)..],
                checked((int)((long)target - (long)outer.Value - call - 5)));
            code[call + 5] = 0xC3;
            gc.Methods[index] = method with {
                Info = new MethodGcInfo {
                    Flags = sourceRole,
                    ValidRangeStart = 9,
                    GenericContextSlot = 32,
                    CodeLength = 23
                }
            };
            PeImage changed = new(bytes);
            DictionarySlotConsumers actual = new(changed,
                new RuntimeMemory(changed, Hydration.Read(changed, header)), unwind, gc, []);
            Assert(actual.Relations.Count(relation => relation.Owner == outer.Value) == expectedRelations
                && actual.SlotAccesses.Count(access => access.Owner == outer.Value) == expectedAccesses,
                $"Incorrect symbolic dictionary provenance in case {cases}.");
            gc.Methods[index] = method;
            ++cases;
        }
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
