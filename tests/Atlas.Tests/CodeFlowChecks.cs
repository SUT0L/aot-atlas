using System.Buffers.Binary;
using Atlas;

internal static class CodeFlowChecks {
    private const ulong Start = 0x140001000;
    private const ulong Owner = 0x140003000;

    internal static void Run() {
        var code = Decode(Convert.FromHexString("48B8E800000000000000EB05E800000000E801000000C3C3"));
        Assert(code.InstructionCount == 5);
        Assert(code.Calls.SequenceEqual([new CodeEdge(Start + 17, Start + 23)]));
        Assert(code.Jumps.SequenceEqual([new CodeEdge(Start + 10, Start + 17)]));
        Assert(code.Addresses.SequenceEqual([new CodeEdge(Start, 0xE8)]));

        code = Decode(Convert.FromHexString("65488B050000000065488D05000000000F1F0500000000C3"));
        Assert(code.InstructionCount == 4);
        Assert(code.Addresses.SequenceEqual([new CodeEdge(Start + 8, Start + 16)]));

        code = Decode(Convert.FromHexString("0F180D000000000FAE3D000000000F013D00000000C3"));
        Assert(code.Addresses.SequenceEqual([
            new CodeEdge(Start, Start + 7), new CodeEdge(Start + 7, Start + 14), new CodeEdge(Start + 14, Start + 21)]));

        code = Decode(Convert.FromHexString("65488B410865488D4110C3"));
        Assert(code.ReceiverAccesses.SequenceEqual([
            new ReceiverAccess(Owner, 16, Start, Start + 5, MemoryAccessKind.Address)]));

        code = Decode(Convert.FromHexString("4889CB8B4308488D431031DB8B4308C3"));
        Assert(code.ReceiverAccesses.SequenceEqual([
            new ReceiverAccess(Owner, 8, Start, Start + 3, MemoryAccessKind.Read, 4),
            new ReceiverAccess(Owner, 16, Start, Start + 6, MemoryAccessKind.Address)]));

        code = Decode(Convert.FromHexString("E8040000008B4108C3FFE0"));
        Assert(code.ReceiverAccesses.Count == 0 && code.IndirectBranches.SequenceEqual([Start + 9]));
        Assert(code.Calls.SequenceEqual([new CodeEdge(Start, Start + 9)]));

        code = Decode(Convert.FromHexString("FF71088F4110C3"));
        Assert(code.ReceiverAccesses.SequenceEqual([
            new ReceiverAccess(Owner, 8, Start, Start, MemoryAccessKind.Read, 8),
            new ReceiverAccess(Owner, 16, Start, Start + 3, MemoryAccessKind.Write, 8)]));

        code = Decode(Convert.FromHexString("FF4108C3"));
        Assert(code.ReceiverAccesses.SequenceEqual([
            new ReceiverAccess(Owner, 8, Start, Start, MemoryAccessKind.ReadWrite, 4)]));

        // The backedge is discovered after its target and invalidates the receiver there.
        code = Decode(Convert.FromHexString("4889CB8B430831DBEBF7"));
        Assert(code.ReceiverAccesses.Count == 0);

        // A branch to the entry bypasses its call ABI contract on later iterations.
        code = Decode(Convert.FromHexString("8B410831C9EBF9"));
        Assert(code.ReceiverAccesses.Count == 0);

        // An access before an interior loop header remains independently proven.
        code = Decode(Convert.FromHexString("8B41084889CB8B430831DBEBF7"));
        Assert(code.ReceiverAccesses.SequenceEqual([
            new ReceiverAccess(Owner, 8, Start, Start, MemoryAccessKind.Read, 4)]));

        // Calls enter under the ABI contract, unlike internal branches.
        code = Decode(Convert.FromHexString("8B4108E8F8FFFFFFC3"));
        Assert(code.ReceiverAccesses.Count == 1);

        // A tailcall from another rooted function still observes the target ABI.
        code = new CodeFlow(
            PeFixture.Create(Convert.FromHexString("8B4108C3EBFA"), ".text", 0x60000020),
            [Start, Start + 4], new Dictionary<ulong, ulong> { [Start] = Owner });
        Assert(code.ReceiverAccesses.SequenceEqual([
            new ReceiverAccess(Owner, 8, Start, Start, MemoryAccessKind.Read, 4)]));

        // Vary the loop header independently of the field observations. The oracle
        // is the straight prefix before that header, not the decoder's traversal.
        var loopRandom = new Random(0x41544C41);

        for (int sample = 0; sample < 512; ++sample) {
            int accesses = loopRandom.Next(1, 24);
            int header = loopRandom.Next(accesses);
            byte[] loop = new byte[accesses * 3 + 7];

            for (int i = 0; i < accesses; ++i) {
                loop[i * 3] = 0x8B; // mov eax,[rcx+offset]
                loop[i * 3 + 1] = 0x41;
                loop[i * 3 + 2] = (byte)(i * 4 + 8);
            }

            loop[accesses * 3] = 0x31; // xor ecx,ecx
            loop[accesses * 3 + 1] = 0xC9;
            loop[accesses * 3 + 2] = 0xE9;
            BinaryPrimitives.WriteInt32LittleEndian(loop.AsSpan(accesses * 3 + 3), header * 3 - loop.Length);

            code = Decode(loop);
            Assert(code.ReceiverAccesses.SequenceEqual(Enumerable.Range(0, header).Select(i =>
                new ReceiverAccess(
                    Owner, (uint)(i * 4 + 8), Start, Start + (uint)i * 3, MemoryAccessKind.Read, 4))));
        }

        const int blocks = 128;
        var random = new Random(0xC0DEF10);
        byte[] bytes = new byte[blocks * 16];
        Array.Fill(bytes, (byte)0xCC);

        int[] calls = new int[blocks];
        int[] jumps = new int[blocks];

        for (int i = 0; i < blocks; ++i) {
            calls[i] = random.Next(blocks / 2);
            jumps[i] = random.Next(blocks / 2);
            bytes[i * 16] = 0xE8;
            bytes[i * 16 + 5] = 0xE9;
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(i * 16 + 1), calls[i] * 16 - (i * 16 + 5));
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(i * 16 + 6), jumps[i] * 16 - (i * 16 + 10));
        }

        var reachable = new HashSet<int>();
        var pending = new Stack<int>();
        pending.Push(0);

        while (pending.TryPop(out int index)) {
            if (!reachable.Add(index))
                continue;

            pending.Push(calls[index]);
            pending.Push(jumps[index]);
        }

        code = Decode(bytes);
        Assert(code.InstructionCount == reachable.Count * 2 && code.Addresses.Count == 0);
        Assert(code.Calls.ToHashSet().SetEquals(reachable.Select(i =>
            new CodeEdge(Start + (uint)i * 16, Start + (uint)calls[i] * 16))));
        Assert(code.Jumps.ToHashSet().SetEquals(reachable.Select(i =>
            new CodeEdge(Start + (uint)i * 16 + 5, Start + (uint)jumps[i] * 16))));

        Console.WriteLine($"Code flow: 13 instruction fixtures, 512 seeded receiver loops, and seeded graph, {reachable.Count}/{blocks} blocks reached.");
    }

    private static CodeFlow Decode(byte[] instructions) {
        return new CodeFlow(
            PeFixture.Create(instructions, ".text", 0x60000020),
            [Start], new Dictionary<ulong, ulong> { [Start] = Owner });
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Code flow assertion failed.");
    }
}
