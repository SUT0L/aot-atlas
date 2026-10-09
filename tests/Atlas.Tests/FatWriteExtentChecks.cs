using Atlas;
using Iced.Intel;
using System.Buffers.Binary;
using System.Reflection;

internal static class FatWriteExtentChecks {
    internal static void Run() {
        const ulong target = 0x140010000;
        MethodInfo checker = Type.GetType("Atlas.ImageWriteProof, Atlas", throwOnError: true)!
            .GetMethod("MayWrite", BindingFlags.Static | BindingFlags.NonPublic)!;
        int[] lengths = [8, 16];

        foreach (int length in lengths) {
            Check([0x48, 0xAB], target - 8, length, false); // One STOSQ is disjoint.
            Check([0x48, 0xAB], target, length, true);
            Check([0xF3, 0x48, 0xAB], target - 8, length, true); // Repeated elements cover target.
            Check([0xF3, 0xAA], target - 16, length, true); // Count may exceed an element width.
            Check([0xFD, 0xF3, 0xAA], target + 16, length, true); // DF reverses traversal.
            Check([0x0F, 0xAE, 0x27], target - 8, length, true); // XSAVE extent is not fixed.
            Check([0x48, 0x89, 0x07], target - 8, length, false);
            Check([0x48, 0x89, 0x07], target - 7, length, true);
        }

        byte[] frameLoop = [
            0x48, 0x81, 0xEC, 0xB8, 0, 0, 0,
            0x48, 0xB8, 0xA0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x0F, 0x29, 0xA4, 0x04, 0xB0, 0, 0, 0,
            0x0F, 0x29, 0xA4, 0x04, 0xC0, 0, 0, 0,
            0x0F, 0x29, 0xA4, 0x04, 0xD0, 0, 0, 0,
            0x48, 0x83, 0xC0, 0x30, 0x75, 0xE2, 0xC3
        ];
        Prove(frameLoop, false);
        Prove(frameLoop, true, [0, 17]); // An independent entry has no induction initializer.
        byte[] unboundedLoop = (byte[])frameLoop.Clone();
        unboundedLoop[45] = 0xEB;
        Prove(unboundedLoop, true);
        byte[] pivot = [0x48, 0x89, 0xC4, 0x48, 0x89, 0x04, 0x24, 0xC3];
        Prove(pivot, true);
        Prove([0x48, 0x83, 0xEC, 0x40, 0x48, 0x8D, 0x7C, 0x24, 0x20,
            0x48, 0x89, 0x07, 0xC3], false);
        Prove([0x48, 0x83, 0xEC, 0x40, 0x48, 0x8D, 0x7C, 0x24, 0x40,
            0xB9, 32, 0, 0, 0, 0x48, 0x89, 0x04, 0xCF, 0xC3], true);
        Prove([0x48, 0xBB, 0, 0, 1, 0x40, 1, 0, 0, 0,
            0x48, 0x8B, 0x0B, 0x48, 0x83, 0xC3, 8, 0x85, 0xF6, 0x75, 0xF5, 0xC3], false);
        byte[] forwarded = [0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0xC3];
        BinaryPrimitives.WriteUInt64LittleEndian(forwarded.AsSpan(2), target);
        Prove(forwarded, true);
        Prove(forwarded, false, consumer: 0x14000100A);
        byte[] stackArgument = [0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
            0x48, 0x89, 0x44, 0x24, 0x20, 0xE8, 0, 0, 0, 0, 0xC3];
        BinaryPrimitives.WriteUInt64LittleEndian(stackArgument.AsSpan(2), target);
        Prove(stackArgument, true);
        byte[] pushedAlias = [0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0xC3];
        BinaryPrimitives.WriteUInt64LittleEndian(pushedAlias.AsSpan(2), target);
        Prove(pushedAlias, true);
        Console.WriteLine($"Image writes: {string.Join("/", lengths)}-byte extents, bounded stack induction, aliases, independent roots, loop budget, pivot, REP and XSAVE cases passed.");

        void Prove(byte[] bytes, bool expected, int[]? roots = null, ulong consumer = 0) {
            object graph = MethodControlFlowChecks.Decode(bytes, roots);
            IReadOnlyList<bool> mask = MethodControlFlowChecks.Reachability(graph);
            bool actual = (bool)checker.Invoke(null, [graph, mask, target, 16, consumer, null, CancellationToken.None])!;

            if (actual != expected)
                throw new Exception($"Image write proof failed for {Convert.ToHexString(bytes)}.");
        }

        void Check(byte[] tail, ulong address, int length, bool expected) {
            byte[] bytes = new byte[21 + tail.Length];
            bytes[0] = 0x48;
            bytes[1] = 0xBF;
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(2), address);
            bytes[10] = 0x48;
            bytes[11] = 0xB9;
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(12), 32);
            tail.CopyTo(bytes, 20);
            bytes[^1] = 0xC3;

            object graph = MethodControlFlowChecks.Decode(bytes);
            IReadOnlyList<bool> mask = MethodControlFlowChecks.Reachability(graph);
            bool actual = (bool)checker.Invoke(null, [graph, mask, target, length, 0UL, null, CancellationToken.None])!;

            if (actual != expected)
                throw new Exception($"Image write extent failed for {Convert.ToHexString(tail)} at {address:X}.");
        }
    }
}
