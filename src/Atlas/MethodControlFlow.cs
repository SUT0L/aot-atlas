using System.Collections.Frozen;
using System.Diagnostics;
using Iced.Intel;

namespace Atlas;

// Consumers share one bounded decode per logical method. Published graphs own
// their instruction and reachability arrays; decoder scratch remains local.
internal sealed class MethodControlFlows {
    private readonly PeImage image;
    private readonly UnwindTables unwind;
    private readonly uint[] entries;
    private readonly CancellationToken cancellationToken;

    private readonly List<Instruction> decoded = new();
    private readonly Dictionary<(uint Begin, uint Length), MethodControlFlow?> methods = new();

    internal MethodControlFlows(PeImage image, UnwindTables unwind, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        this.image = image;
        this.unwind = unwind;
        this.cancellationToken = cancellationToken;
        entries = new uint[unwind.DirectoryCount];

        for (int index = 0; index < entries.Length; ++index)
            entries[index] = unwind.Entries[index].Function.Begin;
    }

    internal bool TryBytes(in MethodGcEntry method, out ReadOnlySpan<byte> bytes) {
        if (!TryRange(method, out int offset, out int length)) {
            bytes = default;
            return false;
        }

        bytes = image.FileData.AsSpan(offset, length);

        return true;
    }

    private bool TryRange(in MethodGcEntry method, out int offset, out int length) {
        Debug.Assert(method.Info is not null);

        offset = length = 0;
        uint declared = method.Info.CodeLength;

        if (declared == 0 || method.End <= method.Begin || declared > method.End - method.Begin)
            return false;

        var file = image.FileRange(image.ImageBase + method.Begin);
        if (declared > file.Count)
            return false;

        offset = file.Start;
        length = (int)declared;

        return true;
    }

    internal MethodControlFlow? Read(in MethodGcEntry method) {
        if (!TryRange(method, out int offset, out int length))
            return null;

        var key = (method.Begin, method.Info!.CodeLength);
        if (methods.TryGetValue(key, out var cached))
            return cached;

        var graph = Decode(method.Begin, offset, length);
        methods.Add(key, graph);

        return graph;
    }

    internal MethodControlFlow? Read(uint begin, uint end) {
        if (end <= begin)
            return null;

        uint length = end - begin;
        var file = image.FileRange(image.ImageBase + begin);
        if (length > file.Count)
            return null;

        var key = (begin, length);
        if (methods.TryGetValue(key, out var cached))
            return cached;

        var graph = Decode(begin, file.Start, (int)length);
        methods.Add(key, graph);

        return graph;
    }

    internal MethodControlFlow? ReadTarget(ulong address) {
        if (address < image.ImageBase || address - image.ImageBase > uint.MaxValue)
            return null;

        int index = Array.BinarySearch(entries, (uint)(address - image.ImageBase));
        if (index < 0)
            return null;

        RuntimeFunction function = unwind.Entries[index].Function;
        return Read(function.Begin, function.End);
    }

    private MethodControlFlow? Decode(uint begin, int offset, int length) {
        cancellationToken.ThrowIfCancellationRequested();

        ulong owner = image.ImageBase + begin;
        var reader = new ByteArrayCodeReader(image.FileData, offset, length);
        var decoder = Decoder.Create(64, reader, owner);

        decoded.Clear();

        while (reader.CanReadByte) {
            if ((decoded.Count & 1023) == 0)
                cancellationToken.ThrowIfCancellationRequested();

            decoder.Decode(out var instruction);
            if (instruction.IsInvalid)
                return null;

            decoded.Add(instruction);
        }

        var code = decoded.ToArray();
        var successors = new MethodSuccessors[code.Length];

        for (int index = 0; index < code.Length; ++index) {
            if ((index & 1023) == 0)
                cancellationToken.ThrowIfCancellationRequested();

            var instruction = code[index];
            int next = index + 1 < code.Length
                && instruction.FlowControl is FlowControl.Next
                    or FlowControl.Call
                    or FlowControl.IndirectCall
                    or FlowControl.ConditionalBranch
                ? index + 1
                : -1;
            int branch = instruction.FlowControl is FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch
                && instruction.Op0Kind == OpKind.NearBranch64
                ? MethodControlFlow.Index(code, instruction.NearBranchTarget)
                : -1;

            successors[index] = new(branch == next ? -1 : branch, next);
        }

        var roots = new List<int>();
        var joins = new HashSet<ulong>();
        bool unknown = false;

        int first = Array.BinarySearch(entries, begin);
        if (first < 0)
            first = ~first;

        for (int index = first;
            index < entries.Length && (ulong)entries[index] < (ulong)begin + (uint)length;
            ++index) {
            ulong address = image.ImageBase + entries[index];
            int root = MethodControlFlow.Index(code, address);

            if (root < 0)
                unknown = true;
            else
                roots.Add(root);

            joins.Add(address);
        }

        var reachable = new bool[code.Length];
        var pending = new Stack<int>(roots);

        while (pending.TryPop(out int index)) {
            cancellationToken.ThrowIfCancellationRequested();

            if (reachable[index])
                continue;

            reachable[index] = true;
            var instruction = code[index];

            if (instruction.FlowControl is FlowControl.IndirectBranch or FlowControl.XbeginXabortXend)
                unknown = true;

            if (instruction.FlowControl is FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch) {
                if (instruction.Op0Kind != OpKind.NearBranch64) {
                    unknown = true;
                } else {
                    ulong target = instruction.NearBranchTarget;
                    joins.Add(target);

                    if (target >= owner
                        && target - owner < (uint)length
                        && MethodControlFlow.Index(code, target) < 0)
                        unknown = true;
                }
            }

            var edges = successors[index];
            if (edges.Branch >= 0)
                pending.Push(edges.Branch);

            if (edges.Next >= 0)
                pending.Push(edges.Next);
        }

        return new(owner, code, successors, roots.ToArray(), reachable, joins, unknown || roots.Count == 0);
    }
}

internal readonly record struct MethodSuccessors(int Branch, int Next);

internal sealed class MethodControlFlow {
    private readonly Instruction[] code;
    private readonly MethodSuccessors[] successors;
    private readonly int[] roots;
    private readonly bool[] reachable;
    private readonly FrozenSet<ulong> joins;

    internal ulong Owner { get; }
    internal ReadOnlySpan<Instruction> Code => code;
    internal ReadOnlySpan<MethodSuccessors> Successors => successors;
    internal ReadOnlySpan<int> Roots => roots;
    internal ReadOnlySpan<bool> Reachable => reachable;

    internal IReadOnlyList<Instruction> Instructions { get; }
    internal IReadOnlyList<bool> Reachability { get; }
    internal IReadOnlySet<ulong> Joins => joins;
    internal bool Unknown { get; }

    private int[]? predecessorStarts;
    private int[]? predecessors;
    private readonly Dictionary<int, IReadOnlyList<bool>> beforeMasks = new();

    internal MethodControlFlow(
        ulong owner,
        Instruction[] code,
        MethodSuccessors[] successors,
        int[] roots,
        bool[] reachable,
        HashSet<ulong> joins,
        bool unknown) {
        Owner = owner;
        this.code = code;
        this.successors = successors;
        this.roots = roots;
        this.reachable = reachable;
        this.joins = joins.ToFrozenSet();
        Unknown = unknown;

        Instructions = Array.AsReadOnly(code);
        Reachability = Array.AsReadOnly(reachable);
    }

    internal IReadOnlyList<bool> Before(ulong instruction) {
        int index = Index(code, instruction);
        int target = index;
        Debug.Assert(index >= 0);

        if (beforeMasks.TryGetValue(index, out var cached))
            return cached;

        if (predecessorStarts is null)
            ReadPredecessors();

        var before = new bool[code.Length];
        var pending = new Stack<int>();
        pending.Push(index);

        while (pending.TryPop(out index)) {
            if (before[index] || !reachable[index])
                continue;

            before[index] = true;

            for (int edge = predecessorStarts![index]; edge < predecessorStarts[index + 1]; ++edge)
                pending.Push(predecessors![edge]);
        }

        var mask = Array.AsReadOnly(before);
        beforeMasks.Add(target, mask);

        return mask;
    }

    private void ReadPredecessors() {
        var starts = new int[code.Length + 1];

        foreach (var edges in successors) {
            if (edges.Branch >= 0)
                ++starts[edges.Branch + 1];

            if (edges.Next >= 0)
                ++starts[edges.Next + 1];
        }

        for (int index = 1; index < starts.Length; ++index)
            starts[index] += starts[index - 1];

        var values = new int[starts[^1]];
        var cursors = (int[])starts.Clone();

        for (int index = 0; index < successors.Length; ++index) {
            var edges = successors[index];
            if (edges.Branch >= 0)
                values[cursors[edges.Branch]++] = index;

            if (edges.Next >= 0)
                values[cursors[edges.Next]++] = index;
        }

        predecessorStarts = starts;
        predecessors = values;
    }

    internal static int Index(Instruction[] code, ulong address) {
        int low = 0;
        int high = code.Length;

        while (low < high) {
            int middle = low + (high - low) / 2;
            if (code[middle].IP < address)
                low = middle + 1;
            else
                high = middle;
        }

        return low < code.Length && code[low].IP == address ? low : -1;
    }
}
