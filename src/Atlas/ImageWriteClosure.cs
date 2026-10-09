namespace Atlas;

// No-write results cover every reachable body, including recursive groups.
// A failed query can retain closed components without reading queued callees
// after the first unsafe body.
internal sealed class ImageWriteClosure {
    private readonly MethodControlFlows flows;
    private readonly CancellationToken cancellationToken;
    private readonly Dictionary<ulong, MethodGcEntry> methods = new();
    private readonly HashSet<ulong> conflicted = new();
    private readonly Dictionary<(ulong Address, int Length), RangeProof> ranges = new();

    internal ImageWriteClosure(PeImage image, MethodControlFlows flows, MethodGcMap map, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        this.flows = flows;
        this.cancellationToken = cancellationToken;

        foreach (MethodGcEntry method in map.Methods) {
            cancellationToken.ThrowIfCancellationRequested();

            ulong address = image.ImageBase + method.Begin;
            if (!methods.TryAdd(address, method)
                && (methods[address].Info?.CodeLength != method.Info?.CodeLength || methods[address].End != method.End))
                conflicted.Add(address);
        }
    }

    internal bool MayWrite(MethodControlFlow graph, IReadOnlyList<bool> reachable, ulong address, int length, ulong consumer) {
        cancellationToken.ThrowIfCancellationRequested();

        if (!ranges.TryGetValue((address, length), out RangeProof? range)) {
            range = new(this, address, length);
            ranges.Add((address, length), range);
        }

        return ImageWriteProof.MayWrite(graph, reachable, address, length, consumer, range.Callee, cancellationToken);
    }

    private sealed class RangeProof {
        private readonly ImageWriteClosure owner;
        private readonly ulong address;
        private readonly int length;
        private readonly Dictionary<ulong, bool> results = new();
        internal readonly Func<ulong, bool> Callee;

        internal RangeProof(ImageWriteClosure owner, ulong address, int length) {
            this.owner = owner;
            this.address = address;
            this.length = length;
            Callee = MayWrite;
        }

        private bool MayWrite(ulong target) {
            owner.cancellationToken.ThrowIfCancellationRequested();

            if (results.TryGetValue(target, out bool written))
                return written;

            if (results.Count >= 4096)
                return true;

            Dictionary<ulong, int> visited = new() { [target] = 0 };
            HashSet<(int Caller, int Callee)> dependencies = new();
            List<(ulong Target, int Parent)> pending = [(target, -1)];

            int current = 0;
            int retainedCount = results.Count;

            bool dependenciesClosed = false;
            bool exhausted = false;
            Func<ulong, bool> dependency = Dependency;

            for (; current < pending.Count; ++current) {
                owner.cancellationToken.ThrowIfCancellationRequested();

                ulong callee = pending[current].Target;
                dependenciesClosed = true;
                MethodControlFlow? graph = null;
                if (!owner.conflicted.Contains(callee)) {
                    if (owner.methods.TryGetValue(callee, out MethodGcEntry method)) {
                        if (method.Info is not null)
                            graph = owner.flows.Read(method);
                    } else {
                        graph = owner.flows.ReadTarget(callee);
                    }
                }

                written = graph is null || graph.Unknown
                    || ImageWriteProof.MayWrite(graph, graph.Reachability, address, length, 0, dependency, owner.cancellationToken);
                if (written) {
                    // A rejected closure must leave room for smaller queries.
                    if (exhausted) {
                        foreach ((ulong pendingTarget, _) in pending)
                            results.Remove(pendingTarget);
                        results[target] = true;

                        return true;
                    }

                    // Each discovery ancestor can reach this unsafe body.
                    for (int index = current; index >= 0; index = pending[index].Parent)
                        results[pending[index].Target] = true;

                    break;
                }

                // No edge still depends on this closure's unfinished work.
                if (dependenciesClosed)
                    results.Add(callee, false);
            }

            if (current == pending.Count) {
                foreach ((ulong callee, _) in pending)
                    results.TryAdd(callee, false);

                return false;
            }

            bool unsettled = false;
            for (int index = 0; index <= current; ++index)
                unsettled |= !results.ContainsKey(pending[index].Target);

            if (!unsettled)
                return true;

            // Reverse edges belong only to this query. A completed component
            // must reach neither an unsafe body nor an unvisited dependency.
            int[] starts = new int[pending.Count + 1];
            foreach ((int _, int callee) in dependencies)
                ++starts[callee + 1];

            for (int index = 1; index < starts.Length; ++index)
                starts[index] += starts[index - 1];

            int[] callers = new int[dependencies.Count];
            int[] filled = new int[pending.Count];
            foreach ((int caller, int callee) in dependencies)
                callers[starts[callee] + filled[callee]++] = caller;

            const byte unsafeFlag = 1;
            const byte unfinishedFlag = 2;
            byte[] status = new byte[pending.Count];
            int[] statusQueue = new int[2 * pending.Count];
            int statusCount = 0;
            for (int index = 0; index < pending.Count; ++index) {
                if (index > current)
                    status[index] = unfinishedFlag;
                else if (results.TryGetValue(pending[index].Target, out bool unsafeBody) && unsafeBody)
                    status[index] = unsafeFlag;

                if (status[index] != 0)
                    statusQueue[statusCount++] = index;
            }

            for (int next = 0; next < statusCount; ++next) {
                owner.cancellationToken.ThrowIfCancellationRequested();

                int callee = statusQueue[next];
                for (int edge = starts[callee]; edge < starts[callee + 1]; ++edge) {
                    int caller = callers[edge];
                    byte flags = (byte)(status[caller] | status[callee]);
                    if (flags != status[caller]) {
                        status[caller] = flags;
                        statusQueue[statusCount++] = caller;
                    }
                }
            }

            for (int index = 0; index <= current; ++index) {
                if ((status[index] & unsafeFlag) != 0)
                    results.TryAdd(pending[index].Target, true);
                else if (status[index] == 0)
                    results.TryAdd(pending[index].Target, false);
            }

            return true;

            bool Dependency(ulong callee) {
                if (results.TryGetValue(callee, out bool cached))
                    return cached;

                dependenciesClosed = false;
                if (!visited.TryGetValue(callee, out int index)) {
                    if (retainedCount + pending.Count >= 4096) {
                        exhausted = true;

                        return true;
                    }

                    index = pending.Count;
                    visited.Add(callee, index);
                    pending.Add((callee, current));
                }

                if (!dependencies.Contains((current, index))) {
                    if (dependencies.Count == 65536) {
                        exhausted = true;

                        return true;
                    }

                    dependencies.Add((current, index));
                }

                return false;
            }
        }
    }
}
