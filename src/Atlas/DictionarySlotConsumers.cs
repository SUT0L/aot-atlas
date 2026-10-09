using System.Buffers.Binary;
using Iced.Intel;

namespace Atlas;

public readonly record struct DictionaryContextTransfer(
    ulong Owner,
    ulong Dictionary,
    ulong Load,
    ulong Slot,
    ulong Value,
    ulong Instruction,
    ulong Target,
    ulong Seed,
    ImageValueUseEvidence Evidence = ImageValueUseEvidence.InitialImage);

public readonly record struct DictionaryDelegateSlot(
    ulong Owner,
    ulong Dictionary,
    ulong Instruction,
    ulong Load,
    ulong Slot,
    ulong Pointer,
    ulong Stub,
    ulong Consumer,
    ulong Seed,
    ImageValueUseEvidence Evidence = ImageValueUseEvidence.InitialImage);

public readonly record struct DictionaryConsumerFailure(ulong Owner, ulong Dictionary, ulong Instruction, string Error);

public enum DictionaryContextRelationKind : byte {
    ForwardedParameter,
    LoadedSlot,
    DelegateSlot
}

// The relation binds values at the observed load and call, without asserting an
// image address, immutable slot contents, or a dictionary extent.
public readonly record struct DictionaryContextRelation(
    ulong Owner,
    int ParameterRegister,
    ulong ParameterStore,
    uint GcInfoRva,
    DictionaryContextRelationKind Kind,
    uint SlotOffset,
    ulong Load,
    ulong Instruction,
    ulong Target,
    int TargetRegister,
    ulong Consumer);

public readonly record struct DictionaryContextSlotAccess(
    ulong Owner,
    int ParameterRegister,
    ulong ParameterStore,
    uint GcInfoRva,
    ulong Instruction,
    uint SlotOffset,
    int DestinationRegister);

// Only observed slot loads that reach a declared context argument or validated delegate
// consumer are instantiated. No dictionary extent or unobserved recipe is inferred.
// Initial records describe image bytes. Published consumer facts additionally
// exclude writes in retained seed/caller/ancestor plans and reachable callees.
public sealed class DictionarySlotConsumers {
    public IReadOnlyList<DictionaryContextTransfer> ContextTransfers { get; }
    public IReadOnlyList<DictionaryDelegateSlot> DelegateSlots { get; }
    public IReadOnlyList<DictionaryContextTransfer> InitialContextTransfers { get; }
    public IReadOnlyList<DictionaryDelegateSlot> InitialDelegateSlots { get; }
    public IReadOnlyList<DictionaryConsumerFailure> Failures { get; }
    public IReadOnlyList<DictionaryContextRelation> Relations { get; }
    public IReadOnlyList<DictionaryContextSlotAccess> SlotAccesses { get; }
    public IReadOnlyList<ulong> UnresolvedOwners { get; }
    public GenericContextReferences ContextReferences { get; }

    private readonly Dictionary<ulong, Plan> plans = new();
    private readonly Dictionary<(ulong Owner, ulong Dictionary), Instance> instances = new();
    private readonly ImageWriteClosure writes;
    private readonly CancellationToken cancellationToken;

    private sealed class Instance(ulong owner, ulong dictionary, ulong seed) {
        internal readonly ulong Owner = owner;
        internal readonly ulong Dictionary = dictionary;
        internal readonly ulong Seed = seed;

        internal readonly List<(Plan? Caller, ulong Instruction)> Roots = new();
        internal readonly List<Edge> Incoming = new();
        internal bool Unsafe;
    }

    private sealed record Edge(Instance Source, Instance Target, ulong Instruction, DictionaryContextTransfer? Fact) {
        internal bool Unsafe;
    }

    private readonly record struct Origin(byte Kind, uint Offset, ulong Load);
    private readonly record struct Stub(ulong Address, uint Offset, ulong Load, ulong Consumer);
    private readonly record struct Use(ulong Instruction, ulong Target, Origin Origin, Stub Delegate);
    private sealed record Plan(MethodControlFlow Flow, List<Use> Uses, List<DictionaryContextSlotAccess> SlotAccesses);

    public DictionarySlotConsumers(
        PeImage image,
        RuntimeMemory memory,
        UnwindTables unwind,
        MethodGcMap map,
        ReadOnlySpan<FunctionPointerConsumer> consumers,
        CancellationToken cancellationToken = default)
        : this(image, memory, map, new MethodControlFlows(image, unwind, cancellationToken), consumers,
            cancellationToken: cancellationToken) { }

    internal DictionarySlotConsumers(
        PeImage image,
        RuntimeMemory memory,
        MethodGcMap map,
        MethodControlFlows flows,
        ReadOnlySpan<FunctionPointerConsumer> consumers,
        ImageWriteClosure? writes = null,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        this.cancellationToken = cancellationToken;
        this.writes = writes ?? new(image, flows, map, cancellationToken);
        GenericContextReferences direct = ContextReferences = new(image, map, flows, cancellationToken);
        var parameters = direct.Parameters.ToDictionary(parameter => parameter.Target);
        Dictionary<ulong, Stub> stubs = ReadStubs(image, consumers, cancellationToken);
        var unresolved = new HashSet<ulong>(direct.UnresolvedControlFlowOwners);
        List<DictionaryContextRelation> relations = new();
        List<DictionaryContextSlotAccess> accesses = new();

        foreach (var method in map.Methods) {
            cancellationToken.ThrowIfCancellationRequested();

            ulong owner = image.ImageBase + method.Begin;
            if (plans.ContainsKey(owner) || !parameters.TryGetValue(owner, out var parameter))
                continue;

            Plan? plan = ReadPlan(flows, method, parameter, parameters, stubs, out bool unknown, cancellationToken);
            if (unknown)
                unresolved.Add(owner);

            if (plan is not null) {
                plans.Add(owner, plan);
                accesses.AddRange(plan.SlotAccesses);

                foreach (Use use in plan.Uses) {
                    bool delegated = use.Delegate.Address != 0;
                    relations.Add(new(
                        owner,
                        parameter.Register,
                        parameter.Store,
                        parameter.GcInfoRva,
                        delegated ? DictionaryContextRelationKind.DelegateSlot
                            : use.Origin.Kind == 2 ? DictionaryContextRelationKind.LoadedSlot
                            : DictionaryContextRelationKind.ForwardedParameter,
                        delegated ? use.Delegate.Offset : use.Origin.Offset,
                        delegated ? use.Delegate.Load : use.Origin.Load,
                        use.Instruction,
                        delegated ? use.Delegate.Address : use.Target,
                        delegated ? 8 : parameters[use.Target].Register,
                        delegated ? use.Delegate.Consumer : use.Instruction));
                }
            }
        }

        var contexts = new List<DictionaryContextTransfer>();
        var delegates = new List<DictionaryDelegateSlot>();
        var failures = new List<DictionaryConsumerFailure>();

        var edges = new List<Edge>();
        var candidates = new List<(Instance Instance, DictionaryDelegateSlot Slot)>();
        var pending = new Queue<Instance>();

        Instance GetInstance(ulong owner, ulong dictionary, ulong seed) {
            if (!instances.TryGetValue((owner, dictionary), out var instance)) {
                instance = new(owner, dictionary, seed);
                instances.Add((owner, dictionary), instance);
                pending.Enqueue(instance);
            }

            return instance;
        }

        foreach (var reference in direct.Values) {
            var instance = GetInstance(reference.Target, reference.Context, reference.Instruction);
            Plan? caller = null;

            foreach (var method in map.Methods) {
                ulong owner = image.ImageBase + method.Begin;
                if (method.Info is not { } info
                    || reference.Instruction < owner
                    || reference.Instruction - owner >= info.CodeLength)
                    continue;

                if (!plans.TryGetValue(owner, out caller)) {
                    caller = ReadPlan(flows, method, null, parameters, stubs, out bool unknown, cancellationToken);
                    if (unknown)
                        unresolved.Add(owner);

                    if (caller is not null)
                        plans.Add(owner, caller);
                }

                break;
            }

            instance.Roots.Add((caller, reference.Instruction));
        }

        while (pending.TryDequeue(out var instance)) {
            cancellationToken.ThrowIfCancellationRequested();

            if (!plans.TryGetValue(instance.Owner, out var plan))
                continue;

            foreach (var use in plan.Uses) {
                uint offset = use.Delegate.Address == 0 ? use.Origin.Offset : use.Delegate.Offset;
                ulong slot = 0;
                ulong value = instance.Dictionary;

                if (use.Origin.Kind == 2 || use.Delegate.Address != 0) {
                    if (!TrySlot(image, memory, instance.Dictionary, offset, out slot, out value)) {
                        failures.Add(new(
                            instance.Owner,
                            instance.Dictionary,
                            use.Instruction,
                            "Observed dictionary slot has no eligible initialized image bytes."));
                        continue;
                    }
                }

                if (use.Delegate.Address != 0) {
                    var stub = use.Delegate;
                    candidates.Add((instance, new(
                        instance.Owner,
                        instance.Dictionary,
                        use.Instruction,
                        stub.Load,
                        slot,
                        value,
                        stub.Address,
                        stub.Consumer,
                        instance.Seed)));
                } else if (ValidContext(image, memory, value)) {
                    var target = GetInstance(use.Target, value, instance.Seed);
                    DictionaryContextTransfer? fact = use.Origin.Kind == 2
                        ? new(instance.Owner, instance.Dictionary, use.Origin.Load,
                            slot, value, use.Instruction, use.Target, instance.Seed)
                        : null;
                    var edge = new Edge(instance, target, use.Instruction, fact);
                    edges.Add(edge);
                    target.Incoming.Add(edge);
                } else {
                    failures.Add(new(
                        instance.Owner,
                        instance.Dictionary,
                        use.Instruction,
                        "Declared method context argument is not an initialized image data address."));
                }
            }
        }

        foreach (var edge in edges) {
            if (edge.Fact is { } fact && WritesBefore(edge.Source, fact.Load, fact.Slot, 8)) {
                edge.Unsafe = true;
                failures.Add(new(
                    fact.Owner,
                    fact.Dictionary,
                    fact.Load,
                    "A reachable caller or ancestor write may alter the context slot."));
            }
        }

        // An unsafe incoming route taints the identity derived from that route. Resolve
        // cycles and all incoming evidence before any context or descriptor is published.
        bool changed;

        do {
            cancellationToken.ThrowIfCancellationRequested();

            changed = false;

            foreach (var edge in edges) {
                if (!edge.Target.Unsafe && (edge.Unsafe || edge.Source.Unsafe)) {
                    edge.Target.Unsafe = true;
                    changed = true;
                }
            }
        } while (changed);

        foreach (var edge in edges) {
            if (!edge.Source.Unsafe && !edge.Target.Unsafe && edge.Fact is { } fact)
                contexts.Add(fact with { Evidence = ImageValueUseEvidence.PreservedFromRetainedRootEntries });
        }

        foreach (var candidate in candidates) {
            var slot = candidate.Slot;
            if (candidate.Instance.Unsafe || WritesBefore(candidate.Instance, slot.Instruction, slot.Slot, 8)) {
                failures.Add(new(
                    slot.Owner,
                    slot.Dictionary,
                    slot.Instruction,
                    "A reachable caller or ancestor write may alter the delegate slot or its dictionary identity."));
                continue;
            }

            if ((slot.Pointer & 7) == 2 && WritesBefore(candidate.Instance, slot.Instruction, slot.Pointer - 2, 16)) {
                failures.Add(new(
                    slot.Owner,
                    slot.Dictionary,
                    slot.Instruction,
                    "A reachable caller or ancestor write may alter the consumed descriptor."));
                continue;
            }

            delegates.Add(slot with { Evidence = ImageValueUseEvidence.PreservedFromRetainedRootEntries });
        }

        InitialContextTransfers = Array.AsReadOnly(edges.Where(edge => edge.Fact is not null).Select(edge => edge.Fact!.Value).ToArray());
        InitialDelegateSlots = Array.AsReadOnly(candidates.Select(candidate => candidate.Slot).ToArray());
        ContextTransfers = contexts.AsReadOnly();
        DelegateSlots = delegates.AsReadOnly();
        Failures = failures.AsReadOnly();
        Relations = relations.AsReadOnly();
        SlotAccesses = accesses.AsReadOnly();
        UnresolvedOwners = Array.AsReadOnly(unresolved.Order().ToArray());

        plans.Clear();
        instances.Clear();
    }

    private bool WritesBefore(Instance instance, ulong instruction, ulong address, int length) {
        var pending = new Queue<(Instance Instance, ulong Instruction)>();
        var seen = new HashSet<(Instance, ulong)>();
        pending.Enqueue((instance, instruction));

        while (pending.TryDequeue(out var source)) {
            cancellationToken.ThrowIfCancellationRequested();

            if (!seen.Add(source))
                continue;

            if (!plans.TryGetValue(source.Instance.Owner, out var plan)
                || writes.MayWrite(
                    plan.Flow,
                    plan.Flow.Before(source.Instruction),
                    address,
                    length,
                    source.Instruction))
                return true;

            foreach (var root in source.Instance.Roots) {
                if (root.Caller is null || writes.MayWrite(
                    root.Caller.Flow,
                    root.Caller.Flow.Before(root.Instruction),
                    address,
                    length,
                    root.Instruction))
                    return true;
            }

            foreach (var edge in source.Instance.Incoming)
                pending.Enqueue((edge.Source, edge.Instruction));
        }

        return false;
    }

    private static bool ValidContext(PeImage image, RuntimeMemory memory, ulong address) {
        int section = image.FindSection(address);

        return (address & 7) == 0
            && section >= 0
            && !image.Sections[section].Executable
            && memory.Find(address) >= 0;
    }

    private static bool TrySlot(
        PeImage image,
        RuntimeMemory memory,
        ulong dictionary,
        uint offset,
        out ulong slot,
        out ulong value) {
        slot = value = 0;
        if (dictionary > ulong.MaxValue - offset || !ValidContext(image, memory, dictionary))
            return false;

        slot = dictionary + offset;
        int index = memory.Find(slot);
        if (index < 0 || image.IsExecutable(slot))
            return false;

        var region = memory.Regions[index];
        ulong within = slot - region.Start;
        if (region.Writable && !region.Hydrated
            || within > (ulong)region.Data.Length
            || region.Data.Length - (long)within < 8)
            return false;

        value = BinaryPrimitives.ReadUInt64LittleEndian(region.Data.Span[(int)within..]);

        return true;
    }

    private static Dictionary<ulong, Stub> ReadStubs(
        PeImage image,
        ReadOnlySpan<FunctionPointerConsumer> consumers,
        CancellationToken cancellationToken) {
        var targets = new HashSet<ulong>();

        foreach (var consumer in consumers) {
            if (consumer.Register == 8)
                targets.Add(consumer.Target);
        }

        var stubs = new Dictionary<ulong, Stub>();
        if (targets.Count == 0)
            return stubs;

        foreach (var section in image.Sections) {
            if (!section.Executable)
                continue;

            var bytes = image.FileData.AsSpan(section.FileOffset, section.FileSize);

            for (int offset = 0; offset + 4 <= bytes.Length; ++offset) {
                if ((offset & 4095) == 0)
                    cancellationToken.ThrowIfCancellationRequested();

                if (bytes[offset] != 0x4D
                    || bytes[offset + 1] != 0x8B
                    || (bytes[offset + 2] & 0x3F) != 0)
                    continue;

                ulong start = image.ImageBase + section.Rva + (uint)offset;
                var reader = new ByteArrayCodeReader(
                    image.FileData,
                    section.FileOffset + offset,
                    Math.Min(24, bytes.Length - offset));
                var decoder = Decoder.Create(64, reader, start);
                decoder.Decode(out var load);
                decoder.Decode(out var thunk);
                decoder.Decode(out var jump);

                if (load.Mnemonic == Mnemonic.Mov
                    && load.Op0Register == Register.R8
                    && load.Op1Kind == OpKind.Memory
                    && load.MemoryBase == Register.R8
                    && load.MemoryIndex == Register.None
                    && load.MemorySize.GetSize() == 8
                    && load.SegmentPrefix is not (Register.FS or Register.GS)
                    && load.MemoryDisplacement64 <= int.MaxValue
                    && (load.MemoryDisplacement64 & 7) == 0
                    && thunk.Mnemonic == Mnemonic.Lea
                    && thunk.Op0Register == Register.R9
                    && thunk.IsIPRelativeMemoryOperand
                    && image.IsExecutable(thunk.IPRelativeMemoryAddress)
                    && jump.Code is Code.Jmp_rel8_64 or Code.Jmp_rel32_64
                    && targets.Contains(jump.NearBranchTarget))
                    stubs.TryAdd(start, new(start, (uint)load.MemoryDisplacement64, load.IP, jump.IP));
            }
        }

        return stubs;
    }

    private static Plan? ReadPlan(
        MethodControlFlows flows,
        MethodGcEntry method,
        GenericContextParameter? parameter,
        Dictionary<ulong, GenericContextParameter> parameters,
        Dictionary<ulong, Stub> stubs,
        out bool unknown,
        CancellationToken cancellationToken) {
        var graph = flows.Read(method);
        unknown = graph is null || graph.Unknown;
        if (unknown)
            return null;

        if (parameter is null)
            return new(graph!, [], []);

        var code = graph!.Code;
        var successors = graph.Successors;

        var inputs = new Origin[checked(code.Length * 16)];
        var visited = new bool[code.Length];
        var pending = new Queue<int>();

        foreach (int root in graph.Roots) {
            visited[root] = true;
            if (code[root].IP == graph.Owner)
                inputs[root * 16 + parameter.Value.Register] = new(1, 0, 0);

            pending.Enqueue(root);
        }

        var factory = new InstructionInfoFactory();
        Span<Origin> state = stackalloc Origin[16];

        while (pending.TryDequeue(out int position)) {
            cancellationToken.ThrowIfCancellationRequested();

            var instruction = code[position];
            inputs.AsSpan(position * 16, 16).CopyTo(state);

            int source = instruction.Op1Register - Register.RAX;
            int destination = instruction.Op0Register - Register.RAX;
            Origin origin = default;

            if (instruction.Mnemonic == Mnemonic.Mov
                && instruction.Op0Kind == OpKind.Register
                && instruction.Op0Register.GetSize() == 8) {
                if (instruction.Op1Kind == OpKind.Register
                    && instruction.Op1Register.GetSize() == 8
                    && (uint)source < 16)
                    origin = state[source];
                else if (instruction.Op1Kind == OpKind.Memory
                    && instruction.MemorySize.GetSize() == 8
                    && instruction.MemoryIndex == Register.None
                    && instruction.SegmentPrefix is not (Register.FS or Register.GS)
                    && (uint)(instruction.MemoryBase - Register.RAX) < 16
                    && state[instruction.MemoryBase - Register.RAX].Kind == 1
                    && instruction.MemoryDisplacement64 <= int.MaxValue
                    && (instruction.MemoryDisplacement64 & 7) == 0)
                    origin = new(2, (uint)instruction.MemoryDisplacement64, instruction.IP);
            }

            ref readonly var usage = ref factory.GetInfo(in instruction);

            foreach (var use in usage.GetUsedRegisters()) {
                if (use.Access is OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite) {
                    int register = use.Register.GetFullRegister() - Register.RAX;
                    if ((uint)register < 16)
                        state[register] = default;
                }
            }

            if (instruction.Mnemonic == Mnemonic.Mov
                && instruction.Op0Kind == OpKind.Register
                && instruction.Op0Register.GetSize() == 8
                && (uint)destination < 16)
                state[destination] = origin;

            if (instruction.FlowControl is FlowControl.Call or FlowControl.IndirectCall) {
                for (int register = 0; register < 16; ++register) {
                    if ((0xF0F8 & (1 << register)) == 0)
                        state[register] = default;
                }
            }

            for (int edge = 0; edge < 2; ++edge) {
                int successor = edge == 0 ? successors[position].Branch : successors[position].Next;
                if (successor < 0)
                    continue;

                bool changed = !visited[successor];
                var input = inputs.AsSpan(successor * 16, 16);

                if (changed) {
                    state.CopyTo(input);
                } else {
                    for (int register = 0; register < 16; ++register) {
                        if (input[register].Kind != 0 && input[register] != state[register]) {
                            input[register] = default;
                            changed = true;
                        }
                    }
                }

                visited[successor] = true;
                if (changed)
                    pending.Enqueue(successor);
            }
        }

        var uses = new List<Use>();
        List<DictionaryContextSlotAccess> accesses = new();

        for (int i = 0; i < code.Length; ++i) {
            var instruction = code[i];
            if (!graph.Reachable[i])
                continue;

            int baseRegister = instruction.MemoryBase - Register.RAX;
            int destination = instruction.Op0Register - Register.RAX;
            if (instruction.Mnemonic == Mnemonic.Mov
                && instruction.Op0Kind == OpKind.Register
                && instruction.Op0Register.GetSize() == 8
                && (uint)destination < 16
                && instruction.Op1Kind == OpKind.Memory
                && instruction.MemorySize.GetSize() == 8
                && instruction.MemoryIndex == Register.None
                && instruction.SegmentPrefix is not (Register.FS or Register.GS)
                && (uint)baseRegister < 16
                && inputs[i * 16 + baseRegister].Kind == 1
                && instruction.MemoryDisplacement64 <= int.MaxValue
                && (instruction.MemoryDisplacement64 & 7) == 0) {
                GenericContextParameter source = parameter.Value;
                accesses.Add(new(graph.Owner, source.Register, source.Store, source.GcInfoRva,
                    instruction.IP, (uint)instruction.MemoryDisplacement64, destination));
            }

            if (instruction.FlowControl is not (FlowControl.Call or FlowControl.UnconditionalBranch)
                || instruction.Op0Kind != OpKind.NearBranch64)
                continue;

            if (parameters.TryGetValue(instruction.NearBranchTarget, out var target)) {
                var value = inputs[i * 16 + target.Register];
                if (value.Kind != 0)
                    uses.Add(new(instruction.IP, target.Target, value, default));
            }

            if (stubs.TryGetValue(instruction.NearBranchTarget, out var stub) && inputs[i * 16 + 8].Kind == 1)
                uses.Add(new(instruction.IP, 0, new(1, 0, 0), stub));
        }

        return new(graph, uses, accesses);
    }
}
