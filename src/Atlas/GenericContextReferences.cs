using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Iced.Intel;

namespace Atlas;

public readonly record struct GenericContextParameter(ulong Target, int Register, ulong Store, uint GcInfoRva);
public readonly record struct GenericContextReference(ulong Instruction, ulong Target, ulong Context, int ParameterIndex,
    ImageValueUseEvidence Evidence = ImageValueUseEvidence.InstructionConstant);

public sealed class GenericContextReferences {
    [InlineArray(16)]
    private struct RegisterConstants {
        private ulong first;
    }

    private struct LiteralState {
        internal RegisterConstants Values;
        internal uint Known;
    }

    internal readonly List<GenericContextReference> Values = new();
    internal readonly List<ulong> UnresolvedControlFlowOwners = new();
    internal readonly GenericContextParameter[] Parameters;
    public ReadOnlySpan<GenericContextReference> ReferenceEntries => CollectionsMarshal.AsSpan(Values);
    public ReadOnlySpan<ulong> UnresolvedControlFlowAddresses => CollectionsMarshal.AsSpan(UnresolvedControlFlowOwners);
    public ReadOnlySpan<GenericContextParameter> ParameterEntries => Parameters;
    public readonly int DeclaredMethodContexts;

    public GenericContextReferences(
        PeImage image,
        UnwindTables unwind,
        MethodGcMap map,
        CancellationToken cancellationToken = default)
        : this(image, map, new MethodControlFlows(image, unwind, cancellationToken), cancellationToken) {
    }

    internal GenericContextReferences(
        PeImage image,
        MethodGcMap map,
        MethodControlFlows flows,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        var candidates = new Dictionary<ulong, GenericContextParameter?>();

        foreach (var method in map.Methods) {
            cancellationToken.ThrowIfCancellationRequested();

            if (method.Info is not { } info || (info.Flags & 0x30) != 0x20)
                continue;

            ++DeclaredMethodContexts;

            if (!flows.TryBytes(method, out _)) {
                UnresolvedControlFlowOwners.Add(image.ImageBase + method.Begin);
                continue;
            }

            if (!ReadParameter(image, method, out var parameter))
                continue;

            ref var candidate = ref CollectionsMarshal.GetValueRefOrAddDefault(
                candidates, parameter.Target, out bool present);

            if (!present)
                candidate = parameter;
            else if (candidate is { } previous && previous.Register != parameter.Register)
                candidate = null;
        }

        var parameters = new List<GenericContextParameter>(candidates.Count);
        var helpers = new Dictionary<ulong, int>(candidates.Count);

        foreach (var candidate in candidates.Values) {
            if (candidate is not { } parameter)
                continue;

            helpers.Add(parameter.Target, parameters.Count);
            parameters.Add(parameter);
        }

        Parameters = parameters.ToArray();
        if (helpers.Count == 0)
            return;

        var infoFactory = new InstructionInfoFactory();
        bool[] leaders = [];
        int[] blockForInstruction = [];
        var blockStarts = new List<int>();
        LiteralState[] blockInputs = [];
        bool[] blockVisited = [];
        var pending = new Queue<int>();

        foreach (var method in map.Methods) {
            cancellationToken.ThrowIfCancellationRequested();

            if (method.Info is null)
                continue;

            ulong start = image.ImageBase + method.Begin;
            if (!flows.TryBytes(method, out var bytes)) {
                UnresolvedControlFlowOwners.Add(start);
                continue;
            }

            if (!CallsHelper(bytes, start, helpers))
                continue;

            var graph = flows.Read(method);
            if (graph is null || graph.Unknown) {
                UnresolvedControlFlowOwners.Add(start);
                continue;
            }

            var instructions = graph.Code;
            if (leaders.Length < instructions.Length) {
                int capacity = Math.Max(instructions.Length, checked(leaders.Length * 2));
                leaders = new bool[capacity];
                blockForInstruction = new int[capacity];
            } else {
                leaders.AsSpan(0, instructions.Length).Clear();
            }

            foreach (int root in graph.Roots)
                leaders[root] = true;

            for (int position = 0; position < instructions.Length; ++position) {
                if ((position & 1023) == 0)
                    cancellationToken.ThrowIfCancellationRequested();

                if (!graph.Reachable[position])
                    continue;

                var edges = graph.Successors[position];
                if (edges.Branch >= 0)
                    leaders[edges.Branch] = true;
                if (instructions[position].FlowControl == FlowControl.ConditionalBranch && edges.Next >= 0)
                    leaders[edges.Next] = true;
            }

            blockStarts.Clear();
            for (int position = 0; position < instructions.Length; ++position) {
                if ((position & 1023) == 0)
                    cancellationToken.ThrowIfCancellationRequested();

                if (leaders[position])
                    blockStarts.Add(position);
                blockForInstruction[position] = blockStarts.Count - 1;
            }
            int blockCount = blockStarts.Count;
            blockStarts.Add(instructions.Length);

            if (blockInputs.Length < blockCount) {
                int capacity = Math.Max(blockCount, checked(blockInputs.Length * 2));
                blockInputs = new LiteralState[capacity];
                blockVisited = new bool[capacity];
            } else {
                blockVisited.AsSpan(0, blockCount).Clear();
            }

            // Each callable entry starts without a known incoming constant. A join
            // retains a value only when every incoming path establishes the same one.
            foreach (int root in graph.Roots) {
                int block = blockForInstruction[root];
                blockInputs[block] = default;
                blockVisited[block] = true;
                pending.Enqueue(block);
            }

            while (pending.TryDequeue(out int block)) {
                cancellationToken.ThrowIfCancellationRequested();

                var state = blockInputs[block];
                int last = blockStarts[block];
                for (int position = blockStarts[block]; position < blockStarts[block + 1]; ++position) {
                    if ((position & 1023) == 0)
                        cancellationToken.ThrowIfCancellationRequested();

                    ApplyLiteralInstruction(in instructions[position], ref state, infoFactory);
                    last = position;
                    if (graph.Successors[position].Next != position + 1)
                        break;
                }

                var successors = graph.Successors[last];
                for (int edge = 0; edge < 2; ++edge) {
                    int position = edge == 0 ? successors.Branch : successors.Next;
                    if (position < 0)
                        continue;

                    int successor = blockForInstruction[position];
                    bool changed = !blockVisited[successor];
                    ref var input = ref blockInputs[successor];
                    if (changed) {
                        input = state;
                    } else {
                        uint common = input.Known & state.Known;
                        for (int register = 0; register < 16; ++register) {
                            uint bit = 1U << register;
                            if ((common & bit) != 0 && input.Values[register] != state.Values[register])
                                common &= ~bit;
                        }

                        changed = common != input.Known;
                        input.Known = common;
                    }

                    blockVisited[successor] = true;
                    if (changed)
                        pending.Enqueue(successor);
                }
            }

            // Publish from stabilized inputs so a later backedge cannot invalidate
            // a context that has already been emitted.
            for (int block = 0; block < blockCount; ++block) {
                if (!blockVisited[block])
                    continue;

                var state = blockInputs[block];
                for (int position = blockStarts[block]; position < blockStarts[block + 1]; ++position) {
                    if ((position & 1023) == 0)
                        cancellationToken.ThrowIfCancellationRequested();

                    ref readonly var instruction = ref instructions[position];
                    if (instruction.FlowControl is FlowControl.Call or FlowControl.UnconditionalBranch
                        && instruction.Op0Kind == OpKind.NearBranch64
                        && helpers.TryGetValue(instruction.NearBranchTarget, out int parameterIndex)) {
                        int register = Parameters[parameterIndex].Register;
                        if ((state.Known & (1U << register)) != 0) {
                            ulong context = state.Values[register];
                            int sectionIndex = image.FindSection(context);
                            if ((context & 7) == 0 && sectionIndex >= 0 && !image.Sections[sectionIndex].Executable)
                                Values.Add(new GenericContextReference(
                                    instruction.IP, instruction.NearBranchTarget, context, parameterIndex));
                        }
                    }

                    ApplyLiteralInstruction(in instruction, ref state, infoFactory);
                    if (graph.Successors[position].Next != position + 1)
                        break;
                }
            }
        }
    }

    private static void ApplyLiteralInstruction(
        in Instruction instruction,
        ref LiteralState state,
        InstructionInfoFactory infoFactory) {
        ulong value = 0;
        bool defined = false;

        if (instruction.Op0Kind == OpKind.Register && instruction.Op0Register.GetSize() == 8) {
            if (instruction.Mnemonic == Mnemonic.Lea && instruction.IsIPRelativeMemoryOperand) {
                defined = true;
                value = instruction.IPRelativeMemoryAddress;
            } else if (instruction.Mnemonic == Mnemonic.Mov && instruction.Op1Kind == OpKind.Immediate64) {
                defined = true;
                value = instruction.Immediate64;
            } else if (instruction.Mnemonic == Mnemonic.Mov
                && instruction.Op1Kind == OpKind.Register
                && instruction.Op1Register.GetSize() == 8) {
                int source = instruction.Op1Register - Register.RAX;

                if ((uint)source < 16 && (state.Known & (1U << source)) != 0) {
                    defined = true;
                    value = state.Values[source];
                }
            }
        }

        ref readonly var info = ref infoFactory.GetInfo(in instruction);

        foreach (var use in info.GetUsedRegisters()) {
            if (use.Access is OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite) {
                int register = use.Register.GetFullRegister() - Register.RAX;

                if ((uint)register < 16)
                    state.Known &= ~(1U << register);
            }
        }

        int destination = instruction.Op0Register - Register.RAX;

        if (defined && (uint)destination < 16) {
            state.Values[destination] = value;
            state.Known |= 1U << destination;
        }

        if (instruction.FlowControl is FlowControl.Call or FlowControl.IndirectCall)
            state.Known = 0;
    }

    private static bool ReadParameter(
        PeImage image,
        in MethodGcEntry method,
        out GenericContextParameter parameter) {
        parameter = default;
        var info = method.Info!;
        int stackBase = info.StackBaseRegister < 0 ? 4 : info.StackBaseRegister;

        if (info.StackBaseRegister < -1 || stackBase >= 16)
            return false;

        ulong start = image.ImageBase + method.Begin;
        var file = image.FileRange(start);

        if (info.ValidRangeStart > file.Count || info.ValidRangeStart > info.CodeLength)
            return false;

        var reader = new ByteArrayCodeReader(image.FileData, file.Start, checked((int)info.ValidRangeStart));
        var decoder = Decoder.Create(64, reader, start);

        Span<int> origins = stackalloc int[16];
        origins.Clear();
        origins[1] = 2;
        origins[2] = 3;
        origins[8] = 9;
        origins[9] = 10;

        Span<long> stackOffsets = stackalloc long[16];
        stackOffsets.Clear();
        uint stackKnown = 1U << 4;

        var stores = new List<(long Offset, int Origin, ulong Instruction)>();
        var factory = new InstructionInfoFactory();

        while (reader.CanReadByte) {
            decoder.Decode(out var instruction);
            if (instruction.IsInvalid || instruction.FlowControl != FlowControl.Next)
                return false;

            int source = instruction.Op1Register - Register.RAX;
            int destination = instruction.Op0Register - Register.RAX;

            bool copied = instruction.Mnemonic == Mnemonic.Mov
                && instruction.Op0Kind == OpKind.Register
                && instruction.Op1Kind == OpKind.Register
                && instruction.Op0Register.GetSize() == 8
                && instruction.Op1Register.GetSize() == 8
                && (uint)source < 16;
            int origin = copied ? origins[source] : 0;
            bool defined = copied && (stackKnown & (1U << source)) != 0;
            long offset = defined ? stackOffsets[source] : 0;

            int baseRegister = instruction.MemoryBase - Register.RAX;
            if (instruction.Mnemonic == Mnemonic.Lea
                && instruction.Op0Register.GetSize() == 8
                && instruction.MemoryIndex == Register.None
                && (uint)baseRegister < 16
                && (stackKnown & (1U << baseRegister)) != 0) {
                defined = true;
                offset = checked(stackOffsets[baseRegister] + unchecked((long)instruction.MemoryDisplacement64));
            }

            if (instruction.Mnemonic is Mnemonic.Add or Mnemonic.Sub
                && (uint)destination < 16
                && instruction.Op0Register.GetSize() == 8
                && (stackKnown & (1U << destination)) != 0
                && instruction.Op1Kind is OpKind.Immediate8to64 or OpKind.Immediate32to64) {
                defined = true;
                long delta = instruction.Op1Kind == OpKind.Immediate8to64
                    ? instruction.Immediate8to64
                    : instruction.Immediate32to64;
                offset = instruction.Mnemonic == Mnemonic.Add
                    ? checked(stackOffsets[destination] + delta)
                    : checked(stackOffsets[destination] - delta);
            }

            bool ordinaryStack = instruction.Mnemonic == Mnemonic.Push
                || instruction.Mnemonic == Mnemonic.Pop
                    && instruction.Op0Register.GetFullRegister() != Register.RSP;
            bool savedStack = ordinaryStack && (stackKnown & (1U << 4)) != 0;
            long nextStack = savedStack ? checked(stackOffsets[4] + instruction.StackPointerIncrement) : 0;

            ref readonly var usage = ref factory.GetInfo(in instruction);

            foreach (var use in usage.GetUsedMemory()) {
                if (use.Access is not (OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite))
                    continue;

                int size = use.MemorySize.GetSize();
                if (size <= 0 || instruction.HasRepPrefix || instruction.HasRepnePrefix) {
                    stores.Clear();
                    continue;
                }

                int register = use.Base - Register.RAX;
                bool located = use.Index == Register.None
                    && (uint)register < 16
                    && (stackKnown & (1U << register)) != 0
                    && use.Segment is not (Register.FS or Register.GS);

                if (!located) {
                    stores.Clear();
                    continue;
                }

                long address = checked(stackOffsets[register] + unchecked((long)use.Displacement));

                for (int index = stores.Count - 1; index >= 0; --index) {
                    long previous = stores[index].Offset;

                    if (address >= previous ? address - previous < 8 : previous - address < size)
                        stores.RemoveAt(index);
                }

                if (instruction.Mnemonic == Mnemonic.Mov
                    && instruction.Op0Kind == OpKind.Memory
                    && instruction.Op1Kind == OpKind.Register
                    && instruction.Op1Register.GetSize() == 8
                    && (uint)source < 16
                    && origins[source] != 0
                    && size == 8)
                    stores.Add((address, origins[source], instruction.IP));
            }

            foreach (var use in usage.GetUsedRegisters()) {
                if (use.Access is OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite) {
                    int register = use.Register.GetFullRegister() - Register.RAX;

                    if ((uint)register < 16) {
                        origins[register] = 0;
                        stackKnown &= ~(1U << register);
                    }
                }
            }

            if ((uint)destination < 16) {
                if (copied)
                    origins[destination] = origin;

                if (defined) {
                    stackOffsets[destination] = offset;
                    stackKnown |= 1U << destination;
                }
            }

            if (savedStack) {
                stackOffsets[4] = nextStack;
                stackKnown |= 1U << 4;
            }
        }

        if ((stackKnown & (1U << stackBase)) == 0)
            return false;

        // The GC slot is relative to the final frame. An incoming argument must
        // still occupy those exact bytes after the complete prologue has executed.
        long slot = checked(stackOffsets[stackBase] + info.GenericContextSlot);

        foreach (var store in stores) {
            if (store.Offset == slot) {
                parameter = new(start, store.Origin - 1, store.Instruction, method.Address);
                return true;
            }
        }

        return false;
    }

    private static bool CallsHelper(ReadOnlySpan<byte> bytes, ulong start, Dictionary<ulong, int> helpers) {
        // A byte match selects a method to decode; only its reachable instructions
        // can establish a call and the corresponding declared context argument.
        for (int offset = 0; offset + 2 <= bytes.Length; ++offset) {
            byte opcode = bytes[offset];

            if (opcode != 0xEB && (opcode is not (0xE8 or 0xE9) || offset + 5 > bytes.Length))
                continue;

            int length = opcode == 0xEB ? 2 : 5;
            int displacement = opcode == 0xEB
                ? unchecked((sbyte)bytes[offset + 1])
                : BinaryPrimitives.ReadInt32LittleEndian(bytes[(offset + 1)..]);
            ulong target = unchecked(start + (ulong)(offset + length) + (ulong)displacement);

            if (helpers.ContainsKey(target))
                return true;
        }

        return false;
    }
}
