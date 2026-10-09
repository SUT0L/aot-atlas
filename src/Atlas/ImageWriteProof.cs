using System.Runtime.CompilerServices;
using Iced.Intel;

namespace Atlas;

// Each retained state describes one path. Bounded enumeration preserves the
// correlation between an induction value and the flags that terminate its loop.
internal static class ImageWriteProof {
    private const uint GeneralRegisters = 0xFFFF;
    private const uint StackPointerBit = 1U << 4;
    // Windows x64 integer arguments: RCX, RDX, R8 and R9.
    private const uint ArgumentRegisters = (1U << 1) | (1U << 2) | (1U << 8) | (1U << 9);
    // RBX, RSP, RBP, RSI, RDI and R12-R15 survive a call.
    private const uint CalleeSavedRegisters = 0xF0F8;
    private const uint ZeroFlagBit = 1U << 16;

    [InlineArray(16)]
    private struct RegisterValues {
        private ulong first;
    }

    private readonly record struct LivenessTransfer(
        uint Preserved,
        uint Required,
        uint ConditionalSources,
        uint DemandedOutputs);

    private struct State {
        internal RegisterValues Values;
        internal uint Known;
        internal uint Stack;
        internal byte Zero;
        // A backedge can place an earlier consumer invocation in this prefix.
        internal bool Consumed;
    }

    internal static bool MayWrite(MethodControlFlow graph, IReadOnlyList<bool> reachable, ulong address, int length,
        ulong consumer = 0, Func<ulong, bool>? callee = null, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        if (graph.Unknown)
            return true;

        int[] slots = new int[graph.Code.Length];
        int count = 0;

        for (int position = 0; position < graph.Code.Length; ++position) {
            if (reachable[position])
                slots[position] = count++;
        }

        State[] firstStates = new State[count];
        bool[] visited = new bool[count];
        List<State>?[] additionalStates = new List<State>?[count];
        Queue<(int Position, int State)> pending = new();
        State initial = new() { Known = StackPointerBit, Stack = StackPointerBit };
        int stateCount = 0;

        foreach (int root in graph.Roots) {
            if (!Enqueue(root, initial))
                return true;
        }

        InstructionInfoFactory factory = new();
        uint[] needed = new uint[graph.Code.Length];
        Span<LivenessTransfer> requirements = count <= 128
            ? stackalloc LivenessTransfer[count]
            : new LivenessTransfer[count];

        // Instruction effects stay fixed while successor demand converges.
        for (int position = 0; position < graph.Code.Length; ++position) {
            if ((position & 1023) == 0)
                cancellationToken.ThrowIfCancellationRequested();
            if (!reachable[position])
                continue;

            Instruction instruction = graph.Code[position];
            ref readonly InstructionInfo usage = ref factory.GetInfo(in instruction);
            uint preserved = GeneralRegisters | ZeroFlagBit;
            uint required = 0;
            uint conditionalSources = 0;
            uint demandedOutputs = 0;

            foreach (UsedRegister use in usage.GetUsedRegisters()) {
                int register = use.Register.GetFullRegister() - Register.RAX;
                if ((uint)register >= 16)
                    continue;

                if (use.Access is OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite)
                    preserved &= ~(1U << register);
                if (use.Access is OpAccess.Read or OpAccess.CondRead or OpAccess.ReadWrite or OpAccess.ReadCondWrite)
                    conditionalSources |= 1U << register;
            }

            int destination = instruction.Op0Register.GetFullRegister() - Register.RAX;
            bool registerValue = instruction.Op0Kind == OpKind.Register && (uint)destination < 16
                && instruction.Op0Register.GetSize() is 4 or 8;
            bool arithmetic = registerValue
                && (instruction.Mnemonic is Mnemonic.Add or Mnemonic.Sub && Immediate(instruction, out _)
                    || instruction.Mnemonic is Mnemonic.Inc or Mnemonic.Dec);
            bool copy = registerValue
                && (instruction.Mnemonic == Mnemonic.Mov && instruction.Op1Kind == OpKind.Register
                    || instruction.Mnemonic == Mnemonic.Lea && !instruction.IsIPRelativeMemoryOperand);

            if (copy || arithmetic)
                demandedOutputs |= 1U << destination;
            if (arithmetic || registerValue && instruction.Mnemonic is Mnemonic.Cmp or Mnemonic.Test)
                demandedOutputs |= ZeroFlagBit;
            if (instruction.RflagsModified != 0)
                preserved &= ~ZeroFlagBit;

            foreach (UsedMemory use in usage.GetUsedMemory()) {
                if (use.Access is not (OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite))
                    continue;

                int baseRegister = use.Base.GetFullRegister() - Register.RAX;
                int indexRegister = use.Index.GetFullRegister() - Register.RAX;
                if ((uint)baseRegister < 16)
                    required |= 1U << baseRegister;
                if ((uint)indexRegister < 16)
                    required |= 1U << indexRegister;

                int stored = StoredRegister(instruction);
                if ((uint)stored < 16)
                    required |= 1U << stored;
            }

            if (instruction.FlowControl is FlowControl.Call or FlowControl.IndirectCall) {
                preserved &= CalleeSavedRegisters;
                required &= CalleeSavedRegisters;
                required |= ArgumentRegisters;
            } else if (instruction.FlowControl == FlowControl.UnconditionalBranch && graph.Successors[position].Branch < 0) {
                required |= ArgumentRegisters;
            }

            if (instruction.Mnemonic is Mnemonic.Je or Mnemonic.Jne)
                required |= ZeroFlagBit;

            requirements[slots[position]] = new(preserved, required | StackPointerBit, conditionalSources, demandedOutputs);
        }

        bool changed;
        do {
            cancellationToken.ThrowIfCancellationRequested();
            changed = false;

            for (int position = graph.Code.Length - 1; position >= 0; --position) {
                if ((position & 1023) == 0)
                    cancellationToken.ThrowIfCancellationRequested();
                if (!reachable[position])
                    continue;

                uint future = Future(graph.Successors[position]);
                LivenessTransfer requirement = requirements[slots[position]];
                uint input = (future & requirement.Preserved) | requirement.Required;
                if ((future & requirement.DemandedOutputs) != 0)
                    input |= requirement.ConditionalSources;

                if (needed[position] != input) {
                    needed[position] = input;
                    changed = true;
                }
            }
        } while (changed);

        while (pending.TryDequeue(out (int Position, int State) item)) {
            cancellationToken.ThrowIfCancellationRequested();

            int position = item.Position;
            int slot = slots[position];
            State state = item.State == 0 ? firstStates[slot] : additionalStates[slot]![item.State - 1];
            Instruction instruction = graph.Code[position];
            ref readonly InstructionInfo usage = ref factory.GetInfo(in instruction);

            bool firstConsumer = instruction.IP == consumer && !state.Consumed;
            if (!firstConsumer && graph.Successors[position].Next < 0
                && instruction.FlowControl is FlowControl.Next or FlowControl.Call or FlowControl.IndirectCall or FlowControl.ConditionalBranch)
                return true;

            if (!firstConsumer && (instruction.FlowControl is FlowControl.Call or FlowControl.IndirectCall
                || instruction.FlowControl == FlowControl.UnconditionalBranch && graph.Successors[position].Branch < 0)) {
                if (instruction.Op0Kind != OpKind.NearBranch64 || callee is null || callee(instruction.NearBranchTarget))
                    return true;

                for (int register = 0; register < 16; ++register) {
                    if ((ArgumentRegisters & (1 << register)) == 0)
                        continue;

                    if ((state.Known & (1U << register)) != 0 && (state.Stack & (1U << register)) == 0
                        && state.Values[register] >= address && state.Values[register] - address < (ulong)length)
                        return true;
                }
            }

            foreach (UsedMemory use in usage.GetUsedMemory()) {
                if (use.Access is not (OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite))
                    continue;

                // A known protected pointer stored into memory can become a stack
                // argument or another writable alias without remaining in a register.
                int escaped = StoredRegister(instruction);
                if ((uint)escaped < 16 && (state.Known & (1U << escaped)) != 0
                    && (state.Stack & (1U << escaped)) == 0 && state.Values[escaped] >= address
                    && state.Values[escaped] - address < (ulong)length)
                    return true;

                int size = use.MemorySize.GetSize();
                if (size <= 0 || instruction.HasRepPrefix || instruction.HasRepnePrefix)
                    return true;

                if (!Location(state, use.Base, use.Index, use.Scale, use.Displacement, use.Segment, out ulong location, out bool stack))
                    return true;

                if (stack) {
                    // A frame-relative index or alias needs a bounded location inside
                    // the frame. Ordinary implicit/direct RSP accesses retain the ABI.
                    bool ordinary = use.Base == Register.RSP && use.Index == Register.None;
                    long offset = unchecked((long)location);
                    if (!ordinary && ((state.Stack & StackPointerBit) == 0
                        || offset < unchecked((long)state.Values[4])
                        || offset > 40 - size))
                        return true;
                } else if (location >= address ? location - address < (ulong)length
                    : address - location < (ulong)size) {
                    return true;
                }
            }

            int destination = instruction.Op0Register.GetFullRegister() - Register.RAX;
            int source = instruction.Op1Register.GetFullRegister() - Register.RAX;
            bool defined = false;
            bool stackValue = false;
            ulong value = 0;
            byte zero = 0;
            bool flags = false;
            int width = instruction.Op0Register.GetSize();

            if (instruction.Op0Kind == OpKind.Register && (uint)destination < 16 && width is 4 or 8) {
                if (instruction.Mnemonic == Mnemonic.Mov) {
                    if (instruction.Op1Kind == OpKind.Register && (uint)source < 16
                        && instruction.Op1Register.GetSize() == width && (state.Known & (1U << source)) != 0) {
                        defined = true;
                        value = state.Values[source];
                        stackValue = width == 8 && (state.Stack & (1U << source)) != 0;
                    } else {
                        defined = Immediate(instruction, out value);
                    }
                } else if (instruction.Mnemonic == Mnemonic.Lea && width == 8) {
                    if (instruction.IsIPRelativeMemoryOperand) {
                        defined = true;
                        value = instruction.IPRelativeMemoryAddress;
                    } else {
                        defined = Location(state, instruction.MemoryBase, instruction.MemoryIndex,
                            instruction.MemoryIndexScale, instruction.MemoryDisplacement64, Register.None, out value, out stackValue);
                    }
                } else if (instruction.Mnemonic == Mnemonic.Xor && instruction.Op1Kind == OpKind.Register
                    && instruction.Op1Register == instruction.Op0Register) {
                    defined = flags = true;
                    zero = 1;
                } else if (instruction.Mnemonic is Mnemonic.Add or Mnemonic.Sub
                    && (state.Known & (1U << destination)) != 0 && Immediate(instruction, out ulong increment)) {
                    defined = flags = true;
                    value = instruction.Mnemonic == Mnemonic.Add
                        ? unchecked(state.Values[destination] + increment)
                        : unchecked(state.Values[destination] - increment);
                    stackValue = width == 8 && (state.Stack & (1U << destination)) != 0;
                } else if (instruction.Mnemonic is Mnemonic.Inc or Mnemonic.Dec
                    && (state.Known & (1U << destination)) != 0) {
                    defined = flags = true;
                    value = instruction.Mnemonic == Mnemonic.Inc
                        ? unchecked(state.Values[destination] + 1)
                        : unchecked(state.Values[destination] - 1);
                    stackValue = width == 8 && (state.Stack & (1U << destination)) != 0;
                }

                if (defined && width == 4)
                    value = (uint)value;

                if (defined && flags && zero == 0 && !stackValue)
                    zero = value == 0 ? (byte)1 : (byte)2;

                if (stackValue && (unchecked((long)value) < -1_048_576 || unchecked((long)value) > 1_048_576))
                    defined = false;
            }

            if (instruction.Mnemonic is Mnemonic.Cmp or Mnemonic.Test
                && instruction.Op0Kind == OpKind.Register && width is 4 or 8 && (uint)destination < 16
                && (state.Known & (1U << destination)) != 0 && (state.Stack & (1U << destination)) == 0) {
                bool second = Immediate(instruction, out ulong right);

                if (!second && instruction.Op1Kind == OpKind.Register && (uint)source < 16
                    && (state.Known & (1U << source)) != 0 && (state.Stack & (1U << source)) == 0) {
                    second = true;
                    right = state.Values[source];
                }

                if (second) {
                    ulong left = state.Values[destination];
                    if (width == 4) {
                        left = (uint)left;
                        right = (uint)right;
                    }

                    flags = true;
                    bool equal = instruction.Mnemonic == Mnemonic.Cmp ? left == right : (left & right) == 0;
                    zero = equal ? (byte)1 : (byte)2;
                }
            }

            bool ordinaryStack = instruction.Mnemonic is Mnemonic.Push or Mnemonic.Pop
                && instruction.Op0Register.GetFullRegister() != Register.RSP;
            bool retainStack = (state.Stack & StackPointerBit) != 0;
            ulong nextStack = state.Values[4];

            if (ordinaryStack && retainStack)
                nextStack = unchecked(nextStack + (ulong)instruction.StackPointerIncrement);

            foreach (UsedRegister use in usage.GetUsedRegisters()) {
                if (use.Access is not (OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite))
                    continue;

                int register = use.Register.GetFullRegister() - Register.RAX;
                if ((uint)register < 16) {
                    state.Known &= ~(1U << register);
                    state.Stack &= ~(1U << register);
                }
            }

            if (defined) {
                state.Values[destination] = value;
                state.Known |= 1U << destination;
                if (stackValue)
                    state.Stack |= 1U << destination;
            }

            if (retainStack && (ordinaryStack || instruction.FlowControl is FlowControl.Call or FlowControl.IndirectCall)) {
                state.Values[4] = nextStack;
                state.Known |= StackPointerBit;
                state.Stack |= StackPointerBit;
            }

            if (instruction.FlowControl is FlowControl.Call or FlowControl.IndirectCall) {
                state.Known &= CalleeSavedRegisters;
                state.Stack &= state.Known;
                state.Zero = 0;
            } else if (instruction.RflagsModified != 0) {
                state.Zero = flags ? zero : (byte)0;
            }

            if (firstConsumer)
                state.Consumed = true;

            MethodSuccessors edges = graph.Successors[position];
            uint future = Future(edges);
            // Read-only iteration values die at their last relevant use. Forgetting
            // them cannot remove a write address or a forwarded call argument.
            state.Known &= future & GeneralRegisters;
            state.Stack &= state.Known;

            bool branch = true;
            bool next = true;

            if (instruction.Mnemonic is Mnemonic.Je or Mnemonic.Jne && state.Zero != 0) {
                branch = instruction.Mnemonic == Mnemonic.Je ? state.Zero == 1 : state.Zero == 2;
                next = !branch;
            }

            if (branch && instruction.FlowControl == FlowControl.ConditionalBranch
                && edges.Branch < 0 && instruction.Op0Kind == OpKind.NearBranch64
                && (instruction.NearBranchTarget < graph.Owner || instruction.NearBranchTarget >= graph.Code[^1].NextIP)
                && (callee is null || callee(instruction.NearBranchTarget)))
                return true;

            if ((future & ZeroFlagBit) == 0)
                state.Zero = 0;

            if (branch && edges.Branch >= 0 && !Enqueue(edges.Branch, state)
                || next && edges.Next >= 0 && !Enqueue(edges.Next, state))
                return true;
        }

        return false;

        uint Future(MethodSuccessors edges) {
            uint result = 0;
            if (edges.Branch >= 0 && reachable[edges.Branch])
                result |= needed[edges.Branch];
            if (edges.Next >= 0 && reachable[edges.Next])
                result |= needed[edges.Next];

            return result;
        }

        bool Enqueue(int position, State state) {
            if (!reachable[position])
                return true;

            int slot = slots[position];
            if (!visited[slot]) {
                if (++stateCount > 65536)
                    return false;

                visited[slot] = true;
                firstStates[slot] = state;
                pending.Enqueue((position, 0));

                return true;
            }

            if (Equal(firstStates[slot], state))
                return true;

            List<State> previous = additionalStates[slot] ??= new List<State>(2);
            foreach (State other in previous) {
                if (Equal(other, state))
                    return true;
            }

            if (previous.Count == 31 || ++stateCount > 65536)
                return false;

            previous.Add(state);
            pending.Enqueue((position, previous.Count));

            return true;
        }
    }

    private static bool Equal(in State left, in State right) {
        if (left.Known != right.Known || left.Stack != right.Stack || left.Zero != right.Zero || left.Consumed != right.Consumed)
            return false;

        for (int register = 0; register < 16; ++register) {
            if ((left.Known & (1U << register)) != 0 && left.Values[register] != right.Values[register])
                return false;
        }

        return true;
    }

    private static bool Immediate(in Instruction instruction, out ulong value) {
        value = instruction.Op1Kind switch {
            OpKind.Immediate8 => instruction.Immediate8,
            OpKind.Immediate32 => instruction.Immediate32,
            OpKind.Immediate64 => instruction.Immediate64,
            OpKind.Immediate8to64 => unchecked((ulong)instruction.Immediate8to64),
            OpKind.Immediate32to64 => unchecked((ulong)instruction.Immediate32to64),
            OpKind.Immediate8to32 => unchecked((uint)instruction.Immediate8to32),
            _ => 0
        };

        return instruction.Op1Kind is OpKind.Immediate8 or OpKind.Immediate32 or OpKind.Immediate64
            or OpKind.Immediate8to64 or OpKind.Immediate32to64 or OpKind.Immediate8to32;
    }

    private static int StoredRegister(in Instruction instruction) {
        if (instruction.Op0Kind == OpKind.Memory && instruction.Op1Kind == OpKind.Register
            && instruction.Op1Register.GetSize() == 8)
            return instruction.Op1Register.GetFullRegister() - Register.RAX;

        if (instruction.Mnemonic == Mnemonic.Push && instruction.Op0Kind == OpKind.Register
            && instruction.Op0Register.GetSize() == 8)
            return instruction.Op0Register.GetFullRegister() - Register.RAX;

        return instruction.Mnemonic == Mnemonic.Stosq ? 0 : -1;
    }

    private static bool Location(State state, Register baseRegister, Register indexRegister, int scale,
        ulong displacement, Register segment, out ulong value, out bool stack) {
        value = displacement;
        stack = false;
        if (segment is Register.FS or Register.GS)
            return false;

        if (baseRegister != Register.None) {
            int register = baseRegister.GetFullRegister() - Register.RAX;
            if (baseRegister.GetSize() != 8 || (uint)register >= 16 || (state.Known & (1U << register)) == 0)
                return false;

            value = unchecked(value + state.Values[register]);
            stack = (state.Stack & (1U << register)) != 0;
        }

        if (indexRegister != Register.None) {
            int register = indexRegister.GetFullRegister() - Register.RAX;
            if (indexRegister.GetSize() != 8 || (uint)register >= 16
                || (state.Known & (1U << register)) == 0 || (state.Stack & (1U << register)) != 0)
                return false;

            value = unchecked(value + state.Values[register] * (uint)scale);
        }

        return true;
    }
}
