using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Iced.Intel;

namespace Atlas;

public enum RuntimeHelperStatus : byte {
    NoModuleArray,
    UnsupportedStartup,
    Ambiguous,
    Complete
}

public readonly record struct RuntimeHelper(ulong Address, ulong Cell, string Role);

public sealed class RuntimeHelpers {
    public readonly RuntimeHelperStatus Status;
    public readonly ulong ModuleArray;
    public readonly ulong Table;

    public readonly ulong Registration;
    public readonly ulong InitializeModules;

    public readonly ulong ArrayType;

    public readonly int TableCount;

    public readonly uint ManagedStart;
    public readonly uint ManagedLength;
    public readonly uint UnboxingStart;
    public readonly uint UnboxingLength;

    internal readonly RuntimeHelper[] Helpers = [];
    internal readonly CodeEdge[] StartupPath = [];
    public ReadOnlySpan<RuntimeHelper> HelperEntries => Helpers;
    public ReadOnlySpan<CodeEdge> StartupEdges => StartupPath;

    public RuntimeHelpers(Extraction extraction, CodeFlow code, CancellationToken cancellationToken = default)
        : this(
            extraction.Image,
            extraction.Header,
            extraction.Memory,
            extraction.Unwind,
            code.Addresses,
            cancellationToken) {
    }

    public RuntimeHelpers(PeImage image, ReadyToRun header, RuntimeMemory memory, UnwindTables unwind, CancellationToken cancellationToken = default)
        : this(image, header, memory, unwind, null, cancellationToken) {
    }

    private RuntimeHelpers(
        PeImage image,
        ReadyToRun rtr,
        RuntimeMemory memory,
        UnwindTables unwind,
        List<CodeEdge>? addressReferences,
        CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();

        rtr = rtr.ValidateSource(image);

        ulong header = 0;

        foreach (var section in image.Sections) {
            if (rtr.FileOffset >= section.FileOffset
                && rtr.FileOffset - section.FileOffset < section.FileSize)
                header = image.ImageBase + section.Rva + (uint)(rtr.FileOffset - section.FileOffset);
        }

        var modules = new HashSet<ulong>();

        foreach (var section in image.Sections) {
            if (section.Executable || section.Writable)
                continue;

            var bytes = image.FileData.AsSpan(section.FileOffset, section.FileSize);

            for (int offset = 8; offset + 16 <= bytes.Length; offset += 8) {
                if ((offset & 4095) == 8)
                    cancellationToken.ThrowIfCancellationRequested();

                if (BinaryPrimitives.ReadUInt64LittleEndian(bytes[offset..]) == header
                    && BinaryPrimitives.ReadUInt64LittleEndian(bytes[(offset - 8)..]) == 0
                    && BinaryPrimitives.ReadUInt64LittleEndian(bytes[(offset + 8)..]) == 0)
                    modules.Add(image.ImageBase + section.Rva + (uint)offset - 8);
            }
        }

        if (modules.Count == 0)
            return;

        Status = RuntimeHelperStatus.UnsupportedStartup;

        var ranges = new RuntimeFunction[unwind.DirectoryCount];

        for (int i = 0; i < ranges.Length; ++i)
            ranges[i] = unwind.Entries[i].Function;

        var candidates = new HashSet<int>();
        if (addressReferences is not null) {
            foreach (var edge in CollectionsMarshal.AsSpan(addressReferences)) {
                if (modules.Contains(edge.Target) || edge.Target >= 16 && modules.Contains(edge.Target - 16)) {
                    int owner = Owner(edge.Instruction, image.ImageBase, ranges);
                    if (owner >= 0)
                        candidates.Add(owner);
                }
            }
        } else {
            for (int index = 0; index < ranges.Length; ++index) {
                cancellationToken.ThrowIfCancellationRequested();

                var function = ranges[index];
                ulong begin = image.ImageBase + function.Begin;
                var file = image.FileRange(begin);
                int length = checked((int)(function.End - function.Begin));
                if (length > file.Count)
                    continue;

                var bytes = image.FileData.AsSpan(file.Start, length);

                // A byte match selects an owner. The complete instruction stream must prove registration.
                for (int offset = 0; offset + 6 <= bytes.Length; ++offset) {
                    if (bytes[offset] != 0x8D || (bytes[offset + 1] & 0xC7) != 5)
                        continue;

                    ulong target = unchecked((ulong)((long)begin + offset + 6
                        + BinaryPrimitives.ReadInt32LittleEndian(bytes[(offset + 2)..])));
                    if (modules.Contains(target) || target >= 16 && modules.Contains(target - 16)) {
                        candidates.Add(index);
                        break;
                    }
                }
            }
        }

        var records = new List<RegistrationRecord>();
        var flows = new MethodControlFlows(image, unwind, cancellationToken);

        foreach (int candidate in candidates) {
            cancellationToken.ThrowIfCancellationRequested();

            ReadRegistration(image, ranges[candidate], modules, flows, records);
        }

        if (records.Count == 0)
            return;

        if (records.Count != 1) {
            Status = RuntimeHelperStatus.Ambiguous;
            return;
        }

        var record = records[0];
        int tableSection = image.FindSection(record.Table);
        if (tableSection < 0
            || image.Sections[tableSection].Executable
            || image.Sections[tableSection].Writable)
            return;

        var tableRange = image.FileRange(record.Table);
        if (tableRange.Count < record.Count * 8)
            return;

        var tableBytes = image.FileData.AsSpan(tableRange.Start, record.Count * 8);
        Span<ulong> targets = stackalloc ulong[14];

        for (int slot = 0; slot < record.Count; ++slot) {
            ulong target = BinaryPrimitives.ReadUInt64LittleEndian(tableBytes[(slot * 8)..]);
            bool reserved = slot == 4 || (record.Count == 14
                ? slot == 2 || slot >= 10
                : slot >= 8);
            if (reserved ? target != 0 : !image.IsExecutable(target))
                return;

            targets[slot] = target;
        }

        var helperRange = image.FileRange(targets[5]);
        if (helperRange.Count < 8)
            return;

        var reader = new ByteArrayCodeReader(image.FileData, helperRange.Start, 8);
        var decoder = Decoder.Create(64, reader, targets[5]);
        decoder.Decode(out var helper);
        decoder.Decode(out var ret);
        if (helper.Mnemonic != Mnemonic.Lea
            || helper.Op0Register != Register.RAX
            || !helper.IsIPRelativeMemoryOperand
            || ret.Mnemonic != Mnemonic.Ret)
            return;

        int arrayRegion = memory.Find(helper.IPRelativeMemoryAddress);
        if (arrayRegion < 0)
            return;

        var arrayStorage = memory.Regions[arrayRegion];
        int arrayOffset = checked((int)(helper.IPRelativeMemoryAddress - arrayStorage.Start));
        if (arrayStorage.Data.Length - arrayOffset < 24
            || ((BinaryPrimitives.ReadUInt32LittleEndian(arrayStorage.Data.Span[arrayOffset..]) >> 26) & 31) != 0x16)
            return;

        int nt = BinaryPrimitives.ReadInt32LittleEndian(image.FileData.AsSpan(60));
        ulong entry = image.ImageBase + BinaryPrimitives.ReadUInt32LittleEndian(image.FileData.AsSpan(nt + 40));
        var path = Reachable(image, entry, record.Function, image.ImageBase, ranges, flows);
        if (path == null)
            return;

        string[] roles = [
            "GetRuntimeException",
            "FailFast",
            "ThreadEntryPoint",
            "AppendExceptionStackFrame",
            "",
            "GetSystemArrayEEType",
            "OnFirstChanceException",
            "OnUnhandledException",
            "IDynamicCastableIsInterfaceImplemented",
            "IDynamicCastableGetInterfaceImplementation"
        ];

        var helpers = new List<RuntimeHelper>(9);

        for (int slot = 0; slot < record.Count; ++slot) {
            if (targets[slot] != 0)
                helpers.Add(new RuntimeHelper(
                    targets[slot],
                    record.Table + (uint)slot * 8UL,
                    roles[slot]));
        }

        ModuleArray = record.Modules;
        Table = record.Table;
        TableCount = record.Count;

        ManagedStart = checked((uint)(record.Managed - image.ImageBase));
        ManagedLength = record.ManagedLength;
        UnboxingStart = checked((uint)(record.Unboxing - image.ImageBase));
        UnboxingLength = record.UnboxingLength;

        Registration = record.Instruction;
        InitializeModules = record.Target;

        ArrayType = helper.IPRelativeMemoryAddress;

        Helpers = helpers.ToArray();
        StartupPath = path;

        Status = RuntimeHelperStatus.Complete;
    }

    private readonly record struct RegistrationRecord(
        ulong Function,
        ulong Instruction,
        ulong Target,
        ulong Modules,
        ulong Table,
        int Count,
        ulong Managed,
        uint ManagedLength,
        ulong Unboxing,
        uint UnboxingLength);

    private static void ReadRegistration(
        PeImage image,
        RuntimeFunction range,
        HashSet<ulong> modules,
        MethodControlFlows flows,
        List<RegistrationRecord> records) {
        ulong begin = image.ImageBase + range.Begin;
        var graph = flows.Read(range.Begin, range.End);
        if (graph is null || graph.Unknown)
            return;

        var instructions = graph.Code;
        var reachable = graph.Reachable;
        var joins = graph.Joins;

        Span<ulong> constants = stackalloc ulong[16];

        Span<ulong> stack = stackalloc ulong[8];
        Span<byte> stackWidths = stackalloc byte[8];

        uint known = 0;
        uint stackKnown = 0;

        ulong osTable = 0;
        ulong managed = 0;
        ulong unboxing = 0;

        uint managedLength = 0;
        uint unboxingLength = 0;

        int osCount = 0;

        var factory = new InstructionInfoFactory();

        for (int position = 0; position < instructions.Length; ++position) {
            ref readonly var instruction = ref instructions[position];
            if (!reachable[position]) {
                known = stackKnown = 0;
                osTable = 0;
                continue;
            }

            // Discard incoming values at joins whose other predecessor has not been interpreted.
            if (joins.Contains(instruction.IP)) {
                known = stackKnown = 0;
                osTable = 0;
            }

            if (instruction.FlowControl == FlowControl.Call) {
                if ((stackKnown & 0x70) == 0x70
                    && stack[6] is 12 or 14
                    && stackWidths[5] == 8
                    && (known & 0x304) == 0x304
                    && constants[8] != 0
                    && stack[4] != 0
                    && image.IsExecutable(constants[2])
                    && constants[8] < image.ImageSize
                    && image.IsExecutable(constants[2] + constants[8] - 1)
                    && image.IsExecutable(constants[9])
                    && stack[4] < image.ImageSize
                    && image.IsExecutable(constants[9] + stack[4] - 1)) {
                    osTable = stack[5];
                    osCount = (int)stack[6];

                    managed = constants[2];
                    managedLength = (uint)constants[8];
                    unboxing = constants[9];
                    unboxingLength = (uint)stack[4];
                }

                if ((known & 0x304) == 0x304
                    && modules.Contains(constants[2])
                    && constants[8] == 2
                    && (stackKnown & 0x10) != 0
                    && stack[4] == (ulong)osCount
                    && constants[9] == osTable
                    && osTable != 0)
                    records.Add(new RegistrationRecord(
                        begin,
                        instruction.IP,
                        instruction.NearBranchTarget,
                        constants[2],
                        osTable,
                        osCount,
                        managed,
                        managedLength,
                        unboxing,
                        unboxingLength));

                known &= ~0xF07U;
                stackKnown = 0;

                continue;
            }

            if (instruction.FlowControl == FlowControl.IndirectCall) {
                known &= ~0xF07U;
                stackKnown = 0;
                osTable = 0;

                continue;
            }

            if (instruction.FlowControl is FlowControl.UnconditionalBranch or FlowControl.IndirectBranch
                or FlowControl.Return or FlowControl.Exception or FlowControl.Interrupt) {
                known = stackKnown = 0;
                osTable = 0;

                continue;
            }

            ulong value = 0;
            bool hasValue = false;

            if (instruction.Mnemonic == Mnemonic.Lea && instruction.IsIPRelativeMemoryOperand) {
                value = instruction.IPRelativeMemoryAddress;
                hasValue = true;
            } else if (instruction.Mnemonic == Mnemonic.Mov) {
                hasValue = Operand(in instruction, 1, constants, known, out value);
            } else if (instruction.Mnemonic == Mnemonic.Xor && instruction.Op0Kind == OpKind.Register
                && instruction.Op0Register == instruction.Op1Register) {
                hasValue = true;
            } else if (instruction.Mnemonic is Mnemonic.Sub or Mnemonic.Sar or Mnemonic.Shr
                && Operand(in instruction, 0, constants, known, out ulong left)
                && Operand(in instruction, 1, constants, known, out ulong right)) {
                if (instruction.Mnemonic == Mnemonic.Sub)
                    value = unchecked(left - right);
                else if (instruction.Mnemonic == Mnemonic.Shr)
                    value = instruction.Op0Register.GetSize() == 4 ? (uint)left >> (int)right : left >> (int)right;
                else
                    value = instruction.Op0Register.GetSize() == 4
                        ? unchecked((uint)((int)left >> (int)right))
                        : unchecked((ulong)((long)left >> (int)right));

                hasValue = true;
            }

            ref readonly var info = ref factory.GetInfo(in instruction);

            foreach (var memory in info.GetUsedMemory()) {
                if (memory.Access is not (OpAccess.Write
                    or OpAccess.CondWrite
                    or OpAccess.ReadWrite
                    or OpAccess.ReadCondWrite))
                    continue;

                int size = memory.MemorySize.GetSize();
                if (memory.Base != Register.RSP
                    || memory.Index != Register.None
                    || memory.Segment is Register.FS or Register.GS
                    || size <= 0
                    || instruction.HasRepPrefix
                    || instruction.HasRepnePrefix) {
                    stackKnown = 0;
                    continue;
                }

                long offset = unchecked((long)memory.Displacement);

                for (int index = 0; index < stack.Length; ++index) {
                    long slot = index * 8L;
                    bool overlaps = offset >= slot
                        ? (ulong)(offset - slot) < 8
                        : unchecked((ulong)(slot - offset)) < (uint)size;

                    if (overlaps)
                        stackKnown &= ~(1U << index);
                }
            }

            foreach (var use in info.GetUsedRegisters()) {
                if (use.Access is not (OpAccess.Write
                    or OpAccess.CondWrite
                    or OpAccess.ReadWrite
                    or OpAccess.ReadCondWrite))
                    continue;

                int register = (int)use.Register.GetFullRegister() - (int)Register.RAX;
                if ((uint)register < 16)
                    known &= ~(1U << register);

                if (use.Register.GetFullRegister() == Register.RSP)
                    stackKnown = 0;
            }

            if (instruction.Op0Kind == OpKind.Register
                && hasValue
                && instruction.Op0Register.GetSize() is 4 or 8) {
                int register = (int)instruction.Op0Register.GetFullRegister() - (int)Register.RAX;
                if ((uint)register < 16) {
                    constants[register] = instruction.Op0Register.GetSize() == 4 ? (uint)value : value;
                    known |= 1U << register;
                }
            } else if (instruction.Op0Kind == OpKind.Memory
                && instruction.MemoryBase == Register.RSP
                && instruction.MemoryIndex == Register.None
                && instruction.MemoryDisplacement64 < 64
                && instruction.MemoryDisplacement64 % 8 == 0) {
                int index = (int)(instruction.MemoryDisplacement64 / 8);
                stackKnown &= ~(1U << index);

                if (hasValue
                    && instruction.Mnemonic == Mnemonic.Mov
                    && instruction.SegmentPrefix is not (Register.FS or Register.GS)
                    && !instruction.HasRepPrefix
                    && !instruction.HasRepnePrefix
                    && instruction.MemorySize.GetSize() is 4 or 8) {
                    stack[index] = instruction.MemorySize.GetSize() == 4 ? (uint)value : value;
                    stackWidths[index] = (byte)instruction.MemorySize.GetSize();
                    stackKnown |= 1U << index;
                }
            }
        }
    }

    private static bool Operand(
        in Instruction instruction,
        int operand,
        ReadOnlySpan<ulong> values,
        uint known,
        out ulong value) {
        value = 0;

        if (instruction.GetOpKind(operand) == OpKind.Register) {
            Register register = instruction.GetOpRegister(operand);
            int index = (int)register.GetFullRegister() - (int)Register.RAX;
            if ((uint)index >= 16
                || (known & (1U << index)) == 0
                || register.GetSize() is not (4 or 8))
                return false;

            value = register.GetSize() == 4 ? (uint)values[index] : values[index];

            return true;
        }

        if (instruction.GetOpKind(operand) is not (OpKind.Immediate8
            or OpKind.Immediate16
            or OpKind.Immediate32
            or OpKind.Immediate64
            or OpKind.Immediate8to16
            or OpKind.Immediate8to32
            or OpKind.Immediate8to64
            or OpKind.Immediate32to64))
            return false;

        value = instruction.GetImmediate(operand);

        return true;
    }

    private static int Owner(ulong address, ulong imageBase, RuntimeFunction[] ranges) {
        if (address < imageBase || address - imageBase > uint.MaxValue)
            return -1;

        uint rva = (uint)(address - imageBase);
        int low = 0;
        int high = ranges.Length;

        while (low < high) {
            int middle = low + (high - low) / 2;
            if (ranges[middle].Begin <= rva)
                low = middle + 1;
            else
                high = middle;
        }

        return low != 0 && rva < ranges[low - 1].End ? low - 1 : -1;
    }

    private static CodeEdge[]? Reachable(
        PeImage image,
        ulong entry,
        ulong target,
        ulong imageBase,
        RuntimeFunction[] ranges,
        MethodControlFlows flows) {
        int root = Owner(entry, imageBase, ranges);
        int goal = Owner(target, imageBase, ranges);
        if (goal < 0)
            return null;

        if (root >= 0 && entry != imageBase + ranges[root].Begin)
            return null;

        List<CodeEdge>? entryThunks = null;
        HashSet<ulong>? thunkAddresses = null;

        while (root < 0) {
            if (!image.IsExecutable(entry))
                return null;

            thunkAddresses ??= new HashSet<ulong>();
            if (!thunkAddresses.Add(entry))
                return null;

            var file = image.FileRange(entry);
            var decoder = Decoder.Create(64,
                new ByteArrayCodeReader(image.FileData, file.Start, Math.Min(file.Count, 15)), entry);
            decoder.Decode(out var instruction);

            // Leaf tailcalls need no Windows unwind entry. A direct jump proves their successor.
            if (instruction.FlowControl != FlowControl.UnconditionalBranch
                || instruction.Op0Kind != OpKind.NearBranch64)
                return null;

            entryThunks ??= new List<CodeEdge>();
            entryThunks.Add(new CodeEdge(instruction.IP, instruction.NearBranchTarget));

            entry = instruction.NearBranchTarget;
            root = Owner(entry, imageBase, ranges);
            if (root >= 0 && entry != imageBase + ranges[root].Begin)
                return null;
        }

        int[] previous = new int[ranges.Length];
        ulong[] witnesses = new ulong[ranges.Length];

        var queue = new Queue<int>();

        queue.Enqueue(root);

        previous[root] = root + 1;

        while (previous[goal] == 0 && queue.TryDequeue(out int function)) {
            var range = ranges[function];
            var graph = flows.Read(range.Begin, range.End);
            if (graph is null)
                continue;

            var instructions = graph.Code;
            var reachable = graph.Reachable;

            for (int position = 0; position < instructions.Length; ++position) {
                ref readonly var instruction = ref instructions[position];
                if (!reachable[position]
                    || instruction.FlowControl is not (FlowControl.Call or FlowControl.UnconditionalBranch)
                    || instruction.Op0Kind != OpKind.NearBranch64)
                    continue;

                int next = Owner(instruction.NearBranchTarget, imageBase, ranges);
                if (next < 0
                    || instruction.NearBranchTarget != imageBase + ranges[next].Begin
                    || previous[next] != 0)
                    continue;

                previous[next] = function + 1;
                witnesses[next] = instruction.IP;

                queue.Enqueue(next);
            }
        }

        if (previous[goal] == 0)
            return null;

        var path = new List<CodeEdge>();

        for (int current = goal; current != root; current = previous[current] - 1)
            path.Add(new CodeEdge(witnesses[current], imageBase + ranges[current].Begin));

        path.Reverse();
        if (entryThunks != null)
            path.InsertRange(0, entryThunks);

        return path.ToArray();
    }
}
