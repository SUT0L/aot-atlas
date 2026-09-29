using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Iced.Intel;

namespace Atlas;

public enum RuntimeHelperStatus : byte { NoModuleArray, UnsupportedStartup, Ambiguous, Complete }
public readonly record struct RuntimeHelper(ulong Address, ulong Cell, string Role);

public sealed class RuntimeHelpers {
    public readonly RuntimeHelperStatus Status;
    public readonly ulong ModuleArray, Table, Registration, InitializeModules, ArrayType;
    public readonly int TableCount;
    public readonly RuntimeHelper[] Helpers = [];
    public readonly CodeEdge[] StartupPath = [];

    public RuntimeHelpers(Extraction extraction, CodeFlow code) {
        var image = extraction.Image;
        ulong header = 0;
        foreach (var section in image.Sections) {
            if (extraction.Header.FileOffset >= section.FileOffset && extraction.Header.FileOffset - section.FileOffset < section.FileSize)
                header = image.ImageBase + section.Rva + (uint)(extraction.Header.FileOffset - section.FileOffset);
        }

        var modules = new HashSet<ulong>();
        foreach (var section in image.Sections) {
            if (section.Executable || section.Writable)
                continue;
            var bytes = image.FileData.AsSpan(section.FileOffset, section.FileSize);
            for (int offset = 8; offset + 16 <= bytes.Length; offset += 8) {
                if (BinaryPrimitives.ReadUInt64LittleEndian(bytes[offset..]) == header
                    && BinaryPrimitives.ReadUInt64LittleEndian(bytes[(offset - 8)..]) == 0
                    && BinaryPrimitives.ReadUInt64LittleEndian(bytes[(offset + 8)..]) == 0)
                    modules.Add(image.ImageBase + section.Rva + (uint)offset - 8);
            }
        }
        if (modules.Count == 0)
            return;
        Status = RuntimeHelperStatus.UnsupportedStartup;

        var ranges = new RuntimeFunction[extraction.Unwind.DirectoryCount];
        for (int i = 0; i < ranges.Length; ++i)
            ranges[i] = extraction.Unwind.Entries[i].Function;
        var candidates = new HashSet<int>();
        foreach (var edge in CollectionsMarshal.AsSpan(code.Addresses)) {
            if (modules.Contains(edge.Target) || edge.Target >= 16 && modules.Contains(edge.Target - 16)) {
                int owner = Owner(edge.Instruction, image.ImageBase, ranges);
                if (owner >= 0)
                    candidates.Add(owner);
            }
        }

        var records = new List<RegistrationRecord>();
        foreach (int candidate in candidates)
            ReadRegistration(image, ranges[candidate], modules, records);
        if (records.Count == 0)
            return;
        if (records.Count != 1) {
            Status = RuntimeHelperStatus.Ambiguous;
            return;
        }

        var record = records[0];
        int tableSection = image.FindSection(record.Table);
        if (tableSection < 0 || image.Sections[tableSection].Executable || image.Sections[tableSection].Writable)
            return;
        var tableRange = image.FileRange(record.Table);
        if (tableRange.Count < record.Count * 8)
            return;
        var tableBytes = image.FileData.AsSpan(tableRange.Start, record.Count * 8);
        Span<ulong> targets = stackalloc ulong[14];
        for (int slot = 0; slot < record.Count; ++slot) {
            ulong target = BinaryPrimitives.ReadUInt64LittleEndian(tableBytes[(slot * 8)..]);
            bool reserved = slot == 4 || (record.Count == 14 ? slot == 2 || slot >= 10 : slot >= 8);
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
        if (helper.Mnemonic != Mnemonic.Lea || helper.Op0Register != Register.RAX || !helper.IsIPRelativeMemoryOperand
            || ret.Mnemonic != Mnemonic.Ret || !extraction.Types.Index.TryGetValue(helper.IPRelativeMemoryAddress, out int array)
            || extraction.Types.Types[array].ElementType != 0x16)
            return;

        int nt = BinaryPrimitives.ReadInt32LittleEndian(image.FileData.AsSpan(60));
        ulong entry = image.ImageBase + BinaryPrimitives.ReadUInt32LittleEndian(image.FileData.AsSpan(nt + 40));
        var path = Reachable(entry, record.Function, image.ImageBase, ranges, code);
        if (path == null)
            return;

        string[] roles = ["GetRuntimeException", "FailFast", "ThreadEntryPoint", "AppendExceptionStackFrame", "", "GetSystemArrayEEType",
            "OnFirstChanceException", "OnUnhandledException", "IDynamicCastableIsInterfaceImplemented", "IDynamicCastableGetInterfaceImplementation"];
        var helpers = new List<RuntimeHelper>(9);
        for (int slot = 0; slot < record.Count; ++slot) {
            if (targets[slot] != 0)
                helpers.Add(new RuntimeHelper(targets[slot], record.Table + (uint)slot * 8UL, roles[slot]));
        }
        ModuleArray = record.Modules;
        Table = record.Table;
        TableCount = record.Count;
        Registration = record.Instruction;
        InitializeModules = record.Target;
        ArrayType = helper.IPRelativeMemoryAddress;
        Helpers = helpers.ToArray();
        StartupPath = path;
        Status = RuntimeHelperStatus.Complete;
    }

    private readonly record struct RegistrationRecord(ulong Function, ulong Instruction, ulong Target, ulong Modules, ulong Table, int Count);

    private static void ReadRegistration(PeImage image, RuntimeFunction range, HashSet<ulong> modules, List<RegistrationRecord> records) {
        ulong begin = image.ImageBase + range.Begin;
        var file = image.FileRange(begin);
        if (range.End - range.Begin > file.Count)
            return;
        var reader = new ByteArrayCodeReader(image.FileData, file.Start, (int)(range.End - range.Begin));
        var decoder = Decoder.Create(64, reader, begin);
        var instructions = new List<Instruction>();
        var joins = new HashSet<ulong>();
        while (reader.CanReadByte) {
            decoder.Decode(out var instruction);
            if (instruction.IsInvalid)
                return;
            instructions.Add(instruction);
            if (instruction.FlowControl is FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch)
                joins.Add(instruction.NearBranchTarget);
        }

        Span<ulong> constants = stackalloc ulong[16];
        Span<ulong> stack = stackalloc ulong[8];
        Span<byte> stackWidths = stackalloc byte[8];
        uint known = 0, stackKnown = 0;
        ulong osTable = 0;
        int osCount = 0;
        var factory = new InstructionInfoFactory();
        foreach (ref readonly var instruction in CollectionsMarshal.AsSpan(instructions)) {
            // A branchs other predecessor has not been interpreted
            // Discard its incoming values at the join instead of inheriting one path
            if (joins.Contains(instruction.IP)) {
                known = stackKnown = 0;
                osTable = 0;
            }
            if (instruction.FlowControl == FlowControl.Call) {
                if ((stackKnown & 0x70) == 0x70 && stack[6] is 12 or 14
                    && stackWidths[5] == 8
                    && (known & 0x304) == 0x304 && constants[8] != 0 && stack[4] != 0
                    && image.IsExecutable(constants[2]) && constants[8] < image.ImageSize
                    && image.IsExecutable(constants[2] + constants[8] - 1)
                    && image.IsExecutable(constants[9]) && stack[4] < image.ImageSize
                    && image.IsExecutable(constants[9] + stack[4] - 1)) {
                    osTable = stack[5];
                    osCount = (int)stack[6];
                }
                if ((known & 0x304) == 0x304 && modules.Contains(constants[2]) && constants[8] == 2
                    && (stackKnown & 0x10) != 0 && stack[4] == (ulong)osCount && constants[9] == osTable && osTable != 0)
                    records.Add(new RegistrationRecord(begin, instruction.IP, instruction.NearBranchTarget, constants[2], osTable, osCount));

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
            } else if (instruction.Mnemonic is Mnemonic.Sub or Mnemonic.Sar
                && Operand(in instruction, 0, constants, known, out ulong left)
                && Operand(in instruction, 1, constants, known, out ulong right)) {
                value = instruction.Mnemonic == Mnemonic.Sub ? unchecked(left - right)
                    : instruction.Op0Register.GetSize() == 4 ? unchecked((uint)((int)left >> (int)right))
                    : unchecked((ulong)((long)left >> (int)right));
                hasValue = true;
            }

            ref readonly var info = ref factory.GetInfo(in instruction);
            foreach (var memory in info.GetUsedMemory()) {
                if (memory.Access is not (OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite))
                    continue;
                if (memory.Base != Register.RSP || memory.Index != Register.None) {
                    stackKnown = 0;
                    continue;
                }
                ulong offset = memory.Displacement;
                int size = memory.MemorySize.GetSize();
                for (int index = 0; index < stack.Length; ++index) {
                    if (offset < (uint)(index + 1) * 8 && offset + (uint)size > (uint)index * 8)
                        stackKnown &= ~(1U << index);
                }
            }
            foreach (var use in info.GetUsedRegisters()) {
                if (use.Access is not (OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite))
                    continue;
                int register = (int)use.Register.GetFullRegister() - (int)Register.RAX;
                if ((uint)register < 16)
                    known &= ~(1U << register);
                if (use.Register.GetFullRegister() == Register.RSP)
                    stackKnown = 0;
            }
            if (instruction.Op0Kind == OpKind.Register && hasValue && instruction.Op0Register.GetSize() is 4 or 8) {
                int register = (int)instruction.Op0Register.GetFullRegister() - (int)Register.RAX;
                if ((uint)register < 16) {
                    constants[register] = instruction.Op0Register.GetSize() == 4 ? (uint)value : value;
                    known |= 1U << register;
                }
            } else if (instruction.Op0Kind == OpKind.Memory && instruction.MemoryBase == Register.RSP && instruction.MemoryIndex == Register.None
                && instruction.MemoryDisplacement64 < 64 && instruction.MemoryDisplacement64 % 8 == 0) {
                int index = (int)(instruction.MemoryDisplacement64 / 8);
                stackKnown &= ~(1U << index);
                if (hasValue && instruction.Mnemonic == Mnemonic.Mov && instruction.MemorySize.GetSize() is 4 or 8) {
                    stack[index] = instruction.MemorySize.GetSize() == 4 ? (uint)value : value;
                    stackWidths[index] = (byte)instruction.MemorySize.GetSize();
                    stackKnown |= 1U << index;
                }
            }
        }
    }

    private static bool Operand(in Instruction instruction, int operand, ReadOnlySpan<ulong> values, uint known, out ulong value) {
        value = 0;
        if (instruction.GetOpKind(operand) == OpKind.Register) {
            Register register = instruction.GetOpRegister(operand);
            int index = (int)register.GetFullRegister() - (int)Register.RAX;
            if ((uint)index >= 16 || (known & (1U << index)) == 0 || register.GetSize() is not (4 or 8))
                return false;
            value = register.GetSize() == 4 ? (uint)values[index] : values[index];
            return true;
        }
        if (instruction.GetOpKind(operand) is not (OpKind.Immediate8 or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate64
            or OpKind.Immediate8to16 or OpKind.Immediate8to32 or OpKind.Immediate8to64 or OpKind.Immediate32to64))
            return false;
        value = instruction.GetImmediate(operand);
        return true;
    }

    private static int Owner(ulong address, ulong imageBase, RuntimeFunction[] ranges) {
        if (address < imageBase || address - imageBase > uint.MaxValue)
            return -1;
        uint rva = (uint)(address - imageBase);
        int low = 0, high = ranges.Length;
        while (low < high) {
            int middle = low + (high - low) / 2;
            if (ranges[middle].Begin <= rva)
                low = middle + 1;
            else
                high = middle;
        }
        return low != 0 && rva < ranges[low - 1].End ? low - 1 : -1;
    }

    private static CodeEdge[]? Reachable(ulong entry, ulong target, ulong imageBase, RuntimeFunction[] ranges, CodeFlow code) {
        int root = Owner(entry, imageBase, ranges), goal = Owner(target, imageBase, ranges);
        if (root < 0 || goal < 0)
            return null;
        int[] previous = new int[ranges.Length];
        ulong[] witnesses = new ulong[ranges.Length];
        var queue = new Queue<int>();
        queue.Enqueue(root);
        previous[root] = root + 1;
        while (previous[goal] == 0 && queue.TryDequeue(out int function)) {
            ulong start = imageBase + ranges[function].Begin, end = imageBase + ranges[function].End;
            for (int kind = 0; kind < 2; ++kind) {
                var edges = CollectionsMarshal.AsSpan(kind == 0 ? code.Calls : code.Jumps);
                int low = 0, high = edges.Length;
                while (low < high) {
                    int middle = low + (high - low) / 2;
                    if (edges[middle].Instruction < start)
                        low = middle + 1;
                    else
                        high = middle;
                }
                for (int i = low; i < edges.Length && edges[i].Instruction < end; ++i) {
                    int next = Owner(edges[i].Target, imageBase, ranges);
                    if (next < 0 || previous[next] != 0)
                        continue;
                    previous[next] = function + 1;
                    witnesses[next] = edges[i].Instruction;
                    queue.Enqueue(next);
                }
            }
        }
        if (previous[goal] == 0)
            return null;
        var path = new List<CodeEdge>();
        for (int current = goal; current != root; current = previous[current] - 1)
            path.Add(new CodeEdge(witnesses[current], imageBase + ranges[current].Begin));
        path.Reverse();
        return path.ToArray();
    }
}
