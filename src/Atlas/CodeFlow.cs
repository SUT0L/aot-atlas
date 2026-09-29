using System.Runtime.InteropServices;
using Iced.Intel;

namespace Atlas;

public readonly record struct CodeEdge(ulong Instruction, ulong Target);
public readonly record struct DispatchCellUse(ulong Definition, ulong Instruction, ulong Cell, byte Register = 11);
public enum MemoryAccessKind : byte { None, Address, Read, Write, ReadWrite }
public readonly record struct ReceiverAccess(ulong Type, uint Offset, ulong Function, ulong Instruction, MemoryAccessKind Access, uint Size = 0);

[Flags]
public enum FieldTarget : byte { None, FieldMap = 1, GcDesc = 2, ObjectHeader = 4 }
public readonly record struct CodeFieldReference(int AccessIndex, IndexRange Fields, FieldTarget Evidence);

[Flags]
public enum MetadataTarget : byte {
    None, MethodTable = 1, FrozenString = 2, FrozenObject = 4, MethodDictionary = 8, NonGcStatics = 16
}
public readonly record struct CodeMetadataReference(ulong Instruction, ulong Target, MetadataTarget Evidence);

public sealed class CodeFlow {
    public readonly RuntimeCode Runtime;
    public readonly CodeContext Context;
    public readonly ulong[] Entrypoints;
    public readonly Dictionary<ulong, ulong> Receivers;
    public readonly List<CodeEdge> Calls = new(), Jumps = new(), Addresses = new();
    public readonly List<ReceiverAccess> ReceiverAccesses = new();
    public readonly List<CodeFieldReference> FieldReferences = new();
    public readonly List<int> FieldBindings = new();
    public readonly List<CodeMetadataReference> MetadataReferences = new();
    public readonly List<ulong> IndirectBranches = new();
    public readonly List<DispatchCellUse> DispatchCellUses = new();
    public int InstructionCount { get; private set; }

    public CodeFlow(Extraction extraction, ManagedAbi abi) {
        Runtime = new RuntimeCode(extraction);
        var entries = new List<ulong>(extraction.Unwind.DirectoryCount + extraction.Maps.Methods.Count + Runtime.Functions.Length);
        for (int i = 0; i < extraction.Unwind.DirectoryCount; ++i)
            entries.Add(extraction.Image.ImageBase + extraction.Unwind.Entries[i].Function.Begin);
        foreach (var function in Runtime.Functions)
            entries.Add(Runtime.Roles[function.Start].Target);

        Receivers = new Dictionary<ulong, ulong>();
        for (int i = 0; i < abi.RuntimeCount; ++i) {
            var record = new MethodRecord(extraction, i);
            if (record.InvokeStub != 0)
                Receivers[record.InvokeStub] = 0;
            if (record.Entrypoint == 0)
                continue;
            entries.Add(record.Entrypoint);
            ref readonly var method = ref abi.Methods[i];
            ulong receiver = 0;
            // The instance receiver precedes return buffers
            // Other unresolved signature types do not erase its separately proven RCX binding
            if (method.Status is AbiStatus.Complete or AbiStatus.UnknownType && method.Parameters.Count != 0) {
                ref readonly var parameter = ref abi.Parameters[method.Parameters.Start];
                if (parameter.Role == AbiRole.This && parameter.Slot == 0 && parameter.Value.Kind == AbiKind.Reference)
                    receiver = record.DeclaringType;
            }

            if (Receivers.TryGetValue(record.Entrypoint, out ulong previous) && previous != receiver)
                receiver = 0;
            Receivers[record.Entrypoint] = receiver;
        }

        // Other callable roles cant inherit a methods receiver contract
        foreach (ref readonly var item in CollectionsMarshal.AsSpan(extraction.Statics.Constructors)) {
            if (item.Entrypoint != 0) {
                entries.Add(item.Entrypoint);
                Receivers[item.Entrypoint] = 0;
            }
        }
        foreach (ref readonly var item in CollectionsMarshal.AsSpan(extraction.Marshalling.Structs)) {
            Receivers[item.ToNative] = 0;
            Receivers[item.ToManaged] = 0;
            Receivers[item.Cleanup] = 0;
        }
        foreach (ref readonly var item in CollectionsMarshal.AsSpan(extraction.Marshalling.Delegates)) {
            Receivers[item.Open] = 0;
            Receivers[item.Closed] = 0;
            Receivers[item.Create] = 0;
        }
        foreach (ref readonly var item in CollectionsMarshal.AsSpan(extraction.Templates.Methods))
            Receivers[item.Method.Entrypoint] = 0;
        foreach (ref readonly var trace in CollectionsMarshal.AsSpan(extraction.Traces.Methods)) {
            if (!Receivers.TryGetValue(trace.Entrypoint, out ulong receiver) || receiver == 0)
                continue;
            int owner = extraction.Fields.Bindings.Resolve(trace.DeclaringType);
            var signature = extraction.Metadata.Signatures.Methods[trace.Signature];
            bool hasThis = signature.NativeConvention ? (signature.CallingConvention & 2) == 0 : (signature.CallingConvention & 0x20) != 0;
            if (trace.Hidden || !hasThis || owner == 0 || extraction.Types.Types[owner - 1].Address != receiver)
                Receivers[trace.Entrypoint] = 0;
        }

        Entrypoints = entries.ToArray();
        Array.Sort(Entrypoints);
        Read(extraction.Image);

        int targetCapacity = checked(extraction.Types.Types.Count + extraction.Frozen.Objects.Count + abi.RuntimeCount
            + extraction.Statics.Constructors.Count + extraction.Statics.Generics.Count);
        var targets = new Dictionary<ulong, MetadataTarget>(targetCapacity);
        foreach (ref readonly var type in CollectionsMarshal.AsSpan(extraction.Types.Types))
            targets[type.Address] = MetadataTarget.MethodTable;
        foreach (ref readonly var item in CollectionsMarshal.AsSpan(extraction.Frozen.Objects))
            CollectionsMarshal.GetValueRefOrAddDefault(targets, extraction.Frozen.Start + (uint)item.Offset, out _)
                |= item.Kind == FrozenKind.String ? MetadataTarget.FrozenString : MetadataTarget.FrozenObject;
        for (int i = 0; i < abi.RuntimeCount; ++i) {
            ulong dictionary = new MethodRecord(extraction, i).Dictionary;
            if (dictionary != 0)
                CollectionsMarshal.GetValueRefOrAddDefault(targets, dictionary, out _) |= MetadataTarget.MethodDictionary;
        }
        foreach (ref readonly var item in CollectionsMarshal.AsSpan(extraction.Statics.Constructors))
            CollectionsMarshal.GetValueRefOrAddDefault(targets, item.NonGcBase, out _) |= MetadataTarget.NonGcStatics;
        foreach (ref readonly var item in CollectionsMarshal.AsSpan(extraction.Statics.Generics)) {
            if (item.NonGcBase != 0)
                CollectionsMarshal.GetValueRefOrAddDefault(targets, item.NonGcBase, out _) |= MetadataTarget.NonGcStatics;
        }

        MetadataReferences.EnsureCapacity(Addresses.Count);
        foreach (ref readonly var edge in CollectionsMarshal.AsSpan(Addresses)) {
            if (targets.TryGetValue(edge.Target, out var evidence))
                MetadataReferences.Add(new CodeMetadataReference(edge.Instruction, edge.Target, evidence));
        }

        BindFields(extraction);
        Context = new CodeContext(extraction, abi, this);
    }

    public CodeFlow(PeImage image, ReadOnlySpan<ulong> entrypoints, Dictionary<ulong, ulong> receivers) {
        Runtime = new RuntimeCode();
        Context = new CodeContext();
        Entrypoints = entrypoints.ToArray();
        Array.Sort(Entrypoints);
        Receivers = receivers;
        Read(image);
    }

    private void BindFields(Extraction extraction) {
        var layouts = extraction.Fields.Layouts;
        var gc = new IndexRange[layouts.Length];
        foreach (ref readonly var layout in CollectionsMarshal.AsSpan(extraction.Gc.Layouts)) {
            if (layout.RepeatStride == 0)
                gc[layout.TypeIndex] = layout.Runs;
        }

        FieldReferences.EnsureCapacity(ReceiverAccesses.Count);
        FieldBindings.EnsureCapacity(ReceiverAccesses.Count);
        for (int i = 0; i < ReceiverAccesses.Count; ++i) {
            ref readonly var access = ref CollectionsMarshal.AsSpan(ReceiverAccesses)[i];
            int type = extraction.Types.Index[access.Type];
            int first = FieldBindings.Count;
            for (int owner = type; owner >= 0; owner = layouts[owner].BaseType - 1) {
                var fields = extraction.Fields.Fields.AsSpan(layouts[owner].Fields.Start, layouts[owner].Fields.Count);
                int low = 0, high = fields.Length;
                while (low < high) {
                    int middle = low + (high - low) / 2;
                    if (fields[middle].Offset < access.Offset)
                        low = middle + 1;
                    else
                        high = middle;
                }
                for (int field = low; field < fields.Length && fields[field].Offset == access.Offset; ++field)
                    FieldBindings.Add(fields[field].FieldIndex);
            }

            var evidence = FieldBindings.Count != first ? FieldTarget.FieldMap : FieldTarget.None;
            foreach (ref readonly var run in CollectionsMarshal.AsSpan(extraction.Gc.Runs).Slice(gc[type].Start, gc[type].Count)) {
                if (access.Offset >= run.Offset && (access.Offset - run.Offset) / 8 < run.Count && (access.Offset - run.Offset) % 8 == 0) {
                    evidence |= FieldTarget.GcDesc;
                    break;
                }
            }
            if (access.Offset == 0)
                evidence |= FieldTarget.ObjectHeader;

            if (evidence != FieldTarget.None)
                FieldReferences.Add(new CodeFieldReference(i, new IndexRange(first, FieldBindings.Count - first), evidence));
        }
    }

    private void Read(PeImage image) {
        var readers = new ByteArrayCodeReader[image.Sections.Length];
        var decoders = new Decoder[image.Sections.Length];
        var visited = new uint[image.Sections.Length][];
        int codeBytes = 0;
        for (int i = 0; i < image.Sections.Length; ++i) {
            ref readonly var section = ref image.Sections[i];
            if (!section.Executable)
                continue;
            readers[i] = new ByteArrayCodeReader(image.FileData, section.FileOffset, section.FileSize);
            decoders[i] = Decoder.Create(64, readers[i]);
            visited[i] = new uint[(section.FileSize + 31L) / 32];
            codeBytes = checked(codeBytes + section.FileSize);
        }
        Calls.EnsureCapacity(codeBytes / 32);
        Jumps.EnsureCapacity(codeBytes / 64);
        Addresses.EnsureCapacity(codeBytes / 32);

        var pending = new List<ulong>(Entrypoints);
        var joins = new List<ulong>(Entrypoints);
        pending.Reverse();
        var infoFactory = new InstructionInfoFactory();
        Span<ulong> receivers = stackalloc ulong[16];
        Span<ulong> dispatchCells = stackalloc ulong[2], dispatchDefinitions = stackalloc ulong[2];
        while (pending.Count != 0) {
            ulong start = pending[^1];
            pending.RemoveAt(pending.Count - 1);
            int sectionIndex = image.FindSection(start);
            if (sectionIndex < 0 || !image.Sections[sectionIndex].Executable)
                continue;
            ref readonly var section = ref image.Sections[sectionIndex];
            ulong offset = start - image.ImageBase - section.Rva;
            if (offset >= (ulong)section.FileSize)
                continue;
            var reader = readers[sectionIndex];
            var decoder = decoders[sectionIndex];
            var seen = visited[sectionIndex];
            reader.Position = (int)offset;
            decoder.IP = start;
            receivers.Clear();
            Receivers.TryGetValue(start, out ulong initialReceiver);
            receivers[1] = initialReceiver;
            uint live = initialReceiver == 0 ? 0U : 2U;
            dispatchCells.Clear();

            while (reader.CanReadByte) {
                int position = reader.Position;
                uint bit = 1U << (position & 31);
                if ((seen[position >> 5] & bit) != 0)
                    break;
                decoder.Decode(out var instruction);
                if (instruction.IsInvalid)
                    break;
                seen[position >> 5] |= bit;
                ++InstructionCount;
                int dispatchRegister = instruction.MemoryBase - Register.R10;
                if ((uint)dispatchRegister < 2 && dispatchCells[dispatchRegister] != 0
                    && instruction.FlowControl is FlowControl.IndirectCall or FlowControl.IndirectBranch
                    && instruction.Op0Kind == OpKind.Memory
                    && instruction.MemoryIndex == Register.None && instruction.MemoryDisplacement64 == 0
                    && instruction.SegmentPrefix is not (Register.FS or Register.GS)) {
                    DispatchCellUses.Add(new DispatchCellUse(dispatchDefinitions[dispatchRegister], instruction.IP,
                        dispatchCells[dispatchRegister], (byte)(dispatchRegister + 10)));
                }
                if (instruction.Mnemonic == Mnemonic.Mov && instruction.Op1Kind == OpKind.Immediate64)
                    Addresses.Add(new CodeEdge(instruction.IP, instruction.Immediate64));

                bool dispatchLive = dispatchCells[0] != 0 || dispatchCells[1] != 0;
                if (live != 0 || dispatchLive || instruction.IsIPRelativeMemoryOperand) {
                    ref readonly var info = ref infoFactory.GetInfo(in instruction,
                        live != 0 || dispatchLive ? InstructionInfoOptions.None : InstructionInfoOptions.NoRegisterUsage);
                    if (dispatchLive) {
                        foreach (var register in info.GetUsedRegisters()) {
                            int index = register.Register.GetFullRegister() - Register.R10;
                            if ((uint)index < 2
                                && register.Access is OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite)
                                dispatchCells[index] = 0;
                        }
                    }
                    if (instruction.IsIPRelativeMemoryOperand) {
                        // LEA ignores segment bases
                        // Memory operations through FS/GS need runtime state; a NOPs displacement names no storage
                        bool used = false;
                        if (instruction.Mnemonic == Mnemonic.Lea || instruction.SegmentPrefix is not (Register.FS or Register.GS)) {
                            for (int operand = 0; operand < instruction.OpCount; ++operand)
                                used |= instruction.GetOpKind(operand) == OpKind.Memory && info.GetOpAccess(operand) != OpAccess.None;
                        }
                        if (used)
                            Addresses.Add(new CodeEdge(instruction.IP, instruction.IPRelativeMemoryAddress));
                    }

                    if (live != 0) {
                        int baseRegister = instruction.MemoryBase - Register.RAX;
                        if ((uint)baseRegister < 16 && receivers[baseRegister] != 0
                            && instruction.MemoryIndex == Register.None
                            && (instruction.Mnemonic == Mnemonic.Lea || instruction.SegmentPrefix is not (Register.FS or Register.GS))
                            && instruction.MemoryDisplacement64 < 0x80000000) {
                            var access = instruction.Mnemonic == Mnemonic.Lea ? MemoryAccessKind.Address : MemoryAccessKind.None;
                            uint size = 0;
                            foreach (var memory in info.GetUsedMemory()) {
                                // Stack effects belong to a separate memory operand
                                if (memory.Base != instruction.MemoryBase || memory.Index != Register.None
                                    || memory.Displacement != instruction.MemoryDisplacement64)
                                    continue;
                                access = memory.Access switch {
                                    OpAccess.Write or OpAccess.CondWrite => MemoryAccessKind.Write,
                                    OpAccess.ReadWrite or OpAccess.ReadCondWrite => MemoryAccessKind.ReadWrite,
                                    OpAccess.Read or OpAccess.CondRead => MemoryAccessKind.Read,
                                    _ => access
                                };
                                size = (uint)memory.MemorySize.GetSize();
                            }
                            if (access != MemoryAccessKind.None)
                                ReceiverAccesses.Add(new ReceiverAccess(receivers[baseRegister], (uint)instruction.MemoryDisplacement64,
                                    start, instruction.IP, access, size));
                        }

                        int source = instruction.Op1Register - Register.RAX, destination = instruction.Op0Register - Register.RAX;
                        ulong copied = instruction.Mnemonic == Mnemonic.Mov && instruction.Op0Kind == OpKind.Register
                            && instruction.Op1Kind == OpKind.Register && (uint)source < 16 && (uint)destination < 16 ? receivers[source] : 0;
                        foreach (var register in info.GetUsedRegisters()) {
                            if (register.Access is not (OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite))
                                continue;
                            int index = register.Register.GetFullRegister() - Register.RAX;
                            if ((uint)index < 16) {
                                receivers[index] = 0;
                                live &= ~(1U << index);
                            }
                        }
                        if (copied != 0) {
                            receivers[destination] = copied;
                            live |= 1U << destination;
                        }
                    }
                }

                int definedRegister = instruction.Op0Register - Register.R10;
                if (instruction.Mnemonic == Mnemonic.Lea && (uint)definedRegister < 2
                    && instruction.IsIPRelativeMemoryOperand) {
                    dispatchCells[definedRegister] = instruction.IPRelativeMemoryAddress;
                    dispatchDefinitions[definedRegister] = instruction.IP;
                }

                var flow = instruction.FlowControl;
                if (flow is FlowControl.Call or FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch) {
                    ulong target = instruction.NearBranchTarget;
                    int targetSection = image.FindSection(target);
                    if (targetSection >= 0 && image.Sections[targetSection].Executable
                        && target - image.ImageBase - image.Sections[targetSection].Rva < (ulong)image.Sections[targetSection].FileSize) {
                        pending.Add(target);
                        joins.Add(target);
                        if (flow == FlowControl.Call)
                            Calls.Add(new CodeEdge(instruction.IP, target));
                        else if (flow == FlowControl.UnconditionalBranch)
                            Jumps.Add(new CodeEdge(instruction.IP, target));
                    }
                }
                // Receiver identity does not cross calls or control-flow joins
                if (flow != FlowControl.Next) {
                    live = 0;
                    dispatchCells.Clear();
                }
                if (flow == FlowControl.IndirectBranch)
                    IndirectBranches.Add(instruction.IP);
                if (flow is not (FlowControl.Next or FlowControl.Call or FlowControl.IndirectCall or FlowControl.ConditionalBranch))
                    break;
            }
        }

        Calls.Sort(static (a, b) => a.Instruction.CompareTo(b.Instruction));
        Jumps.Sort(static (a, b) => a.Instruction.CompareTo(b.Instruction));
        Addresses.Sort(static (a, b) => a.Instruction.CompareTo(b.Instruction));
        ReceiverAccesses.Sort(static (a, b) => a.Instruction.CompareTo(b.Instruction));
        IndirectBranches.Sort();
        joins.Sort();
        int useCount = 0;
        for (int i = 0; i < DispatchCellUses.Count; ++i) {
            var use = DispatchCellUses[i];
            int join = joins.BinarySearch(use.Definition + 1);
            if (join < 0)
                join = ~join;
            if (join == joins.Count || joins[join] > use.Instruction)
                DispatchCellUses[useCount++] = use;
        }
        DispatchCellUses.RemoveRange(useCount, DispatchCellUses.Count - useCount);
        DispatchCellUses.Sort(static (left, right) => left.Instruction.CompareTo(right.Instruction));
    }
}
