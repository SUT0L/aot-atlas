using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Iced.Intel;

namespace Atlas;

public enum FunctionPointerContextKind : byte {
    Unknown,
    MethodTable,
    MethodDictionary
}

public enum FatPointerSource : byte {
    ClassConstructor,
    IndirectCall,
    DelegateInitializer,
    DictionarySlotDelegate
}

public readonly record struct FunctionPointerConsumer(ulong Target, int Register);
public readonly record struct FatFunctionPointer(
    ulong Pointer,
    ulong Descriptor,
    ulong Body,
    ulong Context,
    FunctionPointerContextKind ContextKind,
    uint GcInfoRva,
    bool Hydrated);

public readonly record struct FatFunctionPointerReference(
    int PointerIndex,
    FatPointerSource Source,
    ulong Owner,
    ulong Definition,
    ulong Consumer,
    ulong Holder,
    ulong ContextLoad,
    ImageValueUseEvidence Evidence = ImageValueUseEvidence.InitialImage);

public readonly record struct FunctionPointerFailure(FatPointerSource Source, ulong Witness, string Error);
public readonly record struct FunctionPointerUnprovenUse(FatFunctionPointerReference Reference, string Error);

// Sources establish managed function-pointer semantics before a descriptor enters the result.
// Literal and byte searches select code to inspect; plausible pointer pairs alone establish nothing.
public sealed class FatFunctionPointers {
    // These are anchored descriptor bytes in the initialized image. A consumer
    // uses that context only when its prefix and reachable callees preserve it.
    public IReadOnlyList<FatFunctionPointer> Values { get; }
    public IReadOnlyList<FatFunctionPointerReference> References { get; }
    public IReadOnlyList<FunctionPointerUnprovenUse> UnprovenUses { get; }
    public IReadOnlyList<FunctionPointerFailure> Failures { get; }
    public IReadOnlyList<ulong> UnresolvedControlFlowOwners { get; }
    public DictionarySlotConsumers? DictionaryConsumers { get; }
    public string ConstructorMapStatus { get; private set; } = "absent";

    private readonly PeImage image;
    private readonly ReadyToRun header;
    private readonly RuntimeMemory memory;

    private readonly Dictionary<ulong, MethodGcEntry> methods = new();
    private readonly HashSet<ulong> conflictedMethods = new();
    private readonly HashSet<ulong> bodyEntries = new();
    private readonly Dictionary<ulong, bool> typeValidation = new();

    private readonly Dictionary<ulong, FatFunctionPointer> candidates = new();
    private readonly Dictionary<ulong, int> indices = new();
    private readonly List<FatFunctionPointer> values = new();
    private readonly List<FatFunctionPointerReference> references = new();
    private readonly List<FunctionPointerUnprovenUse> unprovenUses = new();
    private readonly List<FunctionPointerFailure> failures = new();
    private readonly List<ulong> unresolved = new();

    private readonly Dictionary<ulong, Stub> stubs = new();
    private readonly CancellationToken cancellationToken;
    private readonly record struct Stub(ulong Pointer, ulong Definition, ulong Consumer);

    public FatFunctionPointers(
        PeImage image,
        ReadyToRun header,
        RuntimeMemory memory,
        UnwindTables? unwind,
        MethodGcMap? map,
        ReadOnlySpan<FunctionPointerConsumer> consumers = default,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        header = header.ValidateSource(image);

        this.image = image;
        this.header = header;
        this.memory = memory;
        this.cancellationToken = cancellationToken;

        if (map is not null) {
            foreach (var method in map.Methods) {
                cancellationToken.ThrowIfCancellationRequested();

                ulong target = image.ImageBase + method.Begin;
                bodyEntries.Add(target);
                if (!methods.TryAdd(target, method)
                    && ((methods[target].Info?.Flags ?? 0) & 0x30) != ((method.Info?.Flags ?? 0) & 0x30))
                    conflictedMethods.Add(target);
            }
        }

        if (unwind is not null) {
            for (int index = 0; index < unwind.DirectoryCount; ++index)
                bodyEntries.Add(image.ImageBase + unwind.Entries[index].Function.Begin);
        }

        ReadConstructors();

        if (unwind is not null && map is not null) {
            ReadStubs(consumers);

            MethodControlFlows flows = new(image, unwind, cancellationToken);
            ImageWriteClosure writes = new(image, flows, map, cancellationToken);
            ReadCode(flows, map, writes);
            DictionaryConsumers = new(image, memory, map, flows, consumers, writes, cancellationToken);

            foreach (var slot in DictionaryConsumers.DelegateSlots) {
                if ((slot.Pointer & 2) == 0)
                    continue;

                if (!TryDescriptor(slot.Pointer, out var descriptor)) {
                    failures.Add(new(
                        FatPointerSource.DictionarySlotDelegate,
                        slot.Slot,
                        "Invalid tagged descriptor in consumed dictionary slot."));
                    continue;
                }

                Add(descriptor, FatPointerSource.DictionarySlotDelegate, slot.Owner, slot.Load, slot.Consumer, slot.Slot, 0);
            }

            HashSet<DictionaryDelegateSlot> provenSlots = DictionaryConsumers.DelegateSlots
                .Select(slot => slot with { Evidence = ImageValueUseEvidence.InitialImage }).ToHashSet();
            foreach (DictionaryDelegateSlot slot in DictionaryConsumers.InitialDelegateSlots) {
                if (provenSlots.Contains(slot) || (slot.Pointer & 2) == 0 || !TryDescriptor(slot.Pointer, out FatFunctionPointer descriptor))
                    continue;

                Add(descriptor, FatPointerSource.DictionarySlotDelegate, slot.Owner, slot.Load, slot.Consumer, slot.Slot, 0,
                    initialOnly: true);
            }
        }

        Values = values.AsReadOnly();
        References = references.AsReadOnly();
        UnprovenUses = unprovenUses.AsReadOnly();
        Failures = failures.AsReadOnly();
        UnresolvedControlFlowOwners = unresolved.AsReadOnly();
    }

    private void ReadConstructors() {
        var section = header.Find(RtrSectionId.CctorContextMap);
        if (section.Length == 0)
            return;

        ConstructorMapStatus = "complete";

        try {
            var common = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
            var data = image.FileSpan(section.Start, checked((int)section.Length));
            var table = new NativeTable(data);

            while (table.MoveNext()) {
                cancellationToken.ThrowIfCancellationRequested();

                var reader = new NativeReader(data, table.Vertex);
                uint type = reader.Unsigned();
                uint location = reader.Unsigned();
                if (type >= common.Length
                    || location >= common.Length
                    || common[(int)type] == 0
                    || common[(int)location] < 8)
                    throw new InvalidDataException("Class constructor map refers outside CommonFixups or to null.");

                ulong holder = common[(int)location] - 8;
                ulong pointer = BinaryPrimitives.ReadUInt64LittleEndian(memory.Read(holder, 8));
                if ((pointer & 2) == 0)
                    continue;

                if (!TryDescriptor(pointer, out var descriptor)) {
                    failures.Add(new(
                        FatPointerSource.ClassConstructor,
                        holder,
                        "Invalid tagged class constructor descriptor."));
                    continue;
                }

                // A .cctor has no method instantiation. Its fat context is its owning constructed type.
                if (descriptor.Context != common[(int)type]
                    || descriptor.ContextKind == FunctionPointerContextKind.MethodDictionary
                    || !ValidType(descriptor.Context)) {
                    failures.Add(new(
                        FatPointerSource.ClassConstructor,
                        holder,
                        "Class constructor descriptor disagrees with its owning type."));
                    continue;
                }

                descriptor = descriptor with { ContextKind = FunctionPointerContextKind.MethodTable };
                Add(descriptor, FatPointerSource.ClassConstructor, common[(int)type], holder, holder, holder, 0);
            }
        } catch (Exception error) when (error is InvalidDataException or NotSupportedException or OverflowException) {
            ConstructorMapStatus = "partial";
            failures.Add(new(FatPointerSource.ClassConstructor, section.Start, error.Message));
        }
    }

    private bool ValidType(ulong address) {
        if (typeValidation.TryGetValue(address, out bool valid))
            return valid;

        try {
            var types = new MethodTables(4);
            types.Add(address, TypeEvidence.StaticConstructor);
            types.Read(image, header, memory);
            cancellationToken.ThrowIfCancellationRequested();
            valid = types.Types[0].Kind == 0 && types.Types[0].IsGeneric;
        } catch (Exception error) when (error is InvalidDataException or NotSupportedException or OverflowException) {
            valid = false;
        }

        typeValidation.Add(address, valid);

        return valid;
    }

    private bool TryDescriptor(ulong pointer, out FatFunctionPointer descriptor) {
        descriptor = default;
        if ((pointer & 7) != 2)
            return false;

        if (candidates.TryGetValue(pointer, out descriptor))
            return true;

        ulong address = pointer - 2;
        int section = image.FindSection(address);
        int region = memory.Find(address);
        if (section < 0 || image.Sections[section].Executable || region < 0)
            return false;

        var storage = memory.Regions[region];
        ulong offset = address - storage.Start;
        if (storage.Writable && !storage.Hydrated
            || offset > (ulong)storage.Data.Length
            || storage.Data.Length - (long)offset < 16)
            return false;

        var bytes = storage.Data.Span[(int)offset..];
        ulong body = BinaryPrimitives.ReadUInt64LittleEndian(bytes);
        ulong context = BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]);

        int contextSection = image.FindSection(context);
        if ((body & 3) != 0
            || !image.IsExecutable(body)
            || memory.Find(body) < 0
            || bodyEntries.Count != 0 && !bodyEntries.Contains(body)
            || (context & 7) != 0
            || contextSection < 0
            || image.Sections[contextSection].Executable
            || !image.IsMapped(context, 1))
            return false;

        FunctionPointerContextKind kind = FunctionPointerContextKind.Unknown;
        uint gcInfo = 0;

        if (!conflictedMethods.Contains(body)
            && methods.TryGetValue(body, out var method)
            && method.Info is { } info) {
            gcInfo = method.Address;
            kind = (info.Flags & 0x30) switch {
                0x10 => FunctionPointerContextKind.MethodTable,
                0x20 => FunctionPointerContextKind.MethodDictionary,
                _ => FunctionPointerContextKind.Unknown
            };
        }

        descriptor = new(pointer, address, body, context, kind, gcInfo, storage.Hydrated);
        candidates.Add(pointer, descriptor);

        return true;
    }

    private void Add(
        FatFunctionPointer descriptor,
        FatPointerSource source,
        ulong owner,
        ulong definition,
        ulong consumer,
        ulong holder,
        ulong contextLoad,
        bool initialOnly = false,
        ImageValueUseEvidence preservation = ImageValueUseEvidence.PreservedFromOwnerEntry) {
        // Method dictionary contents have no standalone size/layout grammar. Their role
        // follows the callee's GC declaration; a pointer's bytes cannot establish that role.
        if (descriptor.ContextKind == FunctionPointerContextKind.MethodTable && !ValidType(descriptor.Context)) {
            failures.Add(new(
                source,
                definition,
                "Function descriptor context disagrees with the callee's declared context role."));
            return;
        }

        if (!indices.TryGetValue(descriptor.Pointer, out int index)) {
            index = values.Count;
            indices.Add(descriptor.Pointer, index);
            values.Add(descriptor);
        }

        ImageValueUseEvidence evidence = initialOnly ? ImageValueUseEvidence.Unproven
            : source == FatPointerSource.ClassConstructor ? ImageValueUseEvidence.InitialImage
            : source == FatPointerSource.DictionarySlotDelegate ? ImageValueUseEvidence.PreservedFromRetainedRootEntries
            : preservation;
        FatFunctionPointerReference reference = new(index, source, owner, definition, consumer, holder, contextLoad, evidence);
        if (initialOnly)
            unprovenUses.Add(new(reference, "Descriptor bytes are not proven unchanged before this consumer."));
        else
            references.Add(reference);
    }

    private void ReadStubs(ReadOnlySpan<FunctionPointerConsumer> consumers) {
        if (consumers.IsEmpty)
            return;

        var targets = new HashSet<ulong>();

        foreach (var consumer in consumers) {
            cancellationToken.ThrowIfCancellationRequested();

            if (consumer.Register == 8)
                targets.Add(consumer.Target);
        }

        foreach (var section in image.Sections) {
            if (!section.Executable)
                continue;

            var bytes = image.FileData.AsSpan(section.FileOffset, section.FileSize);

            for (int offset = 0; offset + 7 <= bytes.Length; ++offset) {
                if ((offset & 4095) == 0)
                    cancellationToken.ThrowIfCancellationRequested();

                if (bytes[offset] != 0x4C || bytes[offset + 1] != 0x8D || bytes[offset + 2] != 0x05)
                    continue;

                ulong start = image.ImageBase + section.Rva + (uint)offset;
                ulong pointer = unchecked((ulong)((long)start + 7
                    + BinaryPrimitives.ReadInt32LittleEndian(bytes[(offset + 3)..])));
                if (!TryDescriptor(pointer, out _))
                    continue;

                var reader = new ByteArrayCodeReader(
                    image.FileData,
                    section.FileOffset + offset,
                    Math.Min(32, bytes.Length - offset));
                var decoder = Decoder.Create(64, reader, start);
                decoder.Decode(out var load);
                decoder.Decode(out var thunk);
                decoder.Decode(out var jump);

                if (load.Mnemonic == Mnemonic.Lea
                    && load.Op0Register == Register.R8
                    && load.IsIPRelativeMemoryOperand
                    && thunk.Mnemonic == Mnemonic.Lea
                    && thunk.Op0Register == Register.R9
                    && thunk.IsIPRelativeMemoryOperand
                    && image.IsExecutable(thunk.IPRelativeMemoryAddress)
                    && jump.FlowControl == FlowControl.UnconditionalBranch
                    && jump.Op0Kind == OpKind.NearBranch64
                    && targets.Contains(jump.NearBranchTarget))
                    stubs.TryAdd(start, new(pointer, load.IP, jump.IP));
            }
        }
    }

    private void ReadCode(MethodControlFlows flows, MethodGcMap map, ImageWriteClosure writes) {
        foreach (var method in map.Methods) {
            cancellationToken.ThrowIfCancellationRequested();

            if (method.Info is not { } info)
                continue;

            ulong start = image.ImageBase + method.Begin;
            if (!flows.TryBytes(method, out var bytes)) {
                unresolved.Add(start);
                continue;
            }

            if (!SelectCode(bytes, start))
                continue;

            var graph = flows.Read(method);
            if (graph is null || graph.Unknown) {
                unresolved.Add(start);
                continue;
            }

            var instructions = graph.Code;
            var reachable = graph.Reachable;
            var joins = graph.Joins;

            for (int position = 0; position < instructions.Length; ++position) {
                if ((position & 1023) == 0)
                    cancellationToken.ThrowIfCancellationRequested();

                if (!reachable[position])
                    continue;

                var instruction = instructions[position];
                if (instruction.FlowControl is FlowControl.Call or FlowControl.UnconditionalBranch
                    && instruction.Op0Kind == OpKind.NearBranch64
                    && stubs.TryGetValue(instruction.NearBranchTarget, out var stub)
                    && TryDescriptor(stub.Pointer, out var delegated))
                    Add(delegated, FatPointerSource.DelegateInitializer,
                        start, stub.Definition, stub.Consumer, instruction.IP, 0,
                        initialOnly: writes.MayWrite(graph, graph.Before(instruction.IP), delegated.Descriptor, 16, instruction.IP),
                        preservation: PreservationEvidence(graph, instruction.IP));

                if (TryLiteral(in instruction, out ulong pointer)
                    && TryDescriptor(pointer, out var descriptor)
                    && ReadIndirectCall(instructions, reachable, joins, position, out ulong call, out ulong contextLoad))
                    Add(descriptor, FatPointerSource.IndirectCall, start, instruction.IP, call, 0, contextLoad,
                        initialOnly: writes.MayWrite(graph, graph.Before(call), descriptor.Descriptor, 16, call),
                        preservation: PreservationEvidence(graph, call));
            }
        }
    }

    private static ImageValueUseEvidence PreservationEvidence(MethodControlFlow graph, ulong consumer) {
        IReadOnlyList<bool> before = graph.Before(consumer);
        foreach (int root in graph.Roots) {
            if (before[root] && graph.Code[root].IP != graph.Owner)
                return ImageValueUseEvidence.PreservedFromRetainedRootEntries;
        }

        return ImageValueUseEvidence.PreservedFromOwnerEntry;
    }

    private bool SelectCode(ReadOnlySpan<byte> bytes, ulong start) {
        for (int offset = 0; offset + 2 <= bytes.Length; ++offset) {
            byte value = bytes[offset];

            if (stubs.Count != 0 && (value == 0xEB
                || value is 0xE8 or 0xE9 && offset + 5 <= bytes.Length)) {
                int length = value == 0xEB ? 2 : 5;
                int displacement = value == 0xEB
                    ? unchecked((sbyte)bytes[offset + 1])
                    : BinaryPrimitives.ReadInt32LittleEndian(bytes[(offset + 1)..]);
                ulong target = unchecked(start + (ulong)(offset + length) + (ulong)displacement);

                if (stubs.ContainsKey(target))
                    return true;
            }

            if (offset + 7 <= bytes.Length
                && value is >= 0x48 and <= 0x4F
                && bytes[offset + 1] == 0x8D
                && (bytes[offset + 2] & 0xC7) == 5) {
                ulong pointer = unchecked((ulong)((long)start + offset + 7
                    + BinaryPrimitives.ReadInt32LittleEndian(bytes[(offset + 3)..])));
                if (TryDescriptor(pointer, out _))
                    return true;
            }

            if (offset + 10 <= bytes.Length
                && value is 0x48 or 0x49
                && bytes[offset + 1] is >= 0xB8 and <= 0xBF
                && TryDescriptor(BinaryPrimitives.ReadUInt64LittleEndian(bytes[(offset + 2)..]), out _))
                return true;
        }

        return false;
    }

    private static bool TryLiteral(in Instruction instruction, out ulong pointer) {
        pointer = 0;
        if (instruction.Op0Kind != OpKind.Register || instruction.Op0Register.GetSize() != 8)
            return false;

        if (instruction.Mnemonic == Mnemonic.Lea && instruction.IsIPRelativeMemoryOperand)
            pointer = instruction.IPRelativeMemoryAddress;
        else if (instruction.Mnemonic == Mnemonic.Mov && instruction.Op1Kind == OpKind.Immediate64)
            pointer = instruction.Immediate64;

        return pointer != 0;
    }

    private static bool ReadIndirectCall(
        ReadOnlySpan<Instruction> instructions,
        ReadOnlySpan<bool> reachable,
        IReadOnlySet<ulong> joins,
        int definition,
        out ulong call,
        out ulong contextLoad) {
        call = contextLoad = 0;
        if (definition + 3 >= instructions.Length)
            return false;

        var literal = instructions[definition];
        int pointer = literal.Op0Register - Register.RAX;

        var test = instructions[definition + 1];
        var branch = instructions[definition + 2];
        if ((uint)pointer >= 16
            || pointer == 4
            || test.Mnemonic != Mnemonic.Test
            || test.Op0Kind != OpKind.Register
            || test.Op0Register != Register.AL + (pointer < 4 ? pointer : pointer + 4)
            || test.Op1Kind != OpKind.Immediate8
            || test.Immediate8 != 2
            || branch.Mnemonic != Mnemonic.Je)
            return false;

        uint pointerRegisters = 1U << pointer;
        uint bodyRegisters = 0;
        uint contextRegisters = 0;

        var factory = new InstructionInfoFactory();

        for (int position = definition + 1;
            position < instructions.Length && position < definition + 19;
            ++position) {
            var instruction = instructions[position];
            if (!reachable[position] || joins.Contains(instruction.IP))
                return false;

            if (position <= definition + 2)
                continue;

            bool fromPointer = instruction.Op1Kind == OpKind.Memory
                && instruction.MemoryIndex == Register.None
                && instruction.SegmentPrefix is not (Register.FS or Register.GS)
                && (uint)(instruction.MemoryBase - Register.RAX) < 16
                && (pointerRegisters & (1U << (instruction.MemoryBase - Register.RAX))) != 0;

            if (instruction.Code == Code.Call_rm64
                && (contextRegisters & 0x306) != 0
                && (instruction.Op0Kind == OpKind.Memory
                    && instruction.MemoryIndex == Register.None
                    && instruction.SegmentPrefix is not (Register.FS or Register.GS)
                    && (uint)(instruction.MemoryBase - Register.RAX) < 16
                    && (pointerRegisters & (1U << (instruction.MemoryBase - Register.RAX))) != 0
                    && unchecked((long)instruction.MemoryDisplacement64) == -2
                    || instruction.Op0Kind == OpKind.Register
                        && (uint)(instruction.Op0Register - Register.RAX) < 16
                        && (bodyRegisters & (1U << (instruction.Op0Register - Register.RAX))) != 0)) {
                call = instruction.IP;
                return true;
            }

            if (instruction.FlowControl != FlowControl.Next)
                return false;

            ref readonly var usage = ref factory.GetInfo(in instruction);

            foreach (var use in usage.GetUsedMemory()) {
                if (use.Access is OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite)
                    return false;
            }

            int destination = instruction.Op0Register - Register.RAX;
            int source = instruction.Op1Register - Register.RAX;

            uint originPointer = 0;
            uint originBody = 0;
            uint originContext = 0;

            if (instruction.Mnemonic == Mnemonic.Mov
                && instruction.Op0Kind == OpKind.Register
                && instruction.Op0Register.GetSize() == 8) {
                if (fromPointer && instruction.MemorySize.GetSize() == 8) {
                    if (unchecked((long)instruction.MemoryDisplacement64) == -2)
                        originBody = 1;

                    if (instruction.MemoryDisplacement64 == 6) {
                        originContext = 1;
                        contextLoad = instruction.IP;
                    }
                } else if (instruction.Op1Kind == OpKind.Register
                    && instruction.Op1Register.GetSize() == 8
                    && (uint)source < 16) {
                    originPointer = (pointerRegisters >> source) & 1;
                    originBody = (bodyRegisters >> source) & 1;
                    originContext = (contextRegisters >> source) & 1;
                }
            }

            foreach (var use in usage.GetUsedRegisters()) {
                if (use.Access is OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite) {
                    int register = use.Register.GetFullRegister() - Register.RAX;
                    if ((uint)register < 16) {
                        pointerRegisters &= ~(1U << register);
                        bodyRegisters &= ~(1U << register);
                        contextRegisters &= ~(1U << register);
                    }
                }
            }

            if ((uint)destination < 16) {
                pointerRegisters |= originPointer << destination;
                bodyRegisters |= originBody << destination;
                contextRegisters |= originContext << destination;
            }
        }

        return false;
    }

}
