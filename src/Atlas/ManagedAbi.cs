using System.Runtime.InteropServices;
using Iced.Intel;

namespace Atlas;

public enum AbiStatus : byte {
    Unknown, Complete, NoEntrypoint, AsyncVariant, UnmanagedConvention, Varargs, UniversalCanonical, UnknownType, SharedTemplate,
    GenericDefinition, HiddenRecord, TraceIdentity
}

public enum AbiKind : byte {
    Unknown, Void, Integer, Float, Value, Reference, Pointer, ByReference, FunctionPointer, BoxedReference, Context, UnboxedReference
}

public enum AbiRole : byte { Parameter, This, GenericContext, Vararg }

public struct AbiValue {
    public int Signature, Binding;
    public uint Size;
    public AbiKind Kind;

    public readonly bool Indirect => Kind == AbiKind.Value && Size is not (1 or 2 or 4 or 8);
}

public struct AbiParameter {
    public AbiValue Value;
    public AbiRole Role;
    public int Slot;
}

public struct MethodAbi {
    public AbiStatus Status;
    public AbiValue Return;
    public IndexRange Parameters;
    public int ReturnSlot;
    public ulong UnboxedTarget;
    public int UnboxingLength;
}

public sealed class ManagedAbi {
    public readonly MethodAbi[] Methods;
    public readonly AbiParameter[] Parameters;
    public readonly int[] Owners;
    public readonly int RuntimeCount;

    public ManagedAbi(Extraction extraction) {
        int count = RuntimeCount = checked(extraction.Maps.Methods.Count + extraction.Generics.Methods.Count);
        Methods = new MethodAbi[checked(count + extraction.Traces.Methods.Count)];
        Owners = new int[Methods.Length];
        var signatures = extraction.Metadata.Signatures;
        int capacity = 0;
        for (int i = 0; i < count; ++i) {
            var entry = new MethodRecord(extraction, i);
            var signature = signatures.Methods[entry.Signature];
            bool hasThis = signature.NativeConvention ? (signature.CallingConvention & 2) == 0 : (signature.CallingConvention & 0x20) != 0;
            bool shared = false;
            if (entry.Dictionary != 0) {
                int templateIndex = extraction.Shared.Templates[i - extraction.Maps.Methods.Count];
                if (templateIndex > 0) {
                    ref readonly var template = ref CollectionsMarshal.AsSpan(extraction.Templates.Methods)[templateIndex - 1];
                    shared = template.Method.Entrypoint != 0 && !template.UniversalCanonical && !template.AsyncVariant && !entry.AsyncVariant;
                }
            }

            // Dictionary records describe concrete instantiations of a shared body
            // Keep this ABI distinct from an exact function entrypoint
            Methods[i].Status = shared ? AbiStatus.SharedTemplate : AbiStatus.Unknown;
            int parameters = checked(signature.Parameters.Count + signature.Varargs.Count + (hasThis ? 1 : 0)
                + (shared || (entry.Flags & 0x10) != 0 ? 1 : 0));
            Methods[i].Parameters = new IndexRange(capacity, parameters);
            capacity = checked(capacity + parameters);
        }
        var frameFlags = new Dictionary<ulong, byte>(extraction.Managed.Frames.Length);
        foreach (var frame in extraction.Managed.Frames) {
            if ((frame.Flags & 3) == 0) {
                frameFlags.Add(extraction.Image.ImageBase + extraction.Unwind.Entries[frame.Entry - 1].Function.Begin, frame.Flags);
            }
        }

        for (int i = count; i < Methods.Length; ++i) {
            var trace = extraction.Traces.Methods[i - count];
            var signature = signatures.Methods[trace.Signature];
            int parameters = checked(signature.Parameters.Count + ((signature.CallingConvention & 0x20) != 0 ? 1 : 0));
            Methods[i].Parameters = new IndexRange(capacity, parameters);
            capacity = checked(capacity + parameters);
        }

        Parameters = new AbiParameter[capacity];
        var reader = new ByteArrayCodeReader(extraction.Image.FileData);
        var decoder = Decoder.Create(64, reader);
        var unboxing = new Dictionary<ulong, (ulong Target, int Length)>();

        for (int i = 0; i < count; ++i) {
            var entry = new MethodRecord(extraction, i);
            var signature = signatures.Methods[entry.Signature];
            int owner = extraction.Types.Index[entry.DeclaringType] + 1;
            Owners[i] = owner;
            var ownerType = extraction.Types.Types[owner - 1];
            uint convention = signature.CallingConvention;
            bool hasThis = signature.NativeConvention ? (convention & 2) == 0 : (convention & 0x20) != 0;
            bool varargs = signature.Varargs.Count != 0 || (!signature.NativeConvention && (convention & 15) == 5);
            bool managed = signature.NativeConvention ? (convention & ~3U) == 0 : (convention & ~0x30U) == 0;

            ref var method = ref Methods[i];
            bool shared = method.Status == AbiStatus.SharedTemplate;
            method.Status = entry.Entrypoint == 0 && !shared ? AbiStatus.NoEntrypoint
                : entry.AsyncVariant ? AbiStatus.AsyncVariant
                : varargs ? AbiStatus.Varargs
                : !managed || (entry.Flags & 0x7000) != 0 ? AbiStatus.UnmanagedConvention
                : extraction.Header.Major <= 12 && (entry.Flags & 0x40) != 0 ? AbiStatus.UniversalCanonical
                : shared ? AbiStatus.SharedTemplate : AbiStatus.Complete;
            method.Return = Resolve(extraction, signature.ReturnType, owner, entry.Arguments);
            bool unboxingTemplate = false;
            if (shared) {
                int templateIndex = extraction.Shared.Templates[i - extraction.Maps.Methods.Count] - 1;
                unboxingTemplate = (extraction.Templates.Methods[templateIndex].Method.Flags & 2) != 0;
            }
            bool complete = method.Return.Kind != AbiKind.Unknown && (!unboxingTemplate || hasThis && ownerType.IsValueType);
            int cursor = method.Parameters.Start, slot = 0;

            if (hasThis) {
                // These maps name unboxing entrypoints for value receivers
                // Older template maps omit the flag while retaining that entrypoint
                var receiverKind = ownerType.IsValueType ? AbiKind.BoxedReference : AbiKind.Reference;
                Parameters[cursor++] = new AbiParameter {
                    Value = new AbiValue { Binding = owner, Size = 8, Kind = receiverKind },
                    Role = AbiRole.This,
                    Slot = slot++
                };
                complete &= ownerType.IsValueType || ownerType.ElementType is >= 0x14 and <= 0x18;
            }

            method.ReturnSlot = method.Return.Indirect ? slot++ : 0;
            if (shared || (entry.Flags & 0x10) != 0) {
                Parameters[cursor++] = new AbiParameter {
                    Value = new AbiValue { Kind = AbiKind.Context, Size = 8 },
                    Role = AbiRole.GenericContext,
                    Slot = slot++
                };
            }

            for (int kind = 0; kind < 2; ++kind) {
                var range = kind == 0 ? signature.Parameters : signature.Varargs;
                for (int j = range.Start; j < range.End; ++j) {
                    AbiValue value = Resolve(extraction, signatures.Edges[j], owner, entry.Arguments);
                    Parameters[cursor++] = new AbiParameter { Value = value, Role = kind == 0 ? AbiRole.Parameter : AbiRole.Vararg, Slot = slot++ };
                    complete &= value.Kind is not (AbiKind.Unknown or AbiKind.Void);
                }
            }

            if (!complete && method.Status is AbiStatus.Complete or AbiStatus.SharedTemplate)
                method.Status = AbiStatus.UnknownType;

            if (!shared && hasThis && ownerType.IsValueType && method.Status is AbiStatus.Complete or AbiStatus.UnknownType) {
                ref var thunk = ref CollectionsMarshal.GetValueRefOrAddDefault(unboxing, entry.Entrypoint, out bool known);
                if (!known)
                    thunk = ReadUnboxing(extraction.Image, reader, decoder, entry.Entrypoint);
                (method.UnboxedTarget, method.UnboxingLength) = thunk;
            }
        }

        for (int i = count; i < Methods.Length; ++i) {
            var trace = extraction.Traces.Methods[i - count];
            var signature = signatures.Methods[trace.Signature];
            int owner = Owners[i] = extraction.Fields.Bindings.Resolve(trace.DeclaringType);
            bool knownFrame = frameFlags.TryGetValue(trace.Entrypoint, out byte flags);
            ref var method = ref Methods[i];
            method.Status = trace.Hidden || trace.Signature == 0 ? AbiStatus.HiddenRecord
                : signature.GenericParameterCount != 0 || trace.TypeParameterNames.Count != 0 || trace.ParameterNames.Count != 0
                    ? AbiStatus.GenericDefinition
                : signature.Varargs.Count != 0 || (signature.CallingConvention & 15) == 5 ? AbiStatus.Varargs
                : signature.NativeConvention || (signature.CallingConvention & ~0x20U) != 0 || (flags & 8) != 0
                    ? AbiStatus.UnmanagedConvention
                : !knownFrame ? AbiStatus.Unknown
                : owner == 0 ? AbiStatus.UnknownType
                : extraction.Types.Types[owner - 1].Kind == 3 || extraction.Types.Types[owner - 1].IsGeneric ? AbiStatus.GenericDefinition
                : AbiStatus.Complete;
            if (method.Status != AbiStatus.Complete) {
                continue;
            }

            // StackTraceMethodMappingNode emits MethodEntrypoint without an unboxing stub
            // MetadataManager records the typical definition, so generic owners and methods cant establish its hidden ABI
            method.Return = Resolve(extraction, signature.ReturnType, owner, default);
            bool complete = method.Return.Kind != AbiKind.Unknown;
            int cursor = method.Parameters.Start, slot = 0;
            if ((signature.CallingConvention & 0x20) != 0) {
                var table = extraction.Types.Types[owner - 1];
                Parameters[cursor++] = new AbiParameter {
                    Value = new AbiValue { Binding = owner, Size = 8, Kind = table.IsValueType ? AbiKind.UnboxedReference : AbiKind.Reference },
                    Role = AbiRole.This,
                    Slot = slot++
                };
                complete &= table.IsValueType || table.ElementType is >= 0x14 and <= 0x18;
            }

            method.ReturnSlot = method.Return.Indirect ? slot++ : 0;
            for (int j = signature.Parameters.Start; j < signature.Parameters.End; ++j) {
                var value = Resolve(extraction, signatures.Edges[j], owner, default);
                Parameters[cursor++] = new AbiParameter { Value = value, Role = AbiRole.Parameter, Slot = slot++ };
                complete &= value.Kind is not (AbiKind.Unknown or AbiKind.Void);
            }

            if (!complete) {
                method.Status = AbiStatus.UnknownType;
            } else {
                // ObjectDataInterner can merge unrelated methods, and MetadataManager omits their duplicate trace records
                // This ABI belongs to the retained identity, not every caller
                method.Status = AbiStatus.TraceIdentity;
            }
        }
    }

    public static ReadOnlySpan<ulong> Arguments(Extraction extraction, int index) =>
        index < extraction.Maps.Methods.Count + extraction.Generics.Methods.Count ? new MethodRecord(extraction, index).Arguments : default;

    private static (ulong Target, int Length) ReadUnboxing(PeImage image, ByteArrayCodeReader reader, Decoder decoder, ulong entrypoint) {
        int index = image.FindSection(entrypoint);
        if (index < 0 || !image.Sections[index].Executable)
            return default;
        ref readonly var section = ref image.Sections[index];
        ulong offset = entrypoint - image.ImageBase - section.Rva;
        if (offset >= (ulong)section.FileSize)
            return default;

        reader.Position = section.FileOffset + (int)offset;
        decoder.IP = entrypoint;
        decoder.Decode(out var adjustment);
        // This exact adapter preserves every argument except the box pointer
        // Associated-data targets alone do not prove that: special stubs can also introduce a generic context argument
        if (adjustment.Code != Code.Add_rm64_imm8 || adjustment.Op0Kind != OpKind.Register
            || adjustment.Op0Register != Register.RCX || adjustment.Immediate8to64 != 8 || adjustment.HasLockPrefix)
            return default;

        decoder.Decode(out var branch);
        if (branch.Mnemonic != Mnemonic.Jmp || branch.Op0Kind != OpKind.NearBranch64
            || reader.Position > section.FileOffset + section.FileSize || !image.IsExecutable(branch.NearBranchTarget)
            || branch.NearBranchTarget == entrypoint)
            return default;

        return (branch.NearBranchTarget, checked((int)(branch.NextIP - entrypoint)));
    }

    public static AbiValue Resolve(Extraction extraction, int signature, int owner, ReadOnlySpan<ulong> arguments) {
        int binding = extraction.Fields.Bindings.Resolve(signature, owner, arguments);
        AbiValue value = new() { Signature = signature, Binding = binding };
        if (binding != 0) {
            ref readonly var table = ref CollectionsMarshal.AsSpan(extraction.Types.Types)[binding - 1];
            int element = table.ElementType;
            if (table.Kind == 3)
                return value;

            value.Kind = element switch {
                1 => AbiKind.Void,
                >= 2 and <= 13 => AbiKind.Integer,
                14 or 15 => AbiKind.Float,
                16 or 18 => AbiKind.Value,
                >= 20 and <= 24 => AbiKind.Reference,
                25 => AbiKind.ByReference,
                26 => AbiKind.Pointer,
                _ => table.Kind == 1 ? AbiKind.FunctionPointer : AbiKind.Unknown
            };
            value.Size = value.Kind switch {
                AbiKind.Integer or AbiKind.Float or AbiKind.Value => table.ValueSize,
                AbiKind.Reference or AbiKind.ByReference or AbiKind.Pointer or AbiKind.FunctionPointer => 8,
                _ => 0
            };
            if (value.Size == 0 && value.Kind != AbiKind.Void)
                value.Kind = AbiKind.Unknown;
            return value;
        }

        var nodes = CollectionsMarshal.AsSpan(extraction.Metadata.Signatures.Nodes);
        int current = signature;
        while (nodes[current].Kind == SignatureKind.Modified)
            current = nodes[current].Element;
        value.Kind = nodes[current].Kind switch {
            SignatureKind.Pointer => AbiKind.Pointer,
            SignatureKind.ByReference => AbiKind.ByReference,
            SignatureKind.FunctionPointer => AbiKind.FunctionPointer,
            SignatureKind.Array or SignatureKind.SzArray => AbiKind.Reference,
            _ => AbiKind.Unknown
        };
        if (value.Kind != AbiKind.Unknown)
            value.Size = 8;
        return value;
    }

    public bool Compatible(Extraction extraction, int left, int right) {
        ref readonly var first = ref Methods[left];
        ref readonly var second = ref Methods[right];
        if (first.Status != AbiStatus.Complete || second.Status != AbiStatus.Complete
            || first.Parameters.Count != second.Parameters.Count || first.ReturnSlot != second.ReturnSlot)
            return false;

        for (int i = -1; i < first.Parameters.Count; ++i) {
            var a = i == -1 ? first.Return : Parameters[first.Parameters.Start + i].Value;
            var b = i == -1 ? second.Return : Parameters[second.Parameters.Start + i].Value;
            if (a.Kind != b.Kind || a.Size != b.Size || a.Binding != b.Binding)
                return false;
            if (a.Binding == 0 && (a.Signature != b.Signature || (a.Signature != 0
                && (Owners[left] != Owners[right] || !Arguments(extraction, left).SequenceEqual(Arguments(extraction, right))))))
                return false;
            if (i != -1 && (Parameters[first.Parameters.Start + i].Slot != Parameters[second.Parameters.Start + i].Slot
                || Parameters[first.Parameters.Start + i].Role != Parameters[second.Parameters.Start + i].Role))
                return false;
        }

        return true;
    }

    public bool CompatibleTemplate(Extraction extraction, int index, in MethodTemplate template, bool unboxed = false) {
        var record = new MethodRecord(extraction, index);
        ref readonly var method = ref template.Method;
        if (Methods[index].Status != AbiStatus.Complete || template.UniversalCanonical || template.AsyncVariant
            || method.Entrypoint != (unboxed ? Methods[index].UnboxedTarget : record.Entrypoint) || method.Identity.Name != record.Name
            || method.Arguments.Count != record.Arguments.Length)
            return false;

        var bindings = extraction.Fields.Bindings;
        int owner = extraction.Types.Index[record.DeclaringType] + 1;
        if (bindings.Resolve(method.DeclaringType) != owner)
            return false;

        var signatures = extraction.Metadata.Signatures;
        for (int i = 0; i < record.Arguments.Length; ++i) {
            int argument = bindings.Resolve(signatures.Edges[method.Arguments.Start + i], owner);
            if (argument == 0 || extraction.Types.Types[argument - 1].Address != record.Arguments[i])
                return false;
        }

        var expected = signatures.Methods[record.Signature];
        var actual = signatures.Methods[method.Identity.Signature];
        bool hasThis = expected.NativeConvention ? (expected.CallingConvention & 2) == 0 : (expected.CallingConvention & 0x20) != 0;
        bool actualHasThis = actual.NativeConvention ? (actual.CallingConvention & 2) == 0 : (actual.CallingConvention & 0x20) != 0;
        bool managed = actual.NativeConvention ? (actual.CallingConvention & ~3U) == 0 : (actual.CallingConvention & ~0x30U) == 0;
        if (!managed || actualHasThis != hasThis || actual.GenericParameterCount != expected.GenericParameterCount
            || actual.Parameters.Count != expected.Parameters.Count || actual.Varargs.Count != 0
            || ((method.Flags & 2) != 0) != (!unboxed && hasThis && extraction.Types.Types[owner - 1].IsValueType))
            return false;

        // InvokeMap supplies the physical calling convention
        // A template can corroborate it only when the complete instantiated signature agrees
        for (int i = -1; i < actual.Parameters.Count; ++i) {
            int left = i < 0 ? expected.ReturnType : signatures.Edges[expected.Parameters.Start + i];
            int right = i < 0 ? actual.ReturnType : signatures.Edges[actual.Parameters.Start + i];
            var a = Resolve(extraction, left, owner, record.Arguments);
            var b = Resolve(extraction, right, owner, record.Arguments);
            if (a.Kind != b.Kind || a.Size != b.Size || a.Binding != b.Binding
                || (a.Binding == 0 && a.Signature != b.Signature))
                return false;
        }

        return true;
    }
}
