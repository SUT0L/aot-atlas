using Iced.Intel;

namespace Atlas;

public enum PropertyAccessStatus { Unsupported, Exact, SignatureMismatch, HelperRequired }

public struct PropertyAccess {
    public PropertyAccessStatus Status;
    public ulong Body, Helper;
    public int Offset, Size, ReceiverAdjustment;
}

public sealed class PropertyAccessCode {
    private readonly PeImage image;
    private readonly ByteArrayCodeReader reader;
    private readonly Decoder decoder;

    public PropertyAccessCode(PeImage image) {
        this.image = image;
        reader = new ByteArrayCodeReader(image.FileData);
        decoder = Decoder.Create(64, reader);
    }

    public PropertyAccess Read(ulong entrypoint, bool setter, in AbiValue storage, bool byReference = false, ulong assignReference = 0) {
        PropertyAccess result = new() { Body = entrypoint };
        if (storage.Kind is AbiKind.Unknown or AbiKind.Void or AbiKind.Context || storage.Size == 0 || setter && byReference) {
            result.Status = PropertyAccessStatus.SignatureMismatch;
            return result;
        }
        Span<ulong> visited = stackalloc ulong[8];
        Span<Instruction> code = stackalloc Instruction[8];
        int count = 0;
        for (int hop = 0; hop < visited.Length; ++hop) {
            if (visited[..hop].Contains(result.Body))
                return result;
            visited[hop] = result.Body;
            int sectionIndex = image.FindSection(result.Body);
            if (sectionIndex < 0 || !image.Sections[sectionIndex].Executable)
                return result;
            var section = image.Sections[sectionIndex];
            ulong offset = result.Body - image.ImageBase - section.Rva;
            if (offset >= (ulong)section.FileSize)
                return result;
            reader.Position = section.FileOffset + (int)offset;
            decoder.IP = result.Body;
            count = 0;
            while (count < code.Length) {
                decoder.Decode(out var instruction);
                if (instruction.Code == Code.INVALID || reader.Position > section.FileOffset + section.FileSize
                    || instruction.HasLockPrefix || instruction.HasRepPrefix || instruction.HasRepnePrefix
                    || instruction.SegmentPrefix is Register.FS or Register.GS)
                    return result;
                code[count++] = instruction;
                if (instruction.FlowControl is FlowControl.Return or FlowControl.UnconditionalBranch or FlowControl.ConditionalBranch)
                    break;
            }
            int jump = count == 1 ? 0 : count == 2 && code[0].Code == Code.Add_rm64_imm8
                && code[0].Op0Kind == OpKind.Register && code[0].Op0Register == Register.RCX
                && code[0].Immediate8to64 == 8 && result.ReceiverAdjustment == 0 ? 1 : -1;
            if (jump >= 0 && code[jump].Code is Code.Jmp_rel8_64 or Code.Jmp_rel32_64) {
                if (jump != 0)
                    result.ReceiverAdjustment = 8;
                result.Body = code[jump].NearBranchTarget;
                continue;
            }
            break;
        }
        if (count == 0 || code[count - 1].Code != Code.Retnq)
            return result;

        int start = 0;
        if (byReference && count == 3 && code[0].Code == Code.Cmp_rm8_r8
            && Memory(code[0], Register.RCX, 0) && code[0].Op1Register == Register.CL)
            start = 1;
        ref readonly var first = ref code[start];
        int instructions = count - start;

        if (!setter && byReference && instructions == 2 && first.Code == Code.Lea_r64_m
            && first.Op0Register == Register.RAX && Memory(first, Register.RCX)) {
            result.Offset = (int)first.MemoryDisplacement64;
            result.Size = checked((int)storage.Size);
            result.Status = storage.Size != 0 ? PropertyAccessStatus.Exact : PropertyAccessStatus.SignatureMismatch;
            return result;
        }

        if (!setter && !byReference && instructions == 2 && first.Op0Kind == OpKind.Register
            && first.Op1Kind == OpKind.Memory && Memory(first, Register.RCX)) {
            bool integer = first.Mnemonic is Mnemonic.Mov or Mnemonic.Movsx or Mnemonic.Movzx
                && first.Op0Register is Register.EAX or Register.RAX;
            bool floating = first.Code is Code.Movss_xmm_xmmm32 or Code.Movsd_xmm_xmmm64
                && first.Op0Register == Register.XMM0;
            if (integer || floating) {
                result.Offset = (int)first.MemoryDisplacement64;
                result.Size = first.MemorySize.GetSize();
                result.Status = result.Size == storage.Size && floating == (storage.Kind == AbiKind.Float)
                    ? PropertyAccessStatus.Exact : PropertyAccessStatus.SignatureMismatch;
            }
            return result;
        }

        if (setter && !byReference && instructions == 2 && first.Op0Kind == OpKind.Memory
            && first.Op1Kind == OpKind.Register && Memory(first, Register.RCX)) {
            bool integer = first.Mnemonic == Mnemonic.Mov
                && first.Op1Register is Register.DL or Register.DX or Register.EDX or Register.RDX;
            bool floating = first.Code is Code.Movss_xmmm32_xmm or Code.Movsd_xmmm64_xmm
                && first.Op1Register == Register.XMM1;
            if (integer || floating) {
                result.Offset = (int)first.MemoryDisplacement64;
                result.Size = first.MemorySize.GetSize();
                result.Status = result.Size == storage.Size && floating == (storage.Kind == AbiKind.Float)
                    && !storage.Indirect ? PropertyAccessStatus.Exact : PropertyAccessStatus.SignatureMismatch;
            }
            return result;
        }

        if (!byReference && storage.Kind == AbiKind.Value && storage.Size == 16 && instructions is 3 or 4) {
            bool copy = first.Code == Code.Movups_xmm_xmmm128 && first.Op0Register == Register.XMM0
                && code[start + 1].Code == Code.Movups_xmmm128_xmm && code[start + 1].Op1Register == Register.XMM0;
            if (!setter && instructions == 4 && copy && Memory(first, Register.RCX)
                && Memory(code[start + 1], Register.RDX, 0) && code[start + 2].Code == Code.Mov_r64_rm64
                && code[start + 2].Op0Register == Register.RAX && code[start + 2].Op1Register == Register.RDX) {
                result.Offset = (int)first.MemoryDisplacement64;
                result.Size = 16;
                result.Status = PropertyAccessStatus.Exact;
            } else if (setter && instructions == 3 && copy && Memory(first, Register.RDX, 0)
                && Memory(code[start + 1], Register.RCX)) {
                result.Offset = (int)code[start + 1].MemoryDisplacement64;
                result.Size = 16;
                result.Status = PropertyAccessStatus.Exact;
            }
            return result;
        }

        if (setter && storage.Kind == AbiKind.Reference && storage.Size == 8 && instructions is 3 or 4
            && first.Code == Code.Lea_r64_m && first.Op0Register == Register.RCX && Memory(first, Register.RCX)
            && code[start + 1].Code == Code.Call_rel32_64
            && (instructions == 3 || code[start + 2].Mnemonic == Mnemonic.Nop)) {
            result.Offset = (int)first.MemoryDisplacement64;
            result.Size = 8;
            result.Helper = code[start + 1].NearBranchTarget;
            result.Status = assignReference != 0 && result.Helper == assignReference
                ? PropertyAccessStatus.Exact : PropertyAccessStatus.HelperRequired;
        }
        return result;
    }

    private static bool Memory(in Instruction instruction, Register receiver, int displacement = -1) =>
        instruction.MemoryBase == receiver && instruction.MemoryIndex == Register.None
        && instruction.MemoryDisplacement64 <= int.MaxValue
        && (displacement < 0 || instruction.MemoryDisplacement64 == (uint)displacement);
}
