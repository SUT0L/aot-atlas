using System.Buffers;
using System.Buffers.Text;

namespace Atlas.Binja;

internal static class SymbolNames {
    internal static int Function(ReadOnlySpan<byte> full, ulong rva, Span<byte> output) {
        int first = full.IndexOf("::"u8);
        if (first < 0) {
            full.CopyTo(output);
            return full.Length;
        }

        ReadOnlySpan<byte> prefix = full[..first];
        ReadOnlySpan<byte> rest = full[(first + 2)..];
        int separator = rest.IndexOf("::"u8);
        ReadOnlySpan<byte> relation = separator < 0 ? default : rest[..separator];
        bool contextual = prefix.SequenceEqual("context"u8) && (
            relation.SequenceEqual("called_by"u8) || relation.SequenceEqual("calls"u8)
            || relation.SequenceEqual("funclet_of"u8) || relation.SequenceEqual("address_referenced_by"u8)
            || relation.SequenceEqual("between"u8) || relation.SequenceEqual("reference_path"u8));

        int length = Append(full[..first], 24, output);
        "::"u8.CopyTo(output[length..]);
        length += 2;
        if (contextual) {
            length += Append(relation, 24, output[length..]);
            rest = rest[(separator + 2)..];
            int address = rest.LastIndexOf("::"u8);
            if (address >= 0)
                rest = rest[..address];
            int depth = rest.LastIndexOf("::depth_"u8);
            if (depth >= 0)
                rest = rest[..depth];
            if (relation.SequenceEqual("between"u8))
                rest = default;
            else {
                "::"u8.CopyTo(output[length..]);
                length += 2;
            }
        }

        int last = rest.LastIndexOf("::"u8);
        if (last >= 0) {
            ReadOnlySpan<byte> owner = rest[..last];
            int ownerPrefix = owner.LastIndexOf("::"u8);
            if (ownerPrefix >= 0)
                owner = owner[(ownerPrefix + 2)..];
            int generic = owner.IndexOf((byte)'<');
            if (generic >= 0)
                owner = owner[..generic];
            owner = owner[(owner.LastIndexOf((byte)'.') + 1)..];
            length += Append(owner, 24, output[length..]);
            "::"u8.CopyTo(output[length..]);
            length += 2;
            rest = rest[(last + 2)..];
        } else {
            rest = rest[(rest.LastIndexOf((byte)'.') + 1)..];
        }
        length += Append(rest, 32, output[length..]);

        output[length++] = (byte)'_';
        Utf8Formatter.TryFormat(rva, output[length..], out int digits, new StandardFormat('X', 8));
        return length + digits;
    }

    private static int Append(ReadOnlySpan<byte> text, int limit, Span<byte> output) {
        int visible = Math.Min(text.Length, limit);
        while (visible < text.Length && (text[visible] & 0xC0) == 0x80)
            --visible;
        text[..visible].CopyTo(output);
        if (visible != text.Length) {
            "..."u8.CopyTo(output[visible..]);
            visible += 3;
        }
        return visible;
    }

    internal static bool IsDefault(ReadOnlySpan<byte> name, ulong address) {
        if (name.StartsWith("j_"u8))
            return true;
        if (!name.StartsWith("sub_"u8) && !name.StartsWith("data_"u8))
            return false;

        int prefix = name[0] == 's' ? 4 : 5;
        return Utf8Parser.TryParse(name[prefix..], out ulong value, out int consumed, 'x')
            && consumed == name.Length - prefix && value == address;
    }
}
