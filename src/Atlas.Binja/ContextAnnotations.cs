using System.Text;
using System.Text.Unicode;

namespace Atlas.Binja;

internal static unsafe class ContextAnnotations {
    internal static void Apply(Symbols symbols, TagOwnership ownership, nint view, PeImage image, CodeContext context, ref ApplyStats stats, nint task) {
        if (context.Count == 0)
            return;

        nint platform = Core.BNGetDefaultPlatform(view);
        if (platform == 0)
            throw new NotSupportedException("The Binary Ninja view has no platform for contextual functions.");

        char[] text = new char[context.Origins.NameCapacity];
        byte[] utf8 = new byte[checked(Encoding.UTF8.GetMaxByteCount(text.Length) + 1)];
        byte[] tagText = new byte[checked(utf8.Length + 512)];
        ownership.Reserve(context.Count);
        nint tagType;
        fixed (byte* name = "AOT Atlas context\0"u8)
        fixed (byte* icon = "🔗\0"u8) {
            tagType = Core.BNGetTagType(view, name);
            if (tagType == 0) {
                tagType = Core.BNCreateTagType(view);
                Core.BNTagTypeSetName(tagType, name);
                Core.BNTagTypeSetIcon(tagType, icon);
                Core.BNAddTagType(view, tagType);
            }
        }

        try {
            fixed (byte* name = utf8) {
                int processed = 0;
                foreach (ref readonly var item in context.Functions.AsSpan()) {
                    if (item.Depth == 0)
                        continue;
                    if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();

                    ulong address = stats.ImageBase + (item.Address - image.ImageBase);
                    nint function = Core.BNGetAnalysisFunction(view, platform, address);
                    if (function == 0)
                        function = Core.BNAddFunctionForAnalysis(view, platform, address, 0, 0);
                    if (function == 0)
                        throw new InvalidOperationException($"Binary Ninja rejected contextual function 0x{address:X}.");
                    Core.BNFreeFunction(function);

                    int length = context.WriteName(item, image.ImageBase, text);
                    int bytes = Encoding.UTF8.GetBytes(text.AsSpan(0, length), utf8);
                    utf8[bytes] = 0;
                    symbols.Define(address, 0, name);
                    ++stats.Symbols;

                    var origin = context.Origins.Values[item.Origin - 1];
                    ulong parent = stats.ImageBase + (context.Functions[item.Parent].Address - image.ImageBase);
                    ulong witness = stats.ImageBase + (item.Witness - image.ImageBase);
                    ulong anchor = stats.ImageBase + (origin.Address - image.ImageBase);
                    ulong anchorWitness = stats.ImageBase + (origin.Witness - image.ImageBase);
                    string relation = CodeContext.RelationName(item.Relation), kind = CodeOrigins.KindName(origin.Kind);
                    Utf8.TryWrite(tagText, $"context::{relation}::source=0x{parent:X}::witness=0x{witness:X}::anchor=0x{anchor:X}::depth={item.Depth}::anchor_kind={kind}::anchor_witness=0x{anchorWitness:X}::anchor_aliases={origin.Aliases}", out int prefix);
                    if (item.Second != 0) {
                        ulong second = stats.ImageBase + (context.Functions[item.Second].Address - image.ImageBase);
                        Utf8.TryWrite(tagText.AsSpan(prefix), $"::second=0x{second:X}", out int extra);
                        prefix += extra;
                    }
                    "::name="u8.CopyTo(tagText.AsSpan(prefix));
                    prefix += 7;
                    utf8.AsSpan(0, bytes + 1).CopyTo(tagText.AsSpan(prefix));
                    DataTags.Set(ownership, view, tagType, address, tagText.AsSpan(0, prefix + bytes + 1));
                }
            }
        } finally {
            Core.BNFreeTagType(tagType);
            Core.BNFreePlatform(platform);
        }
    }
}
