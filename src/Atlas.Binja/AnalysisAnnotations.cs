using System.Text;

namespace Atlas.Binja;

internal static unsafe class AnalysisAnnotations {
    internal static void Apply(
        TagOwnership ownership,
        nint view,
        AnalysisEvidence evidence,
        ref ApplyStats stats,
        nint task) {
        ownership.Reserve(evidence.Tags.Length);

        nint[] tagTypes = new nint[5];

        byte[] text = [];

        int processed = 0;

        try {
            foreach (var tag in evidence.Tags) {
                if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                    throw new OperationCanceledException();

                int kind = (int)tag.Kind;

                if (tagTypes[kind] == 0) {
                    string label = tag.Kind switch {
                        AnalysisEvidenceKind.GcInfo => "AOT Atlas GC",
                        AnalysisEvidenceKind.GenericContext => "AOT Atlas generic context",
                        AnalysisEvidenceKind.FunctionPointer => "AOT Atlas function pointer",
                        AnalysisEvidenceKind.RuntimeType => "AOT Atlas runtime type",
                        _ => "AOT Atlas analysis"
                    };

                    byte[] name = Encoding.UTF8.GetBytes(label + "\0");

                    fixed (byte* namePointer = name)
                    fixed (byte* icon = "🔗\0"u8) {
                        nint tagType = Core.BNGetTagType(view, namePointer);

                        if (tagType == 0) {
                            tagType = Core.BNCreateTagType(view);
                            Core.BNTagTypeSetName(tagType, namePointer);
                            Core.BNTagTypeSetIcon(tagType, icon);
                            Core.BNAddTagType(view, tagType);
                        }

                        tagTypes[kind] = tagType;
                    }
                }

                int required = checked(Encoding.UTF8.GetByteCount(tag.Text) + 1);

                if (text.Length < required)
                    Array.Resize(ref text, required);

                int length = Encoding.UTF8.GetBytes(tag.Text, text);
                text[length] = 0;

                DataTags.Set(ownership, view, tagTypes[kind], tag.Address, text.AsSpan(0, length + 1));
            }

            foreach (var reference in evidence.References) {
                if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                    throw new OperationCanceledException();

                Core.BNAddUserDataReference(view, reference.From, reference.To);
                ++stats.DataReferences;
            }
        } finally {
            foreach (nint tagType in tagTypes) {
                if (tagType != 0)
                    Core.BNFreeTagType(tagType);
            }
        }
    }
}
