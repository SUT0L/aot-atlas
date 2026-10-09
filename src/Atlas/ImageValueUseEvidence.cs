namespace Atlas;

public enum ImageValueUseEvidence : byte {
    InitialImage,
    PreservedFromOwnerEntry,
    PreservedFromRetainedRootEntries,
    Unproven,
    InstructionConstant
}
