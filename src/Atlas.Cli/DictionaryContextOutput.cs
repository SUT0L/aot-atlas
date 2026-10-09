using System.Text.Json;
using Atlas;

internal static class DictionaryContextOutput {
    internal static void Write(Utf8JsonWriter json, DictionarySlotConsumers? dictionaries) {
        json.WriteStartArray("dictionary_context_relations");

        if (dictionaries is not null) {
            foreach (DictionaryContextRelation relation in dictionaries.Relations) {
                json.WriteStartObject();
                json.WriteNumber("owner", relation.Owner);
                json.WriteNumber("parameter_register", relation.ParameterRegister);
                json.WriteNumber("parameter_store", relation.ParameterStore);
                json.WriteNumber("gcinfo_rva", relation.GcInfoRva);
                json.WriteString("kind", relation.Kind switch {
                    DictionaryContextRelationKind.LoadedSlot => "loaded_slot",
                    DictionaryContextRelationKind.DelegateSlot => "delegate_slot",
                    _ => "forwarded_parameter"
                });
                json.WriteNumber("slot_offset", relation.SlotOffset);
                json.WriteNumber("load", relation.Load);
                json.WriteNumber("instruction", relation.Instruction);
                json.WriteNumber("target", relation.Target);
                json.WriteNumber("target_register", relation.TargetRegister);
                json.WriteNumber("consumer", relation.Consumer);
                json.WriteEndObject();
            }
        }

        json.WriteEndArray();
        json.WriteStartArray("dictionary_context_slot_accesses");

        if (dictionaries is not null) {
            foreach (DictionaryContextSlotAccess access in dictionaries.SlotAccesses) {
                json.WriteStartObject();
                json.WriteNumber("owner", access.Owner);
                json.WriteNumber("parameter_register", access.ParameterRegister);
                json.WriteNumber("parameter_store", access.ParameterStore);
                json.WriteNumber("gcinfo_rva", access.GcInfoRva);
                json.WriteNumber("instruction", access.Instruction);
                json.WriteNumber("slot_offset", access.SlotOffset);
                json.WriteNumber("destination_register", access.DestinationRegister);
                json.WriteEndObject();
            }
        }

        json.WriteEndArray();
        WriteTransfers("dictionary_context_transfers", dictionaries?.ContextTransfers);
        WriteTransfers("initial_dictionary_context_transfers", dictionaries?.InitialContextTransfers);
        WriteSlots("dictionary_delegate_slots", dictionaries?.DelegateSlots);
        WriteSlots("initial_dictionary_delegate_slots", dictionaries?.InitialDelegateSlots);

        void WriteTransfers(string name, IReadOnlyList<DictionaryContextTransfer>? transfers) {
            json.WriteStartArray(name);
            if (transfers is not null) {
                foreach (DictionaryContextTransfer transfer in transfers) {
                    json.WriteStartObject();
                    json.WriteNumber("owner", transfer.Owner);
                    json.WriteNumber("dictionary", transfer.Dictionary);
                    json.WriteNumber("load", transfer.Load);
                    json.WriteNumber("slot", transfer.Slot);
                    json.WriteNumber("value", transfer.Value);
                    json.WriteNumber("instruction", transfer.Instruction);
                    json.WriteNumber("target", transfer.Target);
                    json.WriteNumber("seed", transfer.Seed);
                    WriteEvidence(json, transfer.Evidence);
                    json.WriteEndObject();
                }
            }
            json.WriteEndArray();
        }

        void WriteSlots(string name, IReadOnlyList<DictionaryDelegateSlot>? slots) {
            json.WriteStartArray(name);
            if (slots is not null) {
                foreach (DictionaryDelegateSlot slot in slots) {
                    json.WriteStartObject();
                    json.WriteNumber("owner", slot.Owner);
                    json.WriteNumber("dictionary", slot.Dictionary);
                    json.WriteNumber("instruction", slot.Instruction);
                    json.WriteNumber("load", slot.Load);
                    json.WriteNumber("slot", slot.Slot);
                    json.WriteNumber("pointer", slot.Pointer);
                    json.WriteNumber("stub", slot.Stub);
                    json.WriteNumber("consumer", slot.Consumer);
                    json.WriteNumber("seed", slot.Seed);
                    WriteEvidence(json, slot.Evidence);
                    json.WriteEndObject();
                }
            }
            json.WriteEndArray();
        }
    }

    internal static void WriteEvidence(Utf8JsonWriter json, ImageValueUseEvidence evidence) {
        json.WriteString("value_state", evidence == ImageValueUseEvidence.InstructionConstant ? "instruction_constant" : "initial_image");
        json.WriteString("use_evidence", evidence switch {
            ImageValueUseEvidence.PreservedFromOwnerEntry => "preserved_from_owner_entry",
            ImageValueUseEvidence.PreservedFromRetainedRootEntries => "preserved_from_retained_root_entries",
            ImageValueUseEvidence.Unproven => "unproven",
            ImageValueUseEvidence.InstructionConstant => "instruction_constant",
            _ => "initial_image"
        });
        if (evidence == ImageValueUseEvidence.PreservedFromOwnerEntry)
            json.WriteString("entry_condition", "matches_initial_image_at_owner_entry");
        else if (evidence == ImageValueUseEvidence.PreservedFromRetainedRootEntries)
            json.WriteString("entry_condition", "matches_initial_image_at_retained_root_entries");
    }
}
