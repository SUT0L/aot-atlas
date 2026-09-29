using System.Text.Json;
using Atlas;

internal static class DispatchCellsOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction, DispatchCells cells, double seconds) {
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("dispatch_cell_seconds", seconds);
        json.WriteStartArray("cells");
        foreach (var cell in cells.Cells) {
            json.WriteStartObject();
            json.WriteNumber("address", cell.Address);
            json.WriteNumber("stub", cell.Stub);
            json.WriteNumber("encoded_interface", cell.EncodedInterface);
            json.WriteNumber("interface", extraction.Types.Types[cell.InterfaceType].Address);
            json.WriteString("interface_name", extraction.Names.Values[cell.InterfaceType]);
            json.WriteNumber("slot", cell.Slot);
            json.WriteNumber("terminator", cell.Terminator);
            json.WriteString("cell_register", cell.Register == 10 ? "r10" : "r11");
            json.WriteString("storage", cell.Hydrated ? "rehydrated" : "file");
            json.WriteStartArray("calls");
            for (int i = cell.Uses.Start; i < cell.Uses.End; ++i) {
                var use = cells.Uses[i];
                json.WriteStartObject();
                json.WriteNumber("definition", use.Definition);
                json.WriteNumber("instruction", use.Instruction);
                json.WriteEndObject();
            }
            json.WriteEndArray();
            json.WriteStartArray("dictionary_slots");
            for (int i = cell.DictionarySlots.Start; i < cell.DictionarySlots.End; ++i) {
                var source = extraction.Dictionaries.Slots[cells.DictionarySlots[i]];
                json.WriteNumberValue(source.Address);
            }
            json.WriteEndArray();
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteStartArray("rejected");
        foreach (var rejected in cells.Rejected) {
            json.WriteStartObject();
            json.WriteNumber("address", rejected.Address);
            json.WriteString("status", rejected.Status.ToString());
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }

    internal static void WriteResolution(Utf8JsonWriter json, string inputSha256, Extraction extraction,
        ulong receiver, ulong contract, ushort slot) {
        var result = new DispatchResolver(extraction).Resolve(receiver, contract, slot);
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("receiver", receiver);
        json.WriteNumber("interface", contract);
        json.WriteNumber("interface_slot", slot);
        json.WriteString("status", result.Status.ToString());
        json.WriteNumber("target", result.Target);
        json.WriteNumber("witness", result.Witness);
        json.WriteBoolean("variant", result.Variant);
        if (result.MappingOwner != 0) {
            json.WriteNumber("mapping_owner", extraction.Types.Types[result.MappingOwner - 1].Address);
            json.WriteNumber("target_owner", extraction.Types.Types[result.TargetOwner - 1].Address);
            json.WriteNumber("matched_interface", extraction.Types.Types[result.MatchedInterface - 1].Address);
            json.WriteNumber("entry_index", result.Entry - 1);
        }
        json.WriteEndObject();
    }
}
