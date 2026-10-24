using System.Text.Json;
using Atlas;

internal static class DispatchCellsOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction,
        DispatchCells cells, double seconds) {
        JsonOutput.StartDocument(json, "dispatch-cells");
        json.WriteString("input_sha256", inputSha256);
        ExtractionStatusOutput.Write(json, extraction);
        json.WriteNumber("dispatch_cell_seconds", seconds);

        json.WriteStartArray("cells");

        foreach (var cell in cells.Cells) {
            json.WriteStartObject();
            json.WriteNumber("address", cell.Address);
            if (cell.Metadata == 0) {
                json.WriteNumber("stub", cell.Stub);
                json.WriteNumber("encoded_interface", cell.EncodedInterface);
            } else {
                json.WriteNumber("metadata", cell.Metadata - 1);
                json.WriteNumber("cached_method_table", cell.CachedMethodTable);
                json.WriteNumber("cached_code", cell.CachedCode);
            }
            json.WriteNumber("interface", extraction.Types.Types[cell.InterfaceType].Address);
            JsonOutput.WriteString(json, "interface_name", extraction.Names.Values[cell.InterfaceType]);
            json.WriteNumber("slot", cell.Slot);
            if (cell.Metadata == 0)
                json.WriteNumber("terminator", cell.Terminator);
            json.WriteString("cell_register", cell.Register == 10 ? "r10" : "r11");
            json.WriteString("storage", Storage(cell.Storage));

            json.WriteStartArray("calls");

            for (int i = cell.Uses.Start; i < cell.Uses.End; ++i) {
                var use = cells.Uses[i];

                json.WriteStartObject();
                json.WriteNumber("definition", use.Definition);
                json.WriteNumber("instruction", use.Instruction);
                if (use.Target != 0)
                    json.WriteNumber("helper", use.Target);
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

        if (extraction.DispatchCellMetadata.Layout == DispatchCellLayout.CachedMethodTableAndCode) {
            json.WriteString("cell_layout", "cached_method_table_and_code");
            json.WriteStartArray("gvm_cells");
            foreach (var cell in cells.GvmCellEntries) {
                json.WriteStartObject();
                json.WriteNumber("address", cell.Address);
                json.WriteNumber("metadata", cell.Metadata - 1);
                json.WriteNumber("cached_method_table", cell.CachedMethodTable);
                json.WriteNumber("cached_code", cell.CachedCode);
                json.WriteString("storage", Storage(cell.Storage));
                json.WriteString("cell_register", "r11");
                json.WriteStartArray("calls");
                foreach (var use in cells.UseEntries.Slice(cell.Uses.Start, cell.Uses.Count)) {
                    json.WriteStartObject();
                    json.WriteNumber("definition", use.Definition);
                    json.WriteNumber("instruction", use.Instruction);
                    if (use.Target != 0)
                        json.WriteNumber("helper", use.Target);
                    json.WriteEndObject();
                }
                json.WriteEndArray();
                json.WriteStartArray("dictionary_slots");
                foreach (int position in cells.DictionarySlotPositions.Slice(cell.DictionarySlots.Start, cell.DictionarySlots.Count))
                    json.WriteNumberValue(extraction.Dictionaries.Slots[position].Address);
                json.WriteEndArray();
                json.WriteEndObject();
            }
            json.WriteEndArray();

            json.WriteStartArray("metadata");
            foreach (var info in extraction.DispatchCellMetadata.Entries) {
                json.WriteStartObject();
                json.WriteString("kind", info.IsGvm ? "gvm" : "interface");
                json.WriteNumber("section", (int)info.Section);
                json.WriteNumber("vertex", info.Vertex);
                json.WriteNumber("length", info.Length);
                if (info.Status != MetadataFactStatus.Valid)
                    json.WriteString("status", info.Status.ToString());
                json.WriteNumber("witness", extraction.Header.Find(info.Section).Start + (uint)info.Vertex);
                json.WriteNumber("first_cell", info.FirstCell);
                json.WriteNumber("cell_index", info.CellIndex);
                json.WriteNumber("cell_count", info.CellCount);
                json.WriteNumber("type_fixup", info.TypeFixup);
                json.WriteNumber("declaring_type", info.Type);
                JsonOutput.WriteString(json, "declaring_type_name", extraction.Names.Values[extraction.Types.Index[info.Type]]);
                if (info.IsGvm) {
                    json.WriteNumber("instantiation_fixup", info.InstantiationFixup);
                    json.WriteNumber("instantiation", info.Instantiation);
                    json.WriteNumber("token", info.Token);
                    json.WriteNumber("async_flag", info.AsyncFlag);
                    json.WriteNumber("metadata_offset", info.Method.MetadataOffset);
                    json.WriteNumber("native_offset", info.Method.NativeOffset);
                    JsonOutput.WriteString(json, "method_name", info.Method.Name);
                    if (info.Method.NameStatus != MetadataFactStatus.Valid)
                        json.WriteString("method_name_status", info.Method.NameStatus.ToString());
                    if (info.Method.Signature != 0)
                        JsonOutput.WriteString(json, "signature", extraction.Signatures.MethodSignatures[info.Method.Signature].Render(info.Method.Name));
                    else
                        json.WriteString("signature_status", "unavailable");
                    if (info.Status != MetadataFactStatus.Valid)
                        json.WriteString("arguments_status", "unavailable");
                    json.WriteStartArray("arguments");
                    foreach (ulong argument in extraction.DispatchCellMetadata.ArgumentAddresses.Slice(info.Arguments.Start, info.Arguments.Count))
                        json.WriteNumberValue(argument);
                    json.WriteEndArray();
                } else {
                    json.WriteNumber("slot", info.Slot);
                }
                json.WriteEndObject();
            }
            json.WriteEndArray();
        }

        if (extraction.DispatchCellMetadata.Layout == DispatchCellLayout.CachedMethodTableAndCode
            || !extraction.DispatchCellMetadata.Failures.IsEmpty) {
            json.WriteString("dispatch_metadata_status", extraction.DispatchCellMetadata.Failures.IsEmpty ? "complete" : "partial");
            json.WriteStartArray("dispatch_metadata_failures");
            foreach (var failure in extraction.DispatchCellMetadata.Failures) {
                json.WriteStartObject();
                json.WriteNumber("section", (int)failure.Section);
                json.WriteNumber("vertex", failure.Vertex);
                json.WriteNumber("cell_index", failure.CellIndex);
                JsonOutput.WriteString(json, "error", failure.Error);
                json.WriteEndObject();
            }
            json.WriteEndArray();
        }

        if (!cells.UnprovenUseEntries.IsEmpty) {
            json.WriteString("dispatch_uses_status", "partial");
            json.WriteStartArray("unproven_calls");
            foreach (var use in cells.UnprovenUseEntries) {
                json.WriteStartObject();
                if (use.Cell == 0) {
                    json.WriteNull("definition");
                    json.WriteNull("cell");
                } else {
                    json.WriteNumber("definition", use.Definition);
                    json.WriteNumber("cell", use.Cell);
                }
                json.WriteNumber("instruction", use.Instruction);
                json.WriteNumber("target", use.Target);
                json.WriteString("status", use.Cell == 0 ? "unknown_cell" : "unknown_helper");
                json.WriteEndObject();
            }
            json.WriteEndArray();
        }

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

    private static string Storage(DispatchCellStorage storage) => storage switch {
        DispatchCellStorage.Rehydrated => "rehydrated",
        DispatchCellStorage.ZeroInitialized => "zero_initialized",
        DispatchCellStorage.FileAndZeroInitialized => "file_and_zero_initialized",
        _ => "file"
    };

    internal static void WriteResolution(Utf8JsonWriter json, string inputSha256, Extraction extraction,
        ulong receiver, ulong contract, ushort slot) {
        var result = new DispatchResolver(extraction).Resolve(receiver, contract, slot);

        JsonOutput.StartDocument(json, "resolve-dispatch");
        json.WriteString("input_sha256", inputSha256);
        ExtractionStatusOutput.Write(json, extraction);
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
            json.WriteNumber("matched_interface",
                extraction.Types.Types[result.MatchedInterface - 1].Address);
            json.WriteNumber("entry_index", result.Entry - 1);
        }

        json.WriteEndObject();
    }
}
