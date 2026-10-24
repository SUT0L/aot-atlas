using System.Text.Json;
using Atlas;

internal static class GcInfoOutput {
    private static readonly string[] Registers = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    ];

    internal static void Write(
        Utf8JsonWriter json,
        string inputSha256,
        PeImage image,
        ManagedUnwind managed,
        MethodGcMap map,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        bool partial = false;

        if (managed.RegionSource != ManagedRegionSource.Unknown) {
            foreach (var method in map.Methods) {
                cancellationToken.ThrowIfCancellationRequested();

                if (method.Error is not null) {
                    partial = true;
                    break;
                }
            }
        }

        JsonOutput.StartDocument(json, "gcinfo");
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("image_base", image.ImageBase);
        json.WriteNumber("version", map.Version);
        json.WriteString("region_source", managed.RegionSource.ToString());
        json.WriteString("status", managed.RegionSource == ManagedRegionSource.Unknown ? "unknown_region"
            : partial ? "partial" : "complete");

        json.WriteStartArray("methods");

        foreach (var method in map.Methods) {
            cancellationToken.ThrowIfCancellationRequested();

            json.WriteStartObject();
            json.WriteNumber("begin", method.Begin);
            json.WriteNumber("end", method.End);
            json.WriteNumber("gcinfo_rva", method.Address);

            if (method.Info is not { } info) {
                json.WriteString("status", "unavailable");
                json.WriteString("error", method.Error);
                json.WriteEndObject();

                continue;
            }

            json.WriteString("status", "complete");
            json.WriteString("liveness", info.SafePoints.Length != 0 ? "safepoints"
                : info.Ranges.Length != 0 ? "interruptible_ranges" : "untracked_only");
            json.WriteNumber("code_length", info.CodeLength);
            json.WriteNumber("header_bytes", info.HeaderBytes);
            json.WriteNumber("flags", info.Flags);
            json.WriteNumber("outgoing_stack_bytes", info.OutgoingStackBytes);
            if (info.ReturnKind >= 0)
                json.WriteNumber("return_kind", info.ReturnKind);
            if (info.StackBaseRegister >= 0)
                json.WriteString("frame_register", Registers[info.StackBaseRegister]);
            if ((info.Flags & 2) != 0)
                json.WriteNumber("security_object_stack_offset", info.SecurityObjectSlot);
            if ((info.Flags & 4) != 0) {
                json.WriteNumber("cookie_caller_sp_offset", info.CookieSlot);
                json.WriteStartArray("cookie_valid_range");
                json.WriteNumberValue(info.ValidRangeStart);
                json.WriteNumberValue(info.ValidRangeEnd);
                json.WriteEndArray();
            }
            if ((info.Flags & 8) != 0)
                json.WriteNumber("psp_initial_sp_offset", info.PspSlot);

            // These slots use the header frame base rather than caller SP.
            string headerStackBase = info.StackBaseRegister < 0 ? "sp" : "frame_register";

            if ((info.Flags & 0x30) != 0) {
                json.WriteString("generic_context_stack_base", headerStackBase);
                json.WriteNumber("generic_context_stack_offset", info.GenericContextSlot);
                json.WriteNumber("generic_context_valid_from", info.ValidRangeStart);
                json.WriteString("generic_context_kind", (info.Flags & 0x30) switch {
                    0x10 => "method_table",
                    0x20 => "method_descriptor",
                    _ => "this"
                });
            }
            if ((info.Flags & 0x100) != 0)
                json.WriteNumber("edit_and_continue_bytes", info.EditAndContinueBytes);
            if ((info.Flags & 0x200) != 0) {
                json.WriteString("reverse_pinvoke_stack_base", headerStackBase);
                json.WriteNumber("reverse_pinvoke_stack_offset", info.ReversePInvokeSlot);
            }

            json.WriteStartArray("slots");

            for (int index = 0; index < info.Slots.Length; ++index) {
                cancellationToken.ThrowIfCancellationRequested();
                var slot = info.Slots[index];

                json.WriteStartObject();
                json.WriteNumber("index", index);
                if (slot.Register >= 0) {
                    json.WriteString("register", Registers[slot.Register]);
                } else {
                    json.WriteString("stack_base", slot.StackBase switch {
                        0 => "caller_sp",
                        1 => "sp",
                        _ => "frame_register"
                    });
                    json.WriteNumber("stack_offset", slot.StackOffset);
                }

                json.WriteBoolean("interior", (slot.Flags & 1) != 0);
                json.WriteBoolean("pinned", (slot.Flags & 2) != 0);
                json.WriteBoolean("untracked", (slot.Flags & 4) != 0);
                json.WriteEndObject();
            }

            json.WriteEndArray();

            json.WriteStartArray("safepoints");

            for (int point = 0; point < info.SafePoints.Length; ++point) {
                cancellationToken.ThrowIfCancellationRequested();
                json.WriteStartObject();
                json.WriteNumber("offset", info.SafePoints[point]);
                json.WriteStartArray("live_slots");

                if (info.LiveSlotRuns.Length != 0) {
                    foreach (var run in info.LiveSlotRuns[point]) {
                        for (int slot = run.Start; slot < run.Start + run.Count; ++slot) {
                            cancellationToken.ThrowIfCancellationRequested();
                            json.WriteNumberValue(slot);
                        }
                    }
                }

                json.WriteEndArray();
                json.WriteEndObject();
            }

            json.WriteEndArray();

            json.WriteStartArray("interruptible_ranges");

            foreach (var range in info.Ranges) {
                cancellationToken.ThrowIfCancellationRequested();

                json.WriteStartArray();
                json.WriteNumberValue(range.Start);
                json.WriteNumberValue(range.End);
                json.WriteEndArray();
            }

            json.WriteEndArray();

            json.WriteStartArray("transitions");

            foreach (var transition in info.Transitions) {
                cancellationToken.ThrowIfCancellationRequested();

                json.WriteStartObject();
                json.WriteNumber("offset", transition.Offset);
                json.WriteNumber("slot", transition.Slot);
                json.WriteBoolean("live", transition.Live);
                json.WriteBoolean("chunk_start", transition.ChunkStart);
                json.WriteEndObject();
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }

        cancellationToken.ThrowIfCancellationRequested();
        json.WriteEndArray();
        json.WriteEndObject();
    }
}
