using System.Runtime.InteropServices;
using System.Text;

namespace Atlas.Binja;

internal enum AnalysisEvidenceKind : byte {
    GcInfo,
    GenericContext,
    FunctionPointer,
    RuntimeType,
    DispatchCell,
    Status
}

internal readonly record struct AnalysisTag(AnalysisEvidenceKind Kind, ulong Address, string Text);
internal readonly record struct AnalysisReference(ulong From, ulong To);

internal sealed class AnalysisEvidence {
    private static readonly string[] Registers = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    ];

    internal AnalysisTag[] Tags { get; }
    internal AnalysisReference[] References { get; }

    private AnalysisEvidence(AnalysisTag[] tags, AnalysisReference[] references) {
        Tags = tags;
        References = references;
    }

    internal static AnalysisEvidence Read(PreparedAnalysis prepared, ulong imageBase, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        var image = prepared.Extraction.Image;
        if (imageBase > ulong.MaxValue - image.ImageSize)
            throw new InvalidDataException("The rebased image exceeds the address space.");

        var tags = new Dictionary<(AnalysisEvidenceKind Kind, ulong Address), object>();
        var references = new HashSet<AnalysisReference>();

        var extraction = prepared.Extraction;
        var analysis = extraction.UnwindAnalysis;

        AddTypeMap(extraction.TypeMaps.External);
        AddTypeMap(extraction.TypeMaps.Proxy);

        foreach (GcLayout layout in extraction.Gc.Layouts) {
            cancellationToken.ThrowIfCancellationRequested();

            if (layout.Source == GcLayoutSource.Descriptor)
                continue;

            MethodTable type = extraction.Types.Types[layout.TypeIndex];

            foreach (ref readonly var run in CollectionsMarshal.AsSpan(extraction.Gc.Runs)
                .Slice(layout.Runs.Start, layout.Runs.Count)) {
                Add(AnalysisEvidenceKind.RuntimeType, Rebase(type.Address),
                    $"gc_shape::source={layout.Source}::construction_proven=false::offset={run.Offset}::pointer_count={run.Count}::repeat_stride={layout.RepeatStride}");
            }
        }

        foreach (InheritedGcRuns inherited in extraction.Gc.Inherited) {
            cancellationToken.ThrowIfCancellationRequested();
            MethodTable type = extraction.Types.Types[inherited.TypeIndex];
            MethodTable baseType = extraction.Types.Types[inherited.BaseTypeIndex];

            foreach (ref readonly var run in CollectionsMarshal.AsSpan(extraction.Gc.Runs)
                .Slice(inherited.Runs.Start, inherited.Runs.Count)) {
                Add(AnalysisEvidenceKind.RuntimeType, Rebase(type.Address),
                    $"gc_inherited::base_type=0x{Rebase(baseType.Address):X}::offset={run.Offset}::pointer_count={run.Count}");
            }
        }

        foreach (var section in image.Sections) {
            int offset = extraction.Header.FileOffset - section.FileOffset;
            if (offset < 0 || offset >= section.FileSize)
                continue;

            ulong address = imageBase + section.Rva + (uint)offset;
            string gcStatus = prepared.GcInfo is null || analysis.Managed?.RegionSource == ManagedRegionSource.Unknown
                ? "unavailable"
                : prepared.GcInfo.Methods.Any(method => method.Error is not null) ? "partial" : "available";
            var dictionaryConsumers = prepared.FunctionPointers.DictionaryConsumers;
            string dictionaryStatus = dictionaryConsumers is null ? "unavailable"
                : dictionaryConsumers.Failures.Count != 0 || dictionaryConsumers.UnresolvedOwners.Count != 0
                    ? "partial" : "complete";

            Add(AnalysisEvidenceKind.Status, address,
                $"metadata::status={(extraction.Metadata.IsComplete ? "complete" : "partial")}::decode_status={extraction.Metadata.Facts.Status}::projection_failures={extraction.Metadata.ProjectionDiagnostics.Count}");
            Add(AnalysisEvidenceKind.Status, address,
                $"analysis::unwind={(analysis.Unwind is null ? "unavailable" : "available")}::managed_unwind={(analysis.Managed is null ? "unavailable" : "available")}::gcinfo={gcStatus}::constructor_map={prepared.FunctionPointers.ConstructorMapStatus}");
            Add(AnalysisEvidenceKind.Status, address,
                $"function_pointers::failures={prepared.FunctionPointers.Failures.Count}::unproven_uses={prepared.FunctionPointers.UnprovenUses.Count}::unresolved_flow_owners={prepared.FunctionPointers.UnresolvedControlFlowOwners.Count}::dictionary_consumers={dictionaryStatus}");
            Add(AnalysisEvidenceKind.Status, address,
                $"dictionary_signatures={(extraction.DictionarySignatureGaps.IsEmpty ? "complete" : "partial")}");
            Add(AnalysisEvidenceKind.Status, address,
                $"type_maps::external={(extraction.TypeMaps.External.Present ? "decoded" : "absent")}::proxy={(extraction.TypeMaps.Proxy.Present ? "decoded" : "absent")}");

            if (extraction.DispatchCellMetadata.Layout == DispatchCellLayout.CachedMethodTableAndCode
                || !extraction.DispatchCellMetadata.Failures.IsEmpty) {
                Add(AnalysisEvidenceKind.Status, address,
                    $"dispatch_metadata::status={(extraction.DispatchCellMetadata.Failures.IsEmpty ? "complete" : "partial")}::failures={extraction.DispatchCellMetadata.Failures.Length}");
            }

            if ((extraction.Stages & ExtractionStage.Enums) != 0) {
                Add(AnalysisEvidenceKind.Status, address,
                    $"enums::status={(extraction.Enums.Failures.IsEmpty ? "complete" : "partial")}::failures={extraction.Enums.Failures.Length}");
            }
            if (prepared.Code is { } codeForStatus && !codeForStatus.UnprovenDispatchCellUseEntries.IsEmpty) {
                Add(AnalysisEvidenceKind.Status, address,
                    $"dispatch_uses::status=partial::unproven_uses={codeForStatus.UnprovenDispatchCellUseEntries.Length}");
            }

            foreach (var failure in analysis.Failures)
                Add(AnalysisEvidenceKind.Status, address, $"{failure.Phase}::error={failure.Error}");

            foreach (var gap in extraction.DictionarySignatureGaps) {
                Add(AnalysisEvidenceKind.Status, address,
                    $"dictionary_signature_gap::layout_offset=0x{gap.LayoutOffset:X}::recipe_offset=0x{gap.RecipeOffset:X}::kind={gap.Kind}::remaining_slots={gap.RemainingSlots}");
            }

            break;
        }

        if ((extraction.Stages & ExtractionStage.Enums) != 0) {
            ulong metadataStart = extraction.Header.Find(RtrSectionId.EmbeddedMetadata).Start;
            foreach (var definition in extraction.Enums.DefinitionEntries) {
                if (definition.Status == MetadataFactStatus.Valid)
                    continue;
                uint typeOffset = extraction.Metadata.TypeDefinitions[definition.MetadataType].Offset;
                Add(AnalysisEvidenceKind.Status, Rebase(metadataStart + typeOffset),
                    $"enum::status={definition.Status}::failures={definition.Failures.Count}");
                int shown = Math.Min(definition.Failures.Count, 8);
                foreach (var failure in extraction.Enums.Failures.Slice(definition.Failures.Start, shown)) {
                    ulong witness = metadataStart + (failure.FieldOffset == 0 ? typeOffset : failure.FieldOffset);
                    Add(AnalysisEvidenceKind.Status, Rebase(witness),
                        $"enum_member::status={failure.Status}::error={failure.Error}");
                }
            }
        }

        if (extraction.DispatchCellMetadata.Layout == DispatchCellLayout.CachedMethodTableAndCode) {
            foreach (var info in extraction.DispatchCellMetadata.Entries) {
                cancellationToken.ThrowIfCancellationRequested();
                ulong witness = extraction.Header.Find(info.Section).Start + (uint)info.Vertex;
                string contract = info.IsGvm
                    ? $"gvm_dispatch_contract::declaring_type=0x{Rebase(info.Type):X}::method={info.Method.Name}::async={info.Method.AsyncVariant}::arguments={(info.Status == MetadataFactStatus.Valid ? info.Arguments.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) : "unavailable")}"
                    : $"interface_dispatch_contract::interface=0x{Rebase(info.Type):X}::slot={info.Slot}";
                Add(AnalysisEvidenceKind.DispatchCell, Rebase(witness),
                    $"{contract}::first_cell=0x{Rebase(info.FirstCell):X}::cell_count={info.CellCount}::status={info.Status}");
                Reference(witness, info.Type);
                if (info.IsGvm) {
                    Reference(witness, info.Instantiation);
                    ulong method = info.Method.MetadataOffset != 0
                        ? extraction.Header.Find(RtrSectionId.EmbeddedMetadata).Start + info.Method.MetadataOffset
                        : extraction.Header.Find(RtrSectionId.NativeLayoutInfo).Start + info.Method.NativeOffset;
                    Reference(witness, method);
                    for (int argument = 0; argument < info.Arguments.Count; ++argument) {
                        ulong type = extraction.DispatchCellMetadata.ArgumentAddresses[info.Arguments.Start + argument];
                        Reference(witness, type);
                        Reference(info.Instantiation + (uint)argument * 4UL, type);
                    }
                }
                for (int cell = 0; cell < info.CellCount; ++cell) {
                    ulong address = info.FirstCell + (uint)cell * 16UL;
                    Add(AnalysisEvidenceKind.DispatchCell, Rebase(address),
                        $"dispatch_cell::kind={(info.IsGvm ? "gvm" : "interface")}::contract=0x{Rebase(witness):X}::layout=cached_method_table_and_code");
                    Reference(witness, address);
                    Reference(address, witness);
                    Reference(address, info.Type);
                }
            }

            if (prepared.DispatchCells is { } cells) {
                foreach (var cell in cells.CellEntries)
                    AddDispatchUses(cell.Address, cell.Uses, cell.DictionarySlots);
                foreach (var cell in cells.GvmCellEntries)
                    AddDispatchUses(cell.Address, cell.Uses, cell.DictionarySlots);

                void AddDispatchUses(ulong address, IndexRange uses, IndexRange slots) {
                    foreach (var use in cells.UseEntries.Slice(uses.Start, uses.Count)) {
                        Reference(use.Definition, address);
                        Reference(use.Instruction, address);
                    }
                    foreach (int position in cells.DictionarySlotPositions.Slice(slots.Start, slots.Count)) {
                        ulong slot = extraction.Dictionaries.SlotEntries[position].Address;
                        Reference(address, slot);
                        Reference(slot, address);
                    }
                }
            }

        }

        if (prepared.Code is { } code) {
            foreach (var use in code.UnprovenDispatchCellUseEntries) {
                string status = use.Cell == 0 ? "unknown_cell::cell=unavailable"
                    : $"unknown_helper::cell=0x{Rebase(use.Cell):X}";
                Add(AnalysisEvidenceKind.Status, Rebase(use.Instruction),
                    $"dispatch_cell_use::status={status}::target=0x{Rebase(use.Target):X}");
            }
        }

        foreach (var failure in extraction.DispatchCellMetadata.Failures) {
            ulong witness = extraction.Header.Find(failure.Section).Start;
            if (failure.Vertex >= 0)
                witness += (uint)failure.Vertex;
            Add(AnalysisEvidenceKind.Status, Rebase(witness),
                $"dispatch_metadata::status=partial::section={(int)failure.Section}::cell_index={failure.CellIndex}::error={failure.Error}");
        }

        foreach (var association in extraction.Frozen.RuntimeTypes) {
            cancellationToken.ThrowIfCancellationRequested();

            var instance = extraction.Frozen.Objects[association.ObjectIndex];
            var type = extraction.Types.Types[association.TypeIndex];
            ulong address = extraction.Frozen.Start + (uint)instance.Offset;
            ulong typeField = extraction.Frozen.Start + (uint)instance.Data.Start;

            Add(AnalysisEvidenceKind.RuntimeType, Rebase(address),
                $"runtime_type::eetype=0x{Rebase(type.Address):X}::writable_data=0x{Rebase(type.WritableData):X}::evidence=reciprocal_eetype_cache");
            Reference(typeField, type.Address);
            Reference(type.WritableData, address);
        }

        if (prepared.GcInfo is { } map) {
            foreach (var method in map.Methods) {
                cancellationToken.ThrowIfCancellationRequested();

                ulong address = imageBase + method.Begin;
                var text = Begin(AnalysisEvidenceKind.GcInfo, address);

                text.Append($"gcinfo::rva=0x{method.Address:X}::version={map.Version}");

                if (method.Info is not { } info) {
                    text.Append($"::status=unavailable::error={method.Error}");

                    continue;
                }

                text.Append($"::code_length={info.CodeLength}::outgoing_stack_bytes={info.OutgoingStackBytes}");
                text.Append($"::slots={info.Slots.Length}::safepoints={info.SafePoints.Length}::ranges={info.Ranges.Length}");

                string stackBase = info.StackBaseRegister < 0 ? "sp" : Registers[info.StackBaseRegister];

                if ((info.Flags & 0x30) != 0) {
                    string kind = (info.Flags & 0x30) switch {
                        0x10 => "method_table",
                        0x20 => "method_descriptor",
                        _ => "this"
                    };

                    text.Append($"::context={kind}::context_base={stackBase}::context_offset={info.GenericContextSlot}::valid_from={info.ValidRangeStart}");
                }
                if ((info.Flags & 4) != 0)
                    text.Append($"::cookie_caller_sp_offset={info.CookieSlot}::cookie_range={info.ValidRangeStart}-{info.ValidRangeEnd}");
                if ((info.Flags & 8) != 0)
                    text.Append($"::psp_initial_sp_offset={info.PspSlot}");
                if ((info.Flags & 0x200) != 0)
                    text.Append($"::reverse_pinvoke_base={stackBase}::reverse_pinvoke_offset={info.ReversePInvokeSlot}");

                for (int index = 0; index < info.Slots.Length; ++index) {
                    var slot = info.Slots[index];
                    string location = slot.Register >= 0 ? Registers[slot.Register]
                        : $"{(slot.StackBase == 0 ? "caller_sp" : slot.StackBase == 1 ? "sp" : stackBase)}{slot.StackOffset:+0;-0;+0}";

                    text.Append($"\nslot[{index}]={location}::interior={(slot.Flags & 1) != 0}::pinned={(slot.Flags & 2) != 0}::untracked={(slot.Flags & 4) != 0}");
                }
            }
        }

        if (prepared.GenericContexts is { } contexts) {
            foreach (var parameter in contexts.Parameters) {
                cancellationToken.ThrowIfCancellationRequested();

                Add(AnalysisEvidenceKind.GenericContext, Rebase(parameter.Target),
                    $"method_context::register={Registers[parameter.Register]}::prologue_store=0x{Rebase(parameter.Store):X}::gcinfo_rva=0x{parameter.GcInfoRva:X}");
            }

            foreach (var reference in contexts.Values) {
                cancellationToken.ThrowIfCancellationRequested();

                Add(AnalysisEvidenceKind.GenericContext, Rebase(reference.Instruction),
                    $"method_dictionary::address=0x{Rebase(reference.Context):X}::target=0x{Rebase(reference.Target):X}::parameter={reference.ParameterIndex}::{ValueEvidence(reference.Evidence)}");
                Reference(reference.Instruction, reference.Context);
            }
        }

        var pointers = prepared.FunctionPointers;

        foreach (var pointer in pointers.Values) {
            cancellationToken.ThrowIfCancellationRequested();

            string role = pointer.ContextKind switch {
                FunctionPointerContextKind.MethodTable => "method_table",
                FunctionPointerContextKind.MethodDictionary => "method_dictionary",
                _ => "unknown"
            };

            Add(AnalysisEvidenceKind.FunctionPointer, Rebase(pointer.Descriptor),
                $"fat_function_pointer::value_state=initial_image::body=0x{Rebase(pointer.Body):X}::context=0x{Rebase(pointer.Context):X}::context_role={role}::gcinfo_rva=0x{pointer.GcInfoRva:X}::hydrated={pointer.Hydrated}");
            Reference(pointer.Descriptor, pointer.Body);
            Reference(pointer.Descriptor + 8, pointer.Context);
        }

        foreach (var reference in pointers.References) {
            cancellationToken.ThrowIfCancellationRequested();

            var pointer = pointers.Values[reference.PointerIndex];
            Add(AnalysisEvidenceKind.FunctionPointer, Rebase(reference.Definition),
                $"fat_function_pointer::{reference.Source}::descriptor=0x{Rebase(pointer.Descriptor):X}::owner=0x{Rebase(reference.Owner):X}::consumer=0x{Rebase(reference.Consumer):X}::holder=0x{Rebase(reference.Holder):X}::context_load=0x{Rebase(reference.ContextLoad):X}::{ValueEvidence(reference.Evidence)}");
        }

        foreach (FunctionPointerUnprovenUse use in pointers.UnprovenUses) {
            cancellationToken.ThrowIfCancellationRequested();

            FatFunctionPointerReference reference = use.Reference;
            FatFunctionPointer pointer = pointers.Values[reference.PointerIndex];
            Add(AnalysisEvidenceKind.FunctionPointer, Rebase(reference.Definition),
                $"fat_function_pointer::{reference.Source}::descriptor=0x{Rebase(pointer.Descriptor):X}::owner=0x{Rebase(reference.Owner):X}::consumer=0x{Rebase(reference.Consumer):X}::holder=0x{Rebase(reference.Holder):X}::context_load=0x{Rebase(reference.ContextLoad):X}::{ValueEvidence(reference.Evidence)}::error={use.Error}");
        }

        if (pointers.DictionaryConsumers is { } dictionaries) {
            foreach (DictionaryContextRelation relation in dictionaries.Relations) {
                Add(AnalysisEvidenceKind.GenericContext, Rebase(relation.Instruction),
                    $"dictionary_context_relation::{relation.Kind}::owner=0x{Rebase(relation.Owner):X}::parameter={Registers[relation.ParameterRegister]}::parameter_store=0x{Rebase(relation.ParameterStore):X}::gcinfo_rva=0x{relation.GcInfoRva:X}::slot_offset={relation.SlotOffset}::load=0x{Rebase(relation.Load):X}::target=0x{Rebase(relation.Target):X}::target_register={Registers[relation.TargetRegister]}::consumer=0x{Rebase(relation.Consumer):X}");
            }

            foreach (DictionaryContextSlotAccess access in dictionaries.SlotAccesses) {
                Add(AnalysisEvidenceKind.GenericContext, Rebase(access.Instruction),
                    $"dictionary_context_slot::owner=0x{Rebase(access.Owner):X}::parameter={Registers[access.ParameterRegister]}::parameter_store=0x{Rebase(access.ParameterStore):X}::gcinfo_rva=0x{access.GcInfoRva:X}::slot_offset={access.SlotOffset}::destination={Registers[access.DestinationRegister]}");
            }

            foreach (var transfer in dictionaries.ContextTransfers) {
                Add(AnalysisEvidenceKind.GenericContext, Rebase(transfer.Instruction),
                    $"dictionary_context_transfer::dictionary=0x{Rebase(transfer.Dictionary):X}::slot=0x{Rebase(transfer.Slot):X}::value=0x{Rebase(transfer.Value):X}::load=0x{Rebase(transfer.Load):X}::target=0x{Rebase(transfer.Target):X}::seed=0x{Rebase(transfer.Seed):X}::{ValueEvidence(transfer.Evidence)}");
                Reference(transfer.Load, transfer.Slot);
                Reference(transfer.Slot, transfer.Value);
            }

            foreach (var slot in dictionaries.DelegateSlots) {
                Add(AnalysisEvidenceKind.FunctionPointer, Rebase(slot.Instruction),
                    $"dictionary_delegate_slot::dictionary=0x{Rebase(slot.Dictionary):X}::slot=0x{Rebase(slot.Slot):X}::load=0x{Rebase(slot.Load):X}::stub=0x{Rebase(slot.Stub):X}::consumer=0x{Rebase(slot.Consumer):X}::seed=0x{Rebase(slot.Seed):X}::{ValueEvidence(slot.Evidence)}");
                Reference(slot.Load, slot.Slot);
            }

            foreach (DictionaryContextTransfer transfer in dictionaries.InitialContextTransfers) {
                Add(AnalysisEvidenceKind.GenericContext, Rebase(transfer.Load),
                    $"initial_dictionary_context::dictionary=0x{Rebase(transfer.Dictionary):X}::slot=0x{Rebase(transfer.Slot):X}::value=0x{Rebase(transfer.Value):X}::target=0x{Rebase(transfer.Target):X}::{ValueEvidence(transfer.Evidence)}");
                Reference(transfer.Slot, transfer.Value);
            }

            foreach (DictionaryDelegateSlot slot in dictionaries.InitialDelegateSlots) {
                Add(AnalysisEvidenceKind.FunctionPointer, Rebase(slot.Instruction),
                    $"initial_dictionary_delegate_slot::dictionary=0x{Rebase(slot.Dictionary):X}::slot=0x{Rebase(slot.Slot):X}::pointer=0x{Rebase(slot.Pointer):X}::{ValueEvidence(slot.Evidence)}");
            }
        }

        var result = new AnalysisTag[tags.Count];

        int next = 0;

        foreach (var tag in tags) {
            cancellationToken.ThrowIfCancellationRequested();

            string text = tag.Value is string single ? single : ((StringBuilder)tag.Value).ToString();

            if (text.Contains('\0'))
                throw new InvalidDataException("An analysis annotation contains a NUL.");

            result[next++] = new AnalysisTag(tag.Key.Kind, tag.Key.Address, text);
        }

        return new AnalysisEvidence(result, references.ToArray());

        void AddTypeMap(InteropTypeMap typeMap) {
            foreach (ref readonly var group in typeMap.Groups) {
                cancellationToken.ThrowIfCancellationRequested();
                ulong witness = typeMap.Address + (uint)group.Vertex;
                Add(AnalysisEvidenceKind.RuntimeType, Rebase(witness),
                    $"type_map::section={(int)typeMap.Section}::group=0x{Rebase(group.GroupType):X}::state={group.State}::hash=0x{group.Hash:X}::entries={group.Entries.Count}");
                Reference(witness, group.GroupType);
                Reference(witness, group.ThrowingStub);

                foreach (ref readonly var entry in typeMap.Entries.Slice(group.Entries.Start, group.Entries.Count)) {
                    cancellationToken.ThrowIfCancellationRequested();
                    ulong record = typeMap.Address + (uint)entry.Vertex;
                    string source = entry.Name is null ? $"source=0x{Rebase(entry.SourceType):X}"
                        : "name=" + entry.Name.Replace("\\", "\\\\").Replace("\0", "\\0").Replace("\r", "\\r").Replace("\n", "\\n");
                    Add(AnalysisEvidenceKind.RuntimeType, Rebase(record),
                        $"type_mapping::section={(int)typeMap.Section}::group_record=0x{Rebase(witness):X}::{source}::target=0x{Rebase(entry.TargetType):X}::hash=0x{entry.Hash:X}");
                    Reference(witness, record);
                    Reference(record, group.GroupType);
                    Reference(record, entry.SourceType);
                    Reference(record, entry.TargetType);
                }
            }
        }

        ulong Rebase(ulong address) => address == 0 ? 0 : checked(imageBase + (address - image.ImageBase));

        static string ValueEvidence(ImageValueUseEvidence evidence) => evidence == ImageValueUseEvidence.InstructionConstant
            ? "value_state=instruction_constant::use_evidence=InstructionConstant"
            : evidence == ImageValueUseEvidence.PreservedFromOwnerEntry
            ? "value_state=initial_image::use_evidence=PreservedFromOwnerEntry::entry_condition=matches_initial_image_at_owner_entry"
            : evidence == ImageValueUseEvidence.PreservedFromRetainedRootEntries
            ? "value_state=initial_image::use_evidence=PreservedFromRetainedRootEntries::entry_condition=matches_initial_image_at_retained_root_entries"
            : $"value_state=initial_image::use_evidence={evidence}";

        void Add(AnalysisEvidenceKind kind, ulong address, string text) {
            if (address == 0)
                return;

            // Most addresses have one line. Promote shared addresses without repeatedly copying their text.
            ref object? value = ref CollectionsMarshal.GetValueRefOrAddDefault(tags, (kind, address), out bool exists);
            if (!exists)
                value = text;
            else if (value is StringBuilder builder)
                builder.Append('\n').Append(text);
            else {
                string first = (string)value!;
                value = new StringBuilder(checked(first.Length + 1 + text.Length)).Append(first).Append('\n').Append(text);
            }
        }

        StringBuilder Begin(AnalysisEvidenceKind kind, ulong address) {
            ref object? value = ref CollectionsMarshal.GetValueRefOrAddDefault(tags, (kind, address), out bool exists);
            StringBuilder builder;
            if (!exists)
                builder = new StringBuilder();
            else if (value is string single)
                builder = new StringBuilder(checked(single.Length + 1)).Append(single).Append('\n');
            else
                builder = ((StringBuilder)value!).Append('\n');
            value = builder;
            return builder;
        }

        void Reference(ulong from, ulong to) {
            if (from != 0 && to != 0)
                references.Add(new AnalysisReference(Rebase(from), Rebase(to)));
        }
    }
}
