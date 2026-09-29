using System.Buffers;
using System.Buffers.Text;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace Atlas.Binja;

internal struct MethodAnnotation {
    internal uint Witness;
    internal int Section, Text, NameLength, TextLength;
}

internal struct FunctionSite {
    internal uint Address;
    internal int Record, Prototype;
    internal FunctionRole Role;
}

internal enum FunctionRole : byte {
    Entrypoint, InvokeStub, ToNative, ToManaged, Cleanup, Open, Closed, Create, Constructor, Unboxed
}

internal static unsafe class MethodAnnotations {
    internal static void Apply(Symbols symbols, TagOwnership ownership, nint view, Extraction extraction, ManagedAbi managedAbi, ReadOnlySpan<nint> runtimeTypes, nint headerType, nint voidType,
        nint voidPointer, ref ApplyStats stats, nint task) {
        int runtimeCount = extraction.Maps.Methods.Count + extraction.Generics.Methods.Count;
        int traceEnd = checked(runtimeCount + extraction.Traces.Methods.Count);
        int templateEnd = checked(traceEnd + extraction.Templates.Methods.Count);
        int structEnd = checked(templateEnd + extraction.Marshalling.Structs.Count);
        int delegateEnd = checked(structEnd + extraction.Marshalling.Delegates.Count);
        int count = checked(delegateEnd + extraction.Statics.Constructors.Count);
        var records = new MethodAnnotation[count];
        var sites = new List<FunctionSite>(checked(templateEnd + 2 * runtimeCount + 3 * (count - templateEnd)));
        var text = new ArrayBufferWriter<byte>(Math.Max(1024, checked(count * 192)));
        var renderer = new MethodText(extraction);
        byte[] buffer = new byte[1024];
        ulong originalBase = extraction.Image.ImageBase;
        Span<ulong> targets = stackalloc ulong[7];
        Span<ulong> code = stackalloc ulong[10];
        Span<ulong> sections = stackalloc ulong[337];
        sections.Clear();
        foreach (var section in extraction.Header.Sections) {
            if ((uint)section.Id < sections.Length)
                sections[section.Id] = section.Start;
        }

        for (int i = 0; i < count; ++i) {
            if (task != 0 && (i & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                throw new OperationCanceledException();

            ref var record = ref records[i];
            ReadOnlySpan<char> signature;
            ReadOnlySpan<byte> recordPrefix = default;
            ReadOnlySpan<ulong> arguments = default;
            int offset, nameLength;
            targets.Clear();
            code.Clear();
            if (i < runtimeCount) {
                var method = new MethodRecord(extraction, i);
                record.Section = method.Section;
                offset = method.Vertex;
                signature = renderer.Render(method);
                nameLength = renderer.NameLength;
                recordPrefix = "context::"u8;
                targets[0] = method.DeclaringType;
                targets[1] = method.Entrypoint;
                targets[2] = method.InvokeStub;
                targets[3] = method.Dictionary;
                if (method.Dictionary != 0) {
                    int templateIndex = extraction.Shared.Templates[i - extraction.Maps.Methods.Count];
                    if (templateIndex > 0) {
                        ref readonly var template = ref CollectionsMarshal.AsSpan(extraction.Templates.Methods)[templateIndex - 1];
                        targets[4] = sections[322] + (uint)template.Vertex;
                        targets[5] = template.Method.Entrypoint;
                        targets[6] = extraction.Shared.JumpTargets[templateIndex - 1];
                    }
                }
                arguments = method.Arguments;
                code[(int)FunctionRole.Entrypoint] = method.Entrypoint;
                code[(int)FunctionRole.InvokeStub] = method.InvokeStub;
                code[(int)FunctionRole.Unboxed] = managedAbi.Methods[i].UnboxedTarget;
            } else if (i < traceEnd) {
                ref readonly var trace = ref CollectionsMarshal.AsSpan(extraction.Traces.Methods)[i - runtimeCount];
                record.Section = 327;
                offset = trace.Offset;
                signature = renderer.Render(trace);
                nameLength = renderer.NameLength;
                targets[1] = trace.Entrypoint;
                code[(int)FunctionRole.Entrypoint] = trace.Entrypoint;
            } else if (i < templateEnd) {
                ref readonly var template = ref CollectionsMarshal.AsSpan(extraction.Templates.Methods)[i - traceEnd];
                ref readonly var entry = ref template.Method;
                record.Section = 322;
                offset = template.Vertex;
                signature = renderer.Render(template);
                nameLength = renderer.NameLength;
                targets[0] = extraction.Metadata.Signatures.Nodes[entry.DeclaringType].TypeAddress;
                targets[1] = entry.Entrypoint;
                targets[2] = sections[330] + entry.Offset;
                targets[3] = sections[330] + template.LayoutOffset;
                targets[4] = extraction.Shared.JumpTargets[i - traceEnd];
                code[(int)FunctionRole.Entrypoint] = entry.Entrypoint;
            } else if (i < structEnd) {
                ref readonly var entry = ref CollectionsMarshal.AsSpan(extraction.Marshalling.Structs)[i - templateEnd];
                record.Section = 316;
                offset = entry.Vertex;
                signature = extraction.Names.Values[entry.TypeIndex];
                nameLength = signature.Length;
                recordPrefix = "native::"u8;
                targets[0] = extraction.Types.Types[entry.TypeIndex].Address;
                targets[1] = code[(int)FunctionRole.ToNative] = entry.ToNative;
                targets[2] = code[(int)FunctionRole.ToManaged] = entry.ToManaged;
                targets[3] = code[(int)FunctionRole.Cleanup] = entry.Cleanup;
            } else if (i < delegateEnd) {
                ref readonly var entry = ref CollectionsMarshal.AsSpan(extraction.Marshalling.Delegates)[i - structEnd];
                record.Section = 317;
                offset = entry.Vertex;
                signature = extraction.Names.Values[entry.TypeIndex];
                nameLength = signature.Length;
                recordPrefix = "delegate_marshalling::"u8;
                targets[0] = extraction.Types.Types[entry.TypeIndex].Address;
                targets[1] = code[(int)FunctionRole.Open] = entry.Open;
                targets[2] = code[(int)FunctionRole.Closed] = entry.Closed;
                targets[3] = code[(int)FunctionRole.Create] = entry.Create;
            } else {
                ref readonly var entry = ref CollectionsMarshal.AsSpan(extraction.Statics.Constructors)[i - delegateEnd];
                record.Section = 310;
                offset = entry.Vertex;
                signature = extraction.Names.Values[extraction.Types.Index[entry.Type]];
                nameLength = signature.Length;
                recordPrefix = "context::"u8;
                code[(int)FunctionRole.Constructor] = entry.Entrypoint;
            }

            if (signature.Contains('\0'))
                throw new InvalidDataException("A method name or signature contains a NUL and cant be represented by native annotations.");

            record.Witness = checked((uint)(sections[record.Section] + (uint)offset - originalBase));
            record.Text = text.WrittenCount;
            var destination = text.GetSpan(checked(Encoding.UTF8.GetMaxByteCount(signature.Length) + recordPrefix.Length + 1));
            recordPrefix.CopyTo(destination);

            int nameBytes = Encoding.UTF8.GetBytes(signature[..nameLength], destination[recordPrefix.Length..]);
            record.NameLength = recordPrefix.Length + nameBytes;
            record.TextLength = record.NameLength + Encoding.UTF8.GetBytes(signature[nameLength..], destination[record.NameLength..]);
            destination[record.TextLength] = 0;
            text.Advance(record.TextLength + 1);

            if (record.TextLength + 64 > buffer.Length)
                Array.Resize(ref buffer, Math.Max(record.TextLength + 64, buffer.Length * 2));

            ulong witness = stats.ImageBase + record.Witness;
            if (i < delegateEnd) {
                "rtr::"u8.CopyTo(buffer);
                Utf8Formatter.TryFormat(record.Section, buffer.AsSpan(5), out int sectionBytes);
                "::"u8.CopyTo(buffer.AsSpan(5 + sectionBytes));
                text.WrittenSpan.Slice(record.Text, record.NameLength).CopyTo(buffer.AsSpan(7 + sectionBytes));
                buffer[7 + sectionBytes + record.NameLength] = 0;
                fixed (byte* name = buffer)
                    symbols.Define(witness, 3, name);
                ++stats.Symbols;
            }

            if (i < runtimeCount && targets[3] != 0) {
                "dictionary::"u8.CopyTo(buffer);
                text.WrittenSpan.Slice(record.Text, record.NameLength).CopyTo(buffer.AsSpan(12));
                buffer[12 + record.NameLength] = 0;
                ulong dictionary = stats.ImageBase + (targets[3] - originalBase);
                fixed (byte* name = buffer)
                    symbols.Define(dictionary, 3, name);
                ++stats.Symbols;

                Core.BNAddUserDataReference(view, dictionary, witness);
                ++stats.DataReferences;
            }

            foreach (ulong target in targets) {
                if (target == 0)
                    continue;
                Core.BNAddUserDataReference(view, witness, stats.ImageBase + (target - originalBase));
                ++stats.DataReferences;
            }

            foreach (ulong argument in arguments) {
                Core.BNAddUserDataReference(view, witness, stats.ImageBase + (argument - originalBase));
                ++stats.DataReferences;
            }

            if (code[(int)FunctionRole.Unboxed] != 0) {
                Core.BNAddUserDataReference(view, witness, stats.ImageBase + (code[(int)FunctionRole.Unboxed] - originalBase));
                ++stats.DataReferences;
            }

            for (int role = 0; role < code.Length; ++role) {
                ulong address = code[role];
                if (address == 0)
                    continue;

                int prototype = 0;
                if (role is >= (int)FunctionRole.ToNative and <= (int)FunctionRole.Cleanup)
                    prototype = 4 + 3 * (i - templateEnd) + role - (int)FunctionRole.ToNative;
                else if (role == (int)FunctionRole.Create)
                    prototype = 4 + 3 * (structEnd - templateEnd) + i - structEnd;

                sites.Add(new FunctionSite {
                    Address = checked((uint)(address - originalBase)),
                    Record = i,
                    Role = (FunctionRole)role,
                    Prototype = prototype
                });
            }
        }

        if (sites.Count == 0)
            return;

        ownership.Reserve(sites.Count);

        // Sorting groups shared bodies and shared invoke stubs without discarding any metadata identity
        sites.Sort(static (a, b) => {
            int order = a.Address.CompareTo(b.Address);
            if (order == 0)
                order = ((byte)a.Role).CompareTo((byte)b.Role);
            return order != 0 ? order : a.Record.CompareTo(b.Record);
        });

        nint platform = Core.BNGetDefaultPlatform(view);
        if (platform == 0)
            throw new NotSupportedException("The Binary Ninja view has no default platform for NativeAOT functions.");

        nint tagType = 0, constructorType = 0;
        var marshallingTypes = new MarshallingTypes();
        var managedTypes = new ManagedTypes();
        try {
            marshallingTypes.Build(view, platform, extraction, runtimeTypes, voidType, voidPointer);
            managedTypes.Initialize(platform, managedAbi);
            constructorType = managedTypes.Constructor(voidType);
            for (int i = runtimeCount; i < traceEnd; ++i) {
                if (managedAbi.Methods[i].Status != AbiStatus.TraceIdentity) {
                    continue;
                }

                ref readonly var record = ref records[i];
                nint type = managedTypes.Function(view, extraction, managedAbi, i,
                    runtimeTypes, headerType, voidType, voidPointer, false);
                try {
                    managedTypes.DefineTrace(view, record.Witness, text.WrittenSpan.Slice(record.Text, record.NameLength), type);
                } finally {
                    Core.BNFreeType(type);
                }
            }

            fixed (byte* name = "AOT Atlas methods\0"u8)
            fixed (byte* icon = "🔎\0"u8) {
                tagType = Core.BNGetTagType(view, name);
                if (tagType == 0) {
                    tagType = Core.BNCreateTagType(view);
                    Core.BNTagTypeSetName(tagType, name);
                    Core.BNTagTypeSetIcon(tagType, icon);
                    Core.BNAddTagType(view, tagType);
                }
            }

            var existing = new Dictionary<ulong, int>();
            nint[] oldText = new nint[16];
            bool[] used = new bool[16];
            var functions = CollectionsMarshal.AsSpan(sites);
            fixed (byte* output = buffer) {
                for (int begin = 0; begin < functions.Length;) {
                    if (task != 0 && (begin & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();

                    int end = begin + 1;
                    while (end < functions.Length && functions[end].Address == functions[begin].Address)
                        ++end;

                    ulong address = stats.ImageBase + functions[begin].Address;
                    nint function = Core.BNGetAnalysisFunction(view, platform, address);
                    if (function == 0)
                        function = Core.BNAddFunctionForAnalysis(view, platform, address, 0, 0);
                    if (function == 0)
                        throw new InvalidDataException($"Binary Ninja rejected the metadata-proven function at 0x{address:X}.");

                    try {
                        // ClassConstructorRunner invokes these pointers as delegate*<void>
                        // A shared body must have that contract at every recorded entry
                        bool constructor = true;
                        for (int j = begin; constructor && j < end; ++j)
                            constructor = functions[j].Role == FunctionRole.Constructor
                                && extraction.Statics.Constructors[functions[j].Record - delegateEnd].GenericContext == 0;
                        if (constructor && Core.BNFunctionHasUserType(function) == 0)
                            Core.BNApplyAutoDiscoveredFunctionType(function, constructorType);

                        int prototype = functions[begin].Prototype;
                        for (int j = begin + 1; prototype != 0 && j < end; ++j) {
                            int next = functions[j].Prototype;
                            if (next == 0 || marshallingTypes.Prototypes[next].Shape != marshallingTypes.Prototypes[prototype].Shape)
                                prototype = 0;
                            else if (next != prototype)
                                prototype = marshallingTypes.Prototypes[prototype].Shape;
                        }

                        // A shared body can retain the common pointer ABI, but a metadata role with an unknown ABI prevents that conclusion
                        if (prototype != 0 && Core.BNFunctionHasUserType(function) == 0)
                            Core.BNApplyAutoDiscoveredFunctionType(function, marshallingTypes.Prototypes[prototype].Type);

                        int managed = -1;
                        bool unboxed = false;
                        for (int j = begin; j < end; ++j) {
                            ref readonly var site = ref functions[j];
                            if (site.Record < runtimeCount && site.Role is FunctionRole.Entrypoint or FunctionRole.Unboxed) {
                                managed = site.Record;
                                unboxed = site.Role == FunctionRole.Unboxed;
                                break;
                            }
                        }

                        if (managed >= 0 && managedAbi.Methods[managed].Status == AbiStatus.Complete) {
                            var method = new MethodRecord(extraction, managed);
                            bool compatible = true;
                            for (int j = begin; compatible && j < end; ++j) {
                                ref readonly var site = ref functions[j];
                                if (site.Record < runtimeCount)
                                    compatible = site.Role == (unboxed ? FunctionRole.Unboxed : FunctionRole.Entrypoint)
                                        && managedAbi.Compatible(extraction, managed, site.Record);
                                else if (site.Role != FunctionRole.Entrypoint || site.Record >= templateEnd)
                                    compatible = false;
                                else if (site.Record >= traceEnd)
                                    compatible = managedAbi.CompatibleTemplate(extraction, managed, extraction.Templates.Methods[site.Record - traceEnd], unboxed);
                                else {
                                    ref readonly var trace = ref CollectionsMarshal.AsSpan(extraction.Traces.Methods)[site.Record - runtimeCount];
                                    // Generic traces can corroborate a map-backed ABI even when the trace cant independently supply its context
                                    compatible = !trace.Hidden && trace.Name == method.Name && trace.Signature == method.Signature
                                        && extraction.Fields.Bindings.Resolve(trace.DeclaringType) == extraction.Types.Index[method.DeclaringType] + 1;
                                }
                            }

                            if (compatible && Core.BNFunctionHasUserType(function) == 0) {
                                nint type = managedTypes.Function(view, extraction, managedAbi, managed,
                                    runtimeTypes, headerType, voidType, voidPointer, unboxed);
                                Core.BNApplyAutoDiscoveredFunctionType(function, type);
                                Core.BNFreeType(type);
                            }
                        }

                        ref readonly var first = ref functions[begin];
                        if (first.Role == FunctionRole.InvokeStub) {
                            "invoke_stub::"u8.CopyTo(buffer);
                            Utf8Formatter.TryFormat(first.Address, buffer.AsSpan(13), out int bytes, new StandardFormat('X', 8));
                            buffer[13 + bytes] = 0;
                        } else {
                            ref readonly var record = ref records[first.Record];
                            int prefix = 0;
                            if (first.Role != FunctionRole.Entrypoint) {
                                var role = RoleName(first.Role);
                                role.CopyTo(buffer);
                                "::"u8.CopyTo(buffer.AsSpan(role.Length));
                                prefix = role.Length + 2;
                            }
                            text.WrittenSpan.Slice(record.Text, record.NameLength).CopyTo(buffer.AsSpan(prefix));
                            buffer[prefix + record.NameLength] = 0;
                        }

                        symbols.Define(address, 0, output);
                        ++stats.Symbols;

                        nuint oldCount = 0;
                        nint* tags = Core.BNGetUserFunctionTagsOfType(function, tagType, &oldCount);
                        int previous = checked((int)oldCount);
                        if (previous > oldText.Length) {
                            Array.Resize(ref oldText, previous);
                            Array.Resize(ref used, previous);
                        }

                        existing.Clear();
                        used.AsSpan(0, previous).Clear();
                        oldText.AsSpan(0, previous).Clear();
                        try {
                            for (int j = 0; j < previous; ++j) {
                                if (!ownership.Contains(tags[j])) {
                                    used[j] = true;
                                    continue;
                                }
                                byte* data = Core.BNTagGetData(tags[j]);
                                oldText[j] = (nint)data;
                                var value = MemoryMarshal.CreateReadOnlySpanFromNullTerminated(data);
                                if (value.Length > 20 && value.StartsWith("rtr::"u8)
                                    && uint.TryParse(value.Slice(5, 8), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint rva)) {
                                    var suffix = value[20..];
                                    int separator = suffix.IndexOf("::"u8);
                                    if (separator < 0)
                                        continue;

                                    for (var role = FunctionRole.Entrypoint; role <= FunctionRole.Unboxed; ++role) {
                                        if (suffix[..separator].SequenceEqual(RoleName(role))) {
                                            ulong key = ((ulong)rva << 8) | (byte)role;
                                            existing.TryAdd(key, j);
                                            break;
                                        }
                                    }
                                }
                            }

                            for (int j = begin; j < end; ++j) {
                                if (task != 0 && (j & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                                    throw new OperationCanceledException();

                                ref readonly var site = ref functions[j];
                                ref readonly var record = ref records[site.Record];
                                "rtr::"u8.CopyTo(buffer);
                                Utf8Formatter.TryFormat(record.Witness, buffer.AsSpan(5), out _, new StandardFormat('X', 8));
                                "::"u8.CopyTo(buffer.AsSpan(13));
                                Utf8Formatter.TryFormat(record.Section, buffer.AsSpan(15), out _);
                                "::"u8.CopyTo(buffer.AsSpan(18));
                                var role = RoleName(site.Role);
                                role.CopyTo(buffer.AsSpan(20));
                                "::"u8.CopyTo(buffer.AsSpan(20 + role.Length));
                                int prefix = 22 + role.Length;
                                text.WrittenSpan.Slice(record.Text, record.TextLength + 1).CopyTo(buffer.AsSpan(prefix));
                                ulong key = ((ulong)record.Witness << 8) | (byte)site.Role;

                                if (existing.TryGetValue(key, out int old)) {
                                    used[old] = true;
                                    var value = MemoryMarshal.CreateReadOnlySpanFromNullTerminated((byte*)oldText[old]);
                                    if (!value.SequenceEqual(buffer.AsSpan(0, prefix + record.TextLength)))
                                        Core.BNTagSetData(tags[old], output);
                                } else {
                                    nint tag = Core.BNCreateTag(tagType, output);
                                    ownership.Register(tag);
                                    Core.BNAddUserFunctionTag(function, tag);
                                    Core.BNFreeTag(tag);
                                }
                            }

                            for (int j = 0; j < previous; ++j) {
                                if (!used[j]) {
                                    ownership.Remove(tags[j]);
                                    Core.BNRemoveUserFunctionTag(function, tags[j]);
                                    Core.BNRemoveTag(view, tags[j], 1);
                                }
                            }
                        } finally {
                            for (int j = 0; j < previous; ++j)
                                Core.BNFreeString((byte*)oldText[j]);
                            Core.BNFreeTagList(tags, oldCount);
                        }
                    } finally {
                        Core.BNFreeFunction(function);
                    }

                    begin = end;
                }
            }
        } finally {
            if (constructorType != 0)
                Core.BNFreeType(constructorType);
            managedTypes.Free();
            marshallingTypes.Free();
            if (tagType != 0)
                Core.BNFreeTagType(tagType);
            Core.BNFreePlatform(platform);
        }
    }

    private static ReadOnlySpan<byte> RoleName(FunctionRole role) => role switch {
        FunctionRole.Entrypoint => "entrypoint"u8,
        FunctionRole.InvokeStub => "invoke_stub"u8,
        FunctionRole.ToNative => "to_native"u8,
        FunctionRole.ToManaged => "to_managed"u8,
        FunctionRole.Cleanup => "cleanup"u8,
        FunctionRole.Open => "open"u8,
        FunctionRole.Closed => "closed"u8,
        FunctionRole.Create => "create"u8,
        FunctionRole.Constructor => "cctor"u8,
        FunctionRole.Unboxed => "unboxed"u8,
        _ => throw new ArgumentOutOfRangeException(nameof(role))
    };
}
