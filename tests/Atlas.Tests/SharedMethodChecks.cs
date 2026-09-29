using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Atlas;

internal static class SharedMethodChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        foreach (string binary in binaries) {
            var image = new PeImage(File.ReadAllBytes(binary));
            var header = ReadyToRun.Read(image);
            var section = header.Find(313);
            var metadata = new Metadata(image.FileMemory(section.Start, checked((int)section.Length)),
                header.MetadataHandleBits, header.Major < 10);
            metadata.ReadDefinitions();
            var fixups = RuntimeTables.Fixups(image, header.Find(308));
            var maps = new ReflectionMaps();
            maps.Read(image, header, metadata, fixups, MapFormat.Auto);
            var extraction = new Extraction(image, header, metadata, maps, fixups);
            var shared = extraction.Shared;
            var abi = new ManagedAbi(extraction);
            string[] lines = Invoke(binary, extended: true).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            Assert(lines.Length == 13, "The fixture must expose twelve shared calls and one exact call.");

            var audit = new StringBuilder();
            int linked = 0, forwarded = 0, exact = 0, firstRecord = -1;
            ulong integerType = 0;
            foreach (string line in lines) {
                string[] parts = line.Split('|');
                Assert(parts.Length is 5 or 6, "A runtime observation has an unexpected shape.");
                ulong owner = image.ImageBase + Convert.ToUInt64(parts[1], 16);
                ulong code = image.ImageBase + Convert.ToUInt64(parts[2], 16);
                ulong dictionaryRva = Convert.ToUInt64(parts[3], 16);
                ulong dictionary = dictionaryRva == 0 ? 0 : image.ImageBase + dictionaryRva;
                ulong[] arguments = new ulong[parts.Length - 4];
                for (int i = 0; i < arguments.Length; ++i)
                    arguments[i] = image.ImageBase + Convert.ToUInt64(parts[i + 4], 16);

                if (dictionary == 0) {
                    Assert(parts[0] == "type" && arguments.Length == 1 && image.IsExecutable(code),
                        "The exact fixture call must expose its executable code and Int32 argument.");
                    integerType = arguments[0];
                    Assert(extraction.Types.Types[extraction.Types.Index[integerType]].ElementType == 8,
                        "The exact call did not report the Int32 runtime identity.");
                    ++exact;
                    continue;
                }

                int matched = -1;
                for (int i = 0; i < extraction.Generics.Methods.Count; ++i) {
                    var record = extraction.Generics.Methods[i];
                    if (record.DeclaringType != owner || record.Dictionary != dictionary
                        || record.Arguments.Count != arguments.Length)
                        continue;

                    bool sameArguments = true;
                    for (int j = 0; j < arguments.Length; ++j)
                        sameArguments &= extraction.Generics.Arguments[record.Arguments.Start + j] == arguments[j];
                    if (!sameArguments)
                        continue;

                    Assert(matched < 0, "A live dictionary and its concrete components must identify one record.");
                    matched = i;
                }

                Assert(matched >= 0, $"No runtime generic record matches {line}.");
                int templateIndex = shared.Templates[matched] - 1;
                Assert(templateIndex >= 0, $"The live dictionary has no unique template: {line}.");
                ulong templateCode = extraction.Templates.Methods[templateIndex].Method.Entrypoint;
                Assert(templateCode == code || shared.JumpTargets[templateIndex] == code,
                    $"The template neither equals nor directly forwards to the live code: {line}; template={templateCode:X}, "
                    + $"jump={shared.JumpTargets[templateIndex]:X}, flags={extraction.Templates.Methods[templateIndex].Method.Flags}.");
                Assert(extraction.Generics.Methods[matched].Entrypoint == 0,
                    "Resolving a template must not invent an exact-instantiation entrypoint.");
                int abiIndex = maps.Methods.Count + matched;
                ref readonly var methodAbi = ref abi.Methods[abiIndex];
                Assert(methodAbi.Status == AbiStatus.SharedTemplate,
                    $"The live template call has no concrete shared ABI: {line}; status={methodAbi.Status}, return={methodAbi.Return.Kind}, "
                    + string.Join(", ", abi.Parameters.AsSpan(methodAbi.Parameters.Start, methodAbi.Parameters.Count).ToArray()
                        .Select(parameter => $"{parameter.Role}:{parameter.Value.Kind}/binding={parameter.Value.Binding}/signature={parameter.Value.Signature}")));
                var parameters = abi.Parameters.AsSpan(methodAbi.Parameters.Start, methodAbi.Parameters.Count);
                bool instance = parts[0] is "instance" or "value-instance";
                bool pair = parts[0] == "pair" || instance;
                Assert(methodAbi.Return.Kind == (pair ? AbiKind.Value : AbiKind.Integer)
                    && methodAbi.Return.Size == (pair ? 24U : 8U) && methodAbi.Return.Indirect == pair
                    && methodAbi.ReturnSlot == (instance ? 1 : 0),
                    "The fixture return must be NativeInt in RAX or TypePair through RCX/RDX after an optional receiver.");
                bool overload = parts[0] is "int-overload" or "float-overload";
                int context = instance ? 1 : 0;
                Assert(parameters.Length == (instance ? 3 : overload ? 2 : 1) && parameters[context].Role == AbiRole.GenericContext
                    && parameters[context].Value.Kind == AbiKind.Context && parameters[context].Value.Size == 8
                    && parameters[context].Slot == (instance ? 2 : pair ? 1 : 0),
                    "The dictionary must follow the receiver and return buffer.");
                if (instance) {
                    Assert(parameters[0].Role == AbiRole.This && parameters[0].Slot == 0 && parameters[0].Value.Size == 8
                        && parameters[0].Value.Binding == extraction.Types.Index[owner] + 1
                        && parameters[0].Value.Kind == (parts[0] == "value-instance" ? AbiKind.BoxedReference : AbiKind.Reference)
                        && parameters[2].Role == AbiRole.Parameter && parameters[2].Slot == 3
                        && parameters[2].Value.Kind == AbiKind.Integer && parameters[2].Value.Size == 8,
                        $"The direct instance template must receive this in RCX and the declared Int64 argument in R9: {line}; owner={extraction.Types.Index[owner] + 1}, "
                        + string.Join(", ", parameters.ToArray().Select(parameter => $"{parameter.Role}:{parameter.Value.Kind}/binding={parameter.Value.Binding}/size={parameter.Value.Size}/slot={parameter.Slot}")));
                }
                if (overload) {
                    Assert(parameters[1].Role == AbiRole.Parameter && parameters[1].Slot == 1
                        && parameters[1].Value.Size == 4
                        && parameters[1].Value.Kind == (parts[0] == "float-overload" ? AbiKind.Float : AbiKind.Integer),
                        "The declared overload argument must follow the dictionary in RDX or XMM1.");
                }
                if (templateCode != code)
                    ++forwarded;
                if (firstRecord < 0)
                    firstRecord = matched;

                audit.Append(parts[0]).Append('|').Append(parts[1]).Append('|')
                    .Append((templateCode - image.ImageBase).ToString("X")).Append('|').Append(parts[3]);
                for (int i = 4; i < parts.Length; ++i)
                    audit.Append('|').Append(parts[i]);
                audit.AppendLine();
                ++linked;
            }

            Assert(linked == 12 && exact == 1 && integerType != 0, "The fixture did not exercise every generic call.");
            string auditPath = Path.GetTempFileName();
            try {
                File.WriteAllText(auditPath, audit.ToString());
                Assert(Invoke(binary, auditPath, extended: true).Trim() == "12 callable templates validated.",
                    "The fixture did not validate all predicted template/dictionary calls.");
            } finally {
                File.Delete(auditPath);
            }

            CheckAbiRejections(extraction, firstRecord);
            CheckMutations(extraction, firstRecord, integerType);
            CheckArrayBounds(extraction, firstRecord, integerType);
            Console.WriteLine($"{Convert.ToHexStringLower(SHA256.HashData(image.FileData))}: twelve live template/dictionary calls agree, "
                + $"{forwarded} address-identity stubs, one exact body; concrete dictionary/return-buffer slots agree; conflicting evidence rejected.");
        }
    }

    private static void CheckAbiRejections(Extraction extraction, int recordIndex) {
        int templateIndex = extraction.Shared.Templates[recordIndex] - 1;
        var record = extraction.Generics.Methods[recordIndex];
        var template = extraction.Templates.Methods[templateIndex];
        var signature = extraction.Metadata.Signatures.Methods[record.Signature];
        int abiIndex = extraction.Maps.Methods.Count + recordIndex;

        for (int mutation = 0; mutation < 10; ++mutation) {
            var changed = template;
            var changedRecord = record;
            var changedSignature = signature;
            switch (mutation) {
                case 0: extraction.Shared.Templates[recordIndex] = 0; break;
                case 1: extraction.Shared.Templates[recordIndex] = -1; break;
                case 2: changed.Method.Entrypoint = 0; break;
                case 3: changed.UniversalCanonical = true; break;
                case 4: changed.AsyncVariant = true; break;
                case 5: changedRecord.AsyncVariant = true; break;
                case 6: changedSignature.CallingConvention |= 0x100; break;
                case 7: changedSignature.NativeConvention = false; changedSignature.CallingConvention = 0x15; break;
                case 8: changedSignature.ReturnType = 0; break;
                case 9: changed.Method.Flags |= 2; break;
            }
            extraction.Templates.Methods[templateIndex] = changed;
            extraction.Generics.Methods[recordIndex] = changedRecord;
            extraction.Metadata.Signatures.Methods[record.Signature] = changedSignature;

            var expected = mutation < 6 ? AbiStatus.NoEntrypoint : mutation == 6 ? AbiStatus.UnmanagedConvention
                : mutation == 7 ? AbiStatus.Varargs : AbiStatus.UnknownType;
            Assert(new ManagedAbi(extraction).Methods[abiIndex].Status == expected,
                $"Unsupported or incomplete shared ABI was accepted after mutation {mutation}.");

            extraction.Shared.Templates[recordIndex] = templateIndex + 1;
            extraction.Templates.Methods[templateIndex] = template;
            extraction.Generics.Methods[recordIndex] = record;
            extraction.Metadata.Signatures.Methods[record.Signature] = signature;
        }

        Assert(new ManagedAbi(extraction).Methods[abiIndex].Status == AbiStatus.SharedTemplate,
            "Restoring the template and signature must restore the shared ABI.");
    }

    private static void CheckMutations(Extraction extraction, int recordIndex, ulong integerType) {
        int templateIndex = extraction.Shared.Templates[recordIndex] - 1;
        var records = extraction.Generics.Methods;
        var templates = extraction.Templates.Methods;
        var record = records[recordIndex];
        var template = templates[templateIndex];
        ulong argument = extraction.Generics.Arguments[record.Arguments.Start];
        var other = templates.First(value => value.Method.Identity.Name == template.Method.Identity.Name
            && extraction.Metadata.Signatures.Methods[value.Method.Identity.Signature].Parameters.Count != 0);

        for (int mutation = 0; mutation < 10; ++mutation) {
            var changed = template;
            var changedRecord = record;
            switch (mutation) {
                case 0: templates.RemoveAt(templateIndex); break;
                case 1: changed.Method.Identity = other.Method.Identity; break;
                case 2: changed.Method.Identity.Name = "MissingMethod"; break;
                case 3: changed.Method.Arguments = default; break;
                case 4: extraction.Generics.Arguments[record.Arguments.Start] = integerType; break;
                case 5: changed.UniversalCanonical = true; break;
                case 6: changed.AsyncVariant = true; break;
                case 7: changedRecord.AsyncVariant = true; break;
                case 8: templates.Add(template); break;
                case 9: changedRecord.Dictionary = 0; break;
            }
            if (mutation != 0)
                templates[templateIndex] = changed;
            records[recordIndex] = changedRecord;

            int expected = mutation == 8 ? -1 : 0;
            Assert(new SharedMethods(extraction).Templates[recordIndex] == expected,
                $"Conflicting generic evidence was accepted after mutation {mutation}.");

            if (mutation == 0)
                templates.Insert(templateIndex, template);
            else if (mutation == 8)
                templates.RemoveAt(templates.Count - 1);
            templates[templateIndex] = template;
            records[recordIndex] = record;
            extraction.Generics.Arguments[record.Arguments.Start] = argument;
            Assert(new SharedMethods(extraction).Templates[recordIndex] == templateIndex + 1,
                $"Restoring evidence did not restore the unique template after mutation {mutation}.");
        }
    }

    private static void CheckArrayBounds(Extraction extraction, int recordIndex, ulong integerType) {
        var signatures = extraction.Metadata.Signatures;
        int templateIndex = extraction.Shared.Templates[recordIndex] - 1;
        var record = extraction.Generics.Methods[recordIndex];
        var template = extraction.Templates.Methods[templateIndex];

        // Binding caches borrow node identities, so these signatures live until this fixtures extraction is discarded
        int element = signatures.Nodes.Count;
        signatures.Nodes.Add(new SignatureNode { Kind = SignatureKind.RuntimeType, TypeAddress = integerType });
        for (int bound = 3; bound <= 4; ++bound) {
            signatures.Nodes.Add(new SignatureNode {
                Kind = SignatureKind.Array,
                Element = element,
                Value = 2,
                Sizes = new IndexRange(signatures.Edges.Count, 1)
            });
            signatures.Edges.Add(bound);
        }

        int left = element + 1, right = element + 2;
        var bindings = extraction.Fields.Bindings;
        Assert(bindings.Resolve(left) != 0 && bindings.Resolve(left) == bindings.Resolve(right),
            "Array-bound variants must share the fixture's actual multidimensional-array MethodTable; candidates: "
            + string.Join(", ", extraction.Types.Types.Where(type => type.Kind == 2 && type.ElementType == 0x17)
                .Select(type => $"0x{type.Address:X}/element=0x{type.RelatedType:X}/size={type.BaseSize}")));
        var signature = signatures.Methods[record.Signature];
        signature.ReturnType = left;
        var changedRecord = record;
        changedRecord.MetadataOffset = 0;
        changedRecord.Signature = signatures.Methods.Count;
        signatures.Methods.Add(signature);
        signature.ReturnType = right;
        var changedTemplate = template;
        changedTemplate.Method.Identity.MetadataOffset = 0;
        changedTemplate.Method.Identity.Signature = signatures.Methods.Count;
        signatures.Methods.Add(signature);
        extraction.Generics.Methods[recordIndex] = changedRecord;
        extraction.Templates.Methods[templateIndex] = changedTemplate;

        Assert(new SharedMethods(extraction).Templates[recordIndex] == 0,
            "Matching runtime array types must not erase distinct method-signature bounds.");
        signature.ReturnType = left;
        signatures.Methods[changedTemplate.Method.Identity.Signature] = signature;
        Assert(new SharedMethods(extraction).Templates[recordIndex] == templateIndex + 1,
            "Equal array signatures must restore the template match.");

        extraction.Generics.Methods[recordIndex] = record;
        extraction.Templates.Methods[templateIndex] = template;
    }

    private static string Invoke(string binary, string? auditPath = null, bool extended = false) {
        var start = new ProcessStartInfo(Path.GetFullPath(binary)) {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        if (auditPath != null)
            start.ArgumentList.Add(auditPath);
        if (extended)
            start.ArgumentList.Add("--abi");

        using var process = Process.Start(start)!;
        var error = process.StandardError.ReadToEndAsync();
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        Assert(process.ExitCode == 0, $"The shared-generic fixture failed: {error.GetAwaiter().GetResult()}");
        return output;
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new InvalidDataException(message);
    }
}
