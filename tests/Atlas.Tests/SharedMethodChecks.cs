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
            var metadata = MetadataBuilder.FromImage(image, header);
            metadata.ReadDefinitions();

            var fixups = RuntimeTables.Fixups(image, header.Find(308));
            var maps = new ReflectionMaps();
            maps.Read(image, header, metadata, fixups, MapFormat.Auto);

            var extraction = new Extraction(image, header, metadata, maps, fixups);
            var shared = extraction.Shared;
            var abi = new ManagedAbi(extraction, extraction.Signatures);

            string[] lines = Invoke(binary, extended: true).Split(
                '\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            Assert(lines.Length == 13, "The fixture must expose twelve shared calls and one exact call.");

            var audit = new StringBuilder();

            int linked = 0;
            int forwarded = 0;
            int exact = 0;

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
                    + string.Join(", ", abi.Parameters
                        .AsSpan(methodAbi.Parameters.Start, methodAbi.Parameters.Count)
                        .ToArray()
                        .Select(parameter =>
                            $"{parameter.Role}:{parameter.Value.Kind}/binding={parameter.Value.Binding}/signature={parameter.Value.Signature}")));

                var parameters = abi.Parameters.AsSpan(methodAbi.Parameters.Start, methodAbi.Parameters.Count);
                bool instance = parts[0] is "instance" or "value-instance";
                bool pair = parts[0] == "pair" || instance;
                Assert(methodAbi.Return.Kind == (pair ? AbiKind.Value : AbiKind.Integer)
                    && methodAbi.Return.Size == (pair ? 24U : 8U)
                    && methodAbi.Return.Indirect == pair
                    && methodAbi.ReturnSlot == (instance ? 1 : 0),
                    "The fixture return must be NativeInt in RAX or TypePair through RCX/RDX after an optional receiver.");

                bool overload = parts[0] is "int-overload" or "float-overload";
                int context = instance ? 1 : 0;
                Assert(parameters.Length == (instance ? 3 : overload ? 2 : 1)
                    && parameters[context].Role == AbiRole.GenericContext
                    && parameters[context].Value.Kind == AbiKind.Context
                    && parameters[context].Value.Size == 8
                    && parameters[context].Slot == (instance ? 2 : pair ? 1 : 0),
                    "The dictionary must follow the receiver and return buffer.");

                if (instance) {
                    Assert(parameters[0].Role == AbiRole.This
                        && parameters[0].Slot == 0 && parameters[0].Value.Size == 8
                        && parameters[0].Value.Binding == extraction.Types.Index[owner] + 1
                        && parameters[0].Value.Kind == (parts[0] == "value-instance"
                            ? AbiKind.BoxedReference : AbiKind.Reference)
                        && parameters[2].Role == AbiRole.Parameter && parameters[2].Slot == 3
                        && parameters[2].Value.Kind == AbiKind.Integer && parameters[2].Value.Size == 8,
                        $"The direct instance template must receive this in RCX and the declared Int64 argument in R9: {line}; owner={extraction.Types.Index[owner] + 1}, "
                        + string.Join(", ", parameters.ToArray()
                            .Select(parameter =>
                                $"{parameter.Role}:{parameter.Value.Kind}/binding={parameter.Value.Binding}/size={parameter.Value.Size}/slot={parameter.Slot}")));
                }

                if (overload) {
                    Assert(parameters[1].Role == AbiRole.Parameter && parameters[1].Slot == 1
                        && parameters[1].Value.Size == 4
                        && parameters[1].Value.Kind == (parts[0] == "float-overload" ? AbiKind.Float : AbiKind.Integer),
                        "The declared overload argument must follow the dictionary in RDX or XMM1.");
                }

                if (templateCode != code)
                    ++forwarded;

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

            Console.WriteLine($"{Convert.ToHexStringLower(SHA256.HashData(image.FileData))}: twelve live template/dictionary calls agree, "
                + $"{forwarded} address-identity stubs, one exact body; concrete dictionary/return-buffer slots agree.");
        }
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
