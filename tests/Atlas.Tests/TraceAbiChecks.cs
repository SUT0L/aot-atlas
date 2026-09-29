using System.Diagnostics;
using Atlas;

internal static class TraceAbiChecks {
    internal static void Run(string binary, bool folded = false) {
        var image = new PeImage(File.ReadAllBytes(binary));
        var header = ReadyToRun.Read(image);
        var section = header.Find(313);
        var metadata = new Metadata(image.FileMemory(section.Start, checked((int)section.Length)), header.MetadataHandleBits, header.Major < 10);
        metadata.ReadDefinitions();
        var fixups = RuntimeTables.Fixups(image, header.Find(308));
        var maps = new ReflectionMaps();
        maps.Read(image, header, metadata, fixups, MapFormat.Auto);
        var extraction = new Extraction(image, header, metadata, maps, fixups);
        var abi = new ManagedAbi(extraction);
        var signatures = metadata.Signatures;
        var audit = new List<string>();
        var accepted = new Dictionary<string, int>();
        int rejected = 0;

        for (int i = 0; i < extraction.Traces.Methods.Count; ++i) {
            var trace = extraction.Traces.Methods[i];
            string owner = signatures.RenderType(trace.DeclaringType);
            if (owner is not ("TraceFunctions" or "TraceOwner" or "TraceCounter") && !owner.StartsWith("GenericOwner<", StringComparison.Ordinal)
                && !owner.StartsWith("GenericOwner`", StringComparison.Ordinal)) {
                continue;
            }

            int index = abi.RuntimeCount + i;
            var method = abi.Methods[index];
            if (trace.Name is "Generic" or "Scalar" or "Callback") {
                Assert(method.Status == (trace.Name == "Callback" ? AbiStatus.UnmanagedConvention : AbiStatus.GenericDefinition), trace.Name);
                ++rejected;
                continue;
            }
            if (trace.Name is not ("Signed" or "Mix" or "Large" or "ByRef" or "Add")) {
                continue;
            }

            Assert(method.Status == AbiStatus.TraceIdentity, $"{owner}::{trace.Name}: {method.Status}");
            Assert(!maps.Methods.Any(entry => entry.Entrypoint == trace.Entrypoint), "Fixture unexpectedly rooted reflection methods.");
            string name = owner == "TraceOwner" ? "OwnerLarge" : trace.Name;
            var parameters = abi.Parameters.AsSpan(method.Parameters.Start, method.Parameters.Count);
            switch (name) {
                case "Signed":
                    Assert(method.Return.Kind == AbiKind.Integer && method.Return.Size == 4 && parameters.Length == 1 && parameters[0].Slot == 0, name);
                    break;
                case "Mix":
                    Assert(method.Return.Kind == AbiKind.Float && method.Return.Size == 8 && parameters.Length == 5
                        && parameters[1].Value.Kind == AbiKind.Float && parameters[1].Slot == 1
                        && parameters[3].Value.Kind == AbiKind.Float && parameters[3].Slot == 3 && parameters[4].Slot == 4, name);
                    break;
                case "Large":
                    Assert(method.Return.Indirect && method.Return.Size == 24 && method.ReturnSlot == 0
                        && parameters.Length == 1 && parameters[0].Value.Indirect && parameters[0].Slot == 1, name);
                    break;
                case "OwnerLarge":
                    Assert(method.Return.Indirect && method.ReturnSlot == 1 && parameters.Length == 2
                        && parameters[0].Role == AbiRole.This && parameters[0].Value.Kind == AbiKind.Reference
                        && parameters[0].Slot == 0 && parameters[1].Slot == 2, name);
                    break;
                case "Add":
                    Assert(parameters.Length == 2 && parameters[0].Value.Kind == AbiKind.UnboxedReference
                        && parameters[0].Slot == 0 && parameters[1].Slot == 1 && method.UnboxedTarget == 0, name);
                    break;
                case "ByRef":
                    Assert(parameters.Length == 1 && parameters[0].Value.Kind == AbiKind.ByReference && parameters[0].Slot == 0, name);
                    break;
            }

            accepted.Add(name, index);
            audit.Add($"{name}|{trace.Entrypoint - image.ImageBase:X}");
        }

        Assert(accepted.Count == 6 && rejected == 3, $"Accepted {accepted.Count}, rejected {rejected}.");
        Assert(!abi.Compatible(extraction, accepted["Signed"], accepted["Signed"]), "Trace identity escaped into a global callable ABI.");
        Assert(!abi.Compatible(extraction, accepted["Signed"], accepted["ByRef"]), "Conflicting identity accepted.");

        int traceIndex = accepted["Signed"] - abi.RuntimeCount;
        var originalTrace = extraction.Traces.Methods[traceIndex];
        var originalSignature = signatures.Methods[originalTrace.Signature];
        for (int mutation = 0; mutation < 6; ++mutation) {
            var changedTrace = originalTrace;
            var changedSignature = originalSignature;
            AbiStatus expected;
            switch (mutation) {
                case 0: changedTrace.Hidden = true; expected = AbiStatus.HiddenRecord; break;
                case 1: changedTrace.DeclaringType = 0; expected = AbiStatus.UnknownType; break;
                case 2: changedSignature.GenericParameterCount = 1; expected = AbiStatus.GenericDefinition; break;
                case 3: changedSignature.CallingConvention = 0x40; expected = AbiStatus.UnmanagedConvention; break;
                case 4: changedSignature.NativeConvention = true; expected = AbiStatus.UnmanagedConvention; break;
                default: changedSignature.Varargs = changedSignature.Parameters; expected = AbiStatus.Varargs; break;
            }

            extraction.Traces.Methods[traceIndex] = changedTrace;
            signatures.Methods[originalTrace.Signature] = changedSignature;
            try {
                var changed = new ManagedAbi(extraction);
                Assert(changed.Methods[accepted["Signed"]].Status == expected, $"Mutation {mutation} accepted.");
            } finally {
                extraction.Traces.Methods[traceIndex] = originalTrace;
                signatures.Methods[originalTrace.Signature] = originalSignature;
            }
        }

        string path = Path.GetTempFileName();
        try {
            File.WriteAllLines(path, audit);
            var start = new ProcessStartInfo(Path.GetFullPath(binary)) { RedirectStandardOutput = true, RedirectStandardError = true };
            start.ArgumentList.Add(path);
            using var process = Process.Start(start)!;
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            Assert(process.ExitCode == 0 && output.Contains("PASS: six trace entrypoints", StringComparison.Ordinal), output + error);
            if (folded) {
                var aliases = output.Split('\n', StringSplitOptions.TrimEntries).Where(line => line.StartsWith("F|", StringComparison.Ordinal))
                    .Select(line => line.Split('|')).ToDictionary(parts => parts[1], parts => Convert.ToUInt64(parts[2], 16));
                Assert(aliases.Count == 2 && aliases["IntZero"] == aliases["NullObject"], "The fixture did not fold the incompatible signatures.");
                Assert(!extraction.Traces.Methods.Any(trace => trace.Name is "IntZero" or "NullObject"), "The folded trace aliases were unexpectedly retained.");
                Console.WriteLine($"IntZero and NullObject share RVA {aliases["IntZero"]:X}; neither identity survives in section 327.");
            }
        } finally {
            File.Delete(path);
        }

        Console.WriteLine($"{Path.GetFileName(binary)}: six trace-only physical ABIs verified; generic definitions, native callback, and conflicting signature rejected.");
    }

    private static void Assert(bool condition, string message) {
        if (!condition) {
            throw new InvalidDataException(message);
        }
    }
}
