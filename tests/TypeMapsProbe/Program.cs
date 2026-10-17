using System.Runtime.InteropServices;

[assembly: TypeMap<Maps>("alpha", typeof(Target))]
[assembly: TypeMap<Maps>("é😀", typeof(Target))]
#pragma warning disable IL2026 // NAOTs conditional trimming of map entries
[assembly: TypeMap<Maps>("conditional", typeof(Target), typeof(Source))]
[assembly: TypeMap<Maps>("trimmed", typeof(TrimmedTarget), typeof(Unused))]
#pragma warning restore IL2026
[assembly: TypeMapAssociation<Maps>(typeof(Source), typeof(Target))]
[assembly: TypeMapAssociation<Maps>(typeof(Source[]), typeof(Target))]
[assembly: TypeMapAssociation<Maps>(typeof(List<int>), typeof(Target))]
[assembly: TypeMapAssociation<Maps>(typeof(List<>), typeof(Target))]
[assembly: TypeMapAssociation<Maps>(typeof(Unused), typeof(TrimmedTarget))]
[assembly: TypeMap<Invalid>("duplicate", typeof(Source))]
[assembly: TypeMap<Invalid>("duplicate", typeof(Target))]
[assembly: TypeMapAssemblyTarget<Missing>("Atlas.TypeMaps.MissingAssembly")]

var external = TypeMapping.GetOrCreateExternalTypeMapping<Maps>();
foreach (string key in new[] { "alpha", "é😀", "conditional" }) {
    if (external[key] != typeof(Target))
        throw new Exception("Incorrect external mapping.");
    Console.WriteLine($"external|{key}|{external[key]}");
}

if (external.TryGetValue("trimmed", out _))
    throw new Exception("Unused conditional external mapping survived trimming.");

GC.KeepAlive(new Source());
GC.KeepAlive(new Source[1]);
GC.KeepAlive(new List<int>());
var proxy = TypeMapping.GetOrCreateProxyTypeMapping<Maps>();
foreach (Type source in new[] { typeof(Source), typeof(Source[]), typeof(List<int>), typeof(List<>) }) {
    if (proxy[source] != typeof(Target))
        throw new Exception("Incorrect proxy mapping.");
    Console.WriteLine($"proxy|{source}|{proxy[source]}");
}

if (TypeMapping.GetOrCreateExternalTypeMapping<Empty>().TryGetValue("missing", out _)
    || TypeMapping.GetOrCreateProxyTypeMapping<Empty>().TryGetValue(typeof(Source), out _))
    throw new Exception("Empty mapping contains entries.");

try {
    _ = TypeMapping.GetOrCreateExternalTypeMapping<Invalid>();
    throw new Exception("Duplicate external mapping accepted.");
} catch (BadImageFormatException) {
    Console.WriteLine("invalid|external|duplicate");
}

try {
    _ = TypeMapping.GetOrCreateExternalTypeMapping<Missing>();
    throw new Exception("Missing assembly accepted.");
} catch (FileNotFoundException) {
    Console.WriteLine("invalid|external|missing");
}

try {
    _ = TypeMapping.GetOrCreateProxyTypeMapping<Missing>();
    throw new Exception("Missing assembly accepted.");
} catch (FileNotFoundException) {
    Console.WriteLine("invalid|proxy|missing");
}

public class Maps;
public class Invalid;
public class Missing;
public class Empty;
public class Source;
public class Target;
public class Unused;
public class TrimmedTarget;
