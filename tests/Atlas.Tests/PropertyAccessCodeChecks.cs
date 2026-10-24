using Atlas;

internal static class PropertyAccessCodeChecks {
    private const ulong Start = 0x140001000;

    internal static void Run() {
        var value = new AbiValue { Kind = AbiKind.Value, Size = 16 };

        byte[] net9Getter = Convert.FromHexString(
            "5756488D7118488BFAE80A00000048A5488BC25E5FC39090C3");
        byte[] net9Setter = Convert.FromHexString(
            "5756488D7918488BF2E80A00000048A55E5FC39090909090C3");
        byte[] net8Getter = Convert.FromHexString(
            "575653488BDA488D7118488BFBE80E00000048A5488BC35B5E5FC39090909090C3");

        CheckCall(net9Getter, setter: false, value);
        CheckCall(net9Setter, setter: true, value);
        CheckCall(net8Getter, setter: false, value);

        net9Getter[9] = 0x90;
        var image = PeFixture.Create(net9Getter, ".text", 0x60000020);
        var withoutCall = new PropertyAccessCode(image).Read(Start, setter: false, value);
        if (withoutCall.Status == PropertyAccessStatus.HelperRequired)
            throw new Exception("A value accessor without a call was labelled as needing a helper.");

        Console.WriteLine("Property access: .NET 8 and 9 guarded value copies retain exact call witnesses and remain unprojected.");
    }

    private static void CheckCall(byte[] body, bool setter, AbiValue value) {
        var image = PeFixture.Create(body, ".text", 0x60000020);
        var access = new PropertyAccessCode(image).Read(Start, setter, value);
        if (access.Status != PropertyAccessStatus.HelperRequired
            || access.Body != Start
            || access.FirstInstruction != Start
            || access.Helper != Start + (body.Length == 33 ? 32UL : 24UL))
            throw new Exception("Guarded value copy lost its call target or was accepted without helper proof.");
    }
}
