using System.Diagnostics;

public sealed class DefaultSuiteTests {
    [Xunit.Fact]
    public void ConsoleAssertionsRunUnderDotnetTest() {
        var start = new ProcessStartInfo("dotnet") {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "Atlas.Tests.dll"));

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("Could not start the Atlas test executable.");
        string output = process.StandardOutput.ReadToEnd();
        string error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        Xunit.Assert.True(process.ExitCode == 0, $"Atlas test executable exited {process.ExitCode}: {error}\n{output}");
        Xunit.Assert.Contains("Native strings:", output);
        Xunit.Assert.Contains("Hydration boundaries:", output);
    }
}
