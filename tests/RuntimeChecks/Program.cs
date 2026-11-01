if (args is ["--native-integers"])
    NativeIntegerChecks.Run();
else
    RuntimeChecks.Run(args);
