public sealed class DefaultSuiteTests {
    [Xunit.Fact]
    public void RtrEmptySections() => RtrEmptySectionChecks.Run();

    [Xunit.Fact]
    public void RtrSourceOwnership() => RtrSourceChecks.Run();

    [Xunit.Fact]
    public void TemplateRelations() => TemplateRelationChecks.Run();

    [Xunit.Fact]
    public void MethodControlFlow() => MethodControlFlowChecks.Run();

    [Xunit.Fact]
    public void ShortTailcalls() => ShortTailcallChecks.Run();

    [Xunit.Fact]
    public void Rtr32() => Rtr32Checks.Run();

    [Xunit.Fact]
    public void JsonOutput() => JsonOutputChecks.Run();

    [Xunit.Fact]
    public void MetadataFacts() => MetadataFactsChecks.Run();

    [Xunit.Fact]
    public void MetadataSignatures() => MetadataChecks.Run();

    [Xunit.Fact]
    public void MetadataValues() => MetadataValueChecks.Run();

    [Xunit.Fact]
    public void MetadataPayloads() => MetadataPayloadChecks.Run();

    [Xunit.Fact]
    public void OwnedReferences() => OwnedReferenceChecks.Run();

    [Xunit.Fact]
    public void OwnedCollections() => OwnedCollectionChecks.Run();

    [Xunit.Fact]
    public void TemplateFacts() => TemplateFactChecks.Run();

    [Xunit.Fact]
    public void NativeLayout() => NativeLayoutChecks.Run();

    [Xunit.Fact]
    public void NativeLayoutState() => NativeLayoutStateChecks.Run();

    [Xunit.Fact]
    public void NativeReaderSource() => NativeReaderSourceChecks.Run();

    [Xunit.Fact]
    public void SignatureRendering() => SignatureRenderChecks.Run();

    [Xunit.Fact]
    public void SignatureContexts() => SignatureContextChecks.Run();

    [Xunit.Fact]
    public void SignatureParserState() => SignatureParserStateChecks.Run();

    [Xunit.Fact]
    public void RuntimeNames() => RuntimeNameChecks.Run();

    [Xunit.Fact]
    public void MetadataIdentity() => MetadataIdentityChecks.Run();

    [Xunit.Fact]
    public void TypeGraphs() => TypeGraphChecks.Run();

    [Xunit.Fact]
    public void TypeBinding() => TypeBindingChecks.Run();

    [Xunit.Fact]
    public void SharedBindings() => SharedBindingChecks.Run();

    [Xunit.Fact]
    public void SignatureComparison() => SignatureComparisonChecks.Run();

    [Xunit.Fact]
    public void IterativeBinding() => IterativeBindingChecks.Run();

    [Xunit.Fact]
    public void RuntimeTypeIndex() => RuntimeTypeIndexChecks.Run();

    [Xunit.Fact]
    public void ImageWriteExtents() => FatWriteExtentChecks.Run();

    [Xunit.Fact]
    public void FrozenObjects() => FrozenChecks.Run();

    [Xunit.Fact]
    public void Unwind() => UnwindChecks.Run();

    [Xunit.Fact]
    public void ManagedUnwind() => ManagedUnwindChecks.Run();

    [Xunit.Fact]
    public void MethodGc() => MethodGcChecks.Run();

    [Xunit.Fact]
    public void TypeMaps() => TypeMapsChecks.Run();

    [Xunit.Fact]
    public void CodeFlow() => CodeFlowChecks.Run();

    [Xunit.Fact]
    public void PropertyAccess() => PropertyAccessCodeChecks.Run();

    [Xunit.Fact]
    public void NativeStrings() => NativeStringChecks.Run();

    [Xunit.Fact]
    public void Hydration() => HydrationChecks.Run();

    [Xunit.Fact]
    public void HydrationBoundaries() => HydrationBoundaryChecks.Run();
}
