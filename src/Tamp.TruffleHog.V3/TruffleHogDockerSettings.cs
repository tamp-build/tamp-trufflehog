namespace Tamp.TruffleHog.V3;

/// <summary>
/// Settings for <c>trufflehog docker</c> — scan one or more Docker
/// images for embedded secrets. Pairs well with a <c>docker build</c>
/// gate just before push.
/// </summary>
public sealed class TruffleHogDockerSettings : TruffleHogSettingsBase
{
    /// <summary>Images to scan. Repeated as <c>--image &lt;name&gt;</c>. At least one required.</summary>
    public List<string> Images { get; } = [];

    public TruffleHogDockerSettings AddImage(string image) { Images.Add(image); return this; }

    protected override IEnumerable<string> BuildSourceArguments()
    {
        if (Images.Count == 0)
            throw new InvalidOperationException("trufflehog docker: at least one image is required.");
        yield return "docker";
        foreach (var img in Images) { yield return "--image"; yield return img; }
    }
}
