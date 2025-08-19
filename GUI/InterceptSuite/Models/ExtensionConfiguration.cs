using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace InterceptSuite.Models;

public class ExtensionConfiguration
{
    [JsonPropertyName("extensions")]
    public List<ExtensionConfigItem> Extensions { get; set; } = new();
}

public class ExtensionConfigItem
{
    [JsonPropertyName("path")]
    public string Path { get; set; } = string.Empty;

    [JsonPropertyName("isLoaded")]
    public bool IsLoaded { get; set; }
}
