using System.Collections.Generic;
using System.Text.Json.Serialization;
using InterceptSuite.Models;

namespace InterceptSuite.Json;

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(ExtensionConfiguration))]
[JsonSerializable(typeof(ExtensionConfigItem))]
[JsonSerializable(typeof(List<ExtensionConfigItem>))]
public partial class ExtensionJsonContext : JsonSerializerContext
{
}
