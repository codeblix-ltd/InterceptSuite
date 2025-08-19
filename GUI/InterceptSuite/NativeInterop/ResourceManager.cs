using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Linq;

namespace InterceptSuite.NativeInterop
{
    public static class ResourceManager
    {
        private const string ResourceDir = "resource";
        private const string WindowsLibName = "Intercept.dll";
        private const string LinuxLibName = "libIntercept.so";
        private const string MacOSLibName = "libIntercept.dylib";
        private const string MacOSAppPath = "/Applications/InterceptSuite Standard.app/Contents/Frameworks";

        public static string GetNativeLibraryPath()
        {
            string libraryName = GetLibraryName();
            string appDirectory = AppDomain.CurrentDomain.BaseDirectory;

            string[] searchPaths;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                searchPaths = new[]
                {
                    Environment.GetEnvironmentVariable("INTERCEPT_LIB_PATH"),
                    "/usr/lib/InterceptSuite Standard/",
                    "/usr/local/lib/InterceptSuite Standard/",
                    "/opt/InterceptSuite Standard/lib/",
                    Path.Combine(appDirectory, ResourceDir),
                    Path.Combine(appDirectory, "..", "..", "..", ResourceDir),
                    appDirectory
                }.Where(path => !string.IsNullOrEmpty(path)).ToArray()!;
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                searchPaths = new[]
                {
                    MacOSAppPath,
                    Path.Combine(appDirectory, "..", "Frameworks"),
                    appDirectory
                };
            }
            else
            {
                searchPaths = new[]
                {
                    Path.Combine(appDirectory, ResourceDir),
                    Path.Combine(appDirectory, "..", "..", "..", ResourceDir),
                    appDirectory
                };
            }

            foreach (string searchPath in searchPaths)
            {
                try {
                    string fullPath = Path.GetFullPath(Path.Combine(searchPath, libraryName));

                    if (File.Exists(fullPath))
                    {
                        return fullPath;
                    }
                }
                catch {
                }
            }

            throw new FileNotFoundException($"Native library '{libraryName}' not found in any of the search paths.");
        }

        public static string GetResourceDirectory()
        {
            string appDirectory = AppDomain.CurrentDomain.BaseDirectory;
            string resourceDirectory = Path.Combine(appDirectory, ResourceDir);

            if (!Directory.Exists(resourceDirectory))
            {
                string devResourceDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", ResourceDir);
                string absoluteDevPath = Path.GetFullPath(devResourceDirectory);

                if (Directory.Exists(absoluteDevPath))
                    return absoluteDevPath;

                Directory.CreateDirectory(resourceDirectory);
            }

            return resourceDirectory;
        }

        /// <summary>
        /// Gets the appropriate library name based on the current platform
        /// </summary>
        private static string GetLibraryName()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return WindowsLibName;
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return LinuxLibName;
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                return MacOSLibName;
            else
                throw new PlatformNotSupportedException("Current platform is not supported");
        }

        public static bool TryPreloadNativeLibrary(out string? errorMessage)
        {
            try
            {
                string libPath = GetNativeLibraryPath();

                if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    try
                    {
                        // Try using NativeLibrary
                        var handle = System.Runtime.InteropServices.NativeLibrary.Load(libPath);
                        System.Runtime.InteropServices.NativeLibrary.Free(handle);
                    }
                    catch (Exception ex)
                    {
                        errorMessage = ex.Message;
                        return false;
                    }
                }

                errorMessage = null;
                return true;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return false;
            }
        }
    }
}
