using Microsoft.Win32;

namespace SionyxKiosk.Infrastructure;

/// <summary>
/// Reads SIONYX configuration from Windows Registry for production builds.
/// Development builds continue to use .env files.
/// </summary>
public static class RegistryConfig
{
    private const string RegistryKey = @"SOFTWARE\SIONYX";

    /// <summary>
    /// Check if running as a published/packaged executable.
    /// In .NET single-file publish, the entry assembly location will differ.
    /// </summary>
    public static bool IsProduction()
    {
        // In production, we expect the registry key to exist.
        // This mirrors the Python frozen check — production builds write to registry during install.
        return RegistryConfigExists();
    }

    /// <summary>
    /// Read a single value from the SIONYX registry key.
    /// </summary>
    public static string? ReadValue(string name, string? defaultValue = null)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryKey);
            if (key == null) return defaultValue;

            var value = key.GetValue(name);
            return value?.ToString() ?? defaultValue;
        }
        catch (Exception)
        {
            return defaultValue;
        }
    }

    /// <summary>
    /// Read all SIONYX configuration from registry.
    /// </summary>
    public static Dictionary<string, string?> GetAllConfig()
    {
        return new Dictionary<string, string?>
        {
            // Required values
            ["OrgId"] = ReadValue("OrgId"),
            ["ComputerName"] = ReadValue("ComputerName"),
            ["ApiKey"] = ReadValue("FirebaseApiKey"),
            ["AuthDomain"] = ReadValue("FirebaseAuthDomain"),
            ["ProjectId"] = ReadValue("FirebaseProjectId"),
            ["DatabaseUrl"] = ReadValue("FirebaseDatabaseUrl"),
            // Optional values
            ["StorageBucket"] = ReadValue("FirebaseStorageBucket"),
            ["MessagingSenderId"] = ReadValue("FirebaseMessagingSenderId"),
            ["AppId"] = ReadValue("FirebaseAppId"),
            ["MeasurementId"] = ReadValue("FirebaseMeasurementId"),
            // Optional: base URL for HTTP function-equivalents (e.g. a Render
            // service standing in for Cloud Functions that require Blaze).
            ["FunctionsBaseUrl"] = ReadValue("FunctionsBaseUrl"),
        };
    }

    /// <summary>
    /// Check if SIONYX registry key exists with required values.
    /// </summary>
    public static string? ReadValueCurrentUser(string name, string? defaultValue = null)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RegistryKey);
            if (key == null) return defaultValue;
            var value = key.GetValue(name);
            return value?.ToString() ?? defaultValue;
        }
        catch (Exception)
        {
            return defaultValue;
        }
    }

    public static bool WriteValue(string name, string value)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(RegistryKey, writable: true);
            if (key == null) return false;
            key.SetValue(name, value, RegistryValueKind.String);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static bool RegistryConfigExists()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryKey);
            if (key == null) return false;

            var orgId = key.GetValue("OrgId");
            return orgId != null;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
