using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using Serilog;
using SionyxKiosk.Infrastructure;
using SionyxKiosk.Models;
using SionyxKiosk.Services;

namespace SionyxKiosk.Views.Dialogs;

/// <summary>
/// Payment dialog with WebView2 bridge.
/// Loads payment.html via LocalFileServer, communicates with JS via PostWebMessage.
/// </summary>
public partial class PaymentDialog : Window
{
    private static readonly ILogger Logger = Log.ForContext<PaymentDialog>();

    private readonly PurchaseService _purchaseService;
    private readonly OrganizationMetadataService _metadataService;
    private readonly string _userId;
    private readonly Package _package;
    private readonly FirebaseClient _firebase;

    private LocalFileServer? _server;
    private string? _purchaseId;
    private SseListener? _statusListener;

    public bool PaymentSucceeded { get; private set; }

    public PaymentDialog(
        PurchaseService purchaseService,
        OrganizationMetadataService metadataService,
        FirebaseClient firebase,
        string userId,
        Package package)
    {
        _purchaseService = purchaseService;
        _metadataService = metadataService;
        _firebase = firebase;
        _userId = userId;
        _package = package;

        InitializeComponent();
        PopulatePackageSummary();
        Loaded += OnLoaded;
        Closed += OnClosed;
        ContentRendered += OnContentRendered;
    }

    private void OnContentRendered(object? sender, EventArgs e)
    {
        var screenH = SystemParameters.PrimaryScreenHeight;
        var screenW = SystemParameters.PrimaryScreenWidth;

        var dialogH = Math.Clamp(screenH * 0.75, 480, 820);
        var dialogW = Math.Clamp(screenW * 0.55, 700, 1040);

        SummaryColumn.Width = new GridLength(Math.Clamp(dialogW * 0.35, 240, 360));

        DialogCard.Width = dialogW;
        DialogCard.Height = dialogH;

        Logger.Debug("Payment dialog sized to {W}x{H} (screen {SW}x{SH})",
            dialogW, dialogH, screenW, screenH);
    }

    private void PopulatePackageSummary()
    {
        PackageNameText.Text = _package.Name;
        PackageMinutesText.Text = $"{_package.Minutes} דקות";
        PackagePrintsText.Text = $"{_package.Prints}₪";
        PackageValidityText.Text = _package.ValidityDisplay;

        if (_package.HasDiscount)
        {
            OriginalPriceText.Text = $"₪{_package.Price:F0}";
            OriginalPriceText.Visibility = Visibility.Visible;
            PackagePriceText.Text = $"₪{_package.FinalPrice:F0}";
            DiscountBadge.Visibility = Visibility.Visible;
            DiscountBadgeText.Text = $"חסכת ₪{_package.Savings:F0}";
        }
        else
        {
            PackagePriceText.Text = $"₪{_package.Price:F0}";
        }
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            // Start local file server to serve payment.html
            var templatesDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "templates");
            _server = new LocalFileServer(templatesDir, 0); // Port 0 = auto-pick free port
            _server.Start();

            // Initialize WebView2 with a writable user data folder
            var webView2DataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SIONYX", "WebView2");

            CoreWebView2Environment env;
            try
            {
                env = await CoreWebView2Environment.CreateAsync(null, webView2DataDir);
            }
            catch (WebView2RuntimeNotFoundException)
            {
                Logger.Warning("WebView2 Runtime not found — attempting automatic install");
                var installed = await InstallWebView2Async();
                if (!installed)
                {
                    MessageBox.Show("שגיאה בטעינת דף התשלום", "שגיאה", MessageBoxButton.OK, MessageBoxImage.Error);
                    Close();
                    return;
                }
                // Retry after install
                env = await CoreWebView2Environment.CreateAsync(null, webView2DataDir);
            }

            await PaymentWebView.EnsureCoreWebView2Async(env);
            PaymentWebView.CoreWebView2.WebMessageReceived += OnWebMessageReceived;

            // Navigate to payment page
            var url = _server.BaseUrl + "payment.html";
            Logger.Information("Loading payment page: {Url}", url);
            PaymentWebView.CoreWebView2.Navigate(url);

            // Wait for page load, then inject config
            PaymentWebView.CoreWebView2.NavigationCompleted += async (_, args) =>
            {
                if (!args.IsSuccess) return;
                await InjectConfigAsync();
            };
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "Failed to load payment dialog");
            MessageBox.Show("שגיאה בטעינת דף התשלום", "שגיאה", MessageBoxButton.OK, MessageBoxImage.Error);
            Close();
        }
    }

    /// <summary>
    /// Downloads and silently installs WebView2 Evergreen Runtime.
    /// Returns true if install succeeded.
    /// </summary>
    private async Task<bool> InstallWebView2Async()
    {
        try
        {
            // Use unique filename to avoid file-lock conflicts on retry
            var installerPath = Path.Combine(
                Path.GetTempPath(),
                $"MicrosoftEdgeWebview2Setup_{Guid.NewGuid():N}.exe");

            Logger.Information("Downloading WebView2 bootstrapper to {Path}...", installerPath);
            using var httpClient = new HttpClient();
            httpClient.Timeout = TimeSpan.FromMinutes(3);
            var bytes = await httpClient.GetByteArrayAsync(
                "https://go.microsoft.com/fwlink/p/?LinkId=2124703");
            await File.WriteAllBytesAsync(installerPath, bytes);

            Logger.Information("Installing WebView2...");
            var process = System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo
                {
                    FileName = installerPath,
                    Arguments = "/silent /install",
                    UseShellExecute = true,
                    Verb = "runas"
                });

            if (process == null)
            {
                Logger.Error("Failed to start WebView2 installer process");
                return false;
            }

            await process.WaitForExitAsync();
            Logger.Information("WebView2 installer exit code: {Code}", process.ExitCode);

            // Give the runtime a moment to register after install
            await Task.Delay(TimeSpan.FromSeconds(2));

            // Clean up installer
            try { File.Delete(installerPath); } catch { }

            // Exit code 0 = success, 3010 = success + reboot needed
            return process.ExitCode is 0 or 3010;
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "Failed to install WebView2");
            return false;
        }
    }

    private async Task InjectConfigAsync()
    {
        try
        {
            var metaResult = await _metadataService.GetOrganizationMetadataAsync(_firebase.OrgId);
            var mosadId = "";
            var apiValid = "";

            if (metaResult.IsSuccess && metaResult.Data != null)
            {
                var dataType = metaResult.Data.GetType();

                if (dataType.GetProperty("nedarim_mosad_id")?.GetValue(metaResult.Data) is JsonElement mosadEl)
                    mosadId = mosadEl.ValueKind == JsonValueKind.String ? mosadEl.GetString() ?? "" : mosadEl.ToString();

                if (dataType.GetProperty("nedarim_api_valid")?.GetValue(metaResult.Data) is JsonElement apiEl)
                    apiValid = apiEl.ValueKind == JsonValueKind.String ? apiEl.GetString() ?? "" : apiEl.ToString();
            }

            if (string.IsNullOrEmpty(mosadId) || string.IsNullOrEmpty(apiValid))
                Logger.Warning(
                    "Nedarim credentials missing for OrgId={OrgId} — payment will fail. " +
                    "MetaResult.Success={Success} MetaResult.Error={Error} mosadId.IsEmpty={MosadEmpty} apiValid.IsEmpty={ApiEmpty}",
                    _firebase.OrgId, metaResult.IsSuccess, metaResult.Error, string.IsNullOrEmpty(mosadId), string.IsNullOrEmpty(apiValid));

            // Read payment settings (save card feature)
            var saveCardEnabled = false;
            var saveCardApiValid = "";
            var paymentSettingsResult = await _firebase.DbGetAsync("metadata/settings/payment");
            if (paymentSettingsResult.Success && paymentSettingsResult.Data is JsonElement paymentData
                && paymentData.ValueKind == JsonValueKind.Object)
            {
                saveCardEnabled = paymentData.TryGetProperty("saveCardEnabled", out var sce) && sce.GetBoolean();
                saveCardApiValid = paymentData.TryGetProperty("nedarimApiValid", out var scav)
                    ? scav.GetString() ?? "" : "";
            }
            Logger.Information("Payment settings: saveCard={SaveCard}", saveCardEnabled);

            // Uses the same base-URL override as CallFunctionAsync so both
            // point at the Render bridge when configured (see FirebaseConfig.
            // FunctionsBaseUrl), falling back to Cloud Functions otherwise.
            var callbackUrl = string.IsNullOrEmpty(_firebase.FunctionsBaseUrl)
                ? $"https://us-central1-{_firebase.ProjectId}.cloudfunctions.net/nedarimCallback"
                : $"{_firebase.FunctionsBaseUrl}/nedarimCallback";
            // Check if user has a saved card
            var savedKevaId = "";
            var userResult = await _firebase.DbGetAsync($"users/{_userId}");
            if (userResult.Success && userResult.Data is JsonElement userData)
            {
                if (userData.TryGetProperty("savedCard", out var sc) &&
                    sc.TryGetProperty("kevaId", out var keva))
                    savedKevaId = keva.GetString() ?? "";
            }

            var config = new
            {
                mosadId,
                apiValid,
                amount = _package.DisplayPrice.ToString("F0"),
                packageName = _package.Name ?? "",
                packageMinutes = _package.Minutes.ToString(),
                packagePrints = _package.Prints.ToString(),
                userName = "",
                orgId = _firebase.OrgId,
                callbackUrl,
                saveCardEnabled,
                saveCardApiValid,
                savedKevaId
            };

            var message = JsonSerializer.Serialize(new { action = "setConfig", config });
            PaymentWebView.CoreWebView2.PostWebMessageAsJson(message);

            Logger.Information("Payment config injected for package: {Package} amount: {Amount}",
                _package.Name, _package.DisplayPrice);
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "Failed to inject payment config");
        }
    }

    private async void OnWebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        try
        {
            var json = e.WebMessageAsJson;
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var action = root.GetProperty("action").GetString();

            switch (action)
            {
                case "createPendingPurchase":
                    await HandleCreatePurchaseAsync();
                    break;

                case "paymentSuccess":
                    await HandlePaymentSuccessAsync(root);
                    break;

                case "chargeWithSavedCard":
                    await HandleChargeWithSavedCardAsync();
                    break;
                case "deleteCard":
                    await HandleDeleteCardAsync();
                    break;
                case "close":
                    var success = root.TryGetProperty("success", out var s) && s.GetBoolean();
                    PaymentSucceeded = success;
                    _ = Dispatcher.InvokeAsync(Close);
                    break;
            }
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "Error handling web message");
        }
    }

    private async Task HandleCreatePurchaseAsync()
    {
        try
        {
            var result = await _purchaseService.CreatePendingPurchaseAsync(_userId, _package);
            if (result.IsSuccess && result.Data is { } data)
            {
                // Extract purchaseId from anonymous object
                var type = data.GetType();
                _purchaseId = type.GetProperty("purchaseId")?.GetValue(data)?.ToString() ?? "";

                // Start listening for purchase status changes
                StartPurchaseStatusListener(_purchaseId);

                // Post purchase ID back to JS
                var msg = JsonSerializer.Serialize(new { action = "purchaseCreated", purchaseId = _purchaseId });
                _ = Dispatcher.InvokeAsync(() => PaymentWebView.CoreWebView2.PostWebMessageAsJson(msg));
                Logger.Information("Pending purchase created: {PurchaseId}", _purchaseId);
            }
            else
            {
                var errorMsg = JsonSerializer.Serialize(new { action = "purchaseError", error = result.Error ?? "שגיאה" });
                _ = Dispatcher.InvokeAsync(() => PaymentWebView.CoreWebView2.PostWebMessageAsJson(errorMsg));
            }
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "Failed to create pending purchase");
            var errorMsg = JsonSerializer.Serialize(new { action = "purchaseError", error = "שגיאה ביצירת רכישה" });
            _ = Dispatcher.InvokeAsync(() => PaymentWebView.CoreWebView2.PostWebMessageAsJson(errorMsg));
        }
    }

    // Note: the actual Nedarim TashlumBodedNew call and crediting now happen entirely
    // server-side in the chargeWithSavedCard Cloud Function. This keeps ApiPassword
    // (a real Nedarim business secret) out of the kiosk client, and ensures saved-card
    // charges go through the same idempotency/amount-verification path as the regular
    // iframe + nedarimCallback flow, instead of crediting blindly right after a
    // synchronous "OK" response with no server-side check at all.
    private async Task HandleChargeWithSavedCardAsync()
    {
        try
        {
            // Create pending purchase first
            var result = await _purchaseService.CreatePendingPurchaseAsync(_userId, _package);
            if (!result.IsSuccess || result.Data is not { } data)
            {
                Logger.Warning("Saved-card charge aborted: failed to create pending purchase. Error={Error}", result.Error);
                var errMsg = JsonSerializer.Serialize(new { action = "purchaseError", error = result.Error ?? "שגיאה" });
                _ = Dispatcher.InvokeAsync(() => PaymentWebView.CoreWebView2.PostWebMessageAsJson(errMsg));
                return;
            }
            var type = data.GetType();
            _purchaseId = type.GetProperty("purchaseId")?.GetValue(data)?.ToString() ?? "";
            Logger.Information("Pending purchase created for saved card: {PurchaseId}", _purchaseId);

            // Read savedKevaId from Firebase (only used to send to the server for
            // cross-checking - the server re-reads it from the user's own record
            // anyway and never trusts this value blindly).
            var savedKevaId = "";
            var userResult = await _firebase.DbGetAsync($"users/{_userId}");
            if (userResult.Success && userResult.Data is JsonElement userData)
            {
                if (userData.TryGetProperty("savedCard", out var sc) &&
                    sc.TryGetProperty("kevaId", out var keva))
                    savedKevaId = keva.GetString() ?? "";
            }
            if (string.IsNullOrEmpty(savedKevaId))
            {
                Logger.Warning("Saved-card charge aborted: no savedKevaId found for user {UserId}", _userId);
                var errMsg = JsonSerializer.Serialize(new { action = "purchaseError", error = "לא נמצא כרטיס שמור" });
                _ = Dispatcher.InvokeAsync(() => PaymentWebView.CoreWebView2.PostWebMessageAsJson(errMsg));
                return;
            }

            Logger.Information("Calling chargeWithSavedCard function: OrgId={OrgId} PurchaseId={PurchaseId} KevaIdSuffix={KevaIdSuffix}",
                _firebase.OrgId, _purchaseId, savedKevaId.Length > 4 ? savedKevaId[^4..] : savedKevaId);

            var callResult = await _firebase.CallFunctionAsync("chargeWithSavedCard", new
            {
                orgId = _firebase.OrgId,
                purchaseId = _purchaseId,
                kevaId = savedKevaId,
            });

            if (!callResult.Success)
            {
                Logger.Error("chargeWithSavedCard function call failed: {Error}", callResult.Error);
                var errMsg = JsonSerializer.Serialize(new { action = "purchaseError", error = callResult.Error ?? "שגיאה בעיבוד תשלום" });
                _ = Dispatcher.InvokeAsync(() => PaymentWebView.CoreWebView2.PostWebMessageAsJson(errMsg));
                return;
            }

            // The function returns { success, message/error, correlationId, optionUsed }
            // optionUsed tells us which of the numbered TashlumBodedNew parameter
            // strategies (see chargeWithSavedCard in functions/index.js) actually
            // got a response from Nedarim. Logged here too so it shows up in the
            // kiosk's own public logs (C:\Users\Public\Documents\SIONYX\logs\)
            // alongside everything else - once one option is confirmed working
            // consistently in production, the others should be deleted from the
            // Cloud Function.
            var resultData = (JsonElement)callResult.Data!;
            var success = resultData.TryGetProperty("success", out var sEl) && sEl.GetBoolean();
            var correlationId = resultData.TryGetProperty("correlationId", out var cEl) ? cEl.GetString() : null;
            var optionUsed = resultData.TryGetProperty("optionUsed", out var oEl) && oEl.ValueKind == JsonValueKind.Number
                ? oEl.GetInt32().ToString()
                : "none-succeeded";

            if (success)
            {
                Logger.Information("Saved-card charge succeeded server-side via [OPTION {OptionUsed}]. PurchaseId={PurchaseId} CorrelationId={CorrelationId}",
                    optionUsed, _purchaseId, correlationId);
                PaymentSucceeded = true;
                var successMsg = JsonSerializer.Serialize(new { action = "showSuccess" });
                _ = Dispatcher.InvokeAsync(() => PaymentWebView.CoreWebView2.PostWebMessageAsJson(successMsg));
            }
            else
            {
                var errorText = resultData.TryGetProperty("error", out var eEl) ? eEl.GetString() ?? "שגיאה" : "שגיאה";
                Logger.Warning("Saved-card charge declined by server via [OPTION {OptionUsed}]. PurchaseId={PurchaseId} Error={Error} CorrelationId={CorrelationId}",
                    optionUsed, _purchaseId, errorText, correlationId);
                var errMsg = JsonSerializer.Serialize(new { action = "purchaseError", error = errorText });
                _ = Dispatcher.InvokeAsync(() => PaymentWebView.CoreWebView2.PostWebMessageAsJson(errMsg));
            }
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "Failed to charge with saved card. PurchaseId={PurchaseId}", _purchaseId);
            var errMsg = JsonSerializer.Serialize(new { action = "purchaseError", error = "שגיאה בעיבוד תשלום" });
            _ = Dispatcher.InvokeAsync(() => PaymentWebView.CoreWebView2.PostWebMessageAsJson(errMsg));
        }
    }

    private async Task HandleDeleteCardAsync()
    {
        try
        {
            await _firebase.DbUpdateAsync($"users/{_userId}", new Dictionary<string, object> { ["savedCard"] = null! });
            Logger.Information("Saved card deleted for user {UserId}", _userId);
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "Failed to delete saved card");
        }
        finally
        {
            // Notify JS regardless of outcome, so the UI doesn't stay stuck waiting for a confirmation
            // that will never come. If deletion failed, the user will simply see the iframe again
            // and can retry payment normally; savedKevaId will still be present on next dialog open
            // if the Firebase write truly failed.
            var msg = JsonSerializer.Serialize(new { action = "cardDeleted" });
            _ = Dispatcher.InvokeAsync(() => PaymentWebView.CoreWebView2.PostWebMessageAsJson(msg));
        }
    }

    /// <summary>
    /// Called when the Nedarim iframe reports the transaction itself succeeded
    /// (card was charged / token created). This does NOT credit the user -
    /// crediting is the Cloud Function nedarimCallback's job, triggered by
    /// Nedarim's server-to-server callback, which is the only place that can
    /// safely guarantee idempotency and amount verification. The kiosk just
    /// shows a "processing" state and waits for purchases/{id}/status to flip
    /// to "completed" via the SSE listener (started in HandleCreatePurchaseAsync)
    /// or the polling fallback if SSE drops.
    /// </summary>
    private Task HandlePaymentSuccessAsync(JsonElement root)
    {
        Logger.Information("Payment success received from JS (transaction OK, awaiting server credit) - raw: {Raw}", root.ToString());

        if (string.IsNullOrEmpty(_purchaseId))
        {
            Logger.Warning("HandlePaymentSuccessAsync called with no active purchaseId");
            return Task.CompletedTask;
        }

        // Show "processing" UI and kick off the polling fallback in case the
        // SSE listener (already running since purchase creation) misses the
        // update for any reason (dropped connection, etc).
        _ = Dispatcher.InvokeAsync(() =>
        {
            var msg = JsonSerializer.Serialize(new { action = "savedCardCharging" });
            PaymentWebView.CoreWebView2.PostWebMessageAsJson(msg);
        });
        _ = PollPurchaseStatusAsync();

        return Task.CompletedTask;
    }

    private Task ShowTimeoutAsync()
    {
        _ = Dispatcher.InvokeAsync(() =>
        {
            var msg = System.Text.Json.JsonSerializer.Serialize(new { action = "showTimeout" });
            PaymentWebView.CoreWebView2.PostWebMessageAsJson(msg);
        });
        return Task.CompletedTask;
    }

    private void StartPurchaseStatusListener(string purchaseId)
    {
        _statusListener?.Stop();
        _statusListener = _firebase.DbListen($"purchases/{purchaseId}/status", (eventType, data) =>
        {
            if (eventType != "put" || data == null || !data.HasValue) return;
            var status = data.Value.ValueKind == JsonValueKind.String ? data.Value.GetString() : null;

            if (status is "completed" or "approved")
            {
                Logger.Information("Purchase {Id} completed via SSE (server-side credit confirmed)", purchaseId);
                _ = Dispatcher.InvokeAsync(() =>
                {
                    PaymentSucceeded = true;
                    var msg = JsonSerializer.Serialize(new { action = "showSuccess" });
                    PaymentWebView.CoreWebView2.PostWebMessageAsJson(msg);
                });
            }
            else if (status == "failed")
            {
                Logger.Warning("Purchase {Id} marked failed via SSE", purchaseId);
                _ = Dispatcher.InvokeAsync(() =>
                {
                    var msg = JsonSerializer.Serialize(new { action = "purchaseError", error = "התשלום נכשל. אם חויבת, נא לפנות לתמיכה." });
                    PaymentWebView.CoreWebView2.PostWebMessageAsJson(msg);
                });
            }
        });
    }

    private async Task PollPurchaseStatusAsync()
    {
        if (string.IsNullOrEmpty(_purchaseId)) return;

        for (int i = 0; i < 10; i++)
        {
            if (PaymentSucceeded) return;

            await Task.Delay(TimeSpan.FromSeconds(2));
            var result = await _firebase.DbGetAsync($"purchases/{_purchaseId}");
            if (result.Success && result.Data is JsonElement data && data.ValueKind == JsonValueKind.Object)
            {
                var status = data.TryGetProperty("status", out var s) ? s.GetString() : null;
                if (status is "completed" or "approved")
                {
                    Logger.Information("Purchase {Id} confirmed via polling", _purchaseId);
                    _ = Dispatcher.InvokeAsync(() =>
                    {
                        PaymentSucceeded = true;
                        var msg = JsonSerializer.Serialize(new { action = "showSuccess" });
                        PaymentWebView.CoreWebView2.PostWebMessageAsJson(msg);
                    });
                    return;
                }
                if (status == "failed")
                {
                    Logger.Warning("Purchase {Id} marked failed via polling", _purchaseId);
                    _ = Dispatcher.InvokeAsync(() =>
                    {
                        var msg = JsonSerializer.Serialize(new { action = "purchaseError", error = "התשלום נכשל. אם חויבת, נא לפנות לתמיכה." });
                        PaymentWebView.CoreWebView2.PostWebMessageAsJson(msg);
                    });
                    return;
                }
            }
        }

        Logger.Warning("Purchase status polling timed out for {Id}", _purchaseId);
        if (!PaymentSucceeded)
        {
            _ = Dispatcher.InvokeAsync(() =>
            {
                var msg = JsonSerializer.Serialize(new { action = "showTimeout" });
                PaymentWebView.CoreWebView2.PostWebMessageAsJson(msg);
            });
        }
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        _statusListener?.Stop();
        _server?.Stop();
        _server?.Dispose();
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        PaymentSucceeded = false;
        Close();
    }
}
