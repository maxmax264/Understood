using System.Text.Json;

namespace SionyxKiosk.Infrastructure;

public interface IFirebaseClient : IDisposable
{
    string? UserId { get; }
    string? RefreshToken { get; }
    string OrgId { get; }
    string ProjectId { get; }
    string? FunctionsBaseUrl { get; }
    bool IsAuthenticated { get; }

    Task<FirebaseResult> SignUpAsync(string email, string password);
    Task<FirebaseResult> SignInAsync(string email, string password);
    Task<bool> RefreshTokenAsync();
    Task<bool> EnsureValidTokenAsync();
    void ClearAuth();
    void RestoreAuth(string idToken, string refreshToken, string userId);

    Task<FirebaseResult> DbGetAsync(string path);
    Task<FirebaseResult> DbSetAsync(string path, object data);
    Task<FirebaseResult> DbUpdateAsync(string path, object data);
    Task<FirebaseResult> ChangePasswordAsync(string newPassword);
    Task<FirebaseResult> DbDeleteAsync(string path);
    Task<FirebaseResult> CallFunctionAsync(string functionName, object payload);

    SseListener DbListen(string path, Action<string, JsonElement?> callback, Action<string>? errorCallback = null);
}
