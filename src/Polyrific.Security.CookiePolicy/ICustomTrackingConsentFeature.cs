using Microsoft.AspNetCore.Http.Features;

namespace Polyrific.Security.CookiePolicy
{
    public interface ICustomTrackingConsentFeature : ITrackingConsentFeature
    {
        string CreateConsentDeclinedCookie();
        string CreateConsentCookie(string key, string value);
        string GetConsentCookieKey(string key);
        bool CanTrackCustom(string key);
        string ConsentCookieKey { get; }
        string ConsentDeclinedCookieKey { get; }
        bool HasDeclinedConsent { get; }
    }
}
