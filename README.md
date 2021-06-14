# Cookie Policy
Polyrific's Cookie policy is extension of Microsoft's GDPR implementation. This library support declining the consent, as well as allowing user to consent to only a certain cookie category.

## Usage
First, set the cookie policy options to set the flag for checking consent, in `ConfigureServices` method of `Startup.cs`
```
services.Configure<Polyrific.Security.CookiePolicy.CookiePolicyOptions>(options =>
{
    // This lambda determines whether user consent for non-essential 
    // cookies is needed for a given request.
    options.CheckConsentNeeded = context => true;
    // requires using Microsoft.AspNetCore.Http;
    options.MinimumSameSitePolicy = SameSiteMode.None;
});
```

Then activate the feature by calling this code in the `Configure` method of `Startup.cs`
```
app.UseCustomCookiePolicy();
```

Afterwards, you can call the `ICustomTrackingConsentFeature` in the cshtml by calling on the Context.Feature:
```
var consentFeature = Context.Features.Get<ICustomTrackingConsentFeature>();
```

To create a decline cookie string, use the following method:
```
var declineCookieString = consentFeature?.CreateConsentDeclinedCookie();
```

If you need to create a custom cookie to store whether a category of cookie is consented, you can use this method:
```
var performanceCookieString = consentFeature?.CreateConsentCookie("performance", "yes");
```