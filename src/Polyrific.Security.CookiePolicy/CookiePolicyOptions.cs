﻿using System;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Http;

namespace Polyrific.Security.CookiePolicy
{
    /// <summary>
    /// Provides programmatic configuration for the <see cref="CookiePolicyMiddleware"/>.
    /// </summary>
    public class CookiePolicyOptions
    {
        /// <summary>
        /// Affects the cookie's same site attribute.
        /// </summary>
        public SameSiteMode MinimumSameSitePolicy { get; set; } = SameSiteMode.None;

        /// <summary>
        /// Affects whether cookies must be HttpOnly.
        /// </summary>
        public HttpOnlyPolicy HttpOnly { get; set; } = HttpOnlyPolicy.None;

        /// <summary>
        /// Affects whether cookies must be Secure.
        /// </summary>
        public CookieSecurePolicy Secure { get; set; } = CookieSecurePolicy.None;

        /// <summary>
        /// Gets or sets the <see cref="CookieBuilder"/> that is used to track if the user consented to the
        /// cookie use policy.
        /// </summary>
        public CookieBuilder ConsentCookie { get; set; } = new CookieBuilder()
        {
            Name = ".AspNet.Consent",
            Expiration = TimeSpan.FromDays(365),
            IsEssential = true,
        };

        /// <summary>
        /// Gets or sets the <see cref="CookieBuilder"/> that is used to track if the user decline to consent the
        /// cookie use policy.
        /// </summary>
        public CookieBuilder ConsentDeclinedCookie { get; set; } = new CookieBuilder()
        {
            Name = ".AspNet.Consent.Declined",
            Expiration = TimeSpan.FromDays(365),
            IsEssential = true,
        };

        /// <summary>
        /// Gets or sets the <see cref="CookieBuilder"/> for custom cookie consent
        /// </summary>
        public CookieBuilder CustomConsentCookie(string keySuffix)
        {
            return new CookieBuilder()
            {
                Name = ".AspNet.Consent.Custom." + keySuffix,
                Expiration = TimeSpan.FromDays(365),
                IsEssential = true,
            };
        }

        /// <summary>
        /// Checks if consent policies should be evaluated on this request. The default is false.
        /// </summary>
        public Func<HttpContext, bool> CheckConsentNeeded { get; set; }

        /// <summary>
        /// Called when a cookie is appended.
        /// </summary>
        public Action<AppendCookieContext> OnAppendCookie { get; set; }

        /// <summary>
        /// Called when a cookie is deleted.
        /// </summary>
        public Action<DeleteCookieContext> OnDeleteCookie { get; set; }
    }
}