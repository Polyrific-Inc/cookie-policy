using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Options;
using System;

namespace Polyrific.Security.CookiePolicy
{
    public static class CustomCookiePolicyAppBuilderExtensions
    {
        /// <summary>
        /// Adds the <see cref="CookiePolicyMiddleware"/> handler to the specified <see cref="IApplicationBuilder"/>, which enables cookie policy capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> to add the handler to.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static IApplicationBuilder UseCustomCookiePolicy(this IApplicationBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseMiddleware<CookiePolicyMiddleware>();
        }

        /// <summary>
        /// Adds the <see cref="CookiePolicyMiddleware"/> handler to the specified <see cref="IApplicationBuilder"/>, which enables cookie policy capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> to add the handler to.</param>
        /// <param name="options">A <see cref="CookiePolicyOptions"/> that specifies options for the handler.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static IApplicationBuilder UseCustomCookiePolicy(this IApplicationBuilder app, CookiePolicyOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            return app.UseMiddleware<CookiePolicyMiddleware>(Options.Create(options));
        }
    }
}
