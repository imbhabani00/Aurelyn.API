using Aurelyn.API.Middleware;

namespace Aurelyn.API.Extensions
{
    public static class ExceptionExtension
    {
        public static IApplicationBuilder UseExceptionHandling(this IApplicationBuilder app)
        {
            return app.UseMiddleware<ExceptionHandlingMiddleware>();
        }
    }
}
