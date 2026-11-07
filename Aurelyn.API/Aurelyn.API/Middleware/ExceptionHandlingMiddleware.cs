using System.Net;
using System.Text.Json;

namespace Aurelyn.API.Middleware
{
    public class ExceptionHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionHandlingMiddleware> _logger;

        public ExceptionHandlingMiddleware(
            RequestDelegate next,
            ILogger<ExceptionHandlingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "An unexpected error occurred. TraceId: {TraceId}",
                    context.TraceIdentifier);

                if (context.Response.HasStarted)
                {
                    throw;
                }

                context.Response.Clear();

                var statusCode = ex switch
                {
                    KeyNotFoundException => (int)HttpStatusCode.NotFound,
                    UnauthorizedAccessException => (int)HttpStatusCode.Forbidden,
                    ArgumentException => (int)HttpStatusCode.BadRequest,
                    _ => (int)HttpStatusCode.InternalServerError
                };

                var message = statusCode switch
                {
                    404 => "The requested resource was not found.",
                    403 => "You are not authorized to perform this action.",
                    400 => "Invalid request.",
                    _ => "Something went wrong. Please try again later."
                };

                context.Response.StatusCode = statusCode;
                context.Response.ContentType = "application/json";

                var response = new
                {
                    success = false,
                    statusCode = statusCode,
                    message = message,
                    traceId = context.TraceIdentifier
                };

                await context.Response.WriteAsync(
                    JsonSerializer.Serialize(response));
            }
        }
    }
}