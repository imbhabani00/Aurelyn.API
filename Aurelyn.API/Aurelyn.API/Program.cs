using Aurelyn.API.Extensions;
using FluentValidation;
using FluentValidation.AspNetCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Serilog;
using Serilog.Sinks.MSSqlServer;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    Log.Information("Starting Aurelyn API...");

    var builder = WebApplication.CreateBuilder(args);

    var connectionString =
        builder.Configuration.GetConnectionString("AurelynConnection");

    if (string.IsNullOrWhiteSpace(connectionString))
    {
        throw new InvalidOperationException(
            "Database connection string 'AurelynConnection' is missing.");
    }

    #region Serilog Configuration
    builder.Host.UseSerilog((context, services, loggerConfiguration) =>
    {
        loggerConfiguration
            .ReadFrom.Configuration(context.Configuration)
            .ReadFrom.Services(services)
            .Enrich.FromLogContext()
            .Enrich.WithMachineName()
            .Enrich.WithEnvironmentName()
            .WriteTo.Console()
            .WriteTo.MSSqlServer(
                connectionString: connectionString,
                sinkOptions: new MSSqlServerSinkOptions
                {
                    TableName = "tbl_Logs",
                    SchemaName = "dbo",
                    AutoCreateSqlTable = true
                });
    });
    #endregion

    #region Service Binding
    builder.Services.AddControllers();

    builder.Services.AddSwaggerExtension();

    builder.Services.AddCorsPolicy(
        builder.Configuration,
        "CorsPolicy");

    builder.Services.AddJwtAuthentication(
        builder.Configuration);

    builder.Services.AddValidatorsFromAssembly(
        typeof(Aurelyn.Application.AssemblyReference).Assembly);

    builder.Services.AddFluentValidationAutoValidation();

    builder.Services.AddAutoMapper(
        typeof(Aurelyn.Application.AssemblyReference).Assembly);

    builder.Services.AddMemoryCache();

    #region Health Checks
    builder.Services
        .AddHealthChecks()
        .AddSqlServer(
            connectionString,
            name: "sql-server",
            failureStatus: HealthStatus.Unhealthy,
            tags: new[] { "ready", "database" });
    #endregion

    builder.Services.AddVersioningExtension();

    builder.Services.AddDependencyInjection(
        builder.Configuration);

    builder.Services.AddRouting(options =>
    {
        options.LowercaseUrls = true;
        options.LowercaseQueryStrings = true;
    });
    #endregion

    var app = builder.Build();

    #region Middleware PipeLine
    app.UseSerilogRequestLogging();
    app.UseExceptionHandling();
    app.UseHttpsRedirection();
    app.UseRouting();
    app.UseCors("CorsPolicy");
    app.UseAuthentication();
    app.UseAuthorization();
    #endregion

    #region Swagger Configuration

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();

        app.UseSwaggerUI(options =>
        {
            options.SwaggerEndpoint(
                "/swagger/v1/swagger.json",
                "Aurelyn API v1");
            options.RoutePrefix = string.Empty;
        });
    }
    #endregion

    app.MapControllers();
    app.MapHealthChecks("/health");

    app.MapHealthChecks("/health/ready", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
    {
        Predicate = check => check.Tags.Contains("ready")
    });

    await app.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Aurelyn API failed to start");
    Environment.ExitCode = 1;
}
finally
{
    Log.CloseAndFlush();
}