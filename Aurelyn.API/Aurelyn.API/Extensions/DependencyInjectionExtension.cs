using Aurelyn.Application.Services;
using Aurelyn.Domain.Settings;

namespace Aurelyn.API.Extensions
{
    public static class DependencyInjectionExtension
    {
        public static IServiceCollection AddDependencyInjection(
        this IServiceCollection services, IConfiguration configuration)
        {
            var jwtSettings = configuration.GetSection("JwtSettings").Get<JwtSettings>();
            services.AddSingleton(jwtSettings);

            var otpSettings = configuration.GetSection("OtpSettings").Get<OtpSettings>() ?? new OtpSettings();
            services.AddSingleton(otpSettings);

            var emailSettings = configuration.GetSection("EmailSettings").Get<EmailSettings>()
                ?? throw new InvalidOperationException("EmailSettings section is missing in appsettings.");
            services.AddSingleton(emailSettings);

            var storageSettings = configuration.GetSection("Storage").Get<StorageSettings>()
                ?? throw new InvalidOperationException("Storage section is missing in appsettings.");

            if (string.IsNullOrWhiteSpace(storageSettings.R2.AccountId) ||
                string.IsNullOrWhiteSpace(storageSettings.R2.AccessKey) ||
                string.IsNullOrWhiteSpace(storageSettings.R2.SecretKey))
                throw new InvalidOperationException("Storage:R2 credentials are missing.");

            services.Configure<StorageSettings>(configuration.GetSection("Storage"));
            services.AddSingleton<IR2StorageService, R2StorageService>();

            var appAssembly = typeof(Aurelyn.Application.AssemblyReference).Assembly;

            foreach (var type in appAssembly.GetTypes()
                .Where(
                x => x.IsClass && 
                !x.IsAbstract &&
                x.Name.EndsWith("Service") &&
                x.Name != nameof(R2StorageService)
                ))
            {
                var interfaceTypes = type.GetInterfaces()
                    .Where(i => i.Name != "IDisposable");

                foreach (var interfaceType in interfaceTypes)
                {
                    bool needsHttpClient = type.GetConstructors()
                        .Any(c => c.GetParameters()
                            .Any(p => p.ParameterType == typeof(HttpClient)));

                    if (needsHttpClient)
                    {
                        services.AddHttpClient(type.Name);
                        services.AddScoped(interfaceType, type);
                    }
                    else
                    {
                        services.AddScoped(interfaceType, type);
                    }
                }
            }

            foreach (var type in appAssembly.GetTypes()
                .Where(x => x.IsClass
                         && !x.IsAbstract
                         && x.Name.EndsWith("Repository")
                         && x.Name != "BaseRepository"))
            {
                var interfaceType = type.GetInterfaces()
                    .FirstOrDefault(i => i.Name != "IDisposable"
                                     && i.Name != "IBaseRepository");

                if (interfaceType != null)
                    services.AddScoped(interfaceType, type);
            }

            return services;
        }
    }
}