using Aurelyn.Application.Dtos.Response;
using Aurelyn.Application.Dtos.Response.Login;
using Aurelyn.Application.Dtos.Response.OtpResponse;
using Aurelyn.Application.Dtos.Response.Session;
using Aurelyn.Application.Dtos.Response.User;
using Aurelyn.Domain.Models;
using Aurelyn.Domain.Models.Authuntication;
using Aurelyn.Domain.Models.User;
using Aurelyn.Domain.Otp;
using Aurelyn.Domain.Session;
using AutoMapper;

namespace Aurelyn.Application.Mapper
{
    public class UserMapper : Profile
    {
        public UserMapper()
        {
            CreateMap<SaveResponse, GenericSaveResponse>();
            CreateMap<OtpCode, OtpResponse>();
            CreateMap<User, UserResponse>();
            CreateMap<UserSession, UserSessionResponse>();
            CreateMap<AuthenticateResult, AuthenticateResultResponse>();
            CreateMap<LoginFailureResult, LoginFailureResponse>();
            CreateMap<UserLookup, UserLookupResponse>();
        }
    }
}
