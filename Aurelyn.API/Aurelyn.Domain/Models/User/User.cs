using System;
using System.Collections.Generic;
using System.Text;

namespace Aurelyn.Domain.Models.User
{
    public class User
    {
        
    }
    public class AuthenticateResult
    {
        public int ReturnValue { get; set; }
        public User? AuthunticateUser { get; set; }
    }
}
