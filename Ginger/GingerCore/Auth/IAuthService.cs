using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GingerCore.Auth
{
    public interface IAuthService
    {
        Task<string> GetAccessToken(string authURL, string tokenURL, string clientID);
    }
}
