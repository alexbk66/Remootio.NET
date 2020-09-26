using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Encrypt;
using Remootio;
using static Remootio.Remootio;

namespace RemootioTest
{
    class Program
    {
        static void Main(string[] args)
        {
            string APISecretKey = "EFD0E4BF75D49BDD4F5CD5492D55C92FE96040E9CD74BED9F19ACA2658EA0FA9";
            string APIAuthKey = "7B456E7AE95E55F714E2270983C33360514DAD96C93AE1990AFE35FD5BF00A72";
            string APISessionKey = "yzEI7RWCjYDEwFrgc5YrmWo82kXEjFNStbtN+wFM2Qk=";
            string iv = "vz3r424R6v9XFchkkgWQTw==";

            AesEncryption aes = new AesEncryption(base64Key: APISessionKey, hexKey: APIAuthKey);

            ACTION query = new ACTION(type.QUERY, 808411243 + 1); // ???

            encr encr = MakeEncr(query, aes, APIAuthKey, iv);




            var r = new Remootio.Remootio();

            while (true)
            {
                Thread.Sleep(100);
            }
        }
    }
}
