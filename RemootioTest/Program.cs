using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;

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

            string expected_payload = "L6eTyvyY/q4I7oDAfdeDyz17x0vMUqmqvnCYl73zG2UxnYpIKVIQ0DooAWxcm3WT";
            string expected_mac = "legB+2ZnikMtX54VpkPVc8P7o17s61y1JqGDvFrxbts=";

            AesEncryption aes = new AesEncryption(base64Key: APISessionKey, hexKey: APIAuthKey);

            int lastActionID = 808411243;

            // Test MakeEncr directly
            ACTION query = new ACTION(type.QUERY, lastActionID + 1); // ???

            encr encr1 = MakeEncr(query, aes, APIAuthKey, iv);

            Debug.Assert(encr1.payload == expected_payload);
            Debug.Assert(encr1.mac == expected_mac);

            // Test E_ACTION wrapper - should produce same "encr"
            E_ACTION e_ACTION = new E_ACTION(type.QUERY, lastActionID + 1, aes, iv);

            encr encr2 = e_ACTION.data;

            Debug.Assert(encr2.payload == expected_payload);
            Debug.Assert(encr2.mac == expected_mac);


            // Now test Remootio client
            var r = new Remootio.Remootio();

            while (true)
            {
                Thread.Sleep(100);
            }
        }
    }
}
