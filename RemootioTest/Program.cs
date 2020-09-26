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
            // Data from WebsocketApiDocs.pdf
            TestData test1 = new TestData()
            {
                //APISecretKey = "EFD0E4BF75D49BDD4F5CD5492D55C92FE96040E9CD74BED9F19ACA2658EA0FA9",
                APIAuthKey = "7B456E7AE95E55F714E2270983C33360514DAD96C93AE1990AFE35FD5BF00A72",
                APISessionKey = "yzEI7RWCjYDEwFrgc5YrmWo82kXEjFNStbtN+wFM2Qk=",
                iv = "vz3r424R6v9XFchkkgWQTw==",
                lastActionID = 808411243,

                expected_payload = "L6eTyvyY/q4I7oDAfdeDyz17x0vMUqmqvnCYl73zG2UxnYpIKVIQ0DooAWxcm3WT",
                expected_mac = "legB+2ZnikMtX54VpkPVc8P7o17s61y1JqGDvFrxbts=",
            };

            // 
            TestData test2 = new TestData()
            {
                //APISecretKey = "B48C7A34CC64F9E421A64985328619AB6CF1878ECD1649F5E8322F1FE28C93C8",
                APIAuthKey = "EAF97466F0DB4B7BA11AEC9DFFAFBA0D6670FF13FD89377527F104FB5AB62414",
                APISessionKey = "vpynuGWQN2Af8ebTDPvv22UspOuNocXNysUfClq+KWQ=",
                iv = "kVJ3EERytUA+NXNNwuWl7w==",
                lastActionID = 1836946866-1,

                expected_payload = "LQbuP/Khr+h3DbQAtpQ9SU3ZjQkJ65W95/1EgxuygCmJqrYtWzj6jQKaT83qNL9G",
                expected_mac = "IKSPsr8eDwj0c1tr+PwGGIf0185BYy+mluETb7CcSUU=",
            };


            //TestACTION(test1);
            TestACTION(test2);

            // Now test Remootio client
            var r = new Remootio.Remootio();

            while (true)
            {
                Thread.Sleep(100);
            }
        }


        static void TestACTION(TestData t)
        {
            AesEncryption aes = new AesEncryption(base64Key: t.APISessionKey, APIAuthKey: t.APIAuthKey);

            Console.WriteLine($"\nTest MakeEncr");

            // Test MakeEncr directly
            ACTION query = new ACTION(type.QUERY, t.lastActionID + 1);

            encr encr1 = MakeEncr(query, aes/*, t.APIAuthKey*/, t.iv);

            Debug.Assert(encr1.payload == t.expected_payload);
            Debug.Assert(encr1.mac == t.expected_mac);

            Console.WriteLine($"\nTest E_ACTION wrapper");
            // Test E_ACTION wrapper - should produce same "encr"
            E_ACTION e_ACTION = new E_ACTION(type.QUERY, t.lastActionID + 1, aes, t.iv);

            encr encr2 = e_ACTION.data;

            Debug.Assert(encr2.payload == t.expected_payload);
            Debug.Assert(encr2.mac == t.expected_mac);
            Console.WriteLine($"\nDone\n");
        }
    }


    struct TestData
    {
        //public string APISecretKey;
        public string APIAuthKey;
        public string APISessionKey;
        public string iv;
        public int lastActionID;

        public string expected_payload;
        public string expected_mac;
    }
}
