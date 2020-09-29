using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

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
                lastActionID = 808411243,

                iv = "vz3r424R6v9XFchkkgWQTw==",
                expected_payload = "L6eTyvyY/q4I7oDAfdeDyz17x0vMUqmqvnCYl73zG2UxnYpIKVIQ0DooAWxcm3WT",
                expected_mac = "legB+2ZnikMtX54VpkPVc8P7o17s61y1JqGDvFrxbts=",
                expected_frame = @"{""type"":""ENCRYPTED"",""data"":{""iv"":""vz3r424R6v9XFchkkgWQTw=="",""payload"":""L6eTyvyY/q4I7oDAfdeDyz17x0vMUqmqvnCYl73zG2UxnYpIKVIQ0DooAWxcm3WT""},""mac"":""legB+2ZnikMtX54VpkPVc8P7o17s61y1JqGDvFrxbts=""}",
            };

            // 
            TestData test2 = new TestData()
            {
                //APISecretKey = "B48C7A34CC64F9E421A64985328619AB6CF1878ECD1649F5E8322F1FE28C93C8",
                APIAuthKey = "EAF97466F0DB4B7BA11AEC9DFFAFBA0D6670FF13FD89377527F104FB5AB62414",
                APISessionKey = "WxxPiJ12/vvzdnwR9k65yPZqyrVIHschlu1RDFnelck=",
                lastActionID = 1891860987,

                iv = "trPXhC5MwECZOOx1qSFLdg==",
                expected_payload = "umyxh6eo0SNzsA8HBh3GnNEdhNYVgEWskG6aYaMBrliABIkZqJS1ZL1UbHjbBuHp",
                expected_mac = "XnNTHnfCFz5/eeRh8KXYVpHwUOJwqUmH62wxsfEYxkw=",
            };


            //TestACTION(test1);
            //TestACTION(test2);

            // Now test Remootio client
            TestRemootio();
        }


        static void TestRemootio()
        {
            var r = new Remootio.Remootio("192.168.1.137", false);

            r.OnConnectedChanged += R_OnConnectedChanged;
            r.OnLog += R_OnLog;

            r.Start();

            while (true)
            {
                Thread.Sleep(100);
            }
        }


        private static void R_OnConnectedChanged(object sender, ConnectedEventArgs e)
        {
            if(e.connected)
                Console.WriteLine($"WebSocket Connected");
            else
                Console.WriteLine($"WebSocket Closed code: {e.Code}, reason '{e.Reason}'");
        }

        private static void R_OnLog(object sender, LogEventArgs e)
        {
            string what = e.exception != null ? "Exception" : e.error ? "Error" : "Message";
            Console.WriteLine($"{what}: '{e.message}' {e.exception}");
        }

        static void TestACTION(TestData t)
        {
            AesEncryption aes = new AesEncryption(base64Key: t.APISessionKey, APIAuthKey: t.APIAuthKey);

            //Console.WriteLine($"\nTest MakeEncr");
            //
            //// Test MakeEncr directly
            //ACTION query = new ACTION(type.QUERY, t.lastActionID + 1);
            //
            //encr encr1 = MakeEncr(query, aes/*, t.APIAuthKey*/, t.iv);
            //Debug.Assert(encr1.payload == t.expected_payload);
            //
            //string mac1 = hmac(encr1, aes);
            //Debug.Assert(mac1 == t.expected_mac);

            Console.WriteLine($"\nTest E_ACTION wrapper");
            // Test E_ACTION wrapper - should produce same "encr"
            E_ACTION e_ACTION = new E_ACTION(type.QUERY, t.lastActionID + 1, aes, t.iv);

            encr encr2 = e_ACTION.data;
            Debug.Assert(encr2.payload == t.expected_payload);

            //string mac2 = hmac(encr2, aes);
            string mac2 = e_ACTION.mac;
            Debug.Assert(mac2 == t.expected_mac);

            string json = JsonConvert.SerializeObject(e_ACTION);

            Console.WriteLine($"Frame: {json}\n");

            if (t.expected_frame != null)
                Debug.Assert(t.expected_frame == json);
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
        public string expected_frame;
    }
}
