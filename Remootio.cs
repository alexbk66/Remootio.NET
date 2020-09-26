using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Net.Sockets;
using System.IO.Ports;

using SuperSocket.ClientEngine;
using WebSocket4Net;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Encrypt;


namespace Remootio
{
    public class Remootio
    {
        #region Properties

        string url;
        const string testurl = "ws://192.168.1.5:8080";  // TEMP
        WebSocket websocket;
        Timer pingTimer;
        int pingMsec;

        AesEncryption aes;
        bool authenticated = false;

        string APISecretKey = "B48C7A34CC64F9E421A64985328619AB6CF1878ECD1649F5E8322F1FE28C93C8";  // TEMP
        string APIAuthKey = "EAF97466F0DB4B7BA11AEC9DFFAFBA0D6670FF13FD89377527F104FB5AB62414";  // TEMP

        /// <summary>
        /// Should be null normally - then IV will be generated in EncryptStringToBytes
        /// </summary>
        string sIV = "9FbUN/uLWXpQTLpnI56P7A==";  // TEMP


        /// <summary>
        /// Each command the API client sends to Remootio must contain an acionId
        /// that is the last action id(denoted as lastActionId)
        /// incremented by one(and truncated to 31bits)"
        /// </summary>
        int ActionId { get; set; }


        /// <summary>
        /// TEMP - TODO - when recived reply for the IncrActionId - then increment
        /// </summary>
        void IncrActionId()
        {
            // incremented by one(and truncated to 31bits)"
            ActionId = (ActionId + 1) % 0x7FFFFFFF;
        }

        #endregion Properties


        #region Construction


        /// <summary>
        /// 
        /// </summary>
        /// <param name="url"></param>
        /// <param name="pingSec"></param>
        /// <param name="start"></param>
        public Remootio(string url = testurl, int pingSec = 5, bool start = true)
        {
            this.url = url;
            pingMsec = pingSec * 1000;
            if (start)
                Start();
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="o"></param>
        void TimerCallback(object o)
        {
            SendPing();
        }


        /// <summary>
        /// 
        /// </summary>
        void Start()
        {
            if (websocket != null)
                Stop();

            aes = new AesEncryption(APISecretKey: APISecretKey);

            websocket = new WebSocket(url);
            websocket.Opened += new EventHandler(websocket_Opened);
            websocket.Error += new EventHandler<ErrorEventArgs>(websocket_Error);
            websocket.Closed += new EventHandler(websocket_Closed);
            websocket.MessageReceived += new EventHandler<MessageReceivedEventArgs>(websocket_MessageReceived);
            try
            {
                websocket.Open();
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"SocketException {ex}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception {ex}");
            }
        }


        /// <summary>
        /// 
        /// </summary>
        void Stop()
        {
            if (pingTimer != null)
                pingTimer.Dispose();
            pingTimer = null;
            if (websocket != null)
                websocket.Dispose();
            websocket = null;

            authenticated = false;
            //APISessionKey = null;
            aes = null;
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="wait"></param>
        void Restart(int wait = 500)
        {
            Stop();
            Thread.Sleep(wait);
            Start();
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void websocket_Opened(object sender, EventArgs e)
        {
            pingTimer = new Timer(TimerCallback, this, pingMsec, pingMsec);

            if (!authenticated)
                SendAuth();
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void websocket_Closed(object sender, EventArgs e)
        {
            if (e is ClosedEventArgs)
            {
                Console.WriteLine($"Closed: {(e as ClosedEventArgs).Code} : {(e as ClosedEventArgs).Reason}");
            }
            else
            {
                Console.WriteLine($"Closed: {e}");
            }

            Restart();
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void websocket_Error(object sender, ErrorEventArgs e)
        {
            Console.WriteLine($"Error {e.Exception}");

            Restart();
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void websocket_MessageReceived(object sender, MessageReceivedEventArgs e)
        {
            Console.WriteLine($"Received {e.Message}");

            BASE msg = JsonConvert.DeserializeObject<BASE>(e.Message);

            var type = msg.type;

            switch (type)
            {
                case type.PONG:
                    return;

                case type.ERROR:
                case type.INPUT_ERROR:
                    var err = JsonConvert.DeserializeObject<ERROR>(e.Message);
                    Console.WriteLine($"ERROR: {err.errorMessage}");
                    break;

                case type.ENCRYPTED:
                    var enc = JsonConvert.DeserializeObject<ENCRYPTED>(e.Message);
                    //Console.WriteLine($"ENCRYPTED: {msg2.data.iv}");
                    Challenge challenge = aes.DecryptStringFromBytes<Challenge>(enc.data.payload, enc.data.iv);
                    if (challenge?.challenge != null)
                    {
                        ActionId = challenge.challenge.initialActionId;
                        string APISessionKey = challenge.challenge.sessionKey;
                        // After authentication use new APISessionKey for encryption
                        // APIAuthKey is used for HMAC calculation
                        aes = new AesEncryption(base64Key: APISessionKey, APIAuthKey: APIAuthKey);

                        IncrActionId(); // Looks like need to increment?
                        Console.WriteLine($"initialActionId: {ActionId}");
                    }

                    // Reccomended after AUTH send QUERY
                    SendQuery();
                    break;

                default:
                    Console.WriteLine($"unknown msg type {type}");
                    break;
            }
        }


        #endregion Construction


        #region Send

        object websocket_lock = new object();

        private void Send(object msg)
        {
            try
            {
                string json = JsonConvert.SerializeObject(msg);
                Console.WriteLine($"Send: {json}");
                lock (websocket_lock)
                {
                    websocket.Send(json);
                    return;
                }
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"SocketException {ex}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception {ex}");
            }

            Restart();
        }


        /// <summary>
        /// 
        /// </summary>
        private void SendPing()
        {
            Send(ping);
        }

        /// <summary>
        /// 
        /// </summary>
        private void SendAuth()
        {
            Send(auth);
        }

        /// <summary>
        /// 
        /// </summary>
        private void SendQuery()
        {
            Send(new QUERY(ActionId, aes, sIV));
        }



        /// <summary>
        /// Create "encr" data for encrypted ACTION
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="aes"></param>
        /// <param name="APIAuthKey"></param>
        /// <param name="iv">Only for testing, normally pass null to generate</param>
        /// <returns></returns>
        public static encr MakeEncr(ACTION query, AesEncryption aes, string iv = null)
        {
            if (aes == null)
                throw new ArgumentNullException("aes");

            string payload = JsonConvert.SerializeObject(query);

            Console.WriteLine($"ACTION: {payload}, APIAuthKey: {aes.APIAuthKey}, iv: {iv}");

            // create the JSON string for the HMAC calculation
            encr data = new encr()
            {
                payload = aes.EncryptStringToBytes(payload, sIV: iv),
                iv = aes.sIV,
            };

            // Pass NullValueHandling.Ignore to ignore null data.mac above
            string json = JsonConvert.SerializeObject(data, jss);

            data.mac = aes.StringHash(json);

            Console.WriteLine($"ACTION: {json}, mac: {data.mac}");

            return data;
        }


        /// <summary>
        /// Pass NullValueHandling.Ignore to ignore null data.mac above
        /// data.mac above will be set after SerializeObject
        /// </summary>
        static JsonSerializerSettings jss = new JsonSerializerSettings() { NullValueHandling = NullValueHandling.Ignore };


        #endregion Send


        #region JSON classes



        public class _Challenge
        {
            public string sessionKey { get; set; }
            public int initialActionId { get; set; }
        }


        /// <summary>
        /// Received from device in response to "AUTH"
        /// </summary>
        public class Challenge
        {
            public _Challenge challenge { get; set; }
        }


        public enum type
        {
            NOTSET,
            PING,
            PONG,
            ERROR,
            INPUT_ERROR, // Note: not documented
            HELLO,
            AUTH,
            ENCRYPTED,
            QUERY,
        }

        [Serializable]
        public class BASE
        {
            [JsonConverter(typeof(StringEnumConverter))]
            public type type;

            [JsonConstructor]
            BASE()
            {
            }

            protected BASE(type type)
            {
                this.type = type;
            }
        }


        protected class PING : BASE
        {
            public PING() : base(type.PING) { }
        }

        static PING ping = new PING();


        protected class AUTH : BASE
        {
            public AUTH() : base(type.AUTH) { }
        }

        static AUTH auth = new AUTH();


        public class ENCRYPTED : BASE
        {
            [JsonConstructor]
            public ENCRYPTED() : base(type.ENCRYPTED) { }

            public encr data;
        }

        public class encr
        {
            public string iv;
            public string payload;
            public string mac;
        }



        protected class ERROR : BASE
        {
            [JsonConstructor]
            public ERROR() : base(type.ERROR) { }

            public string errorMessage;
        }


        #region ACTIONS


        protected class QUERY : E_ACTION
        {
            /// <summary>
            /// 
            /// </summary>
            /// <param name="id">ActionID</param>
            /// <param name="aes">AesEncryption</param>
            /// <param name="sIV">Only for testing, normally pass null to generate</param>
            [JsonConstructor]
            public QUERY(int id, AesEncryption aes, string sIV = null)
                : base(type.QUERY, id, aes, sIV)
            {
            }
        }


        /// <summary>
        /// ACTION.action field definition
        /// If derive from BASE - then the order in json string changes
        /// from "type, id" to "id, type" - which affects encryption?
        /// {"action":{"type":"QUERY","id":1836946866}}
        /// </summary>
        public class _ACTION// : BASE
        {
            [JsonConstructor]
            public _ACTION(type type, int id)
            //: base(type)
            {
                this.type = type;
                this.id = id;
            }

            [JsonConverter(typeof(StringEnumConverter))]
            public type type;

            // Action ID
            public int id;
        }


        /// <summary>
        /// Unencrypted data.payload of the frame
        /// {"action":{"type":"QUERY","id":1836946866}}
        /// </summary>
        public class ACTION
        {
            [JsonConstructor]
            public ACTION(type type, int id)
            {
                Console.WriteLine($"\nACTION: '{type}', id {id}");
                action = new _ACTION(type, id);
            }

            public _ACTION action;
        }


        /// <summary>
        /// Encrypted wrapper for Action
        /// </summary>
        public class E_ACTION : ENCRYPTED
        {
            /// <summary>
            /// Ctor - create encr data field
            /// </summary>
            /// <param name="type"></param>
            /// <param name="id">Action ID</param>
            /// <param name="aes">AesEncryption</param>
            /// <param name="sIV">Only for testing, normally pass null to generate</param>
            public E_ACTION(type type, int id, AesEncryption aes, string sIV = null)
            {
                ACTION action = new ACTION(type, id);

                data = MakeEncr(action, aes, sIV);
            }
        }


        #endregion ACTIONS

        #endregion JSON classes
    }
}
