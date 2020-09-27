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
    public partial class Remootio
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
        int LastActionId { get; set; }


        /// <summary>
        /// incremented LastActionId by one(and truncated to 31bits)"
        /// </summary>
        int NextActionId => (LastActionId + 1) % 0x7FFFFFFF;


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
            Console.WriteLine($"ERROR {e.Exception}");

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

            // Get type first
            BASE msg;

            try
            {
                msg = JsonConvert.DeserializeObject<BASE>(e.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: Couldn't deserialize '{e.Message}': {ex}");
                return;
            }

            ProcessMessage(msg.type, e.Message);
        }


        private void ProcessMessage(type type, string json)
        {
            switch (type)
            {
                case type.PONG:
                    return;

                case type.ERROR:
                case type.INPUT_ERROR:
                    var err = JsonConvert.DeserializeObject<ERROR>(json);
                    Console.WriteLine($"ERROR: {err.errorMessage}");
                    break;

                case type.SERVER_HELLO:
                    var hello = JsonConvert.DeserializeObject<SERVER_HELLO>(json);
                    Console.WriteLine($"HELLO: api: {hello.apiVersion}, {hello.message}");
                    break;

                case type.ENCRYPTED:
                    var enc = JsonConvert.DeserializeObject<ENCRYPTED>(json);
                    HandleEncrypted(enc);
                    break;

                default:
                    Console.WriteLine($"unknown msg type {type}: {json}");
                    break;
            }
        }


        /// <summary>
        /// Decrypt and process Encrypted message
        /// </summary>
        /// <param name="enc"></param>
        void HandleEncrypted(ENCRYPTED enc)
        {
            // TEMP - TODO: get type and process!
            // Probably call websocket_MessageReceived with decrypted message
            string payload = aes.DecryptStringFromBytes(enc.data.payload, enc.data.iv);
            var obj = JsonConvert.DeserializeObject(payload);
            Challenge challenge = JsonConvert.DeserializeObject<Challenge>(payload);
            //Challenge challenge = aes.DecryptStringFromBytes<Challenge>(enc.data.payload, enc.data.iv);

            if (challenge?.challenge != null)
            {
                LastActionId = challenge.challenge.initialActionId;
                string APISessionKey = challenge.challenge.sessionKey;
                // After authentication use new APISessionKey for encryption
                // APIAuthKey is used for HMAC calculation
                aes = new AesEncryption(base64Key: APISessionKey, APIAuthKey: APIAuthKey);

                Console.WriteLine($"initialActionId: {LastActionId}");
            }

            //SendHello();

            // Reccomended after AUTH send QUERY
            SendQuery();
        }


        #endregion Construction


        #region Public Methods


        /// <summary>
        /// 
        /// </summary>
        public void SendPing()
        {
            Send(new PING());
        }

        /// <summary>
        /// 
        /// </summary>
        public void SendAuth()
        {
            Send(new AUTH());
        }

        /// <summary>
        /// 
        /// </summary>
        public void SendHello()
        {
            Send(new HELLO());
        }

        /// <summary>
        /// 
        /// </summary>
        public void SendQuery()
        {
            Send(new QUERY(NextActionId, aes, sIV));
        }



        #endregion Public Methods


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
    }
}
