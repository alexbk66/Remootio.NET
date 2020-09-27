using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Net.Sockets;
using System.Reflection.Emit;
using System.Text.RegularExpressions;
using System.IO.Ports;


//using SuperSocket.ClientEngine;
//using WebSocket4Net;
using WebSocketSharp;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Encrypt;


namespace Remootio
{
    public partial class Remootio
    {
        #region Saved (Config) Properties

        /// <summary>
        /// To keep connection alive need to send PING every 60-90 sec
        /// </summary>
        [JsonProperty]
        public int PingSec { set; get; } = 60;

        /// <summary>
        /// Device Name given in the App
        /// Not yet available
        /// </summary>
        [JsonProperty]
        public string Name { set; get; }

        [JsonProperty]
        public string APISecretKey
        { 
            get => _APISecretKey;
            set
            {
                VerifyKey(ref value, "APISecretKey");
                _APISecretKey = value;
            }
        }

        string _APISecretKey = "B48C7A34CC64F9E421A64985328619AB6CF1878ECD1649F5E8322F1FE28C93C8";  // TEMP


        [JsonProperty]
        public string APIAuthKey
        { 
            get => _APIAuthKey;
            set
            {
                VerifyKey(ref value, "APIAuthKey");
                _APIAuthKey = value;
            }
        }

        string _APIAuthKey = "EAF97466F0DB4B7BA11AEC9DFFAFBA0D6670FF13FD89377527F104FB5AB62414";  // TEMP


        /// <summary>
        /// Always 8080
        /// </summary>
        [JsonProperty]
        public int Port { set; get; } = 8080;


        [JsonProperty]
        public string IP
        {
            //get => Uri?.ToString();
            get => _IP;

            set
            {
                _IP = value;
                if (_IP != null)
                    _IP = _IP.Replace("https", "").Replace("http", "").Replace("://", "").Trim();

                _uri = null;
            }
        }

        string _IP;


        #endregion Saved Properties


        #region Properties


        [JsonIgnore]
        const string testurl = "192.168.1.5";  // TEMP

        [JsonIgnore]
        public Uri Uri
        {
            get
            {
                if (_uri == null)
                {
                    UriBuilder uriBuilder = new UriBuilder()
                    {
                        Host = IP,
                        Port = Port,
                        Scheme = "ws",
                    };

                    _uri = uriBuilder.Uri;
                }

                return _uri;
            }
        }

        Uri _uri;

        [JsonIgnore]
        public string url => $"{Uri}";

        [JsonIgnore]
        public bool BadIP => Uri == null || Uri.IsLoopback;


        /// <summary>
        /// To keep connection alive need to send PING every 60-90 sec
        /// </summary>
        [JsonIgnore]
        Timer pingTimer;

        [JsonIgnore]
        int pingMsec => PingSec* 1000;

        [JsonIgnore]
        WebSocket websocket;

        [JsonIgnore]
        AesEncryption aes;

        [JsonIgnore]
        bool authenticated = false;

        /// <summary>
        /// Should be null normally - then IV will be generated in EncryptStringToBytes
        /// </summary>
        [JsonIgnore]
        string sIV = "9FbUN/uLWXpQTLpnI56P7A==";  // TEMP


        /// <summary>
        /// Each command the API client sends to Remootio must contain an acionId
        /// that is the last action id(denoted as lastActionId)
        /// incremented by one (and truncated to 31bits)
        /// </summary>
        [JsonIgnore]
        int LastActionId { get; set; }


        /// <summary>
        /// incremented LastActionId by one (and truncated to 31bits)
        /// </summary>
        [JsonIgnore]
        int NextActionId => (LastActionId + 1) % 0x7FFFFFFF;


        /// <summary>
        /// Serialize config
        /// </summary>
        [JsonIgnore]
        public string ConfigJson => IPAddressExtensions.SerializeObject(this);

        /// <summary>
        /// For checking connection status
        /// Not used yet
        /// </summary>
        [JsonIgnore]
        DateTime? PingSent = null;
        DateTime? ReplyReceived = null;


        #endregion Properties


        #region Construction


        /// <summary>
        /// Ctor
        /// </summary>
        /// <param name="url"></param>
        /// <param name="pingSec"></param>
        /// <param name="start"></param>
        public Remootio(string IP = testurl, int pingSec = 5, bool start = true)
        {
            this.IP = IP;
            this.PingSec = pingSec;
            if (start)
                Start();

            //string json = ConfigJson;
            //Remootio test = Remootio.FromJson(json);
        }


        [JsonConstructor]
        private Remootio()
        {
        }


        public override string ToString()
        {
            return $"{Name} {url}";
        }


        /// <summary>
        /// ApiSecretKey must be a hexstring representing a 256bit long byteArray
        /// </summary>
        /// <param name="value"></param>
        /// <param name="name"></param>
        static void VerifyKey(ref string value, string name)
        {
            if (String.IsNullOrEmpty(value))
                throw new ArgumentNullException(name);

            value = value.Trim();
            if (!Regex.IsMatch(value, @"[0-9A-Fa-f]{64}"))
                throw new ArgumentException("Invalid key", name);
        }


        /// <summary>
        /// Create Remootio fro json config string
        /// </summary>
        /// <param name="json"></param>
        /// <returns></returns>
        public static Remootio FromJson(string json)
        {
            try
            {
                if(!String.IsNullOrEmpty(json))
                    return IPAddressExtensions.DeserializeObject<Remootio>(json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FromJson({json}): {ex}");
            }
            return null;
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="IP"></param>
        /// <param name="port"></param>
        /// <param name="APISecretKey"></param>
        /// <param name="APIAuthKey"></param>
        public void SetIpPort(string IP, short port, string APISecretKey = null, string APIAuthKey = null)
        {
            this.IP = IP;
            this.Port = port;

            if (APISecretKey != null)
                this.APISecretKey = APISecretKey;

            if (APIAuthKey != null)
                this.APIAuthKey = APIAuthKey;
        }


        /// <summary>
        /// Open WebSecket connection
        /// </summary>
        void Start()
        {
            if (websocket != null)
                Stop();

            aes = new AesEncryption(APISecretKey: APISecretKey);

            websocket = new WebSocket(url);
            websocket.OnOpen += new EventHandler(websocket_Opened);
            websocket.OnMessage += new EventHandler<MessageEventArgs>(websocket_MessageReceived);
            websocket.OnError += new EventHandler<ErrorEventArgs>(websocket_Error);
            websocket.OnClose += new EventHandler<CloseEventArgs>(websocket_Closed);

            try
            {
                websocket.Connect();
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

            try
            {
                if (websocket != null && websocket.IsAlive)
                    websocket.Close();
            }
            catch (Exception ex) { }
            websocket = null;

            authenticated = false;
            //APISessionKey = null;
            aes = null;

            PingSent = null;
            ReplyReceived = null;
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
            // To keep connection alive need to send PING every 60-90 sec
            StartPingTimer();

            if (!authenticated)
                SendAuth();
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void websocket_Closed(object sender, CloseEventArgs e)
        {
            Console.WriteLine($"Closed code: {e.Code}, reason '{e.Reason}'");

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
        private void websocket_MessageReceived(object sender, MessageEventArgs e)
        {
            if (!e.IsText)
            {
                // use e.RawData
                Console.WriteLine($"Received binary data");
                return;
            }

            string json = e.Data;
            try
            {
                Console.WriteLine($"Received {json}");

                // Get type first
                BASE msg = JsonConvert.DeserializeObject<BASE>(json);
                ProcessMessage(msg.type, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: Couldn't deserialize '{json}': {ex}");
            }
        }


        /// <summary>
        /// Process Wbsocket Message
        /// </summary>
        /// <param name="type"></param>
        /// <param name="json"></param>
        private void ProcessMessage(type type, string json)
        {
            ReplyReceived = DateTime.Now;

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


            HandleChallenge(payload);
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="enc"></param>
        void HandleChallenge(string payload)
        {
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



        /// <summary>
        /// To keep connection alive need to send PING every 60-90 sec
        /// </summary>
        /// <param name="o"></param>
        void TimerCallback(object o)
        {
            SendPing();
            PingSent = DateTime.Now;
        }

        void StartPingTimer()
        {
            pingTimer = new Timer(TimerCallback, this, pingMsec, pingMsec);
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
                    if (websocket == null)
                    {
                        Console.WriteLine($"Sending {msg} - but websocket is closed, trying to open");
                        Start();
                    }
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
