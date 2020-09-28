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

using WebSocketSharp;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Encrypt;
using Newtonsoft.Json.Linq;

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
        const string Scheme = "ws";

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
                        Scheme = Scheme,
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
        int NextActionId => (LastActionId + 1) % mask;

        /// <summary>
        /// truncated to 31bits
        /// </summary>
        const int mask = 0x7FFFFFFF;

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


        /// <summary>
        /// Returned from QUERY_RESPONSE
        /// </summary>
        [JsonIgnore]
        public string State { get; protected set; }

        /// <summary>
        /// Returned from QUERY_RESPONSE
        /// </summary>
        [JsonIgnore]
        public string ErrorCode { get; protected set; }


        /// <summary>
        /// WebSocket API version received from SERVER_HELLO
        /// </summary>
        [JsonIgnore]
        public int apiVersion { get; protected set; } = 0;

        #endregion Properties


        #region Construction


        /// <summary>
        /// Ctor
        /// </summary>
        /// <param name="url"></param>
        /// <param name="pingSec"></param>
        /// <param name="start"></param>
        public Remootio(string IP = testurl, int pingSec = 60, bool start = true)
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

            // TEMP - TODO: Connection timeout?
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
            stopping = true;

            if (pingTimer != null)
                pingTimer.Dispose();
            pingTimer = null;

            try
            {
                if (websocket != null)
                    websocket.Close();
            }
            catch (Exception ex) { }
            websocket = null;

            authenticated = false;
            //APISessionKey = null;
            aes = null;

            PingSent = null;
            ReplyReceived = null;

            stopping = false;
        }


        /// <summary>
        /// To ignore any errors and avoid Restart() from websocket_Closed()
        /// </summary>
        bool stopping = false;


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

            if(!stopping)
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

            if(!stopping)
                Restart();
        }


        /// <summary>
        /// webSocket received message from Remootio
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
            else
            {
                ProcessMessage(e.Data);
            }
        }


        /// <summary>
        /// Process Wbsocket Message
        /// 1. Called from websocket_MessageReceived - without type
        /// 2. After extracting type - call iself again with the type
        /// 3. For ENCRYPTED message - decrypt, extract type and call itself on decrypted message
        /// </summary>
        /// <param name="type"></param>
        /// <param name="json"></param>
        private void ProcessMessage(string json, type type = type.NOTSET)
        {
            ReplyReceived = DateTime.Now;
            Console.WriteLine($"Received({type}): {json}");

            switch (type)
            {
                case type.NOTSET:
                    try
                    {
                        // Get type first
                        BASE msg = JsonConvert.DeserializeObject<BASE>(json);
                        ProcessMessage(json, msg.type);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"ERROR: Couldn't deserialize '{json}': {ex}");
                    }
                    return;

                case type.PONG:
                    return;

                case type.ERROR:
                case type.INPUT_ERROR:
                    var err = JsonConvert.DeserializeObject<ERROR>(json);
                    Console.WriteLine($"ERROR: {err.errorMessage}");
                    break;

                // 
                case type.SERVER_HELLO:
                    var hello = JsonConvert.DeserializeObject<SERVER_HELLO>(json);

                    apiVersion = hello.apiVersion;

                    Console.WriteLine($"HELLO: api: {apiVersion}, {hello.message}");
                    break;

                // Response to QUERY
                case type.QUERY:
                    var query_response = JsonConvert.DeserializeObject<QUERY_RESPONSE>(json);
                    Console.WriteLine($"QUERY: reply_id: {query_response.id}, state: {query_response.state}");
                    HandleResponse(query_response);
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
            object obj = JsonConvert.DeserializeObject(payload);
            if (!(obj is JObject))
                return;

            JObject jo = obj as JObject;

            if (jo["challenge"] != null)
            {
                HandleChallenge(payload);
            }
            else if (jo["response"] != null)
            {
                ProcessMessage(jo["response"].ToString());
            }
            else
            {
                Console.WriteLine($"Something unexpected received: {payload}");
            }
        }


        /// <summary>
        /// Decode "challenge" reply to AUTH request
        /// </summary>
        /// <param name="enc"></param>
        void HandleChallenge(string payload)
        {
            Challenge challenge = JsonConvert.DeserializeObject<Challenge>(payload);

            if (challenge?.challenge != null)
            {
                LastActionId = challenge.challenge.initialActionId;
                string APISessionKey = challenge.challenge.sessionKey;
                // After authentication use new APISessionKey for encryption
                // APIAuthKey is used for HMAC calculation
                aes = new AesEncryption(base64Key: APISessionKey, APIAuthKey: APIAuthKey);

                Console.WriteLine($"initialActionId: {LastActionId}");
            }

            // Reccomended after AUTH send QUERY
            SendQuery();
        }


        /// <summary>
        /// TEMP - Not sure  pass BASE?
        /// </summary>
        /// <param name="response">QUERY_RESPONSE</param>
        void HandleResponse(QUERY_RESPONSE response)
        {
            if (response == null)
                return;

            State = response.state;
            if (!response.success)
                ErrorCode = response.errorCode;

            if (LastActionId <= response.id || (response.id == 0 && LastActionId == mask))
            {
                // We increment the action id (we actually just set it to be equal to the previous message's ID we've sent)
                LastActionId = response.id;
                Console.WriteLine($"Received response to last action, set LastActionId to {LastActionId}");

                // First time received reply to QUERY - send also HELLO
                if(apiVersion <=0 )
                    SendHello();
            }
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
        /// To keep connection alive need to send PING every 60-90 sec
        /// </summary>
        public void SendPing()
        {
            Send(new PING());
        }


        /// <summary>
        /// The API client sends the AUTH frame to start the authentication flow
        /// </summary>
        public void SendAuth()
        {
            Send(new AUTH());
        }


        /// <summary>
        /// The API client can send this frame to check the version of the Websocket API
        /// </summary>
        public void SendHello()
        {
            Send(new HELLO());
        }


        /// <summary>
        /// The API client sends this action to get the current
        /// state of the gate or garage door (open/closed)
        /// </summary>
        public void SendQuery()
        {
            QUERY q = new QUERY(NextActionId, aes, sIV);
            Send(q);
        }


        /// <summary>
        /// The API client sends this action to get the current
        /// state of the gate or garage door (open/closed)
        /// </summary>
        public void SendTrigger()
        {
            TRIGGER q = new TRIGGER(NextActionId, aes, sIV);
            Send(q);
        }


        #endregion Public Methods


        #region Send

        object websocket_lock = new object();


        /// <summary>
        /// Send the msg to Remootio
        /// </summary>
        /// <param name="msg"></param>
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
            return new encr()
            {
                payload = aes.EncryptStringToBytes(payload, sIV: iv),
                iv = aes.sIV,
            };
        }


        public static string hmac(encr data, AesEncryption aes)
        {
            string json = JsonConvert.SerializeObject(data);
            string mac = aes.StringHash(json);

            Console.WriteLine($"ACTION: {json}, mac: {mac}");

            return mac;
        }

        /// <summary>
        /// Pass NullValueHandling.Ignore to ignore null data.mac above
        /// data.mac above will be set after SerializeObject
        /// </summary>
        //static JsonSerializerSettings jss = new JsonSerializerSettings() { NullValueHandling = NullValueHandling.Ignore };


        #endregion Send
    }
}
