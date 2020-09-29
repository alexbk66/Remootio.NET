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
        /// Device Name given in the App
        /// Not yet available
        /// </summary>
        [JsonProperty]
        public string Name { set; get; }


        /// <summary>
        /// 
        /// </summary>
        public const string NewID = "New Remootio";

        /// <summary>
        /// Device ID (i.e. Serial Number)
        /// Not yet available
        /// For now return 6 chars of APIAuthKey
        /// </summary>
        [JsonProperty]
        public string id
        {
            set => _id = value;

            get
            {
                if (_id != null)
                    return _id;

                if (!String.IsNullOrEmpty(APIAuthKey))
                    return $"{APIAuthKey.Substring(0, 3)}-{APIAuthKey.Substring(APIAuthKey.Length-3)}";
                else
                    return NewID;
            }
        }

        string _id;


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

        /// <summary>
        /// To keep connection alive need to send PING every 60-90 sec
        /// </summary>
        [JsonProperty]
        public int PingSec { set; get; } = 60;


        #endregion Saved Properties


        #region Properties

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

                    try
                    {
                        _uri = uriBuilder.Uri;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Uri: {ex}");
                    }
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
        /// time passed since the last restart
        /// </summary>
        [JsonIgnore]
        public TimeSpan? Uptime { get; protected set; }


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
        /// <param name="IP"></param>
        /// <param name="start"></param>
        /// <param name="pingSec"></param>
        public Remootio(string IP, bool start = false, int pingSec = 15)
        {
            this.IP = IP;
            this.PingSec = pingSec;
            if (start)
                Start();
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
                Console.WriteLine($"FromJson({json})", ex);
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
        public void Start()
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
                Log($"Start: SocketException", ex);
            }
            catch (Exception ex)
            {
                Log($"Start: tException", ex);
            }
        }


        /// <summary>
        /// 
        /// </summary>
        public void Stop()
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
        void websocket_Opened(object sender, EventArgs e)
        {
            // To keep connection alive need to send PING every 60-90 sec
            StartPingTimer();

            OnConnectedChanged?.Invoke(this, new ConnectedEventArgs(true));

            if (!authenticated)
                SendAuth();
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void websocket_Closed(object sender, CloseEventArgs e)
        {
            //Log($"Closed code: {e.Code}, reason '{e.Reason}'");

            OnConnectedChanged?.Invoke(this, new ConnectedEventArgs(false, e.Code, e.Reason));

            if (!stopping)
                Restart();
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void websocket_Error(object sender, ErrorEventArgs e)
        {
            Log($"ERROR {e.Exception}");

            if(!stopping)
                Restart();
        }


        /// <summary>
        /// webSocket received message from Remootio
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void websocket_MessageReceived(object sender, MessageEventArgs e)
        {
            if (!e.IsText)
            {
                // use e.RawData
                Log($"Received binary data", true);
                return;
            }
            else
            {
                ProcessMessage(e.Data);
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


        void Log(string message, bool error = false, Exception ex = null)
        {
            //string what = ex != null ? "Exception" : error ? "Error" : "Message";
            //Console.WriteLine($"{what}: '{message}' {ex}");

            OnLog?.Invoke(this, new LogEventArgs(message, error, ex));
        }

        void Log(string message, Exception ex)
        {
            Log(message, true, ex);
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


        #region Client Events


        public class ConnectedEventArgs : EventArgs
        {
            public ConnectedEventArgs(bool connected, ushort Code = 0, string Reason = null)
            {
                this.connected = connected;
                this.Code = Code;
                this.Reason = Reason;
            }

            public bool connected { get; }
            public ushort Code { get; }
            public string Reason { get; }
        }


        public class LogEventArgs : EventArgs
        {
            public LogEventArgs(string message, bool error, Exception ex = null)
            {
                this.error = error;
                this.message = message;
                this.exception = ex;
            }

            public bool error { get; }
            public Exception exception { get; }
            public string message { get; }
        }


        public event EventHandler<ConnectedEventArgs> OnConnectedChanged;
        public event EventHandler<LogEventArgs> OnLog;


        #endregion Client Events


        #region Receive


        /// <summary>
        /// Process Wbsocket Message
        /// 1. Called from websocket_MessageReceived - without type
        /// 2. After extracting type - call iself again with the type
        /// 3. For ENCRYPTED message - decrypt, extract type and call itself on decrypted message
        /// </summary>
        /// <param name="type"></param>
        /// <param name="json"></param>
        /// <param name="isevent">Event received from Remootio</param>
        /// <param name="isresponse">Response to Action received, different format to "event"</param>
        private void ProcessMessage(string json, type type = type.NOTSET, bool isevent = false, bool isresponse = false)
        {
            ReplyReceived = DateTime.Now;

            // Avoid double loogin, ProcessMessage will be called againg with proper type
            if(type != type.NOTSET)
                Log($"Received({type}): {json}");

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
                        Log($"ERROR: Couldn't deserialize '{json}'", ex);
                    }
                    return;

                case type.PONG:
                    return;

                case type.ERROR:
                case type.INPUT_ERROR:
                    var err = JsonConvert.DeserializeObject<ERROR>(json);
                    Log(err.errorMessage, true);
                    break;

                // Response to HELLO
                case type.SERVER_HELLO:
                    var hello = JsonConvert.DeserializeObject<SERVER_HELLO>(json);

                    apiVersion = hello.apiVersion;

                    Log($"HELLO: api: {apiVersion}, {hello.message}");

                    // TEMP!!!
                    SendTrigger();

                    break;

                // events from Remootio
                case type.RelayTrigger:
                    // TEMP - TODO: Implement
                    var @event = JsonConvert.DeserializeObject<RelayTrigger>(json);
                    HandleResponse(@event);

                    break;

                // Response to TRIGGER
                case type.TRIGGER:
                    var trigger_response = JsonConvert.DeserializeObject<TRIGGER_RESPONSE>(json);
                    HandleResponse(trigger_response);
                    break;


                // Response to RESTART, or
                // Restart event received
                case type.Restart:
                    var restart = JsonConvert.DeserializeObject<BASE_RESPONSE>(json);
                    HandleResponse(restart);
                    Log($"Device Restarted {Uptime}", error: true);
                    break;


                // Response to QUERY
                case type.QUERY:
                    var query_response = JsonConvert.DeserializeObject<QUERY_RESPONSE>(json);
                    Log($"QUERY: reply_id: {query_response.id}, state: {query_response.state}");
                    HandleResponse(query_response);
                    break;

                // Encrypted message received
                case type.ENCRYPTED:
                    var enc = JsonConvert.DeserializeObject<ENCRYPTED>(json);
                    HandleEncrypted(enc);
                    break;

                default:
                    Log($"unknown msg type {type}: {json}", true);
                    break;
            }
        }


        /// <summary>
        /// Decrypt and process Encrypted message
        /// </summary>
        /// <param name="enc"></param>
        void HandleEncrypted(ENCRYPTED enc)
        {
            string payload = aes.DecryptStringFromBytes(enc.data.payload, enc.data.iv);
            object obj = JsonConvert.DeserializeObject(payload);
            if (!(obj is JObject))
                return;

            JObject jo = obj as JObject;

            // TEMP - TODO: improve!
            if (jo["challenge"] != null)
            {
                HandleChallenge(payload);
            }
            else if (jo["response"] != null)
            {
                ProcessMessage(jo["response"].ToString(), isresponse: true);
            }
            else if (jo["event"] != null)
            {
                ProcessMessage(jo["event"].ToString(), isevent: true);
            }
            else
            {
                Log($"Something unexpected received: {payload}", true);
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

                Log($"initialActionId: {LastActionId}");
            }

            // Reccomended after AUTH send QUERY
            SendQuery();
        }


        /// <summary>
        /// COMMENT
        /// </summary>
        /// <param name="response">QUERY_RESPONSE</param>
        void HandleResponse(BASE_RESPONSE response)
        {
            if (response == null)
                return;

            // TEMP - TODO: use "success"
            //if (response.success == false)

            ErrorCode = response.errorCode;
            State = response.state;
            Uptime = TimeSpan.FromMilliseconds(response.t100ms * 100);
            Log($"State: {State}, ErrorCode: {ErrorCode}, Uptime: {Uptime}");

            if (response.id != null && LastActionId <= response.id || (response.id == 0 && LastActionId == mask))
            {
                // We increment the action id (we actually just set it to be equal to the previous message's ID we've sent)
                LastActionId = (int)response.id;

                Log($"Received response to last action, set LastActionId to {LastActionId}");

                // First time received reply to QUERY - send also HELLO
                if (apiVersion <= 0)
                    SendHello();
            }
        }


        #endregion Receive


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
                Log($"Send: {json}");

                lock (websocket_lock)
                {
                    if (websocket == null)
                    {
                        Log($"Sending {msg} - but websocket is closed, trying to open", true);
                        Start();
                    }
                    websocket.Send(json);
                    return;
                }
            }
            catch (SocketException ex)
            {
                Log($"Send: SocketException", ex);
            }
            catch (Exception ex)
            {
                Log($"Send: Exception", ex);
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
