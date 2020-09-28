using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Encrypt;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;


namespace Remootio
{
    public partial class Remootio
    {
        /// <summary>
        /// Message types
        /// </summary>
        public enum type
        {
            NOTSET,

            // The API client sends this to keep the connection alive. It is recommended to send one PING frame to the
            // Remootio device every 60-90 seconds and also check for the PONG response to detect a broken connection.
            // Direction: API client → Remootio device
            PING,

            // Response: Remootio device → API client
            PONG,

            // The Remootio device sends error frames to the API client to indicate various errors
            // Direction: Remootio device → API client
            ERROR,

            // Note: not documented
            INPUT_ERROR,

            // The API client can send this frame to check the version of the Websocket API running on the Remootio device
            // Direction: API client → Remootio device
            HELLO,

            // Response: Remootio device → API client
            SERVER_HELLO,

            // The API client sends the AUTH frame to start the authentication flow
            // Direction: API client → Remootio device
            AUTH,

            //
            ENCRYPTED,

            // The API client sends this action to get the current state of the gate or garage door (open/closed)
            // Direction: API client → Remootio device
            QUERY,

            // The API client sends this action to trigger the control output of the Remootio device
            // and thus operate the gate or garage door
            // Direction: API client → Remootio device
            TRIGGER,

            // The API client sends this action to open the gate or the garage door. 
            // This will trigger Remootio's control output only if the gate or garage door status is "closed"
            // Direction: API client → Remootio device
            OPEN,

            // The API client sends this action to close the gate or the garage door. 
            // This will trigger Remootio's control output only if the gate or garage door status is "open"
            // Direction: API client → Remootio device
            CLOSE,

            // The API client sends this action to restart the Remootio device. The UNENCRYPTED_PAYLOAD of the
            // action is shown below (the action id also needs to be calculated id = lastActionId % 0x7FFFFFFF) 
            // Direction: API client → Remootio device
            RESTART,

            // Remootio sends the following event if the status of the gate or garage door has changed
            // (from "open" to "closed" or from "closed" to "open"). 
            // This is the only event that is sent if the API is enabled without logging.
            // It is also sent if the API is enabled with logging. 
            // Direction: Remootio device → API client
            StateChange,

            // Remootio sends the following event if it any key has operated the Remootio device
            // (triggered the control output)
            // Direction: Remootio device → API client
            RelayTrigger,

            // Remootio sends the following event if any key has connected to the Remootio device.
            // Direction: Remootio device → API client
            Connected,

            // Remootio sends the following event if the gate or garage door has been left open for some time
            // Direction: Remootio device → API client
            LeftOpen,

            // Remootio sends the following event if the access rights or notification settings for any key have been changed
            // Direction: Remootio device → API client
            KeyManagement,

            // Remootio sends the following event if it was restarted
            // This is only sent if the API is enabled with logging
            // Direction: Remootio device → API client
            Restart,

            // Remootio sends the following event if the manual button was pushed
            // This is only sent if the API is enabled with logging
            // Direction: Remootio device → API client
            ManualButtonPushed,

            // Remootio sends the following event if the manual button was enabled
            // This is only sent if the API is enabled with logging
            // Direction: Remootio device → API client
            ManualButtonEnabled,

            // Remootio sends the following event if the manual button was disabled. 
            // This is only sent if the API is enabled with logging
            // Direction: Remootio device → API client
            ManualButtonDisabled,

            // Remootio sends the following event if the doorbell was pushed. 
            // This is only sent if the API is enabled with logging
            // Direction: Remootio device → API client
            DoorbellPushed,

            // Remootio sends the following event if the doorbell was enabled
            // This is only sent if the API is enabled with logging
            // Direction: Remootio device → API client
            DoorbellEnabled,

            // Remootio sends the following event if the doorbell was disabled
            // This is only sent if the API is enabled with logging
            // Direction: Remootio device → API client
            DoorbellDisabled,

            // Remootio sends the following event if the status sensor was enabled. 
            // This is only sent if the API is enabled with logging
            // Direction: Remootio device → API client
            SensorEnabled,

            // Remootio sends the following event if the logic of the status sensor was flipped
            // This is only sent if the API is enabled with logging
            // Direction: Remootio device → API client
            SensorFlipped,

            // Remootio sends the following event if the status sensor was disabled
            // This is only sent if the API is enabled with logging
            // Direction: Remootio device → API client
            SensorDisabled,

        }


        #region Messages


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


        [Serializable]
        public class BASE
        {
            // setting the order to 1 will only work if you set an order greater than 1 on all other properties. 
            // By default any property without an Order setting will be given an order of -1. 
            // So you must either give all serialized properties and order, or set your first item to -2
            [JsonConverter(typeof(StringEnumConverter))]
            [JsonProperty(Order = -10)]
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


        protected class AUTH : BASE
        {
            public AUTH() : base(type.AUTH) { }
        }


        protected class HELLO : BASE
        {
            public HELLO() : base(type.HELLO) { }
        }


        public class ENCRYPTED : BASE
        {
            [JsonConstructor]
            public ENCRYPTED() : base(type.ENCRYPTED) { }

            [JsonProperty(Order = -9)]
            public encr data;
            [JsonProperty(Order = -8)]
            public string mac;
        }


        public class encr
        {
            public string iv;
            public string payload;
            //public string mac;
        }



        protected class ERROR : BASE
        {
            [JsonConstructor]
            public ERROR() : base(type.ERROR) { }

            public string errorMessage;
        }

        protected class QUERY_RESPONSE : BASE
        {
            [JsonConstructor]
            public QUERY_RESPONSE() : base(type.QUERY) { }

            public int id { get; set; }
            public bool success { get; set; }
            public string state { get; set; }
            public int t100ms { get; set; }
            public bool relayTriggered { get; set; }
            public string errorCode { get; set; }
        }


        protected class SERVER_HELLO : BASE
        {
            [JsonConstructor]
            public SERVER_HELLO() : base(type.SERVER_HELLO) { }

            public int apiVersion;
            public string message;
        }
         

        #endregion Messages


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
        /// {"action":{"type":"QUERY","id":1836946866}}
        /// </summary>
        public class _ACTION : BASE
        {
            [JsonConstructor]
            public _ACTION(type type, int id)
                : base(type)
            {
                //this.type = type;
                this.id = id;
            }

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
                this.action = new _ACTION(type, id);
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

                this.data = MakeEncr(action, aes, sIV);
                this.mac = hmac(data, aes);
            }
        }


        #endregion ACTIONS
    }
}
