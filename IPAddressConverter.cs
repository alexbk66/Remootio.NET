﻿using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Remootio
{
    /// <summary>
    /// https://pingfu.net//how-to-serialise-ipaddress-ipendpoint
    /// </summary>
    public class IPAddressConverter : JsonConverter
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="objectType"></param>
        /// <returns></returns>
        public override bool CanConvert(Type objectType)
        {
            if (objectType == typeof(IPAddress)) return true;
            if (objectType == typeof(List<IPAddress>)) return true;

            return false;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="objectType"></param>
        /// <param name="existingValue"></param>
        /// <param name="serializer"></param>
        /// <returns></returns>
        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            // convert an ipaddress represented as a string into an IPAddress object and return it to the caller
            if (objectType == typeof(IPAddress))
            {
                return IPAddress.Parse(JToken.Load(reader).ToString());
            }

            // convert a json array of ipaddresses represented as strings into a List<IPAddress> object and return it to the caller
            if (objectType == typeof(List<IPAddress>))
            {
                return JToken.Load(reader).Select(address => IPAddress.Parse((string)address)).ToList();
            }

            throw new NotImplementedException();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="value"></param>
        /// <param name="serializer"></param>
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            // convert an IPAddress object to a string representation of itself and write it to the serialiser
            if (value.GetType() == typeof(IPAddress))
            {
                JToken.FromObject(value.ToString()).WriteTo(writer);
                return;
            }

            // convert a List<IPAddress> object to an array of strings of ipaddresses and write it to the serialiser
            if (value.GetType() == typeof(List<IPAddress>))
            {
                JToken.FromObject((from n in (List<IPAddress>)value select n.ToString()).ToList()).WriteTo(writer);
                return;
            }

            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// 
    /// </summary>
    public class IPEndPointConverter : JsonConverter
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="objectType"></param>
        /// <returns></returns>
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(IPEndPoint);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="objectType"></param>
        /// <param name="existingValue"></param>
        /// <param name="serializer"></param>
        /// <returns></returns>
        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            return JToken.Load(reader).ToString().ToIPEndPoint();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="value"></param>
        /// <param name="serializer"></param>
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            var ipEndPoint = value as IPEndPoint;
            if (ipEndPoint != null)
            {
                if (ipEndPoint.Address != null || ipEndPoint.Port != 0)
                {
                    JToken.FromObject(string.Format("{0}:{1}", ipEndPoint.Address, ipEndPoint.Port)).WriteTo(writer);
                    return;
                }
            }
            writer.WriteNull();
        }
    }

    /// <summary>
    /// 
    /// </summary>
    public static class IPAddressExtensions
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="ipEndPoint"></param>
        /// <returns></returns>
        public static IPEndPoint ToIPEndPoint(this string ipEndPoint)
        {
            if (string.IsNullOrWhiteSpace(ipEndPoint))
            {
                return null;
            }

            var components = ipEndPoint.Split(':');

            return new IPEndPoint(IPAddress.Parse(components[0]), Convert.ToInt32(components[1]));
        }


        /// <summary>
        /// Helper for Deserializing oblects containing IPAddress, IPEndPoint
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="json"></param>
        /// <param name="IPAddress"></param>
        /// <returns></returns>
        public static T DeserializeObject<T>(string json)
        {
            JsonConverter[] converters = { new IPAddressConverter(), new IPEndPointConverter() };
            return JsonConvert.DeserializeObject<T>(json, converters);
        }

        public static string SerializeObject<T>(T obj)
        {
            JsonConverter[] converters = { new IPAddressConverter(), new IPEndPointConverter() };
            return JsonConvert.SerializeObject(obj, converters);
        }

}
}
