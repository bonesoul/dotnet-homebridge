using Newtonsoft.Json.Linq;
using System;
using System.Text;

namespace ColdBear.ConsoleApp
{
    public class CharacteristicsController
    {
        public Tuple<string, byte[]> Get(int aid, int iid, ControllerSession session)
        {
            JArray characteristicsArray = new JArray();
            JObject characteristicObject = new JObject();
            characteristicObject.Add("aid", aid);
            characteristicObject.Add("iid", iid);

            characteristicObject.Add("value", 1);

            characteristicsArray.Add(characteristicObject);

            JObject jsonObj = new JObject();
            jsonObj.Add("characteristics", characteristicsArray);

            var characteristicJson = jsonObj.ToString();

            var output = Encoding.UTF8.GetBytes(characteristicJson);

            return new Tuple<string, byte[]>("application/hap+json", output);
        }

        internal Tuple<string, byte[]> Put(byte[] v, ControllerSession session)
        {
            var json = Encoding.UTF8.GetString(v);
            JObject jsonObject = JObject.Parse(json);

            return new Tuple<string, byte[]>("application/hap+json", new byte[0]);
        }
    }
}
