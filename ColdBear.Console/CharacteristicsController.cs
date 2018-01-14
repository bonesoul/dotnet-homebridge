using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace ColdBear.ConsoleApp
{
    public class CharacteristicsController
    {
        public Tuple<string, byte[]> Get(int aid, int iid, ControllerSession session)
        {
            var json = File.ReadAllText("accessories.json");
            JObject jsonObject = JObject.Parse(json);

            JObject accessory = jsonObject["accessories"].Single(a => a["aid"].Value<int>() == aid) as JObject;

            var characteristics = from c in accessory["services"].SelectMany(i => i["characteristics"]).Values<JArray>() select c;

            var characteristic = characteristics.Single(c => c["iid"].Value<int>() == iid);

            var characteristicJson = characteristic.ToString();

            var output = Encoding.UTF8.GetBytes(characteristicJson);

            return new Tuple<string, byte[]>("application/hap+json", output);
        }
    }
}
