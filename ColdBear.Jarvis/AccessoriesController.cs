using CryptoSysAPI;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace ColdBear.Climenole
{
    public class AccessoriesController
    {
        public Tuple<string, byte[]> Get(ControllerSession session)
        {
            Console.WriteLine("* Accessories Controller");
            Console.WriteLine("* List accessories");

            var output = File.ReadAllBytes(@"C:\Development\dotnet-homebridge\ColdBear.Console\accessories.json");

            return new Tuple<string, byte[]>("application/hap+json", output);
        }

        public byte[] Put(ControllerSession session, int aid, int iid, object value)
        {
            Console.WriteLine("* Accessories Controller");
            Console.WriteLine("* Update accessory");

            if (session == null)
            {
                return new byte[0];
            }

            //var output = File.ReadAllBytes(@"C:\Development\dotnet-homebridge\ColdBear.Console\accessories.json");

            JArray characteristicsArray = new JArray();

            JObject characteristicObject = new JObject();
            characteristicObject.Add("aid", aid);
            characteristicObject.Add("iid", iid);
            characteristicObject.Add("value", (int)value);

            characteristicsArray.Add(characteristicObject);

            JObject jsonObj = new JObject();
            jsonObj.Add("characteristics", characteristicsArray);

            var characteristicJson = jsonObj.ToString();
            var output = Encoding.UTF8.GetBytes(characteristicJson);

            var response = new byte[0];
            var returnChars = new byte[2];
            returnChars[0] = 0x0D;
            returnChars[1] = 0x0A;

            var contentLength = $"Content-Length: {output.Length}";

            response = response.Concat(Encoding.ASCII.GetBytes("EVENT/1.0 200 OK")).Concat(returnChars).ToArray();
            response = response.Concat(Encoding.ASCII.GetBytes($"Content-Type: application/hap+json")).Concat(returnChars).ToArray();
            response = response.Concat(Encoding.ASCII.GetBytes(contentLength)).Concat(returnChars).ToArray();
            response = response.Concat(returnChars).ToArray();
            response = response.Concat(output).ToArray();

            Console.WriteLine("* ENCRYPTING EVENT");

            var resultData = new byte[0];

            for (int offset = 0; offset < response.Length;)
            {
                int length = Math.Min(response.Length - offset, 1024);

                var dataLength = BitConverter.GetBytes((short)length);

                resultData = resultData.Concat(dataLength).ToArray();

                var nonce = Cnv.FromHex("00000000").Concat(BitConverter.GetBytes(session.OutboundBinaryMessageCount++)).ToArray();

                var dataToEncrypt = new byte[length];
                Array.Copy(response, offset, dataToEncrypt, 0, length);

                // Use the AccessoryToController key to decrypt the data.
                //
                var authTag = new byte[16];
                var encryptedData = Aead.Encrypt(out authTag, dataToEncrypt, session.AccessoryToControllerKey, nonce, dataLength, Aead.Algorithm.Chacha20_Poly1305);

                resultData = resultData.Concat(encryptedData).Concat(authTag).ToArray();

                offset += length;
            }

            response = resultData;

            return response;
        }
    }
}
