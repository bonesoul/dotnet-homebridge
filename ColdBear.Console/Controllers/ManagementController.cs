using CryptoSysAPI;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Http;

namespace ColdBear.ConsoleApp.Controllers
{
    public class ManagementController : ApiController
    {
        public IHttpActionResult Put(int value)
        {
            JArray characteristicsArray = new JArray();

            JObject characteristicObject = new JObject();
            characteristicObject.Add("aid", 3);
            characteristicObject.Add("iid", 8);
            characteristicObject.Add("value", value);

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

            Console.WriteLine("********************");
            Console.WriteLine("* ENCRYPTING EVENT *");
            Console.WriteLine("********************");

            var resultData = new byte[0];

            for (int offset = 0; offset < response.Length;)
            {
                int length = Math.Min(response.Length - offset, 1024);

                var dataLength = BitConverter.GetBytes((short)length);

                resultData = resultData.Concat(dataLength).ToArray();

                var nonce = Cnv.FromHex("00000000").Concat(BitConverter.GetBytes(Program.CurrentSession.OutboundBinaryMessageCount++)).ToArray();

                var dataToEncrypt = new byte[length];
                Array.Copy(response, offset, dataToEncrypt, 0, length);

                // Use the AccessoryToController key to decrypt the data.
                //
                var authTag = new byte[16];
                var encryptedData = Aead.Encrypt(out authTag, dataToEncrypt, Program.CurrentSession.AccessoryToControllerKey, nonce, dataLength, Aead.Algorithm.Chacha20_Poly1305);

                resultData = resultData.Concat(encryptedData).Concat(authTag).ToArray();

                offset += length;
            }

            response = resultData;

            Program.CurrentlyConnectedController.GetStream().Write(response, 0, response.Length);
            Program.CurrentlyConnectedController.GetStream().Flush();

            return Ok();
        }
    }
}
