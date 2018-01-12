using Chaos.NaCl;
using CryptoSysAPI;
using Elliptic;
using Org.BouncyCastle.Security;
using SecurityDriven.Inferno.Kdf;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Http;

namespace ColdBear.ConsoleApp
{
    public class PairVerifyController : ApiController
    {
        //public async Task<HttpResponseMessage> Post()
        public byte[] Post(byte[] body, ControllerSession session)
        {
            //var body = await Request.Content.ReadAsByteArrayAsync();

            Debug.WriteLine($"Length of input is {body.Length} bytes");

            var parts = TLVParser.Parse(body);

            var state = parts.GetTypeAsInt(Constants.State);

            Debug.WriteLine($"Pair Setup: Status [{state}]");

            if (state == 1)
            {
                Console.WriteLine("Pair Verify Step 1/4");
                Console.WriteLine("Verify Start Request");

                var clientPublicKey = parts.GetType(Constants.PublicKey);

                byte[] privateKey = new byte[32];
                SecureRandom random = new SecureRandom();
                random.NextBytes(privateKey);

                var publicKey = Curve25519.GetPublicKey(privateKey);

                var sharedSecret = Curve25519.GetSharedSecret(privateKey, clientPublicKey);

                var serverUsername = Encoding.UTF8.GetBytes(Program.ID);

                byte[] material = publicKey.Concat(serverUsername).Concat(clientPublicKey).ToArray();

                var accessoryLTSK = File.ReadAllBytes("PrivateKey");

                byte[] proof = Ed25519.Sign(material, accessoryLTSK);

                HKDF g = new HKDF(() => { return new HMACSHA512(); }, sharedSecret, Encoding.UTF8.GetBytes("Pair-Verify-Encrypt-Salt"), Encoding.UTF8.GetBytes("Pair-Verify-Encrypt-Info"));
                var outputKey = g.GetBytes(32);

                TLV encoder = new TLV();
                encoder.AddType(Constants.Identifier, serverUsername);
                encoder.AddType(Constants.Signature, proof);

                byte[] plaintext = TLVParser.Serialise(encoder);

                var nonce = Cnv.FromHex("00000000").Concat(Encoding.UTF8.GetBytes("PV-Msg02")).ToArray();
                var aad = new byte[0];

                byte[] outputTag = new byte[0];

                var encryptedOutput = Aead.Encrypt(out outputTag, plaintext, outputKey, nonce, aad, Aead.Algorithm.Chacha20_Poly1305);

                byte[] ret = encryptedOutput.Concat(outputTag).ToArray();

                TLV responseTLV = new TLV();
                responseTLV.AddType(Constants.State, 2);
                responseTLV.AddType(Constants.PublicKey, publicKey);
                responseTLV.AddType(Constants.EncryptedData, ret);

                // Store the details on the session.
                //
                session.ClientPublicKey = clientPublicKey;
                session.PrivateKey = privateKey;
                session.PublicKey = publicKey;
                session.SharedSecret = sharedSecret;
                session.HkdfPairEncKey = outputKey;

                var output = TLVParser.Serialise(responseTLV);

                return output;

                //ByteArrayContent content = new ByteArrayContent(output);
                //content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/pairing+tlv8");

                //return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
                //{
                //    Content = content
                //};
            }
            else if (state == 3)
            {
                Console.WriteLine("Pair Verify Step 3/4");
                Console.WriteLine("Verify Start Request");

                // We're looking good here. Need to set the encryption/settings on this session.
                //
                session.IsVerified = true;
                session.SkipFirstEncryption = true;

                TLV responseTLV = new TLV();
                responseTLV.AddType(Constants.State, 4);

                var output = TLVParser.Serialise(responseTLV);

                return output;

                //ByteArrayContent content = new ByteArrayContent(output);
                //content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/pairing+tlv8");

                //return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
                //{
                //    Content = content
                //};
            }

            //return new HttpResponseMessage(System.Net.HttpStatusCode.BadRequest);
            return null;
        }

        public static byte[] StringToByteArray(String hex)
        {
            hex = hex.Replace(" ", "");
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString().ToUpper();
        }
    }
}
