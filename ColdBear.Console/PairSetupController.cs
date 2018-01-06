using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement.Srp;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;

namespace ColdBear.ConsoleApp
{
    public class PairSetupController : ApiController
    {
        //private static Srp6 sessionServer;
        private static Srp6Server sessionServer;

        public async Task<HttpResponseMessage> Post()
        {
            var body = await Request.Content.ReadAsByteArrayAsync();

            Debug.WriteLine($"Length of input is {body.Length} bytes");

            var parts = TLVParser.Parse(body);

            var state = parts.GetTypeAsInt(Constants.State);

            Debug.WriteLine($"Pair Setup: Status [{state}]");

            if (state == 1)
            {
                Debug.WriteLine("Pair Setup starting");

                Random randomNumber = new Random();
                int code = randomNumber.Next(100, 999);

                var CODE = $"123-45-{code}";

                Console.WriteLine($"CODE: {CODE}");

                Random rnd = new Random();
                Byte[] salt = new Byte[16];
                rnd.NextBytes(salt);

                // **** BOUNCY CASTLE CODE ****
                //https://www.programcreek.com/java-api-examples/index.php?api=org.bouncycastle.crypto.agreement.srp.SRP6Server

                //IDigest digest = new Sha512Digest();

                var parms = Srp6StandardGroups.rfc5054_3072;

                Srp6VerifierGenerator gen = new Srp6VerifierGenerator();
                gen.Init(parms, new Sha512Digest());

                BigInteger verifier = gen.GenerateVerifier(salt, Encoding.UTF8.GetBytes(Program.ID), Encoding.UTF8.GetBytes(CODE));

                SecureRandom random = new SecureRandom();

                sessionServer = new Srp6Server();
                sessionServer.Init(parms, verifier, new Sha512Digest(), random);

                BigInteger publicKeyInt = sessionServer.GenerateServerCredentials(); // B
                var publicKey = publicKeyInt.ToByteArray();

                //Srp6Client client = new Srp6Client();
                //client.Init(parms, digest, random);

                //var clientPublicKey = client.GenerateClientCredentials(salt, Encoding.ASCII.GetBytes(Program.ID), Encoding.ASCII.GetBytes("456-45-456"));
                //client.CalculateSecret(publicKeyInt);
                //var clientProof = client.CalculateClientEvidenceMessage();

                //sessionServer.CalculateSecret(clientPublicKey);

                //Console.WriteLine("M1");
                //Console.WriteLine(ByteArrayToString(clientProof.ToByteArray()));

                //var isValid = sessionServer.VerifyClientEvidenceMessage(clientProof);

                TLV responseTLV = new TLV();

                if (publicKey[0] == 0x00)
                {
                    Debug.WriteLine("Server PublicKey starts with a null, so let's strip that off!");
                    Array.Copy(publicKey, 1, publicKey, 0, publicKey.Length - 1);
                }

                responseTLV.AddType(Constants.State, 2);
                responseTLV.AddType(Constants.PublicKey, publicKey);
                responseTLV.AddType(Constants.Salt, salt);

                byte[] output = TLVParser.Serialise(responseTLV);

                ByteArrayContent content = new ByteArrayContent(output);
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/pairing+tlv8");

                return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
                {
                    Content = content
                };
            }
            else if (state == 3)
            {
                Debug.WriteLine("SRP Verify Request");
                var iOSPublicKey = parts.GetType(Constants.PublicKey); // A 
                var iOSProof = parts.GetType(Constants.Proof); // M1

                // Set value A
                //
                var serverSecretInt = sessionServer.CalculateSecret(new BigInteger(iOSPublicKey));

                // Validate M1
                //
                var isValid = sessionServer.VerifyClientEvidenceMessage(new BigInteger(iOSProof));

                TLV responseTLV = new TLV();
                responseTLV.AddType(Constants.State, 4);

                if (isValid)
                {
                    Console.WriteLine("Verification was successful.");

                    var serverProofInt = sessionServer.CalculateServerEvidenceMessage();
                    var serverProof = serverProofInt.ToByteArray();

                    responseTLV.AddType(Constants.Proof, serverProof);
                }
                else
                {
                    Console.WriteLine("Verification failed as iOS provided code was incorrect");
                    responseTLV.AddType(Constants.Error, ErrorCodes.Authentication);
                }

                byte[] output = TLVParser.Serialise(responseTLV);

                ByteArrayContent content = new ByteArrayContent(output);
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/pairing+tlv8");

                return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
                {
                    Content = content
                };
            }

            return new HttpResponseMessage(System.Net.HttpStatusCode.BadRequest);
        }

        private BigInteger FromHex(string hex)
        {
            return new BigInteger(1, StringToByteArray(hex));
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }
    }
}
