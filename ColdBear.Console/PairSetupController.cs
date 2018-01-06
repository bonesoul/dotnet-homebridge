//using Org.BouncyCastle.Crypto.Agreement.Srp;
//using Org.BouncyCastle.Crypto.Digests;
//using Org.BouncyCastle.Math;
//using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement.Srp;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using SRP6;
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

            // BouncyCastle variables
            //
            BigInteger generator = BigInteger.ValueOf(5);
            BigInteger modulus = FromHex("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
+ "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
+ "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
+ "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
+ "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
+ "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
+ "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
+ "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
+ "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
+ "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
+ "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
+ "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
+ "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
+ "E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF");



            // Srp6 variables.
            //
            //int generator = 0x05;
            //string modulus = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
            //"8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
            //"302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
            //"A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
            //"49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
            //"FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            //"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
            //"180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
            //"3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
            //"04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
            //"B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226" +
            //"1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
            //"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC" +
            //"E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
            //int SaltBitLength = 128;
            //int ScramblerBitLength = 256;
            //byte[] identityHash = Encoding.Unicode.GetBytes(("CC:22:3D:E3:CE:A6" + ":" + "456-45-456")).Sha512Hash();

            var parts = TLVParser.Parse(body);
            int state = 1;

            if (parts.HasType(Constants.State))
            {
                state = parts.GetTypeAsInt(Constants.State);
            }

            if (state == 1)
            {
                Debug.WriteLine("Pair Setup starting");

                Random rnd = new Random();
                Byte[] salt = new Byte[16];
                rnd.NextBytes(salt);

                //// Server generates public-key, scrambler, and salt
                ////
                //sessionServer = new Srp6(identityHash, modulus, generator, salt.ToHexString());

                ////var salt = sessionServer.Salt.ToByteArray();
                //var publicKey = sessionServer.PublicKey.ToByteArray();

                // **** BOUNCY CASTLE CODE ****
                //https://www.programcreek.com/java-api-examples/index.php?api=org.bouncycastle.crypto.agreement.srp.SRP6Server

                //Random rnd = new Random();
                //Byte[] salt = new Byte[16];
                //rnd.NextBytes(salt);

                IDigest digest = new Sha512Digest();

                var parms = Srp6StandardGroups.rfc5054_3072;

                Srp6VerifierGenerator gen = new Srp6VerifierGenerator();
                gen.Init(parms, digest);

                BigInteger verifier = gen.GenerateVerifier(salt, Encoding.UTF8.GetBytes("CC:22:3D:E3:CE:A6"), Encoding.UTF8.GetBytes("456-45-456"));

                SecureRandom random = new SecureRandom();

                sessionServer = new Srp6Server();
                sessionServer.Init(parms, verifier, digest, random);

                BigInteger publicKeyInt = sessionServer.GenerateServerCredentials(); // B
                var publicKey = publicKeyInt.ToByteArray();

                //Srp6Client client = new Srp6Client();
                //client.Init(parms, digest, random);

                //var clientPublicKey = client.GenerateClientCredentials(salt, Encoding.ASCII.GetBytes("CC:22:3D:E3:CE:A6"), Encoding.ASCII.GetBytes("456-45-456"));
                //client.CalculateSecret(publicKeyInt);
                //var clientProof = client.CalculateClientEvidenceMessage();

                //sessionServer.CalculateSecret(clientPublicKey);
                //var isValid = sessionServer.VerifyClientEvidenceMessage(clientProof);


                TLV responseTLV = new TLV();

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
                    var serverProofInt = sessionServer.CalculateServerEvidenceMessage();
                    var serverProof = serverProofInt.ToByteArray();

                    responseTLV.AddType(Constants.Proof, serverProof);

                    //if (isValid)
                    //{
                    //    var accessoryProof = sessionServer.CalculateServerEvidenceMessage();

                    //responseTLV.AddType(Constants.State, 4);
                    //    responseTLV.AddType(Constants.Proof, accessoryProof.ToByteArray());
                }
                else
                {
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
