using Org.BouncyCastle.Crypto.Agreement.Srp;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using SRP6;
using System;
using System.Diagnostics;
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

            BigInteger generator = new BigInteger("5");
            BigInteger modulus = new BigInteger("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08" +
            "8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B" +
            "302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9" +
            "A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6" +
            "49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8" +
            "FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" +
            "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C" +
            "180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718" +
            "3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D" +
            "04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D" +
            "B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226" +
            "1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C" +
            "BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC" +
            "E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF");
            //int SaltBitLength = 128;
            //int ScramblerBitLength = 256;
            //byte[] identityHash = Encoding.Unicode.GetBytes(("CC:22:3D:E3:CE:A6" + ":" + "456-45-456")).Sha512Hash();

            if (state == 1)
            {
                Debug.WriteLine("Pair Setup starting");

                //Org.BouncyCastle.Crypto.Agreement.Srp.Srp6Server service = new Org.BouncyCastle.Crypto.Agreement.Srp.Srp6Server();
                //service.

                //// Server generates public-key, scrambler, and salt
                ////
                //sessionServer = new Srp6(identityHash, modulus, Generator, SaltBitLength, ScramblerBitLength);
                //https://www.programcreek.com/java-api-examples/index.php?api=org.bouncycastle.crypto.agreement.srp.SRP6Server

                Random rnd = new Random();
                Byte[] salt = new Byte[16];
                rnd.NextBytes(salt);

                //var salt = sessionServer.Salt;
                //var publicKey = sessionServer.PublicKey;
                Srp6VerifierGenerator gen = new Srp6VerifierGenerator();
                gen.Init(modulus, generator, new Sha512Digest());
                BigInteger verifier = gen.GenerateVerifier(salt, Encoding.ASCII.GetBytes("CC:22:3D:E3:CE:A6"), Encoding.ASCII.GetBytes("456-45-456"));

                SecureRandom random = new SecureRandom();

                sessionServer = new Srp6Server();
                sessionServer.Init(modulus, generator, verifier, new Sha512Digest(), random);

                var serverPublicKey = sessionServer.GenerateServerCredentials();

                TLV responseTLV = new TLV();

                responseTLV.AddType(Constants.State, 2);
                responseTLV.AddType(Constants.PublicKey, serverPublicKey.ToByteArray());
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
                var iOSPublicKey = parts.GetType(Constants.PublicKey);
                var iOSProof = parts.GetType(Constants.Proof);

                var isValid = sessionServer.VerifyClientEvidenceMessage(new BigInteger(iOSProof));// .SetSessionKey(iOSPublicKey.ToHexString());

                TLV responseTLV = new TLV();
                responseTLV.AddType(Constants.State, 4);

                if (isValid)
                {
                    var accessoryProof = sessionServer.CalculateServerEvidenceMessage();

                    responseTLV.AddType(Constants.State, 4);
                    responseTLV.AddType(Constants.Proof, accessoryProof.ToByteArray());
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
    }
}
