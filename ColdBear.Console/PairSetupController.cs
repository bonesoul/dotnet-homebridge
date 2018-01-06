//using Org.BouncyCastle.Crypto.Agreement.Srp;
//using Org.BouncyCastle.Crypto.Digests;
//using Org.BouncyCastle.Math;
//using Org.BouncyCastle.Security;
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
        private static Srp6 sessionServer;
        //private static Srp6Server sessionServer;

        public async Task<HttpResponseMessage> Post()
        {
            var body = await Request.Content.ReadAsByteArrayAsync();

            Debug.WriteLine($"Length of input is {body.Length} bytes");

            //            BigInteger generator = new BigInteger("5");
            //            BigInteger modulus = FromHex("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
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
            //"E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF");

            //BigInteger modulus = new BigInteger("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08" +
            //"8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B" +
            //"302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9" +
            //"A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6" +
            //"49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8" +
            //"FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" +
            //"670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C" +
            //"180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718" +
            //"3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D" +
            //"04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D" +
            //"B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226" +
            //"1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C" +
            //"BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC" +
            //"E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF");
            //System.Numerics.BigInteger generator = new System.Numerics.BigInteger("5");
            //System.Numerics.BigInteger modulus = new System.Numerics.BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
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
            //"E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF");
            int generator = 0x05;
            string modulus = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
            "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
            "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
            "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
            "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
            "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
            "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
            "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
            "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
            "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226" +
            "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
            "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC" +
            "E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
            //int SaltBitLength = 128;
            //int ScramblerBitLength = 256;
            byte[] identityHash = Encoding.Unicode.GetBytes(("CC:22:3D:E3:CE:A6" + ":" + "456-45-456")).Sha512Hash();

            var parts = TLVParser.Parse(body);
            int state = 1;

            if (parts.HasType(Constants.State))
            {
                parts.GetTypeAsInt(Constants.State);
            }

            if (state == 1)
            {
                Debug.WriteLine("Pair Setup starting");

                Random rnd = new Random();
                Byte[] salt = new Byte[16];
                rnd.NextBytes(salt);

                // Server generates public-key, scrambler, and salt
                //
                sessionServer = new Srp6(identityHash, modulus, generator, salt.ToHexString());

                //var salt = sessionServer.Salt.ToByteArray();
                var publicKey = sessionServer.PublicKey.ToByteArray();

                // **** BOUNCY CASTLE CODE ****
                //https://www.programcreek.com/java-api-examples/index.php?api=org.bouncycastle.crypto.agreement.srp.SRP6Server

                //Random rnd = new Random();
                //Byte[] salt = new Byte[16];
                //rnd.NextBytes(salt);

                //Srp6VerifierGenerator gen = new Srp6VerifierGenerator();
                //gen.Init(modulus, generator, new Sha512Digest());

                //BigInteger verifier = gen.GenerateVerifier(salt, Encoding.ASCII.GetBytes("alice"), Encoding.ASCII.GetBytes("password123"));

                ////BigInteger verifier = gen.GenerateVerifier(salt, Encoding.ASCII.GetBytes("CC:22:3D:E3:CE:A6"), Encoding.ASCII.GetBytes("456-45-456"));

                //SecureRandom random = new SecureRandom();

                //sessionServer = new Srp6Server();
                //sessionServer.Init(modulus, generator, verifier, new Sha512Digest(), random);

                //var serverPublicKey = sessionServer.GenerateServerCredentials();
                //var serverPublicKeyByteArray = serverPublicKey.ToByteArray();

                //Debug.WriteLine(ByteArrayToString(serverPublicKeyByteArray));
                //Debug.WriteLine(ByteArrayToString(salt));

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
                var iOSPublicKey = parts.GetType(Constants.PublicKey);
                var iOSProof = parts.GetType(Constants.Proof);

                //var isValid = sessionServer.VerifyClientEvidenceMessage(new BigInteger(iOSProof));// .SetSessionKey(iOSPublicKey.ToHexString());

                TLV responseTLV = new TLV();
                responseTLV.AddType(Constants.State, 4);

                //if (isValid)
                //{
                //    var accessoryProof = sessionServer.CalculateServerEvidenceMessage();

                //    responseTLV.AddType(Constants.State, 4);
                //    responseTLV.AddType(Constants.Proof, accessoryProof.ToByteArray());
                //}
                //else
                //{
                responseTLV.AddType(Constants.Error, ErrorCodes.Authentication);
                //}

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

        //private BigInteger FromHex(string hex)
        //{
        //    return new BigInteger(1, StringToByteArray(hex));
        //}

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
