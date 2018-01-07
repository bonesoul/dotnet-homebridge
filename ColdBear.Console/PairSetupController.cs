using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement.Srp;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using SRP;
using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;

namespace ColdBear.ConsoleApp
{
    public class PairSetupController : ApiController
    {
        //private static Srp6 sessionServer;
        //private static Srp6Server sessionServer;
        private static SRPServer sessionServer;
        private static string CODE;
        private static byte[] salt;

        private static byte[] server_k;
        private static byte[] server_x;
        private static System.Numerics.BigInteger server_v;
        private static byte[] server_b;
        private static System.Numerics.BigInteger server_B;

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

                CODE = $"123-45-{code}";

                Console.WriteLine($"CODE: {CODE}");

                Random rnd = new Random();
                salt = new Byte[16];
                rnd.NextBytes(salt);

                // **** BOUNCY CASTLE CODE ****
                //https://www.programcreek.com/java-api-examples/index.php?api=org.bouncycastle.crypto.agreement.srp.SRP6Server

                //IDigest digest = new Sha512Digest();

                //var parms = Srp6StandardGroups.rfc5054_3072;

                //Srp6VerifierGenerator gen = new Srp6VerifierGenerator();
                //gen.Init(parms, new Sha512Digest());

                //BigInteger verifier = gen.GenerateVerifier(salt, Encoding.UTF8.GetBytes(Program.ID), Encoding.UTF8.GetBytes(CODE));

                //SecureRandom random = new SecureRandom();

                //sessionServer = new Srp6Server();
                //sessionServer.Init(parms, verifier, new Sha512Digest(), random);

                //BigInteger publicKeyInt = sessionServer.GenerateServerCredentials(); // B
                //var publicKey = publicKeyInt.ToByteArray();

                //Srp6Client client = new Srp6Client();
                //client.Init(parms, digest, random);

                //var clientPublicKey = client.GenerateClientCredentials(salt, Encoding.ASCII.GetBytes(Program.ID), Encoding.ASCII.GetBytes("456-45-456"));
                //client.CalculateSecret(publicKeyInt);
                //var clientProof = client.CalculateClientEvidenceMessage();

                //sessionServer.CalculateSecret(clientPublicKey);

                //Console.WriteLine("M1");
                //Console.WriteLine(ByteArrayToString(clientProof.ToByteArray()));

                //var isValid = sessionServer.VerifyClientEvidenceMessage(clientProof);

                var I = "Pair-Setup";// Program.ID;
                var P = CODE;

                //I = "alice";
                //P = "password123";

                salt = StringToByteArray("BEB25379 D1A8581E B5A72767 3A2441EE");
                //byte[] s = StringToByteArray("BEB25379 D1A8581E B5A72767 3A2441EE");

                var hashAlgorithm = SHA512.Create();
                var groupParameter = SRP.SRP.Group_3072;

                sessionServer = new SRPServer(groupParameter, hashAlgorithm);

                server_k = sessionServer.Compute_k();

                server_x = sessionServer.Compute_x(salt, I, P);

                server_v = sessionServer.Compute_v(server_x.ToBigInteger());

                Console.WriteLine($"Verifier [Length={server_v.ToBytes().Length}]");
                Console.WriteLine(server_v.ToString("X"));

                //server_b = StringToByteArray("E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 05284D20");

                server_b = new Byte[32];
                rnd.NextBytes(server_b);

                server_B = sessionServer.Compute_B(server_v, server_k.ToBigInteger(), server_b.ToBigInteger());

                Console.WriteLine($"B [Length={server_B.ToBytes().Length}]");
                Console.WriteLine(server_B.ToString("X"));

                var publicKey = server_B.ToBytes();

                TLV responseTLV = new TLV();

                if (publicKey[0] == 0x00)
                {
                    Debug.WriteLine("Server PublicKey starts with a null, so let's strip that off!");
                    Array.Copy(publicKey, 1, publicKey, 0, publicKey.Length - 1);
                    server_B = publicKey.ToBigInteger();
                }

                if (publicKey[publicKey.Length - 1] == 0x00)
                {
                    Debug.WriteLine("Server PublicKey ends with a null, so let's strip that off!");
                    byte[] tmp = new byte[publicKey.Length - 1];
                    Array.Copy(publicKey, 0, tmp, 0, publicKey.Length - 1);
                    publicKey = tmp;
                    server_B = tmp.ToBigInteger();
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

                // Test Vector
                //              iOSPublicKey = StringToByteArray("FAB6F5D2 615D1E32 3512E799 1CC37443 F487DA60 4CA8C923 0FCB04E5 41DCE628" +
                //"0B27CA46 80B0374F 179DC3BD C7553FE6 2459798C 701AD864 A91390A2 8C93B644" +
                //"ADBF9C00 745B942B 79F9012A 21B9B787 82319D83 A1F83628 66FBD6F4 6BFC0DDB" +
                //"2E1AB6E4 B45A9906 B82E37F0 5D6F97F6 A3EB6E18 2079759C 4F684783 7B62321A" +
                //"C1B4FA68 641FCB4B B98DD697 A0C73641 385F4BAB 25B79358 4CC39FC8 D48D4BD8" +
                //"67A9A3C1 0F8EA121 70268E34 FE3BBE6F F89998D6 0DA2F3E4 283CBEC1 393D52AF" +
                //"724A5723 0C604E9F BCE583D7 613E6BFF D67596AD 121A8707 EEC46944 95703368" +
                //"6A155F64 4D5C5863 B48F61BD BF19A53E AB6DAD0A 186B8C15 2E5F5D8C AD4B0EF8" +
                //"AA4EA500 8834C3CD 342E5E0F 167AD045 92CD8BD2 79639398 EF9E114D FAAAB919" +
                //"E14E8509 89224DDD 98576D79 385D2210 902E9F9B 1F2D86CF A47EE244 635465F7" +
                //"1058421A 0184BE51 DD10CC9D 079E6F16 04E7AA9B 7CF7883C 7D4CE12B 06EBE160" +
                //"81E23F27 A231D184 32D7D1BB 55C28AE2 1FFCF005 F57528D1 5A88881B B3BBB7FE");

                Console.WriteLine("A");
                Console.WriteLine(ByteArrayToString(iOSPublicKey));

                Console.WriteLine("M1 (Client)");
                Console.WriteLine(ByteArrayToString(iOSProof));

                // Compute the scrambler.
                //
                var u = sessionServer.Compute_u(iOSPublicKey, server_B.ToBytes());

                Console.WriteLine("U (Scramber)");
                Console.WriteLine(ByteArrayToString(u));

                // Compute the premaster secret
                //
                var server_S = sessionServer.Compute_S(iOSPublicKey.ToBigInteger(), server_v, u.ToBigInteger(), server_b.ToBigInteger());
                Console.WriteLine("S");
                Console.WriteLine(server_S.ToString("X"));

                // Compute the session key
                //
                var server_K = sessionServer.Compute_K(server_S.ToBytes());

                Console.WriteLine("K (Session Key)");
                Console.WriteLine(ByteArrayToString(server_K));

                // I Think this is where the problem lies. I believe the server is computing a totally different M1
                //
                var server_M1 = sessionServer.Compute_M1("Pair-Setup", salt, iOSPublicKey, server_B.ToBytes(), server_K);
                //var server_M1 = sessionServer.Compute_M1(iOSPublicKey, server_B.ToBytes(), server_K);

                Console.WriteLine("M1 (Server)");
                Console.WriteLine(ByteArrayToString(server_M1));

                bool isValid = iOSProof.CheckEquals(server_M1);

                

                TLV responseTLV = new TLV();
                responseTLV.AddType(Constants.State, 4);

                if (isValid)
                {
                    Console.WriteLine("Verification was successful. Generating Server Proof (M2)");

                    var server_M2 = sessionServer.Compute_M2(iOSPublicKey, server_M1, server_K);

                    responseTLV.AddType(Constants.Proof, server_M2);
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
