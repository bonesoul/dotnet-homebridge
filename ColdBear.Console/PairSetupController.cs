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
            BigInteger modulus = new BigInteger("20E176988FD33DE7AE0D296BF805A49F3F45B92FB59036DCC9F0624B89B2DB67");
            int SaltBitLength = 128;
            int ScramblerBitLength = 256;
            byte[] identityHash = Encoding.Unicode.GetBytes(("CC:22:3D:E3:CE:A6" + ":" + "456-45-456")).Sha512Hash();

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
