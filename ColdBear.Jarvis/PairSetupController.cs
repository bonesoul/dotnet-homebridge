﻿using Chaos.NaCl;
using CryptoSysAPI;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using SecurityDriven.Inferno.Kdf;
using SRP;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ColdBear.Climenole
{
    public class PairSetupController
    {
        private static SRPServer sessionServer;
        private static string CODE;
        private static byte[] salt;

        private static byte[] server_k;
        private static byte[] server_K;
        private static byte[] server_x;
        private static System.Numerics.BigInteger server_v;
        private static byte[] server_b;
        private static System.Numerics.BigInteger server_B;

        public Tuple<string, byte[]> Post(byte[] body)
        {
            Debug.WriteLine($"Length of input is {body.Length} bytes");

            var parts = TLVParser.Parse(body);

            var state = parts.GetTypeAsInt(Constants.State);

            Debug.WriteLine($"Pair Setup: Status [{state}]");

            if (state == 1)
            {
                Console.WriteLine("Pair Setup Step 1/6");
                Console.WriteLine("SRP Start Response");

                Random randomNumber = new Random();
                int code = randomNumber.Next(100, 999);

                CODE = $"123-45-{code}";

                Console.WriteLine($"********************");
                Console.WriteLine($"* PIN CODE: {CODE} *");
                Console.WriteLine($"********************");

                Random rnd = new Random();
                salt = new Byte[16];
                rnd.NextBytes(salt);

                // **** BOUNCY CASTLE CODE - NOT USED ****
                //https://www.programcreek.com/java-api-examples/index.php?api=org.bouncycastle.crypto.agreement.srp.SRP6Server

                var I = "Pair-Setup";// Program.ID;
                var P = CODE;

                var hashAlgorithm = SHA512.Create();
                var groupParameter = SRP.SRP.Group_3072;

                sessionServer = new SRPServer(groupParameter, hashAlgorithm);

                server_k = sessionServer.Compute_k();

                server_x = sessionServer.Compute_x(salt, I, P);

                server_v = sessionServer.Compute_v(server_x.ToBigInteger());

                Console.WriteLine($"Verifier [Length={server_v.ToBytes().Length}]");
                Console.WriteLine(server_v.ToString("X"));

                server_b = new Byte[32];
                rnd.NextBytes(server_b);

                server_B = sessionServer.Compute_B(server_v, server_k.ToBigInteger(), server_b.ToBigInteger());

                Console.WriteLine($"B [Length={server_B.ToBytes().Length}]");
                Console.WriteLine(server_B.ToString("X"));

                var publicKey = server_B.ToBytes();

                TLV responseTLV = new TLV();

                responseTLV.AddType(Constants.State, 2);
                responseTLV.AddType(Constants.PublicKey, publicKey);
                responseTLV.AddType(Constants.Salt, salt);

                byte[] output = TLVParser.Serialise(responseTLV);

                return new Tuple<string, byte[]>("application/pairing+tlv8", output);
            }
            else if (state == 3)
            {
                Console.WriteLine("Pair Setup Step 3/6");
                Console.WriteLine("SRP Verify Request");

                var iOSPublicKey = parts.GetType(Constants.PublicKey); // A 
                var iOSProof = parts.GetType(Constants.Proof); // M1

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
                server_K = sessionServer.Compute_K(server_S.ToBytes());

                Console.WriteLine("K (Session Key)");
                Console.WriteLine(ByteArrayToString(server_K));

                // Compute the client's proof
                //
                var client_M1 = sessionServer.Compute_M1("Pair-Setup", salt, iOSPublicKey, server_B.ToBytes(), server_K);

                Console.WriteLine("M1 (Server)");
                Console.WriteLine(ByteArrayToString(client_M1));

                // Check the proof matches what was sent to us
                //
                bool isValid = iOSProof.CheckEquals(client_M1);

                TLV responseTLV = new TLV();
                responseTLV.AddType(Constants.State, 4);

                if (isValid)
                {
                    Console.WriteLine("Verification was successful. Generating Server Proof (M2)");

                    var server_M2 = sessionServer.Compute_M2(iOSPublicKey, client_M1, server_K);

                    File.WriteAllBytes("SRPProof", server_M2);

                    responseTLV.AddType(Constants.Proof, server_M2);
                }
                else
                {
                    Console.WriteLine("Verification failed as iOS provided code was incorrect");
                    responseTLV.AddType(Constants.Error, ErrorCodes.Authentication);
                }

                byte[] output = TLVParser.Serialise(responseTLV);

                return new Tuple<string, byte[]>("application/pairing+tlv8", output);
            }
            else if (state == 5)
            {
                Debug.WriteLine("Pair Setup Step 5/6");
                Debug.WriteLine("Exchange Response");

                var iOSEncryptedData = parts.GetType(Constants.EncryptedData); // A 

                int messageDataLength = iOSEncryptedData.Length - 16;

                byte[] messageData = new byte[messageDataLength];
                Buffer.BlockCopy(iOSEncryptedData, 0, messageData, 0, messageDataLength);

                byte[] authTag = new byte[16];
                Buffer.BlockCopy(iOSEncryptedData, messageDataLength, authTag, 0, 16);

                HKDF g = new HKDF(() => { return new HMACSHA512(); }, server_K, Encoding.UTF8.GetBytes("Pair-Setup-Encrypt-Salt"), Encoding.UTF8.GetBytes("Pair-Setup-Encrypt-Info"));
                var outputKey = g.GetBytes(32);
                var hkdfEncKey = outputKey;


                //var testKey = StringToByteArray("1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0");

                var testKey = StringToByteArray("bd f0 4a a9 5c e4 de 89 95 b1 4b b6 a1 8f ec af 26 47 8f 50 c0 54 f5 63 db c0 a2 1e 26 15 72 aa");

                var testNonce = StringToByteArray("00 00 00 00 01 02 03 04 05 06 07 08");

                var testCipherText = StringToByteArray("64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd" +
  "5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2" +
  "4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0" +
  "bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf" +
  "33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81" +
  "14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55" +
  "97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38" +
  "36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4" +
  "b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9" +
  "90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e" +
  "af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a" +
  "0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a" +
  "0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e" +
  "ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10" +
  "49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30" +
  "30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29" +
  "a6 ad 5c b4 02 2b 02 70 9b");



                //var tag1 = Aead.Mac(testKey, testNonce, testCipherText, Aead.Algorithm.Chacha20_Poly1305);
                //Console.WriteLine("Tag: " + ByteArrayToString(tag1));
                //Console.WriteLine("");

                //byte[] pt, ct, key, nonce, tag, aad;
                //key = Cnv.FromHex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
                //ct = Cnv.FromHex("64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b");
                //nonce = Cnv.FromHex("000000000102030405060708");
                //aad = Cnv.FromHex("f33388860000000000004e91");
                //tag = Cnv.FromHex("eead9d67890cbb22392336fea1851f39");
                //pt = Aead.Decrypt(ct, key, nonce, aad, tag, Aead.Algorithm.Chacha20_Poly1305);
                //Console.WriteLine("P:" + Cnv.ToHex(pt));

                //// This is UTF-8-encoded text, so display it
                //string Str = Encoding.UTF8.GetString(pt);
                //Console.WriteLine(Str);
                //Console.WriteLine(General.ErrorCode());
                //Console.WriteLine("");



                /*
                var testKey = StringToByteArray("1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0");
                var nonce = StringToByteArray("00 00 00 00 01 02 03 04 05 06 07 08");

                var testChacha = new ChaCha20Poly1305();
                var testParameters = new ParametersWithIV(new KeyParameter(testKey), nonce);
                testChacha.Init(false, testParameters);

                KeyParameter testMacKey = InitRecordMAC(testChacha);

                Console.WriteLine("MAC From Test Vectors");
                Console.WriteLine(ByteArrayToString(testMacKey.GetKey()));

                var testCipherText = StringToByteArray("64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd" +
  "5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2" +
  "4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0" +
  "bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf" +
  "33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81" +
  "14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55" +
  "97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38" +
  "36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4" +
  "b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9" +
  "90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e" +
  "af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a" +
  "0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a" +
  "0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e" +
  "ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10" +
  "49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30" +
  "30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29" +
  "a6 ad 5c b4 02 2b 02 70 9b");


                var testPoly = new ChaCha20Poly1305.Poly1305();

                testPoly.Init(new KeyParameter(testKey));

                var aad = StringToByteArray("f3 33 88 86 00 00 00 00 00 00 4e 91");

                var polyInput = new byte[0];

                var aadPadding = new byte[0];
                var cipherTextPadding = new byte[0];

                if (aad.Length % 16 != 0)
                {
                    int bytesRequiredForRounding = 16 - (aad.Length % 16);
                    aadPadding = new byte[bytesRequiredForRounding];
                }

                if (testCipherText.Length % 16 != 0)
                {
                    int bytesRequiredForRounding = 16 - (testCipherText.Length % 16);
                    cipherTextPadding = new byte[bytesRequiredForRounding];
                }

                //polyInput = aad.Concat(aadPadding).Concat(testCipherText).Concat(cipherTextPadding).Concat(BitConverter.GetBytes(aad.LongLength)).Concat(BitConverter.GetBytes(testCipherText.LongLength)).ToArray();
                polyInput = aad.Concat(aadPadding).Concat(testCipherText).Concat(cipherTextPadding).Concat(BitConverter.GetBytes(aad.LongLength)).Concat(BitConverter.GetBytes(testCipherText.LongLength)).ToArray();

                var expectedPolyInput = StringToByteArray("f3 33 88 86 00 00 00 00 00 00 4e 91 00 00 00 00" +
  "64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd" +
  "5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2" +
  "4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0" +
  "bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf" +
  "33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81" +
  "14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55" +
  "97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38" +
  "36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4" +
  "b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9" +
  "90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e" +
  "af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a" +
  "0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a" +
  "0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e" +
  "ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10" +
  "49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30" +
  "30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29" +
  "a6 ad 5c b4 02 2b 02 70 9b 00 00 00 00 00 00 00" +
  "0c 00 00 00 00 00 00 00 09 01 00 00 00 00 00 00");

                var polyMatchesExpectedValue = polyInput.SequenceEqual(expectedPolyInput);

                Debug.WriteLine("Test Poly AEAD Input");
                Debug.WriteLine(ByteArrayToString(polyInput));

                testPoly.BlockUpdate(polyInput, 0, polyInput.Length);

                byte[] testCalculatedTag = new byte[testPoly.GetMacSize()];
                testPoly.DoFinal(testCalculatedTag, 0);

                Debug.WriteLine("Test Tag");
                Debug.WriteLine(ByteArrayToString(testCalculatedTag));

                Debug.Write("H");
                */

                // *****************************************
                // NaCl test code
                //
                /*
                var testKey = StringToByteArray("1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0");
                var testNonce = StringToByteArray("01 02 03 04 05 06 07 08");

                var testChacha = new ChaChaEngine(20);
                var testParameters = new ParametersWithIV(new KeyParameter(testKey), testNonce);
                testChacha.Init(false, testParameters);

                KeyParameter testMacKey = InitRecordMAC(testChacha);

                var testCipherText = StringToByteArray("64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd" +
  "5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2" +
  "4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0" +
  "bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf" +
  "33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81" +
  "14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55" +
  "97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38" +
  "36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4" +
  "b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9" +
  "90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e" +
  "af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a" +
  "0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a" +
  "0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e" +
  "ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10" +
  "49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30" +
  "30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29" +
  "a6 ad 5c b4 02 2b 02 70 9b");

                var testReceivedTag = StringToByteArray("ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38");
                var testChaChaKey = StringToByteArray("1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0");
                bool verified = OneTimeAuth.Poly1305.Verify(testReceivedTag, testCipherText, testChaChaKey);
                var testLongNonce = StringToByteArray("00 00 00 00 01 02 03 04 05 06 07 08");
                var decryptedTest = XSalsa20Poly1305.TryDecrypt(testCipherText, testKey, testLongNonce);

                Console.WriteLine(verified);
                */

                // COSE

                //**************************************
                // TEST CODE FOR BouncyCastle POLY1305
                /*
                var testKey = StringToByteArray("1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0");
                var nonce = StringToByteArray("01 02 03 04 05 06 07 08");

                var testChacha = new ChaChaEngine(20);
                var testParameters = new ParametersWithIV(new KeyParameter(testKey), nonce);
                testChacha.Init(false, testParameters);

                KeyParameter testMacKey = InitRecordMAC(testChacha);

                Console.WriteLine("MAC From Test Vectors");
                Console.WriteLine(ByteArrayToString(testMacKey.GetKey()));

                var testCipherText = StringToByteArray("64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd" +
  "5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2" +
  "4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0" +
  "bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf" +
  "33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81" +
  "14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55" +
  "97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38" +
  "36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4" +
  "b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9" +
  "90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e" +
  "af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a" +
  "0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a" +
  "0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e" +
  "ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10" +
  "49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30" +
  "30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29" +
  "a6 ad 5c b4 02 2b 02 70 9b");


                var testPoly = new Org.BouncyCastle.Crypto.Macs.Poly1305();

                testPoly.Init(testMacKey);

                var aad = StringToByteArray("f3 33 88 86 00 00 00 00 00 00 4e 91");

                var polyInput = new byte[0];

                var aadPadding = new byte[0];
                var cipherTextPadding = new byte[0];

                if (aad.Length % 16 != 0)
                {
                    int bytesRequiredForRounding = 16 - (aad.Length % 16);
                    aadPadding = new byte[bytesRequiredForRounding];
                }

                if (testCipherText.Length % 16 != 0)
                {
                    int bytesRequiredForRounding = 16 - (testCipherText.Length % 16);
                    cipherTextPadding = new byte[bytesRequiredForRounding];
                }

                polyInput = aad.Concat(aadPadding).Concat(testCipherText).Concat(cipherTextPadding).Concat(BitConverter.GetBytes(aad.LongLength)).Concat(BitConverter.GetBytes(testCipherText.LongLength)).ToArray();

                var expectedPolyInput = StringToByteArray("f3 33 88 86 00 00 00 00 00 00 4e 91 00 00 00 00" +
  "64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd" +
  "5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2" +
  "4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0" +
  "bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf" +
  "33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81" +
  "14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55" +
  "97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38" +
  "36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4" +
  "b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9" +
  "90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e" +
  "af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a" +
  "0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a" +
  "0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e" +
  "ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10" +
  "49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30" +
  "30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29" +
  "a6 ad 5c b4 02 2b 02 70 9b 00 00 00 00 00 00 00" +
  "0c 00 00 00 00 00 00 00 09 01 00 00 00 00 00 00");

                var polyMatchesExpectedValue = polyInput.SequenceEqual(expectedPolyInput);

                Debug.WriteLine("Test Poly AEAD Input");
                Debug.WriteLine(ByteArrayToString(polyInput));

                //byte[] testCalculatedTag = new byte[testPoly.GetMacSize()];

                testPoly.BlockUpdate(polyInput, 0, polyInput.Length);


                byte[] testCalculatedTag = new byte[100];

                for (int i = 0; i < 84; i++)
                {
                    testPoly.DoFinal(testCalculatedTag, i);

                    Debug.WriteLine("Test Tag");
                    Debug.WriteLine(ByteArrayToString(testCalculatedTag));
                }




                Debug.Write("H");

                testPoly = new Org.BouncyCastle.Crypto.Macs.Poly1305();

                testPoly.Init(testMacKey);

                // The AAD
                //
                testPoly.BlockUpdate(aad, 0, aad.Length);

                // The AAD padding
                //
                if (aad.Length % 16 != 0)
                {
                    int bytesRequiredForRounding = 16 - (aad.Length % 16);
                    testPoly.BlockUpdate(new byte[bytesRequiredForRounding], 0, bytesRequiredForRounding);
                }

                // The ciphertext.
                //
                testPoly.BlockUpdate(testCipherText, 0, testCipherText.Length);

                // The ciphertext padding length.
                //
                if (testCipherText.Length % 16 != 0)
                {
                    int bytesRequiredForRounding = 16 - (testCipherText.Length % 16);
                    testPoly.BlockUpdate(new byte[bytesRequiredForRounding], 0, bytesRequiredForRounding);
                }

                // The length of the AAD
                //
                testPoly.BlockUpdate(BitConverter.GetBytes(aad.LongLength), 0, 8);

                // The length of the ciphertext
                //
                testPoly.BlockUpdate(BitConverter.GetBytes(testCipherText.LongLength), 0, 8);

                // Compute the final key
                //
                byte[] alternativeTestCalculatedTag = new byte[testPoly.GetMacSize()];
                testPoly.DoFinal(alternativeTestCalculatedTag, 0);

                Debug.WriteLine("Alternative Test Tag");
                Debug.WriteLine(ByteArrayToString(alternativeTestCalculatedTag));

                // Decrypt
                //
                var testOutput = new byte[testCipherText.Length];
                testChacha.ProcessBytes(testCipherText, 0, testCipherText.Length, testOutput, 0);

                Debug.WriteLine("Decrypted Test CipherText");
                Debug.WriteLine(ByteArrayToString(testOutput));

                */
                // END OF BouncyCastle Poly1305 Test Code
                //********************************************








                //var chacha = new ChaChaEngine(20);
                //var parameters = new ParametersWithIV(new KeyParameter(outputKey), Encoding.UTF8.GetBytes("PS-Msg05"));
                //chacha.Init(false, parameters);

                //KeyParameter macKey = InitRecordMAC(chacha);

                //var iOSPoly = new Org.BouncyCastle.Crypto.Macs.Poly1305();

                #region OLD POLY

                /*
                iOSPoly.Init(macKey);

                // The AAD padding length.
                //
                //iOSPoly.BlockUpdate(new byte[4], 0, 4);

                // The ciphertext.
                //
                iOSPoly.BlockUpdate(messageData, 0, messageData.Length);

                // The ciphertext padding length.
                //
                if (messageData.Length % 16 != 0)
                {
                    int bytesRequiredForRounding = 16 - (messageData.Length % 16);
                    iOSPoly.BlockUpdate(new byte[bytesRequiredForRounding], 0, bytesRequiredForRounding);
                }

                // The length of the AAD
                //
                iOSPoly.BlockUpdate(new byte[8], 0, 8);

                // The length of the ciphertext
                //
                iOSPoly.BlockUpdate(BitConverter.GetBytes(messageData.LongLength), 0, 8);

                // Compute the final key
                //
                byte[] calculatedMAC = new byte[iOSPoly.GetMacSize()];
                iOSPoly.DoFinal(calculatedMAC, 0);

                // Verify this calculatedMac matches the iOS authTag.
                // This is failing, which implies the way I'm generating the MAC is incorrect.
                //
                //bool isAuthTagValid = CryptoBytes.ConstantTimeEquals(authTag, calculatedMAC);
                //if (!isAuthTagValid)
                //{
                //    return new HttpResponseMessage(System.Net.HttpStatusCode.BadRequest);
                //}
                */
                #endregion

                //byte[] output = new byte[messageData.Length];
                //chacha.ProcessBytes(messageData, 0, messageData.Length, output, 0);






                byte[] output, ct, key, nonce, tag, aad;
                key = outputKey;
                ct = messageData;
                nonce = Cnv.FromHex("00000000").Concat(Encoding.UTF8.GetBytes("PS-Msg05")).ToArray();
                aad = new byte[0];
                tag = authTag;
                output = Aead.Decrypt(ct, key, nonce, aad, tag, Aead.Algorithm.Chacha20_Poly1305);
                Console.WriteLine("P:" + Cnv.ToHex(output));

                // This is UTF-8-encoded text, so display it
                string Str = Encoding.UTF8.GetString(output);
                Console.WriteLine(Str);
                Console.WriteLine(General.ErrorCode());
                Console.WriteLine("");


                Debug.WriteLine("Decrypted TLV");
                Debug.WriteLine(ByteArrayToString(output));

                var subData = TLVParser.Parse(output);

                byte[] username = subData.GetType(Constants.Identifier);
                byte[] ltpk = subData.GetType(Constants.PublicKey);
                byte[] proof = subData.GetType(Constants.Signature);



                Console.WriteLine("iOSDeviceInfo");
                Console.WriteLine($"Username [{username.Length}]: {Encoding.UTF8.GetString(username)}");
                Console.WriteLine($"LTPK [{ltpk.Length}]: {ByteArrayToString(ltpk)}");
                Console.WriteLine($"Proof [{proof.Length}]: {ByteArrayToString(proof)}");

                // Verify the proof matches the INFO
                //
                HKDF hkdf = new HKDF(() => { return new HMACSHA512(); }, server_K, Encoding.UTF8.GetBytes("Pair-Setup-Controller-Sign-Salt"), Encoding.UTF8.GetBytes("Pair-Setup-Controller-Sign-Info"));
                byte[] okm = hkdf.GetBytes(32);

                byte[] completeData = okm.Concat(username).Concat(ltpk).ToArray();

                if (!Ed25519.Verify(proof, completeData, ltpk))
                {
                    Console.WriteLine("Verification failed as iOS provided code was incorrect");
                    var errorTLV = new TLV();
                    errorTLV.AddType(Constants.Error, ErrorCodes.Authentication);

                    byte[] errorOutput = TLVParser.Serialise(errorTLV);

                    return new Tuple<string, byte[]>("application/pairing+tlv8", errorOutput);

                    //var errorContent = new ByteArrayContent(output);
                    //errorContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/pairing+tlv8");

                    //return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
                    //{
                    //    Content = errorContent
                    //};
                }

                Console.WriteLine("Step 5/6 is complete.");

                Console.WriteLine("Pair Setup Step 6/6");
                Console.WriteLine("Response Generation");

                g = new HKDF(() => { return new HMACSHA512(); }, server_K, Encoding.UTF8.GetBytes("Pair-Setup-Accessory-Sign-Salt"), Encoding.UTF8.GetBytes("Pair-Setup-Accessory-Sign-Info"));
                outputKey = g.GetBytes(32);

                // Create the AccessoryLTPK
                //
                byte[] accessoryLTSK;
                byte[] accessoryLTPK;

                var seed = new byte[32];
                RandomNumberGenerator.Create().GetBytes(seed);

                Ed25519.KeyPairFromSeed(out accessoryLTPK, out accessoryLTSK, seed);

                File.WriteAllBytes("PrivateKey", accessoryLTSK);

                var serverUsername = Encoding.UTF8.GetBytes(Program.ID);

                byte[] material = outputKey.Concat(serverUsername).Concat(accessoryLTPK).ToArray();

                byte[] signature = Ed25519.Sign(material, accessoryLTSK);

                Console.WriteLine("AccessoryDeviceInfo");
                Console.WriteLine($"Username [{serverUsername.Length}]: {ByteArrayToString(serverUsername)}");
                Console.WriteLine($"LTPK [{accessoryLTPK.Length}]: {ByteArrayToString(accessoryLTPK)}");
                Console.WriteLine($"Proof [{signature.Length}]: {ByteArrayToString(signature)}");

                TLV encoder = new TLV();
                encoder.AddType(Constants.Identifier, serverUsername);
                encoder.AddType(Constants.PublicKey, accessoryLTPK);
                encoder.AddType(Constants.Signature, signature);

                // Verify our own signature
                //
                Ed25519.Verify(signature, material, accessoryLTPK);

                byte[] plaintext = TLVParser.Serialise(encoder);

                //chacha = new ChaChaEngine(20);
                //parameters = new ParametersWithIV(new KeyParameter(hkdfEncKey), Encoding.UTF8.GetBytes("PS-Msg06"));
                //chacha.Init(true, parameters);

                //macKey = InitRecordMAC(chacha);

                //byte[] ciphertext = new byte[plaintext.Length];
                //chacha.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);

                //var poly = new Poly1305();
                //iOSPoly.Init(macKey);

                //iOSPoly.BlockUpdate

                //iOSPoly.BlockUpdate(ciphertext, 0, ciphertext.Length);

                //iOSPoly.BlockUpdate(BitConverter.GetBytes((long)ciphertext.Length), 0, 8);

                //var accessoryCalculatedMAC = new byte[iOSPoly.GetMacSize()];
                //iOSPoly.DoFinal(accessoryCalculatedMAC, 0);
                //var accessoryCalculatedMAC = Sodium.OneTimeAuth.Sign(Encoding.UTF8.GetString(ciphertext), macKey.GetKey());
                //var verifyMac = Sodium.OneTimeAuth.Verify(ciphertext, accessoryCalculatedMAC, macKey.GetKey());

                //byte[] pt, ct, key, nonce, tag, aad;
                //key = Cnv.FromHex("071b113b 0ca743fe cccf3d05 1f737382");
                //nonce = Cnv.FromHex("f0761e8d cd3d0001 76d457ed");
                //aad = Cnv.FromHex("e20106d7 cd0df076 1e8dcd3d 88e54c2a 76d457ed");
                //pt = Cnv.FromHex("08000f10 11121314 15161718 191a1b1c 1d1e1f20 21222324 25262728 292a2b2c 2d2e2f30 31323334 0004");
                //tag = new byte[0];    // Do this to avoid "before it has been assigned a value" error
                //ct = Aead.Encrypt(out tag, pt, key, nonce, aad, Aead.Algorithm.Aes_128_Gcm);
                //Console.WriteLine("C: " + Cnv.ToHex(ct));
                //Console.WriteLine("T: " + Cnv.ToHex(tag));


                //byte[] ret = ciphertext.Concat(accessoryCalculatedMAC).ToArray();





                //TLV responseTLV = new TLV();
                //responseTLV.AddType(Constants.State, 6);
                //responseTLV.AddType(Constants.EncryptedData, ret);

                //output = TLVParser.Serialise(responseTLV);

                //ByteArrayContent content = new ByteArrayContent(output);
                //content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/pairing+tlv8");

                //Console.WriteLine("Step 6/6 is complete.");

                //return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
                //{
                //    Content = content
                //};

                nonce = Cnv.FromHex("00000000").Concat(Encoding.UTF8.GetBytes("PS-Msg06")).ToArray();
                aad = new byte[0];

                byte[] outputTag = new byte[0];

                var encryptedOutput = Aead.Encrypt(out outputTag, plaintext, hkdfEncKey, nonce, aad, Aead.Algorithm.Chacha20_Poly1305);

                Console.WriteLine($"EncryptionStatus: {General.ErrorCode()}");

                // Test the decryption
                //
                Aead.Decrypt(encryptedOutput, hkdfEncKey, nonce, aad, outputTag, Aead.Algorithm.Chacha20_Poly1305);

                Console.WriteLine($"DecryptionStatus: {General.ErrorCode()}");

                byte[] ret = encryptedOutput.Concat(outputTag).ToArray();

                TLV responseTLV = new TLV();
                responseTLV.AddType(Constants.State, 6);
                responseTLV.AddType(Constants.EncryptedData, ret);

                output = TLVParser.Serialise(responseTLV);

                return new Tuple<string, byte[]>("application/pairing+tlv8", output);

                //ByteArrayContent content = new ByteArrayContent(output);
                //content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/pairing+tlv8");

                //Console.WriteLine("Step 6/6 is complete.");

                //return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
                //{
                //    Content = content
                //};
            }

            return null;

            //return new HttpResponseMessage(System.Net.HttpStatusCode.BadRequest);
        }

        static byte[] ReverseBytes(long value)
        {
            byte[] bytes = BitConverter.GetBytes(value);

            //Then, if we need big endian for our protocol for instance,
            //Just check if you need to convert it or not:
            //}
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes); //reverse it so we get big endian.
            }

            return bytes;
        }

        private KeyParameter InitRecordMAC(ChaCha20Poly1305 cipher)
        {
            byte[] zeroes = StringToByteArray(
           "00000000000000000000000000000000"
           + "00000000000000000000000000000000"
           + "00000000000000000000000000000000"
           + "00000000000000000000000000000000");

            byte[] firstBlock = new byte[64];
            cipher.ProcessBytes(zeroes, 0, firstBlock.Length, firstBlock, 0);

            Console.WriteLine("ChaCha OutBytes");
            Console.WriteLine(ByteArrayToString(firstBlock));

            // NOTE: The BC implementation puts 'r' after 'k'
            //Array.Copy(firstBlock, 0, firstBlock, 32, 16);
            //KeyParameter macKey = new KeyParameter(firstBlock, 16, 32);
            //Poly1305KeyGenerator.clamp(macKey.getKey());

            // 8th January, 2018 21:05
            //
            // The above code is from the github HAP-Java implementation. The problem was that the clamp() operator
            // wasn't having any effect! I'm guessing it's because the getKey() returns a new instance each time.
            // To work around this, I create a buffer, clamp it and then create a KeyParameter with the new byte[]
            // How the fuck I spotted this I'll never know.
            //

            KeyParameter macKey = new KeyParameter(firstBlock, 0, 32);

            var key = macKey.GetKey();

            //Console.WriteLine(ByteArrayToString(key));

            Poly1305KeyGenerator.Clamp(key);

            //Console.WriteLine(ByteArrayToString(key));

            Poly1305KeyGenerator.CheckKey(key);

            return new KeyParameter(key);
        }

        private KeyParameter InitRecordMAC(ChaChaEngine cipher)
        {
            byte[] zeroes = StringToByteArray(
           "00000000000000000000000000000000"
           + "00000000000000000000000000000000"
           + "00000000000000000000000000000000"
           + "00000000000000000000000000000000");

            byte[] firstBlock = new byte[64];
            cipher.ProcessBytes(zeroes, 0, firstBlock.Length, firstBlock, 0);

            Console.WriteLine("ChaCha OutBytes");
            Console.WriteLine(ByteArrayToString(firstBlock));

            // NOTE: The BC implementation puts 'r' after 'k'
            //Array.Copy(firstBlock, 0, firstBlock, 32, 16);
            //KeyParameter macKey = new KeyParameter(firstBlock, 16, 32);
            //Poly1305KeyGenerator.clamp(macKey.getKey());

            // 8th January, 2018 21:05
            //
            // The above code is from the github HAP-Java implementation. The problem was that the clamp() operator
            // wasn't having any effect! I'm guessing it's because the getKey() returns a new instance each time.
            // To work around this, I create a buffer, clamp it and then create a KeyParameter with the new byte[]
            // How the fuck I spotted this I'll never know.
            //

            KeyParameter macKey = new KeyParameter(firstBlock, 0, 32);

            var key = macKey.GetKey();

            //Console.WriteLine(ByteArrayToString(key));

            Poly1305KeyGenerator.Clamp(key);

            //Console.WriteLine(ByteArrayToString(key));

            Poly1305KeyGenerator.CheckKey(key);

            return new KeyParameter(key);
        }

        private KeyParameter InitRecordMACWithoutClamp(ChaChaEngine cipher)
        {
            byte[] zeroes = StringToByteArray(
           "00000000000000000000000000000000"
           + "00000000000000000000000000000000"
           + "00000000000000000000000000000000"
           + "00000000000000000000000000000000");

            byte[] firstBlock = new byte[64];
            cipher.ProcessBytes(zeroes, 0, firstBlock.Length, firstBlock, 0);

            Console.WriteLine("ChaCha OutBytes");
            Console.WriteLine(ByteArrayToString(firstBlock));

            // NOTE: The BC implementation puts 'r' after 'k'
            //Array.Copy(firstBlock, 0, firstBlock, 32, 16);
            //KeyParameter macKey = new KeyParameter(firstBlock, 16, 32);
            //Poly1305KeyGenerator.clamp(macKey.getKey());

            // 8th January, 2018 21:05
            //
            // The above code is from the github HAP-Java implementation. The problem was that the clamp() operator
            // wasn't having any effect! I'm guessing it's because the getKey() returns a new instance each time.
            // To work around this, I create a buffer, clamp it and then create a KeyParameter with the new byte[]
            // How the fuck I spotted this I'll never know.
            //

            KeyParameter macKey = new KeyParameter(firstBlock, 0, 32);

            var key = macKey.GetKey();

            Console.WriteLine("Poly1305 Key");
            Console.WriteLine(ByteArrayToString(key));

            return new KeyParameter(key);
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
