using Bonjour;
using CryptoSysAPI;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace ColdBear.ConsoleApp
{
    class Program
    {
        public const string ID = "B6:22:3D:E3:CE:D6";
        
        
        static void Main(string[] args)
        {
            var t1 = new Thread(() =>
            {
                Thread.CurrentThread.IsBackground = true;

                DNSSDService service = new DNSSDService();

                TXTRecord txtRecord = new TXTRecord();
                txtRecord.SetValue("sf", "1"); // 1 means discoverable. 0 means it has been paired.
                txtRecord.SetValue("ff", "0x00");
                txtRecord.SetValue("ci", "2");
                txtRecord.SetValue("id", ID);
                txtRecord.SetValue("md", "Climenole");
                txtRecord.SetValue("s#", "1");
                txtRecord.SetValue("c#", "1");

                var mgr = new DNSSDEventManager();
                mgr.RecordRegistered += Mgr_RecordRegistered;
                mgr.OperationFailed += Mgr_OperationFailed;
                mgr.ServiceRegistered += Mgr_ServiceRegistered;

                var record = service.Register(0, 0, "Climenole", "_hap._tcp", null, null, 51826, txtRecord, mgr);

                Console.WriteLine("Advertising Service in background thread");
            });
            t1.Start();

            //string baseAddress = "http://*:51826/";

            //StartOptions options = new StartOptions();
            //options.Urls.Add("http://*:51826");

            //using (WebApp.Start(baseAddress))
            //{
            //    Console.WriteLine("Server started....");
            //    Console.WriteLine("Press Enter to quit.");
            //    Console.ReadLine();
            //}

            var t2 = new Thread(async () =>
            {
                IPAddress address = IPAddress.Any;
                IPEndPoint port = new IPEndPoint(address, 51826); //port 9999

                TcpListener listener = new TcpListener(port);

                listener.Start();

                Console.WriteLine("--Server Started--");

                while (true) //loop forever
                {
                    Console.WriteLine("Waiting for New Controller to connect");

                    TcpClient client = await listener.AcceptTcpClientAsync();

                    Console.WriteLine("A Controller has connected!");

                    Thread clientThread = new Thread(new ParameterizedThreadStart(HandleClientConnection));
                    clientThread.Start(client);
                }
            });

            t2.Start();

            Console.WriteLine("Press any key to terminate");
            Console.ReadKey();

            t1.Join();
            t2.Join();
        }

        private static void HandleClientConnection(object obj)
        {
            TcpClient tcpClient = (TcpClient)obj;

            string clientEndPoint = tcpClient.Client.RemoteEndPoint.ToString();

            Console.WriteLine($"Handling a new connection from {clientEndPoint}");

            // TODO We might want to put this somewhere else, so that we can access the 
            // output stream to write events to the controller.
            //
            ControllerSession session = new ControllerSession();

            using (var networkStream = tcpClient.GetStream())
            {
                byte[] receiveBuffer = new byte[tcpClient.ReceiveBufferSize];

                var keepListening = true;

                while (keepListening)
                {
                    Console.WriteLine("Waiting for more data from the client....");

                    // This is blocking and will wait for data to come from the client.
                    //
                    var bytesRead = networkStream.Read(receiveBuffer, 0, (int)tcpClient.ReceiveBufferSize);

                    if (bytesRead == 0)
                    {
                        // Read returns 0 if the client closes the connection.
                        //
                        break;
                    }

                    var content = receiveBuffer.CopySlice(0, bytesRead);

                    if (session.IsVerified)
                    {
                        Console.WriteLine("**********************");
                        Console.WriteLine("* DECRYPTING REQUEST *");
                        Console.WriteLine("**********************");

                        var encryptionResult = new byte[0];

                        for (int offset = 0; offset < bytesRead;)
                        {
                            // The first type bytes represent the length of the data.
                            //
                            byte[] twoBytes = new Byte[] { content[0], content[1] };

                            offset += 2;

                            UInt16 frameLength = BitConverter.ToUInt16(twoBytes, 0);

                            int availableDataLength = bytesRead - offset - 16;

                            byte[] messageData = new byte[availableDataLength];
                            Buffer.BlockCopy(content, offset, messageData, 0, availableDataLength);

                            offset += availableDataLength;

                            byte[] authTag = new byte[16];
                            Buffer.BlockCopy(content, offset, authTag, 0, 16);

                            var nonce = Cnv.FromHex("00000000").Concat(BitConverter.GetBytes(session.InboundBinaryMessageCount++)).ToArray();

                            // Use the AccessoryToController key to decrypt the data.
                            //
                            var decryptedData = Aead.Decrypt(messageData, session.ControllerToAccessoryKey, nonce, twoBytes, authTag, Aead.Algorithm.Chacha20_Poly1305);

                            encryptionResult = encryptionResult.Concat(decryptedData).ToArray();

                            offset += (18 + frameLength);
                        }

                        content = encryptionResult;
                    }

                    var ms = new MemoryStream(content);
                    StreamReader sr = new StreamReader(ms);

                    String request = sr.ReadLine();
                    string[] tokens = request.Split(' ');
                    if (tokens.Length != 3)
                    {
                        throw new Exception("Invalid HTTP request line");
                    }
                    var method = tokens[0].ToUpper();
                    var url = tokens[1].Trim('/');
                    var version = tokens[2];

                    string line;

                    Dictionary<string, string> httpHeaders = new Dictionary<string, string>();

                    while ((line = sr.ReadLine()) != null)
                    {
                        if (line.Equals(""))
                        {
                            Console.WriteLine("got headers");
                            break; ;
                        }

                        int separator = line.IndexOf(':');
                        if (separator == -1)
                        {
                            throw new Exception("invalid http header line: " + line);
                        }
                        String name = line.Substring(0, separator);
                        int pos = separator + 1;
                        while ((pos < line.Length) && (line[pos] == ' '))
                        {
                            pos++; // strip any spaces
                        }

                        string value = line.Substring(pos, line.Length - pos);
                        Console.WriteLine("header: {0}:{1}", name, value);
                        httpHeaders[name.ToLower()] = value;
                    }

                    int BUF_SIZE = 4096;
                    int content_len = 0;
                    MemoryStream contentMs = new MemoryStream();

                    Console.WriteLine("Input");
                    Console.WriteLine(ByteArrayToString(ms.ToArray()));

                    if (httpHeaders.ContainsKey("content-length"))
                    {
                        content_len = Convert.ToInt32(httpHeaders["content-length"]);

                        if (content_len > 20000)
                        {
                            throw new Exception(String.Format("POST Content-Length({0}) too big for this simple server", content_len));
                        }

                        ms.Position = ms.Position - content_len;

                        var temp = new byte[ms.Length - ms.Position];
                        Array.Copy(ms.ToArray(), (int)ms.Position, temp, 0, (int)ms.Length - ms.Position);

                        Console.WriteLine("Content");
                        Console.WriteLine(ByteArrayToString(temp));

                        BinaryReader br = new BinaryReader(ms);
                        if (httpHeaders.ContainsKey("content-length"))
                        {
                            byte[] buf = new byte[BUF_SIZE];
                            int to_read = content_len;
                            while (to_read > 0)
                            {
                                Console.WriteLine("starting Read, to_read={0}", to_read);

                                int numread = br.Read(buf, 0, Math.Min(BUF_SIZE, to_read));

                                Console.WriteLine("read finished, numread={0}", numread);

                                if (numread == 0)
                                {
                                    if (to_read == 0)
                                    {
                                        break;
                                    }
                                    else
                                    {
                                        throw new Exception("client disconnected during post");
                                    }
                                }
                                to_read -= numread;
                                contentMs.Write(buf, 0, numread);
                            }
                            contentMs.Seek(0, SeekOrigin.Begin);

                            Console.WriteLine($"Content Length: {contentMs.Length}");
                        }
                    }

                    Tuple<string, byte[]> result = null;

                    if (url == "pair-setup")
                    {
                        PairSetupController controller = new PairSetupController();
                        result = controller.Post(contentMs.ToArray());
                    }
                    else if (url == "pair-verify")
                    {
                        PairVerifyController controller = new PairVerifyController();
                        result = controller.Post(contentMs.ToArray(), session);
                    }
                    else if (url == "accessories")
                    {
                        AccessoriesController controller = new AccessoriesController();
                        result = controller.Get(session);
                    }
                    else if (url == "pairings")
                    {
                        PairingsController controller = new PairingsController();
                        result = controller.Post(contentMs.ToArray(), session);
                    }
                    else if(url == "characteristics")
                    {
                        // The url will contain a query string e.g. id=1.1 meaning accessoryId 1 with characteristic 1
                        //
                        //GET, PUT verbs supported.
                        //


                    }
                    else
                    {
                        Console.WriteLine($"Request for {url} is not yet supported!");
                        throw new Exception("Not Supported");
                    }

                    // Construct the response. We're assuming 100% success, all of the time, for now.
                    //
                    var response = new byte[0];
                    var returnChars = new byte[2];
                    returnChars[0] = 0x0D;
                    returnChars[1] = 0x0A;

                    var contentLength = $"Content-Length: {result.Item2.Length}";

                    response = response.Concat(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK")).Concat(returnChars).ToArray();
                    response = response.Concat(Encoding.ASCII.GetBytes(contentLength)).Concat(returnChars).ToArray();
                    response = response.Concat(Encoding.ASCII.GetBytes($"Content-Type: {result.Item1}")).Concat(returnChars).ToArray();
                    response = response.Concat(returnChars).ToArray();
                    response = response.Concat(result.Item2).ToArray();

                    if (session.IsVerified && !session.SkipFirstEncryption)
                    {
                        // We need to decrypt the request!
                        //
                        Console.WriteLine("***********************");
                        Console.WriteLine("* ENCRYPTING RESPONSE *");
                        Console.WriteLine("***********************");

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

                        networkStream.Write(response, 0, response.Length);
                        networkStream.Flush();
                    }
                    else
                    {
                        networkStream.Write(response, 0, response.Length);
                        networkStream.Flush();

                        if (session.SkipFirstEncryption)
                        {
                            session.SkipFirstEncryption = false;
                        }
                    }
                }
            }

            Console.WriteLine($"Connection from {clientEndPoint} will be closed!");

            tcpClient.Close();
            tcpClient.Dispose();
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

        private static void Mgr_ServiceRegistered(DNSSDService service, DNSSDFlags flags, string name, string regtype, string domain)
        {
            Console.WriteLine("Service registered");
        }

        private static void Mgr_OperationFailed(DNSSDService service, DNSSDError error)
        {
            Console.WriteLine("Operation failed");
        }

        private static void Mgr_RecordRegistered(DNSSDRecord record, DNSSDFlags flags)
        {
            Console.WriteLine("Record registered");
        }
    }
}
