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
using System.Web;

namespace ColdBear.ConsoleApp
{
    class Program
    {
        public const string ID = "C4:22:3D:E3:CE:D6";

        public static TcpClient CurrentlyConnectedController;
        public static ControllerSession CurrentSession;

        static void Main(string[] args)
        {
            bool run = true;

            TcpListener controllerListener = null;
            TcpListener managementListener = null;

            var t1 = new Thread(() =>
            {
                Thread.CurrentThread.IsBackground = true;
                Thread.CurrentThread.Name = "Advertising";

                DNSSDService service = new DNSSDService();

                TXTRecord txtRecord = new TXTRecord();
                txtRecord.SetValue("sf", "1"); // 1 means discoverable. 0 means it has been paired.
                txtRecord.SetValue("ff", "0x00");
                txtRecord.SetValue("ci", "2");
                txtRecord.SetValue("id", ID);
                txtRecord.SetValue("md", "Climenole");
                txtRecord.SetValue("s#", "1");
                txtRecord.SetValue("c#", "678");

                var mgr = new DNSSDEventManager();
                mgr.RecordRegistered += Mgr_RecordRegistered;
                mgr.OperationFailed += Mgr_OperationFailed;
                mgr.ServiceRegistered += Mgr_ServiceRegistered;

                var record = service.Register(0, 0, "Climenole", "_hap._tcp", null, null, 51826, txtRecord, mgr);

                Console.WriteLine("Advertising Service in background thread");
            });
            t1.Start();

            var t2 = new Thread(() =>
            {
                Thread.CurrentThread.IsBackground = true;
                Thread.CurrentThread.Name = "Controller Port";

                IPAddress address = IPAddress.Any;
                IPEndPoint port = new IPEndPoint(address, 51826);

                controllerListener = new TcpListener(port);
                controllerListener.Start();

                Console.WriteLine("--Controller Server Started--");

                while (run) //loop forever
                {
                    try
                    {
                        Console.WriteLine("Waiting for Controller to connect");

                        TcpClient client = controllerListener.AcceptTcpClient();

                        CurrentlyConnectedController = client;

                        Console.WriteLine("A Controller has connected!");

                        Thread clientThread = new Thread(new ParameterizedThreadStart(HandleControllerConnection));
                        clientThread.Start(client);
                    }
                    catch
                    { }
                }
            });

            t2.Start();

            var t3 = new Thread(() =>
            {
                IPAddress address = IPAddress.Any;
                IPEndPoint port = new IPEndPoint(address, 51827);

                managementListener = new TcpListener(port);
                managementListener.Start();

                Console.WriteLine("--Management Server Started--");

                while (run) //loop forever
                {
                    try
                    {
                        Console.WriteLine("Waiting for Manager to connect");

                        TcpClient client = managementListener.AcceptTcpClient();

                        Console.WriteLine("A manager has connected!");

                        Thread clientThread = new Thread(new ParameterizedThreadStart(HandleManagerConnection));
                        clientThread.Start(client);
                    }
                    catch
                    { }
                }
            });

            t3.Start();

            Console.WriteLine("Press any key to terminate");
            Console.ReadKey();

            run = false;

            managementListener?.Stop();
            controllerListener?.Stop();

            t1?.Join();
            t2?.Join();
            t3?.Join();
        }

        private static void HandleControllerConnection(object obj)
        {
            TcpClient tcpClient = (TcpClient)obj;

            // Set keepalive to true!
            //
            //tcpClient.Client.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.KeepAlive, true);

            string clientEndPoint = tcpClient.Client.RemoteEndPoint.ToString();

            Console.WriteLine($"Handling a new controller connection from {clientEndPoint}");

            ControllerSession session = new ControllerSession();

            CurrentSession = session;

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

                    Console.WriteLine("**************************** REQUEST RECEIVED *************************");

                    if (bytesRead == 0)
                    {
                        // Read returns 0 if the client closes the connection.
                        //
                        break;
                    }

                    var content = receiveBuffer.CopySlice(0, bytesRead);

                    if (session.IsVerified)
                    {
                        Console.WriteLine("* DECRYPTING REQUEST *");

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
                            break;
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
                        Console.WriteLine("* Header: {0}:{1}", name, value);
                        httpHeaders[name.ToLower()] = value;
                    }

                    Console.WriteLine($"* URL: {url}");

                    int BUF_SIZE = 4096;
                    int content_len = 0;
                    MemoryStream contentMs = new MemoryStream();

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

                        BinaryReader br = new BinaryReader(ms);

                        if (httpHeaders.ContainsKey("content-length"))
                        {
                            byte[] buf = new byte[BUF_SIZE];
                            int to_read = content_len;
                            while (to_read > 0)
                            {
                                int numread = br.Read(buf, 0, Math.Min(BUF_SIZE, to_read));

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
                    else if (url.StartsWith("characteristics"))
                    {
                        // The url will contain a query string e.g. id=1.1 meaning accessoryId 1 with characteristic 1
                        //
                        CharacteristicsController controller = new CharacteristicsController();
                        if (method == "PUT")
                        {
                            result = controller.Put(contentMs.ToArray(), session);
                        }
                        else if (method == "GET")
                        {
                            var parts = url.Split('?');

                            var queryStringing = parts[1].Replace("id=", "");

                            var accessoriesParts = queryStringing.Split(',');

                            List<Tuple<int, int>> accessories = new List<Tuple<int, int>>();

                            foreach (var accessoryString in accessoriesParts)
                            {
                                var accessoryParts = accessoryString.Split('.');

                                var aid = int.Parse(accessoryParts[0]);
                                var iid = int.Parse(accessoryParts[1]);

                                accessories.Add(new Tuple<int, int>(aid, iid));

                            }

                            result = controller.Get(accessories, session);
                        }
                    }
                    else
                    {
                        Console.WriteLine($"* Request for {url} is not yet supported!");
                        throw new Exception("Not Supported");
                    }

                    // Construct the response. We're assuming 100% success, all of the time, for now.
                    //
                    var response = new byte[0];
                    var returnChars = new byte[2];
                    returnChars[0] = 0x0D;
                    returnChars[1] = 0x0A;

                    var contentLength = $"Content-Length: {result.Item2.Length}";

                    if (result.Item2.Length == 0)
                    {
                        response = response.Concat(Encoding.ASCII.GetBytes("HTTP/1.1 204 No Content")).Concat(returnChars).ToArray();
                    }
                    else
                    {
                        response = response.Concat(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK")).Concat(returnChars).ToArray();
                        response = response.Concat(Encoding.ASCII.GetBytes(contentLength)).Concat(returnChars).ToArray();
                        response = response.Concat(Encoding.ASCII.GetBytes($"Content-Type: {result.Item1}")).Concat(returnChars).ToArray();
                    }

                    response = response.Concat(returnChars).ToArray();
                    response = response.Concat(result.Item2).ToArray();

                    if (session.IsVerified && !session.SkipFirstEncryption)
                    {
                        // We need to decrypt the request!
                        //
                        Console.WriteLine("* ENCRYPTING RESPONSE");

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

                    Console.WriteLine("**************************** RESPONSE SENT ******************************");
                }
            }

            Console.WriteLine($"Connection from {clientEndPoint} will be closed!");

            tcpClient.Close();
            tcpClient.Dispose();
        }

        private static void HandleManagerConnection(object obj)
        {
            TcpClient tcpClient = (TcpClient)obj;

            string clientEndPoint = tcpClient.Client.RemoteEndPoint.ToString();

            Console.WriteLine($"Handling a new connection from {clientEndPoint}");

            using (var networkStream = tcpClient.GetStream())
            {
                byte[] receiveBuffer = new byte[tcpClient.ReceiveBufferSize];

                // This is blocking and will wait for data to come from the client.
                //
                var bytesRead = networkStream.Read(receiveBuffer, 0, (int)tcpClient.ReceiveBufferSize);

                Console.WriteLine("**************************** MANAGEMENT REQUEST RECEIVED *************************");

                if (bytesRead == 0)
                {
                    // Read returns 0 if the client closes the connection.
                    //
                    return;
                }

                var content = receiveBuffer.CopySlice(0, bytesRead);

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
                        break;
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
                    Console.WriteLine("* Header: {0}:{1}", name, value);
                    httpHeaders[name.ToLower()] = value;
                }

                Console.WriteLine($"* URL: {url}");

                int BUF_SIZE = 4096;
                int content_len = 0;
                MemoryStream contentMs = new MemoryStream();

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

                    BinaryReader br = new BinaryReader(ms);

                    if (httpHeaders.ContainsKey("content-length"))
                    {
                        byte[] buf = new byte[BUF_SIZE];
                        int to_read = content_len;
                        while (to_read > 0)
                        {
                            int numread = br.Read(buf, 0, Math.Min(BUF_SIZE, to_read));

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
                    }
                }

                byte[] result = null;

                if (url.StartsWith("accessories"))
                {
                    var parts = url.Split('?');
                    var queryString = HttpUtility.ParseQueryString(parts[1]);

                    var value = int.Parse(queryString["value"]);
                    AccessoriesController controller = new AccessoriesController();
                    result = controller.Put(CurrentSession, 3, 8, value);
                }
                else
                {
                    Console.WriteLine($"* Request for {url} is not yet supported!");
                    throw new Exception("Not Supported");
                }

                if (result.Length != 0)
                {
                    CurrentlyConnectedController.GetStream().Write(result, 0, result.Length);
                    CurrentlyConnectedController.GetStream().Flush();
                }

                var returnChars = new byte[2];
                returnChars[0] = 0x0D;
                returnChars[1] = 0x0A;

                var response = Encoding.ASCII.GetBytes("HTTP/1.1 204 OK").Concat(returnChars).ToArray();
                response = response.Concat(Encoding.ASCII.GetBytes("Content-Length: 0")).Concat(returnChars).ToArray();
                response = response.Concat(returnChars).ToArray();

                networkStream.Write(response, 0, response.Length);
                networkStream.Flush();
                Console.WriteLine("**************************** EVENT SENT ******************************");
            }

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
