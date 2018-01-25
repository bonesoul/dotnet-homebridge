using System;
using System.Collections;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace ColdBear.mDNS
{
    public class mDNSService
    {
        public void Start()
        {
            try
            {
                var signal = new ManualResetEvent(false);

                NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();

                IPv4InterfaceProperties selectedInterface = null;

                foreach (NetworkInterface adapter in nics)
                {
                    IPInterfaceProperties ip_properties = adapter.GetIPProperties();

                    if (adapter.GetIPProperties().MulticastAddresses.Count == 0)
                    {
                        continue; // most of VPN adapters will be skipped
                    }

                    if (OperationalStatus.Up != adapter.OperationalStatus)
                    {
                        continue; // this adapter is off or not connected
                    }

                    IPv4InterfaceProperties p = adapter.GetIPProperties().GetIPv4Properties();

                    if (null == p)
                    {
                        continue; // IPv4 is not configured on this adapter
                    }

                    selectedInterface = p;

                    break;
                }

                Console.WriteLine($"Bound to {selectedInterface.ToString()}");

                IPAddress multicastAddress = IPAddress.Parse("224.0.0.251");
                IPEndPoint multicastEndpoint = new IPEndPoint(multicastAddress, 5353);
                IPAddress localAddress = IPAddress.Parse("192.168.20.107");
                //EndPoint localEndpoint = new IPEndPoint(IPAddress.Any, 5353);
                EndPoint localEndpoint = new IPEndPoint(localAddress, 5353);

                IPEndPoint senderRemote = new IPEndPoint(IPAddress.Any, 0);

                using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    using (var sendSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                    {
                        socket.EnableBroadcast = true;
                        socket.ExclusiveAddressUse = false;
                        socket.MulticastLoopback = true;
                        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1);
                        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, (int)IPAddress.HostToNetworkOrder(selectedInterface.Index));

                        socket.Bind(localEndpoint);

                        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(multicastAddress, IPAddress.Any));

                        while (true)
                        {
                            var buffer = new byte[1024];
                            int numberOfbytesReceived = socket.Receive(buffer);

                            var content = new byte[numberOfbytesReceived];
                            Array.Copy(buffer, 0, content, 0, numberOfbytesReceived);

                            ByteArrayToStringDump(content);

                            if (content[2] != 0x00)
                            {
                                Console.WriteLine("Not a query. Ignoring.");
                                continue;
                            }

                            var outputBuffer = new byte[0];

                            var flags = new byte[2];

                            var bitArray = new BitArray(flags);

                            bitArray.Set(15, true); // QR
                            bitArray.Set(10, true); // AA

                            bitArray.CopyTo(flags, 0);

                            var answerCount = BitConverter.GetBytes((short)1).Reverse().ToArray();
                            var additionalCounts = BitConverter.GetBytes((short)1).Reverse().ToArray();
                            var otherCounts = BitConverter.GetBytes((short)0);
                            outputBuffer = outputBuffer.Concat(otherCounts).Concat(flags.Reverse()).Concat(otherCounts).Concat(answerCount).Concat(otherCounts).Concat(additionalCounts).ToArray();

                            // Add the PTR record.
                            //
                            var ptrNodeName = GetName("_http._tcp");

                            outputBuffer = outputBuffer.Concat(ptrNodeName).ToArray();

                            var type = BitConverter.GetBytes((short)12).Reverse().ToArray(); // TXT

                            outputBuffer = outputBuffer.Concat(type).ToArray();

                            var @class = BitConverter.GetBytes((short)1).Reverse().ToArray(); // Internet

                            outputBuffer = outputBuffer.Concat(@class).ToArray();

                            var ttl = BitConverter.GetBytes(4500).Reverse().ToArray();

                            outputBuffer = outputBuffer.Concat(ttl).ToArray();

                            var ptrServiceName = GetName("_http._tcp.local");

                            var recordLength = BitConverter.GetBytes((short)ptrServiceName.Length).Reverse().ToArray();

                            outputBuffer = outputBuffer.Concat(recordLength).ToArray();

                            outputBuffer = outputBuffer.Concat(ptrServiceName).ToArray();

                            // Add the SRV record
                            //
                            var nodeName = GetName("myserver._http._tcp");

                            outputBuffer = outputBuffer.Concat(nodeName).ToArray();

                            type = BitConverter.GetBytes((short)33).Reverse().ToArray(); // SRV

                            outputBuffer = outputBuffer.Concat(type).ToArray();

                            @class = BitConverter.GetBytes((short)1).Reverse().ToArray(); // Internet

                            outputBuffer = outputBuffer.Concat(@class).ToArray();

                            ttl = BitConverter.GetBytes(4500).Reverse().ToArray();

                            outputBuffer = outputBuffer.Concat(ttl).ToArray();

                            var priority = BitConverter.GetBytes((short)0).Reverse().ToArray();

                            outputBuffer = outputBuffer.Concat(priority).ToArray();

                            var weight = BitConverter.GetBytes((short)0).Reverse().ToArray();

                            outputBuffer = outputBuffer.Concat(weight).ToArray();

                            var port = BitConverter.GetBytes((short)80).Reverse().ToArray();

                            outputBuffer = outputBuffer.Concat(port).ToArray();

                            var dataLength = BitConverter.GetBytes((short)1).Reverse().ToArray();

                            outputBuffer = outputBuffer.Concat(new byte[1] { 0x00 }).ToArray();

                            // Add the TXT record.
                            //
                            nodeName = GetName("myserver._http._tcp");

                            outputBuffer = outputBuffer.Concat(nodeName).ToArray();

                            type = BitConverter.GetBytes((short)16).Reverse().ToArray(); // TXT

                            outputBuffer = outputBuffer.Concat(type).ToArray();

                            @class = BitConverter.GetBytes((short)1).Reverse().ToArray(); // Internet

                            outputBuffer = outputBuffer.Concat(@class).ToArray();

                            ttl = BitConverter.GetBytes(4500).Reverse().ToArray();

                            outputBuffer = outputBuffer.Concat(ttl).ToArray();

                            var txtRecord = GetTxtRecord("value=tom");

                            recordLength = BitConverter.GetBytes((short)txtRecord.Length).Reverse().ToArray();

                            outputBuffer = outputBuffer.Concat(recordLength).ToArray();

                            outputBuffer = outputBuffer.Concat(txtRecord).ToArray();

                            ByteArrayToStringDump(outputBuffer);

                            Thread.Sleep(1000);

                            var bytesSent = socket.SendTo(outputBuffer, 0, outputBuffer.Length, SocketFlags.None, multicastEndpoint);

                            Console.WriteLine($"Wrote {bytesSent}");
                        }
                    }
                }
            }
            catch (Exception exp)
            {
                Console.WriteLine(exp.Message);
            }
        }

        private byte[] GetTxtRecord(string v)
        {
            var result = new byte[0];

            result = result.Concat(new byte[1] { (byte)v.Length }).Concat(Encoding.UTF8.GetBytes(v)).ToArray();

            return result;
        }

        public static void ByteArrayToStringDump(byte[] ba)
        {
            Console.WriteLine("***************************");

            StringBuilder hex = new StringBuilder(ba.Length * 2);

            int count = 0;

            foreach (byte b in ba)
            {
                Console.Write(b.ToString("x2"));
                Console.Write(" ");

                count++;

                if (count % 8 == 0)
                {
                    Console.Write("  ");
                }

                if (count % 16 == 0)
                {
                    Console.WriteLine();
                }
            }

            Console.WriteLine();
            Console.WriteLine("***************************");
        }

        private byte[] GetName(string v)
        {
            var parts = v.Split('.');

            var result = new byte[0];

            foreach (var part in parts)
            {
                int length = part.Length;
                byte lengthByte = Convert.ToByte(length);
                result = result.Concat(new byte[1] { lengthByte }).Concat(Encoding.UTF8.GetBytes(part)).ToArray();
            }

            // Null terminator.
            //
            return result.Concat(new byte[1] { 0x00 }).ToArray();
        }

        private void WriteAsNewLineHexToConsole(byte[] buffer, string description)
        {
            foreach (byte b in buffer)
            {
                Console.Write(b.ToString("X2"));
                Console.Write(" ");
            }

            Console.Write(description);

            Console.WriteLine();
        }
    }
}
