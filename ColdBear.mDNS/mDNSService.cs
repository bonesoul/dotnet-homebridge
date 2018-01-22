using System;
using System.Collections;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ColdBear.mDNS
{
    public class mDNSService
    {
        public void Start()
        {
            try
            {
                UdpClient udpClient = new UdpClient();

                udpClient.ExclusiveAddressUse = false;
                IPEndPoint localEndpoint = new IPEndPoint(IPAddress.Any, 5353);

                udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                udpClient.ExclusiveAddressUse = false;

                udpClient.Client.Bind(localEndpoint);

                IPAddress multicastaddress = IPAddress.Parse("224.0.0.251");
                udpClient.JoinMulticastGroup(multicastaddress);

                while (true)
                {
                    Byte[] data = udpClient.Receive(ref localEndpoint);

                    Console.WriteLine("************************ REQUEST RECEIVED **********************");

                    string dataAsString = Encoding.UTF8.GetString(data);
                    Console.WriteLine(dataAsString);

                    var buffer = new byte[2];

                    int pointer = 0;

                    Array.Copy(data, pointer, buffer, 0, 2);
                    WriteAsNewLineHexToConsole(buffer, "Transaction ID");

                    var requestId = new byte[2];
                    Array.Copy(buffer, 0, buffer, 0, 2);

                    pointer += 2;

                    Array.Copy(data, pointer, buffer, 0, 2);
                    WriteAsNewLineHexToConsole(buffer, "Flags");

                    pointer += 2;

                    Array.Copy(data, pointer, buffer, 0, 2);
                    WriteAsNewLineHexToConsole(buffer, "Number of questions");

                    short numberOfQuestions = BitConverter.ToInt16(buffer, 0);

                    pointer += 2;

                    Array.Copy(data, pointer, buffer, 0, 2);
                    WriteAsNewLineHexToConsole(buffer, "Number of answers");

                    pointer += 2;

                    Array.Copy(data, pointer, buffer, 0, 2);
                    WriteAsNewLineHexToConsole(buffer, "Number of authority resource records");

                    pointer += 2;

                    Array.Copy(data, pointer, buffer, 0, 2);
                    WriteAsNewLineHexToConsole(buffer, "Number of additional resource records");

                    pointer += 2;

                    buffer = new byte[data.Length - pointer];

                    Array.Copy(data, pointer, buffer, 0, data.Length - pointer);

                    var contentBuffer = new byte[data.Length - pointer];

                    int index = 0;

                    foreach (byte b in buffer)
                    {
                        if (b == 0x00)
                        {
                            break;
                        }
                        else
                        {
                            contentBuffer[index++] = b;
                        }
                    }

                    buffer = new byte[index];

                    Array.Copy(data, pointer, buffer, 0, index);

                    WriteAsNewLineHexToConsole(buffer, Encoding.UTF8.GetString(buffer));

                    WriteAsNewLineHexToConsole(new byte[1] { 0x00 }, "Terminator");

                    buffer = new byte[2];

                    pointer += (index + 1);

                    Array.Copy(data, pointer, buffer, 0, 2);
                    WriteAsNewLineHexToConsole(buffer, "Type");

                    pointer += 2;

                    Array.Copy(data, pointer, buffer, 0, 2);
                    WriteAsNewLineHexToConsole(buffer, "Class");

                    if (numberOfQuestions == 0)
                    {
                        continue;
                    }

                    // Create a response!
                    //
                    var outputBuffer = new byte[0];

                    var flags = new byte[2];

                    var bitArray = new BitArray(flags);

                    bitArray.Set(15, true); // QR
                    bitArray.Set(10, true); // AA

                    bitArray.CopyTo(flags, 0);

                    var answerCount = BitConverter.GetBytes((short)1).Reverse().ToArray();
                    var otherCounts = BitConverter.GetBytes((short)0);

                    // Set the header
                    //
                    outputBuffer = outputBuffer.Concat(requestId).Concat(flags.Reverse()).Concat(otherCounts).Concat(answerCount).Concat(otherCounts).Concat(otherCounts).ToArray();

                    // Build the response
                    //
                    var nodeName = GetName("_http._tcp");

                    outputBuffer = outputBuffer.Concat(nodeName).ToArray();

                    var type = BitConverter.GetBytes((short)16).Reverse().ToArray(); // TXT

                    outputBuffer = outputBuffer.Concat(type).ToArray();

                    var @class = BitConverter.GetBytes((short)1).Reverse().ToArray(); // Internet

                    outputBuffer = outputBuffer.Concat(@class).ToArray();

                    var ttl = BitConverter.GetBytes(4500).Reverse().ToArray();

                    outputBuffer = outputBuffer.Concat(ttl).ToArray();

                    var recordLength = BitConverter.GetBytes((short)1).Reverse().ToArray();

                    outputBuffer = outputBuffer.Concat(recordLength).ToArray();

                    ByteArrayToStringDump(outputBuffer);

                    // Send the actual response.
                    //
                    var remoteEndPoint = new IPEndPoint(multicastaddress, 5353);



                    udpClient.Send(outputBuffer, outputBuffer.Length, remoteEndPoint);

                    Console.WriteLine("****************************************************************");
                }
            }
            catch (Exception exp)
            {
                Console.WriteLine(exp.Message);
            }
        }

        public static void ByteArrayToStringDump(byte[] ba)
        {
            Console.WriteLine("*** RESPONSE ***");

            StringBuilder hex = new StringBuilder(ba.Length * 2);

            int count = 0;

            foreach (byte b in ba)
            {
                Console.Write(b.ToString("x2"));
                Console.Write(" ");

                count++;

                if(count % 8 == 0)
                {
                    Console.Write("  ");
                }

                if (count % 16 == 0)
                {
                    Console.WriteLine();
                }
            }
            Console.WriteLine();
            Console.WriteLine("****************");
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
