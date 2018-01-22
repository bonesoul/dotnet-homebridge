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

                    // Create a response!
                    //
                    var outputBuffer = new byte[0];

                    var flags = new byte[2];

                    var bitArray = new BitArray(flags);

                    bitArray.Set(1, true); // QR
                    bitArray.Set(6, true); // AA

                    bitArray.CopyTo(flags, 0);

                    var answerCount = BitConverter.GetBytes((short)1);
                    var otherCounts = BitConverter.GetBytes((short)0);

                    // Set the header
                    //
                    outputBuffer = outputBuffer.Concat(requestId).Concat(flags).Concat(otherCounts).Concat(answerCount).Concat(otherCounts).Concat(otherCounts).ToArray();

                    // Build the response
                    //
                    var nodeName = Encoding.UTF8.GetBytes("_http._tcp").Concat(new byte[1] { 0x00 }).ToArray();

                    outputBuffer = outputBuffer.Concat(nodeName).ToArray();

                    var type = BitConverter.GetBytes((short)16);

                    outputBuffer = outputBuffer.Concat(type).ToArray();

                    var @class = BitConverter.GetBytes((short)1);

                    outputBuffer = outputBuffer.Concat(@class).ToArray();

                    var ttl = BitConverter.GetBytes(60);

                    outputBuffer = outputBuffer.Concat(ttl).ToArray();

                    var recordLength = BitConverter.GetBytes((short)0);

                    outputBuffer = outputBuffer.Concat(recordLength).ToArray();

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
