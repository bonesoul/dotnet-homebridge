using System;
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
                UdpClient client = new UdpClient();

                client.ExclusiveAddressUse = false;
                IPEndPoint localEp = new IPEndPoint(IPAddress.Any, 5353);

                client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                client.ExclusiveAddressUse = false;

                client.Client.Bind(localEp);

                IPAddress multicastaddress = IPAddress.Parse("224.0.0.251");
                client.JoinMulticastGroup(multicastaddress);

                Console.WriteLine("Listening this will never quit so you will need to ctrl-c it");

                while (true)
                {
                    Byte[] data = client.Receive(ref localEp);
                    string strData = Encoding.UTF8.GetString(data);
                    Console.WriteLine(strData);
                }
            }
            catch
            {
                Console.WriteLine("Unable to listen for mDNS broadcasts");
            }
        }
    }
}
