using System;
using System.IO;
using System.Linq;

namespace ColdBear.ConsoleApp
{
    public class TLVParser
    {
        public static TLV Parse(byte[] data)
        {
            if (data.Length < 4)
            {
                throw new Exception();
            }

            int currentIndex = 0;
            TLV result = new TLV();

            while (currentIndex < data.Length)
            {
                var tag = (Constants)data[currentIndex];
                currentIndex++;
                var length = data[currentIndex];
                currentIndex++;

                byte[] value = data.Skip(currentIndex).Take(length).ToArray();

                result.AddType(tag, value);

                currentIndex += length;
            }

            return result;
        }

        public static byte[] Serialise(TLV item)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter br = new BinaryWriter(ms))
                {

                    foreach (var i in item.values)
                    {
                        br.Write((byte)i.Key);
                        br.Write((byte)i.Value.Length);
                        br.Write(i.Value);
                    }
                }

                return ms.ToArray();
            }
        }
    }
}
