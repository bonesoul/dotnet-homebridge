using System;
using System.Collections.Generic;
using System.Linq;

namespace ColdBear.Climenole
{
    public class TLV
    {
        public Dictionary<Constants, byte[]> values = new Dictionary<Constants, byte[]>();

        public byte[] GetType(Constants type)
        {
            return values[type];
        }

        public int GetTypeAsInt(Constants type)
        {
            return values[type][0];
        }

        public void AddType(Constants type, byte[] value)
        {
            if (values.ContainsKey(type))
            {
                values[type] = Combine(values[type], value);
            }
            else
            {
                values.Add(type, value);
            }
        }

        public void AddType(Constants type, ErrorCodes value)
        {
            AddType(type, (int)value);
        }

        public void AddType(Constants type, int value)
        {
            values.Add(type, new byte[1] { (byte)value });
        }

        private byte[] Combine(params byte[][] arrays)
        {
            byte[] rv = new byte[arrays.Sum(a => a.Length)];

            int offset = 0;

            foreach (byte[] array in arrays)
            {
                System.Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }

            return rv;
        }

        public bool HasType(Constants state)
        {
            return values.ContainsKey(state);
        }
    }
}