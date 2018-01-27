using System;
using System.Text;

namespace ColdBear.Climenole
{
    public class PairingsController
    {
        public Tuple<string, byte[]> Post(byte[] body, ControllerSession session)
        {
            var parts = TLVParser.Parse(body);

            var state = parts.GetTypeAsInt(Constants.State);
            var method = parts.GetTypeAsInt(Constants.Method);

            Console.WriteLine("***********************");
            Console.WriteLine("* Pairings Controller *");
            Console.WriteLine($"* State: {state}           *");
            Console.WriteLine($"* Method: {state}         *");
            Console.WriteLine("***********************");

            TLV responseTLV = new TLV();

            if (state == 1)
            {
                if (method == 3) // Add Pairing
                {
                    Console.WriteLine("* Add Pairing");

                    var identifier = parts.GetType(Constants.Identifier);
                    var publickey = parts.GetType(Constants.PublicKey);
                    var permissions = parts.GetType(Constants.Permissions);

                    LiteDB.LiteDatabase database = new LiteDB.LiteDatabase("Filename=Hap.db");

                    var pairingsCollection = database.GetCollection("pairings");

                    var existingPairing = pairingsCollection.FindById(Encoding.UTF8.GetString(identifier));

                    if (existingPairing == null)
                    {
                        var pairing = new LiteDB.BsonDocument();
                        var doc = new LiteDB.BsonDocument();
                        doc.Add("publickey", new LiteDB.BsonValue(publickey));
                        doc.Add("permissions", new LiteDB.BsonValue(permissions));

                        pairing.Add(Encoding.UTF8.GetString(identifier), doc);

                        pairingsCollection.Insert(pairing);
                    }
                    else
                    {
                        // TODO DO something here.
                    }

                    responseTLV.AddType(Constants.State, 2);

                    byte[] output1 = TLVParser.Serialise(responseTLV);

                    return new Tuple<string, byte[]>("application/pairing+tlv8", output1);
                }
                else if (method == 4) // Remove Pairing
                {
                    Console.WriteLine("* Remove Pairing");

                    responseTLV = new TLV();

                    responseTLV.AddType(Constants.State, 2);

                    byte[] output2 = TLVParser.Serialise(responseTLV);

                    return new Tuple<string, byte[]>("application/pairing+tlv8", output2);
                }
                if (method == 5) // List Pairing
                {
                    Console.WriteLine("* List Pairings");

                    responseTLV = new TLV();

                    responseTLV.AddType(Constants.State, 2);

                    byte[] output3 = TLVParser.Serialise(responseTLV);

                    return new Tuple<string, byte[]>("application/pairing+tlv8", output3);
                }
            }

            responseTLV.AddType(Constants.State, 2);
            responseTLV.AddType(Constants.Error, ErrorCodes.Busy);

            byte[] output = TLVParser.Serialise(responseTLV);

            return new Tuple<string, byte[]>("application/pairing+tlv8", output);
        }
    }
}
