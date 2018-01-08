namespace ColdBear.ConsoleApp
{
    public enum Constants
    {
        Method = 0,
        Salt = 2,
        PublicKey = 3,
        Proof = 4,
        EncryptedData = 5,
        State = 6,
        Error = 7,
    }

    public enum ErrorCodes
    {
        Authentication = 2,
        MaxPeers = 4,
        Busy = 7
    }
}
