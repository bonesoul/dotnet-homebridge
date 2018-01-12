namespace ColdBear.ConsoleApp
{
    public class ControllerSession
    {
        public bool IsVerified { get; set; }
        public byte[] SharedSecret { get; internal set; }
        public byte[] HkdfPairEncKey { get; internal set; }
        public byte[] PublicKey { get; internal set; }
        public byte[] PrivateKey { get; internal set; }
        public byte[] ClientPublicKey { get; internal set; }
    }
}
