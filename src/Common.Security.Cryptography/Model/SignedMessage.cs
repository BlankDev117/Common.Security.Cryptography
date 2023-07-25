namespace Common.Security.Cryptography.Model
{
    public class SignedMessage
    {
        public byte[] EncryptedData { get; set; }

        public byte[] Signature { get; set; }
    }
}
