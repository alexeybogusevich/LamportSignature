using System.Security.Cryptography;

namespace Lamport
{
    public class LamportSignature
    {
        private readonly byte[][] _privateKey0;
        private readonly byte[][] _privateKey1;

        public LamportSignature()
        {
            _privateKey0 = new byte[256][];
            _privateKey1 = new byte[256][];

            PublicKey0 = new byte[256][];
            PublicKey1 = new byte[256][];

            using var rng = RandomNumberGenerator.Create();

            for (int i = 0; i < 256; i++)
            {
                _privateKey0[i] = new byte[32];
                _privateKey1[i] = new byte[32];

                rng.GetBytes(_privateKey0[i]);
                rng.GetBytes(_privateKey1[i]);

                PublicKey0[i] = SHA256.HashData(_privateKey0[i]);
                PublicKey1[i] = SHA256.HashData(_privateKey1[i]);
            }
        }

        public byte[][] PublicKey0 { get; private set; }

        public byte[][] PublicKey1 { get; private set; }

        public byte[][] Sign(byte[] messageHash)
        {
            if (messageHash.Length != 32)
            {
                throw new ArgumentException("Message hash must be 32 bytes (SHA-256 output).", nameof(messageHash));
            }

            var signature = new byte[256][];

            for (int i = 0; i < 256; i++)
            {
                signature[i] = ((messageHash[i / 8] >> (i % 8)) & 1) == 0 ? _privateKey0[i] : _privateKey1[i];
            }

            return signature;
        }

        public static bool Verify(byte[][] publicKey0, byte[][] publicKey1, byte[] messageHash, byte[][] signature)
        {
            if (messageHash.Length != 32 || signature.Length != 256)
            {
                return false;
            }

            for (int i = 0; i < 256; i++)
            {
                var expectedHash = ((messageHash[i / 8] >> (i % 8)) & 1) == 0 ? publicKey0[i] : publicKey1[i];
                var actualHash = SHA256.HashData(signature[i]);

                if (!expectedHash.SequenceEqual(actualHash))
                {
                    return false;
                }
            }

            return true;
        }
    }
}