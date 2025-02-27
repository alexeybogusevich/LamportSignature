using System.Security.Cryptography;
using System.Text;

namespace Lamport
{
    public class LamportAuth
    {
        private readonly int _n;

        private int _a = 1;
        private byte[] _currentHash;

        public LamportAuth(int iterations, string password, string serverName)
        {
            _n = iterations;
            byte[] P = Encoding.UTF8.GetBytes(password + serverName);
            _currentHash = ComputeHashChain(P, _n);
        }

        public static byte[] ComputeHashChain(byte[] input, int count)
        {
            byte[] hash = input;

            for (int i = 0; i < count; i++)
            {
                hash = SHA256.HashData(hash);
            }

            return hash;
        }

        private static bool CompareHashes(byte[] hash1, byte[] hash2)
        {
            if (hash1.Length != hash2.Length)
            {
                return false;
            }

            for (int i = 0; i < hash1.Length; i++)
            {
                if (hash1[i] != hash2[i])
                {
                    return false;
                }
            }

            return true;
        }

        public bool Authenticate(byte[] clientHash)
        {
            var computedHash = ComputeHashChain(clientHash, _a);

            if (CompareHashes(computedHash, _currentHash))
            {
                _currentHash = computedHash;
                _a++;
                return true;
            }

            return false;
        }
    }
}