using System.Security.Cryptography;

namespace Login_SignUpPage_Backend.Helpers
{
    public class PasswordHasher
    {
        private static RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        private static readonly int SaltSize = 16;                                     //salt se adauga la parola initiala ca sa am ceva total diferit
        private static readonly int HashSize = 20;
        private static readonly int Iterations = 10000;

        public static string HashPassword(string password)
        {
            byte[] salt;
            rng.GetBytes(salt = new byte[SaltSize]);

            var key = new Rfc2898DeriveBytes(password,salt, Iterations);
            var hash = key.GetBytes(HashSize);

            var hashBytes= new byte[SaltSize + HashSize];                              // un nou sir care va stoca valoarea generata anterior
            Array.Copy(salt,0, hashBytes, 0, SaltSize);                                // valoarea de salt se copiaza in SaltSize 
            Array.Copy(hashBytes, 0, hashBytes, SaltSize, HashSize);

            var base64Hash = Convert.ToBase64String(hashBytes);
            return base64Hash;
        }

        public static bool VerifyPassword(string password, string base64Hash)
        { 
         var hashBytes = Convert.FromBase64String(base64Hash);

         var salt = new byte[SaltSize];
            Array.Copy(hashBytes, 0, salt, 0, SaltSize);

            var key = new Rfc2898DeriveBytes(password, salt, Iterations);
            byte[] hash = key.GetBytes(HashSize);

            for (var i = 0; i < HashSize; i++)
            {
                if (hashBytes[i + SaltSize] != hash[i])
                    return false;
            }
            return true;
        }
    }
}
