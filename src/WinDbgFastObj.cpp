#include <windows.h>
#include <vector>
#include <string>
#include "native.hpp"
#include <detours.h>
#include <optional>
#include "WinDbgFastObj.hpp"

#pragma comment(lib,"DbgHelp.lib")

#define KDEXT_64BIT

#include <wdbgexts.h>
#include <DbgHelp.h>

EXT_API_VERSION gExtApiVersion = {
    5 ,
    5 ,
    EXT_API_VERSION_NUMBER64,
    0
};

EXTERN_C WINDBG_EXTENSION_APIS64 ExtensionApis = { 0 };

namespace {
    template <typename T> using opt = std::optional<T>;

    HINSTANCE hInstance;
    ULONG_PTR FindObjectByName;
    ULONG_PTR ObpInfoMaskToOffset;
    UCHAR	  ObInfoMaskToOffset[16];
    ULONG	  ObjectHeaderSize;
    ULONG	  InfoMaskOffset = 0;

    //------------------------------------------------------------------------------
    ULONG_PTR GetFindObjectByNameAddress()
    {
        auto hProcess = GetCurrentProcess();
        auto hKdext = reinterpret_cast<DWORD64>(GetModuleHandleA("kdexts.dll"));
        if (!hKdext)
        {
            dprintf("Unable to locate kdexts.dll\n");
            return {};
        }
        SymInitialize(hProcess, NULL, TRUE);

        auto base = SymLoadModule64(hProcess, NULL, "kdexts.dll", NULL, hKdext, 0);
        if (!base && GetLastError())
        {
            dprintf("SymLoadModule64 failed with error code %u\n", GetLastError());
            return {};
        }

        auto symbolInfo = SymbolInfo_t{};
        symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
        symbolInfo.MaxNameLen = sizeof symbolInfo.Name;
        symbolInfo.ModBase = hKdext;
        auto ok = SymFromName(hProcess, "FindObjectByName", reinterpret_cast<PSYMBOL_INFO>(&symbolInfo));
        if (!ok)
        {
            dprintf("SymFromName failed with error code %u\n", GetLastError());
            return {};
        }
        return symbolInfo.Address;
    }

    //------------------------------------------------------------------------------
    bool NTAPI KernelRead(
        _In_ ULONG_PTR VirtualAddr,
        _Out_ PVOID pBuffer,
        _In_ size_t BufferLength)
    {
        ULONG bytes;
        auto ok = ReadMemory(VirtualAddr, pBuffer, (ULONG)BufferLength, &bytes);
        return (ok && (bytes == BufferLength));
    }

    //------------------------------------------------------------------------------
    opt<std::wstring> NTAPI MmReadUnicodeString(const PUNICODE_STRING pUnicodeString)
    {
        auto str = std::wstring();
        str.resize(static_cast<size_t>(pUnicodeString->Length) + 1);
        auto ok = KernelRead(pUnicodeString->Buffer, str.data(), str.size() - 1);
        if (!ok)
            return {};

        return str;
    }

    //------------------------------------------------------------------------------
    opt<std::wstring> toWstring(const std::string& str, size_t size)
    {
        auto strW = std::wstring();
        strW.resize(size);
        auto ok = MultiByteToWideChar(
            CP_OEMCP,
            0,
            str.c_str(),
            static_cast<int>(size),
            strW.data(),
            static_cast<int>(size)
        );
        if (!ok)
            return {};

        return strW;
    }

    //------------------------------------------------------------------------------
    opt<std::wstring> toWstring(const std::string& str)
    {
        return toWstring(str, str.size());
    }

    //------------------------------------------------------------------------------
    ULONG HashName(std::wstring& str)
    {
        auto HashIndex = ULONG{};
        auto NameLen = str.size();
        auto pBuffer = str.data();

#if defined(_AMD64_)
        if (NameLen >= 4) {

            auto ChunkHash = ULONG64{};
            do {
                auto Chunk = *(PULONG64)pBuffer;
                Chunk &= ~0x0020002000200020;

                ChunkHash += (ChunkHash << 1) + (ChunkHash >> 1);
                ChunkHash += Chunk;
                pBuffer += 4;
                NameLen -= 4;
            } while (NameLen >= 4);

            HashIndex = (ULONG)(ChunkHash + (ChunkHash >> 32));
        }
        else
            HashIndex = 0;
#endif
        while (NameLen--)
        {
            auto Wchar = *pBuffer++;
            HashIndex += (HashIndex << 1) + (HashIndex >> 1);

            if (Wchar < 'a')
                HashIndex += Wchar;
            else if (Wchar > 'z')
                HashIndex += towupper(Wchar);
            else
                HashIndex += (Wchar - ('a' - 'A'));
        }
        return HashIndex;
    }

    //------------------------------------------------------------------------------
    opt<std::wstring> ObGetName(
        _In_ ULONG_PTR	ObjectAddr
    )
    {
        UCHAR					InfoMask;
        OBJECT_HEADER_NAME_INFO	ObjNameInfo;

        auto ok = KernelRead((ObjectAddr - ObjectHeaderSize) + InfoMaskOffset, &InfoMask, sizeof(InfoMask));
        if (!ok)
            return {};
        ok = KernelRead(ObjectAddr - ((size_t)ObjectHeaderSize + ObInfoMaskToOffset[InfoMask & 3]), &ObjNameInfo, sizeof(ObjNameInfo));
        if (!ok)
            return {};
        return MmReadUnicodeString(&ObjNameInfo.Name);
    }


    //------------------------------------------------------------------------------
    ULONG_PTR NTAPI FindObjectHook(
        _In_ PCSTR pObjectName,
        _In_ ULONG_PTR RootDir,
        _In_ ULONG_PTR /*Unused*/
    )
    {
        if (!pObjectName)
            return {};

        // Workaround when no starting \ is specified (ex: Device instead of \Device)
        if (*pObjectName != '\\')
            pObjectName--;

        auto DirObjLength = size_t{};
        auto pNextDelimiter = strchr(pObjectName + 1, '\\');

        if (!pNextDelimiter)
            DirObjLength = strlen(pObjectName + 1);
        else
            DirObjLength = (pNextDelimiter - pObjectName) - 1;

        // If a RootDir is not specified then use the ObRootDirectoryObject one
        if (!RootDir)
        {
            auto ObpRootDirectoryObjectAddr = GetExpression("ObpRootDirectoryObject");
            auto ok = KernelRead(ObpRootDirectoryObjectAddr, &RootDir, sizeof(RootDir));
            if (!ok)
                return {};

            // Special case when accessing only the root directory
            if (!DirObjLength)
                return RootDir;
        }

        auto nameW = toWstring(pObjectName + 1, DirObjLength);
        if (!nameW)
            return {};

        // Hash the current directory name to access the corresponding directory bucket
        auto HashValue = HashName(*nameW);
        auto DirectoryObject = OBJECT_DIRECTORY{};
        auto ok = KernelRead(RootDir, &DirectoryObject, sizeof(DirectoryObject));
        if (!ok)
            return {};

        auto ObjectEntry = OBJECT_DIRECTORY_ENTRY{};
        ObjectEntry.ChainLink = DirectoryObject.HashBuckets[HashValue % NUMBER_HASH_BUCKETS];
        while (ObjectEntry.ChainLink != NULL)
        {
            ok = KernelRead((ULONG_PTR)ObjectEntry.ChainLink, &ObjectEntry, sizeof(ObjectEntry));
            if (!ok)
                return {};

            if (ObjectEntry.HashValue != HashValue)
                continue;

            auto ObjectEntryName = ObGetName(ObjectEntry.Object);
            if (!ObjectEntryName)
                return {};

            if (_wcsicmp(nameW->data(), ObjectEntryName->data()))
                continue;

            if (pNextDelimiter != NULL)
                return FindObjectHook(pNextDelimiter, ObjectEntry.Object, 0);
            else
                return ObjectEntry.Object;
        }
        return {};
    }
}

//------------------------------------------------------------------------------
EXTERN_C bool WINAPI DllMain(
    _In_ HINSTANCE hInstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    /*lpvReserved*/
)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_DETACH:
    {
        DetourTransactionBegin();
        DetourDetach((void**)&::FindObjectByName, ::FindObjectHook);
        DetourTransactionCommit();
        return true;
    }
    break;
    //--
    case DLL_PROCESS_ATTACH:
    {
        ::hInstance = hInstDLL;
        return TRUE;
    }
    break;
    //--
    default:
        break;
    }
    return (TRUE);
}


//------------------------------------------------------------------------------
EXTERN_C __declspec(dllexport) LPEXT_API_VERSION WDBGAPI ExtensionApiVersion(void)
{
    return (&gExtApiVersion);
}

//------------------------------------------------------------------------------
EXTERN_C __declspec(dllexport) void WDBGAPI WinDbgExtensionDllInit(
    PWINDBG_EXTENSION_APIS64 lpExtensionApis,
    USHORT /*usMajorVersion*/,
    USHORT /*usMinorVersion*/)
{
    ExtensionApis = *lpExtensionApis;

    ObpInfoMaskToOffset = GetExpression("ObpInfoMaskToOffset");
    auto ok = KernelRead(ObpInfoMaskToOffset, &ObInfoMaskToOffset, sizeof(ObInfoMaskToOffset));
    if (!ok)
        return;

    auto err = GetFieldOffset("_OBJECT_HEADER", "Body", &ObjectHeaderSize);
    if (err)
        return;

    err = GetFieldOffset("_OBJECT_HEADER", "InfoMask", &InfoMaskOffset);
    if (err)
        return;

    ::FindObjectByName = GetFindObjectByNameAddress();
    if (!::FindObjectByName)
        return;

    DetourTransactionBegin();
    DetourAttach((void**)&::FindObjectByName, ::FindObjectHook);
    err = DetourTransactionCommit();
    if (err != NO_ERROR)
        return;

    dprintf("The kdexts!FindObjectByName is now optimized.\nYou can try !object, !drvobj, !devobj, !devstack...\n");
    return;
}

//------------------------------------------------------------------------------
EXTERN_C __declspec(dllexport) void WDBGAPI help(
    HANDLE                 /*hCurrentProcess*/,
    HANDLE                 /*hCurrentThread*/,
    ULONG64                /*dwCurrentPc*/,
    ULONG                  /*dwProcessor*/,
    PCSTR                  /*args*/)
{
    dprintf("This extension is just an optimization to speed up the object name resultion\n");
}