# How-to-Spoof-WMI-Query


>This guide provides full explanation on how to Spoof WMI.
>WMI is a native Windows API that roblox uses to query the SMBIOS UUID.

>This guide took me a long time to write, every informations are verified (i made a spoofer).
>Dont forget to join my discord server : [https://discord.gg/CgFPbvSaU](https://discord.gg/CgFPbvSaU)

>Author : krypt



---



# Step 0 : What flow you should follow


Basically we hook WMI.


```
1. taskkill wmiprvse.exe

2. copy SmbiosHook.dll

3. spawn a shared host via a NON-cimwin32 provider so the host exists but cimwin32 is NOT loaded yet

4. inject SmbiosHook.dll into wmiprvse.exe (CreateRemoteThread + LoadLibraryW)

5. Sleep 1000

6. query #1  Get-CimInstance Win32_ComputerSystemProduct  -> loads cimwin32 into the already-hooked host

7. Sleep 1500, query #2
```


The order in the step 3 to 6 matters a lot : you spawn the host without `cimwin32`, injects so the hook is live, and then query `Win32_ComputerSystemProduct` wich will force `cimwin32` to load into a host where oleaut32 allocator is already hooked. If you let `cimwin32` load first and hook second it will not work (at least didn't for me).




---



# Step 1 : Read the real UUID


The content filder needs the real UUID. Read it directly in the DLL, same way as `NtQuerySystemInformation` with the SMBIOS provider :


```cpp

typedef NTSTATUS (NTAPI* tNtQSI)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);


static bool readRealUuid(wchar_t out[40]) {

    tNtQSI nt = (tNtQSI)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

    static unsigned char buf[65536] = {0};

    *(ULONG*)(buf + 0)  = RSMB_SIG;

    *(ULONG*)(buf + 4)  = 1;   // = SystemFirmwareTable_Get

    *(ULONG*)(buf + 8)  = 0;

    *(ULONG*)(buf + 12) = sizeof(buf) - 16;

    ULONG retlen = 0;

    NTSTATUS st = nt((SYSTEM_INFORMATION_CLASS)76, buf, sizeof(buf), &retlen);

    unsigned char* t1 = findType1(buf, retlen);   // walk SMBIOS structures

    unsigned char realRaw[16]; memcpy(realRaw, t1 + 8, 16);  // UUID at struct offset +8

    formatUuid(realRaw, out);

    return true;

}

```


SMBIOS Type 1 UUID byte order is *mixed-endian*, so `formatUuid` does : 


```cpp

static void formatUuid(const unsigned char raw[16], wchar_t out[40]) {

    unsigned long  tl = (raw[3]<<24)|(raw[2]<<16)|(raw[1]<<8)|raw[0];

    unsigned short tm = (raw[5]<<8)|raw[4];

    unsigned short th = (raw[7]<<8)|raw[6];

    unsigned short cs = (raw[8]<<8)|raw[9];

    swprintf_s(out, 40, L"%08X-%04X-%04X-%04X-%02X%02X%02X%02X%02X%02X",

        tl, tm, th, cs, raw[10],raw[11],raw[12],raw[13],raw[14],raw[15]);

}
```


This must produce the exact same string WMI returns. If your formatting is off by endianness the needle never matches and the spoof won't do anything.



---



# Step 2 : The oleaut32 BSTR hook


Every WMI string property leaves `cimwin32` as a `BSTR`, allocated by `oleaut32`. The 5 entry points that build a BSTR from a source string :


| **oleaut32 ordinal** | **Export**              | **cimwin32** | **framedynos** | **fastprox** | **wmiutils** |
| -------------------- | ----------------------- | ------------ | -------------- | ------------ | ------------ |
| **2**                | `SysAllocString`        | ✓ (delay)    | ✓ (delay)      | ✓ (delay)    | ✓ (reg)      |
| **3**                | `SysReAllocString`      | ---          | ---            | ✓ (delay)    | ---          |
| **4**                | `SysAllocStringLen`     | ---          | ✓ (delay)      | ✓ (delay)    | ---          |
| **5**                | `SysReAllocStringLen`   | ---          | ---            | ---          | ---          |
| **150**              | `SysAllocStringByteLen` | ✓ (delay)    | ---            | ---          | ---          |

You hook all five. The hook is a content filter : if the incoming strings equals the real UUID allocate the spoof instead.


```cpp

typedef wchar_t* BSTR_t;

typedef BSTR_t (WINAPI* tSysAlloc)(const wchar_t*);

static tSysAlloc origSysAlloc = nullptr;


static bool uuidMatchW(const wchar_t* psz){ return psz && g_realStr[0] && _wcsicmp(psz, g_realStr)==0; }


static BSTR_t WINAPI hookSysAlloc(const wchar_t* psz) {

    if (uuidMatchW(psz)) { InterlockedIncrement(&g_hookHits); return origSysAlloc(g_spoofStr); }

    return origSysAlloc(psz);

}

```


You **do not** modify the WMI object, you only swap the string the moment `cimwin32` allocates it. Hyperion receives a perfectly normal `BSTR` whose bytes = your spoof.



----


# Steap 3 : OLEAUT32 is a dealay-load import


## Regular vs delay-load imports

A normal PE imports lives in `IMAGE_DIRECTORY_ENTRY_IMPORT`. The loader resolves all of them at load time, filling the IAT with real function addresse. Scanning that directory is what every "IAT hook" tuts teaches.

`cimwin32.dll`, `framedynos.dll`, and `fastprox.dll` do **not** import `OLEAUT32` that way. 
They import it as a delay-load import shown in `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`.
Dumpbin confirms it, `OLEAUT32.dll` appears under `Section contains the following delay load imports, not under the regular import section:


| **Entry**                      | **Hex Value**      | **Description**                                                     |
| ------------------------------ | ------------------ | ------------------------------------------------------------------- |
| **Target Module**              | `OLEAUT32.dll`     | Delay-loaded library                                                |
| **Characteristics**            | `00000001`         | `grAttrs` (Bit 0 set: `DLAttrRva` indicates all addresses are RVAs) |
| **Address of HMODULE**         | `00000001801B1248` | `rvaModHname` (Location where the loaded module handle is stored)   |
| **Import Address Table (IAT)** | `00000001801C3138` | `rvaIAT` (Pointer table patched at runtime)                         |
| **Import Name Table (INT)**    | `00000001801A5A58` | `rvaINT` (Array of function names and ordinals)                     |
| **Bound Import Name Table**    | `00000001801A6878` | `rvaBoundIAT` (Optional pre-bound addresses)                        |
| **Unload Import Name Table**   | `0000000000000000` | `rvaUnloadIAT` (Unload handler table; unused)                       |
| **Import: Ordinal 150**        | `000000018008C26A` | Thunk RVA for `SysAllocStringByteLen`                               |
| **Import: Ordinal 2**          | `000000018008C1D2` | Thunk RVA for `SysAllocString`                                      |

A scan of directory 1 finds `OLEAUT32.dll` only in `wmiutils.dll` (wich gets imported regularly).
It sees nothing in the three DLL that matter the most. Result: `origSysAlloc` set, everything else NULL, `hits=0`, the real UUID = unhooked.


## The fix : scan the delay-load directory too


The delay-load descriptor is 8 DWORD = 32 bytes, terminated byNull`rvaDLLName` :

```cpp

typedef struct {

    DWORD grAttrs; // bit0 = DLAttrRva -> all below are RVAs

    DWORD rvaDLLName; // RVA to "OLEAUT32.dll"

    DWORD rvaModHname; // RVA to HMODULE slot

    DWORD rvaIAT; // RVA to Import Address Table (the slot you patch)

    DWORD rvaINT; // RVA to Import Name Table

    DWORD rvaBoundIAT;

    DWORD rvaUnloadIAT;

    DWORD dwTimeStamp;

} DLDesc;// 32 bytes

```


If the first bit of `grAttrs` is set, all `rva*` fields are standard 32 bit RVA. add the module base address to find their memory location.
The `rvaINT` table uses standard import : it either holds an ordinal (`IMAGE_ORDINAL_FLAG64`) or an RVA pointing to the function name.

```cpp

static unsigned short ordFromThunk(uintptr_t t, unsigned char* mod) {

    if (t & IMAGE_ORDINAL_FLAG64) return (unsigned short)(t & 0xFFFF);
    
    IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(mod + t);

    if (_stricmp((char*)ibn->Name, "SysAllocString")==0) return 2;

    if (_stricmp((char*)ibn->Name, "SysAllocStringLen")==0) return 4;

    if (_stricmp((char*)ibn->Name, "SysAllocStringByteLen")==0) return 150;

    if (_stricmp((char*)ibn->Name, "SysReAllocString")==0) return 3;

    if (_stricmp((char*)ibn->Name, "SysReAllocStringLen")==0) return 5;

    return 0;

}


static void hookDelayIAT(uintptr_t base) {

    unsigned char* mod = (unsigned char*)base;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(mod + ((IMAGE_DOS_HEADER*)mod)->e_lfanew);

    IMAGE_DATA_DIRECTORY* dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

    if (!dd->VirtualAddress || !dd->Size) return;

    DLDesc* d = (DLDesc*)(mod + dd->VirtualAddress);

    for (; d->rvaDLLName != 0; d++) {

        if (!(d->grAttrs & 1)) continue;

        if (_stricmp((const char*)(mod + d->rvaDLLName), "OLEAUT32.dll") != 0) continue;

        if (!d->rvaINT || !d->rvaIAT) continue;

        uintptr_t* INT = (uintptr_t*)(mod + d->rvaINT);

        uintptr_t* IAT = (uintptr_t*)(mod + d->rvaIAT);

        for (size_t i = 0; INT[i] != 0; i++) {

            unsigned short ord = ordFromThunk(INT[i], mod);

            uintptr_t hook = hookForOrd(ord); if (!hook) continue;

            if (IAT[i] == hook) continue; // already hooked

            uintptr_t real = resolveOleaut(ord);  // see Step 6

            saveOrig(ord, real);

            patchIat(&IAT[i], hook);

        }

    }

}

```


*BTW* : do not skip the regular directory `wmiutils.dll` is there and you want every oleaut32 caller hooked. Run both on every module.


## The stub problem


At the moment you hook the delay-load IAT slot usually don't hol the real `oleaut32` address. It holds a delay-load stub (a little jmp in the module's `.text` that, when called for first time, runs `LoadLibraryW("oleaut32")` + `GetProcAddress`) overwrites the slop with the real address and jumps to it.

If you saved `IAT[i]` (the stub) as your "original" and your hook triad to call it you would crash or loop into the stub forever.



---



# Step 4 : Resolve the real oleaut32 address yourself


Because the slop might be a stub, never trust `IAT[i]` as the target. Resolve the address from the real `oleaut32.dll` and cache it by ordinal:

```cpp

static uintptr_t g_realOle[256] = {0};

static uintptr_t resolveOleaut(unsigned short ord) {

    if (ord < 256 && g_realOle[ord]) return g_realOle[ord];

    HMODULE oa = GetModuleHandleW(L"oleaut32.dll");

    if (!oa) oa = LoadLibraryW(L"oleaut32.dll");

    const char* name = (ord==2)?"SysAllocString":(ord==3)?"SysReAllocString":

                       (ord==4)?"SysAllocStringLen":(ord==5)?"SysReAllocStringLen":

                       (ord==150)?"SysAllocStringByteLen":nullptr;

    uintptr_t r = (uintptr_t)GetProcAddress(oa, name);

    if (ord < 256) g_realOle[ord] = r;

    return r;

}

static void saveOrig(unsigned short ord, uintptr_t real) {

    switch (ord) {

        case 2: if (!origSysAlloc)        origSysAlloc        = (tSysAlloc)real;       break;

        case 4: if (!origSysAllocLen)     origSysAllocLen     = (tSysAllocLen)real;    break;

        case 150:if (!origSysAllocByteLen)origSysAllocByteLen = (tSysAllocByteLen)real;break;

        case 3: if (!origSysReAlloc)      origSysReAlloc      = (tSysReAlloc)real;    break;

        case 5: if (!origSysReAllocLen)   origSysReAllocLen   = (tSysReAllocLen)real; break;

    }

}

```


`oleaut32` is always loaded into `wmiprvse` already (`wmiutils.dll` imports it regularly and loads at start), so `GetModuleHandleW` succeeds. Save the resolved address as the "original" and patch `IAT[i] = hook`. Because the slop no longer points at the delay-load stub, the stub never runs and callers go to your hook wich  calls the real function.


This same `resolveOleaut` path is used for the regular import hook too, so `origSysAlloc` is always the actual oleaut32 export regardless of how the caller imported it.

Patiching the slot is one page `VirtualProtect` + write + `FlushInstructionCache` :

```cpp

static void patchIat(uintptr_t* entry, uintptr_t hook) {

    DWORD oldp;

    if (!VirtualProtect(entry, sizeof(uintptr_t), PAGE_READWRITE, &oldp)) return;

    *entry = hook;

    VirtualProtect(entry, sizeof(uintptr_t), oldp, &oldp);

    FlushInstructionCache(GetCurrentProcess(), entry, sizeof(uintptr_t));

}
```




---



# Step 5 : Preload cimwin32


`K32EnumProcessModules` only returns modules that are **already loaded**. If you enumerate before `cimwin32` is mapped you will not hook it and the first `Win32_ComputerSystemProduct` query allocates the UUID through an unhooked allocator. So you need to force them to load then enumerate and finally hook :


```cpp

wchar_t sys[MAX_PATH]; GetSystemDirectoryW(sys, MAX_PATH);

HMODULE hFramedyn = LoadLibraryW((std::wstring(sys)+L"\\framedynos.dll").c_str());

HMODULE hCimwin32 = LoadLibraryW((std::wstring(sys)+L"\\wbem\\cimwin32.dll").c_str());

HMODULE hFastprox = LoadLibraryW((std::wstring(sys)+L"\\wbem\\fastprox.dll").c_str());

hookAllOleaut(); // now sees all three + their delay-load oleaut32

```


Combined with the step 2 this will guarantee the hook is in place before `cimwin32` builds a UUID BSTR.

Module enumeration uses `K32EnumProcessModules`, fetch it with `GetProcAddress` soyou don't need `psapi.lib` :

```cpp

g_enumProc = (tEnumProc)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "K32EnumProcessModules");

```




---



# Steap 6 : Rehook thread


A second WMI provider may load after your first pass, or a delay-load stub may resolve under you. Rerun the full hook everyon second for approximately 2 minutes.


```cpp

static DWORD WINAPI RehookThread(LPVOID) {

    for (int i = 0; i < 120; i++) { Sleep(1000); hookAllOleaut(); }

    return 0;

}

```



---
# END

This is the end of this guide, if you have any questions join my discord and ping me.
In the future i might add : how to spoof MAC address and Guid for a full spoofer.
Thanks for reading this !





