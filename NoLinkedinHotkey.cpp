/* SPDX-License-Identifier: WTFPL

https://twitter.com/linkofsunshine/status/1702414953431359685
  Fun fact about Windows: if you type Ctrl-Shift-Alt-Win-L, LinkedIn will open.
  This is a hotkey that cannot be turned off-

bet...
*/

#include <tuple>
#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <TlHelp32.h>

std::tuple<HANDLE, BYTE*, DWORD> GetExplorer() {
    HANDLE snapproc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe32{ sizeof(pe32) };
    if (Process32FirstW(snapproc, &pe32)) {
        do {
            if (!_wcsicmp(L"explorer.exe", pe32.szExeFile)) {
                CloseHandle(snapproc);
                HANDLE snapmod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
                MODULEENTRY32W me32{ sizeof(me32) };
                Module32FirstW(snapmod, &me32);
                CloseHandle(snapmod);
                return { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID), me32.modBaseAddr, me32.modBaseSize };
            }
        } while (Process32NextW(snapproc, &pe32));
    }
    CloseHandle(snapproc);
    return { NULL, NULL, 0 };
}

void* mememem(const void *hay, size_t hay_size, const void *needle, size_t needle_size) {
    for (char* p = (char*)hay, *end = p + hay_size; p < end && (p = (char*)memchr(p, *(char*)needle, end - p)); p++)
        if (!memcmp(p, needle, needle_size))
            return (void *)p;
    return NULL;
}

int main() {
    const auto [process, base, size] = GetExplorer();

    auto buf = malloc(size);
    ReadProcessMemory(process, base, buf, size, NULL);

    const wchar_t target[] = L"https://go.microsoft.com/fwlink/?linkid=2044786";
    auto addr = mememem(buf, size, (const void*)target, sizeof(target));
    if (!addr) return puts("couldn't find linkedin link! have you patched it?"),1;
    addr = (char*)addr - (char*)buf + base;
    printf("addr = 0x%llx\n", (unsigned __int64)addr);

    DWORD old_protect;
    VirtualProtectEx(process, addr, sizeof(target), PAGE_READWRITE, &old_protect);
    wchar_t newurl[] = L"䔭䔱䔱䔵䔶䕿䕪䕪䔲䕫䔲䔬䔮䔬䕪䔂䔆䔇䕅";
    for (auto i = 0; i < sizeof(newurl); i++) ((char*)newurl)[i] ^= 69;
    WriteProcessMemory(process, addr, newurl, sizeof(newurl), NULL);
    VirtualProtectEx(process, addr, sizeof(target), PAGE_READONLY, &old_protect);
    
    puts("no more linkedin!");
    return getchar(),0;
}
