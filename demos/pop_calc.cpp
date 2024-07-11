#include <Windows.h>
#include "peb_lookup.h"

int main()
{
    LPVOID base = get_module_by_name((const LPWSTR)L"kernel32.dll");
    if (!base) {
        return 1;
    }
    auto _WinExec = reinterpret_cast<decltype(&WinExec)>(get_func_by_name((HMODULE)base, (LPSTR)"WinExec"));
    if (!_WinExec) return 4;

    _WinExec("calc.exe", SW_SHOWNORMAL);
    return 0;
}
