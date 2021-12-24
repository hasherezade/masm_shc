#include <Windows.h>
#include "peb_lookup.h"

int main()
{
    LPVOID base = get_module_by_name((const LPWSTR)L"kernel32.dll");
    if (!base) {
        return 1;
    }

    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)"LoadLibraryA");
    if (!load_lib) {
        return 2;
    }
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)"GetProcAddress");
    if (!get_proc) {
        return 3;
    }
    auto _LoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(load_lib);
    auto _GetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(get_proc);

    LPVOID u32_dll = _LoadLibraryA("user32.dll");

    auto _MessageBoxW = reinterpret_cast<decltype(&MessageBoxW)>(_GetProcAddress((HMODULE)u32_dll, "MessageBoxW"));
    if (!_MessageBoxW) return 4;

    _MessageBoxW(0, L"Hello World!", L"Demo!", MB_OK);

    return 0;
}
