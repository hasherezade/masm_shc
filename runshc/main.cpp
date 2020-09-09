#include <windows.h>
#include <iostream>
#include "util.h"

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cout << "~ runshc ~\n"
            << "Run shellcode: loads and deploys shellcode file.\n";
#ifdef _WIN64
        std::cout << "For 64-bit shellcodes.\n";
#else
        std::cout << "For 32-bit shellcodes.\n";
#endif
        std::cout << "Args: <shellcode_file>" << std::endl;
        system("pause");
        return 0;
    }

    size_t exe_size = 0;
    char* in_path = argv[1];

    std::cout << "[*] Reading module from: " << in_path << std::endl;
    BYTE *my_exe = util::load_file(in_path, exe_size);
    if (!my_exe) {
        std::cout << "[-] Loading file failed" << std::endl;
        return -1;
    }
    BYTE *test_buf = util::alloc_aligned(exe_size, PAGE_EXECUTE_READWRITE);
    if (!test_buf) {
        util::free_file(my_exe);
        std::cout << "[-] Allocating buffer failed" << std::endl;
        return -2;
    }
    //copy file content into executable buffer:
    memcpy(test_buf, my_exe, exe_size);

    //free the original buffer:
    util::free_file(my_exe);
    my_exe = nullptr;

    std::cout << "[*] Running the shellcode:" << std::endl;
    //run it:
    int(*my_main)() = (int(*)()) ((ULONGLONG)test_buf);
    int ret_val = my_main();

    util::free_aligned(test_buf);
    std::cout << "[+] The shellcode finished with a return value: " << std::hex << ret_val << std::endl;
    return ret_val;
}
