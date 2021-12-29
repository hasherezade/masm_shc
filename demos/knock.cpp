/*
WARNING: the code section will be modified, and must be set writeable! 
Example:
ml64 knock.asm /link /entry:main /section:.text,ERW
*/

#include <Windows.h>
#include "peb_lookup.h"

#define LOCALHOST_ROT13 ">?D;=;=;>"

typedef struct
{
    decltype(&LoadLibraryA) _LoadLibraryA;
    decltype(&GetProcAddress) _GetProcAddress;
} t_mini_iat;

typedef struct
{
    decltype(&WSAStartup) _WSAStartup;
    decltype(&socket) _socket;
    decltype(&inet_addr) _inet_addr;
    decltype(&bind) _bind;
    decltype(&listen) _listen;
    decltype(&accept) _accept;
    decltype(&recv) _recv;
    decltype(&send) _send;
    decltype(&closesocket) _closesocket;
    decltype(&htons) _htons;
    decltype(&WSACleanup) _WSACleanup;
} t_socket_iat;


bool init_iat(t_mini_iat &iat)
{
    LPVOID base = get_module_by_name((const LPWSTR)L"kernel32.dll");
    if (!base) {
        return false;
    }

    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)"LoadLibraryA");
    if (!load_lib) {
        return false;
    }
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)"GetProcAddress");
    if (!get_proc) {
        return false;
    }

    iat._LoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(load_lib);
    iat._GetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(get_proc);
    return true;
}

bool init_socket_iat(t_mini_iat &iat, t_socket_iat &sIAT)
{
    LPVOID WS232_dll = iat._LoadLibraryA("WS2_32.dll");

    sIAT._WSAStartup = reinterpret_cast<decltype(&WSAStartup)>(iat._GetProcAddress((HMODULE)WS232_dll, "WSAStartup"));
    sIAT._socket = reinterpret_cast<decltype(&socket)>(iat._GetProcAddress((HMODULE)WS232_dll, "socket"));
    sIAT._inet_addr = reinterpret_cast<decltype(&inet_addr)>(iat._GetProcAddress((HMODULE)WS232_dll, "inet_addr"));
    sIAT._bind = reinterpret_cast<decltype(&bind)>(iat._GetProcAddress((HMODULE)WS232_dll, "bind"));
    sIAT._listen = reinterpret_cast<decltype(&listen)>(iat._GetProcAddress((HMODULE)WS232_dll, "listen"));
    sIAT._accept = reinterpret_cast<decltype(&accept)>(iat._GetProcAddress((HMODULE)WS232_dll, "accept"));
    sIAT._recv = reinterpret_cast<decltype(&recv)>(iat._GetProcAddress((HMODULE)WS232_dll, "recv"));
    sIAT._send = reinterpret_cast<decltype(&send)>(iat._GetProcAddress((HMODULE)WS232_dll, "send"));
    sIAT._closesocket = reinterpret_cast<decltype(&closesocket)>(iat._GetProcAddress((HMODULE)WS232_dll, "closesocket"));
    sIAT._htons = reinterpret_cast<decltype(&htons)>(iat._GetProcAddress((HMODULE)WS232_dll, "htons"));
    sIAT._WSACleanup = reinterpret_cast<decltype(&WSACleanup)>(iat._GetProcAddress((HMODULE)WS232_dll, "WSACleanup"));

    return true;
}

///---
bool switch_state(char *buf, char *resp)
{
    switch (resp[0]) {
    case 0:
        if (buf[0] != '9') break;
        resp[0] = 'Y';
        return true;
    case 'Y':
        if (buf[0] != '3') break;
        resp[0] = 'E';
        return true;
    case 'E':
        if (buf[0] != '5') break;
        resp[0] = 'S';
        return true;
    default:
        resp[0] = 0; break;
    }
    return false;
}

inline char* rot13(char *str, size_t str_size, bool decode)
{
    for (size_t i = 0; i < str_size; i++) {
        if (decode) {
            str[i] -= 13;
        }
        else {
            str[i] += 13;
        }
    }
    return str;
}

bool listen_for_connect(t_mini_iat &iat, int port, char resp[4])
{
    t_socket_iat sIAT;
    if (!init_socket_iat(iat, sIAT)) {
        return false;
    }
    const size_t buf_size = 4;
    char buf[buf_size];

    LPVOID u32_dll = iat._LoadLibraryA("user32.dll");


    auto _MessageBoxW = reinterpret_cast<decltype(&MessageBoxW)>(iat._GetProcAddress((HMODULE)u32_dll, "MessageBoxW"));

    bool got_resp = false;
    WSADATA wsaData;
    SecureZeroMemory(&wsaData, sizeof(wsaData));
    /// code:
    if (sIAT._WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    struct sockaddr_in sock_config;
    SecureZeroMemory(&sock_config, sizeof(sock_config));
    SOCKET listen_socket = sIAT._socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket == INVALID_SOCKET) {
        _MessageBoxW(NULL, L"Creating the socket failed", L"Stage 2", MB_ICONEXCLAMATION);
        sIAT._WSACleanup();
        return false;
    }
    char *host_str = rot13(LOCALHOST_ROT13, _countof(LOCALHOST_ROT13) - 1, true);
    sock_config.sin_addr.s_addr = sIAT._inet_addr(host_str);
    sock_config.sin_family = AF_INET;
    sock_config.sin_port = sIAT._htons(port);

    rot13(host_str, _countof(LOCALHOST_ROT13) - 1, false); //encode it back

    bool is_ok = true;
    if (sIAT._bind(listen_socket, (SOCKADDR*)&sock_config, sizeof(sock_config)) == SOCKET_ERROR) {
        is_ok = false;
        _MessageBoxW(NULL, L"Binding the socket failed", L"Stage 2", MB_ICONEXCLAMATION);

    }
    if (sIAT._listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        is_ok = false;
        _MessageBoxW(NULL, L"Listening the socket failed", L"Stage 2", MB_ICONEXCLAMATION);
    }

    SOCKET conn_sock = SOCKET_ERROR;
    while (is_ok && (conn_sock = sIAT._accept(listen_socket, 0, 0)) != SOCKET_ERROR) {
        if (sIAT._recv(conn_sock, buf, buf_size, 0) > 0) {
            got_resp = true;
            if (switch_state(buf, resp)) {
                sIAT._send(conn_sock, resp, buf_size, 0);
                sIAT._closesocket(conn_sock);
                break;
            }
        }
        sIAT._closesocket(conn_sock);
    }

    sIAT._closesocket(listen_socket);
    sIAT._WSACleanup();
    return got_resp;
}

int main()
{
    t_mini_iat iat;
    if (!init_iat(iat)) {
        return 1;
    }
    char resp[4];
    SecureZeroMemory(resp, sizeof(resp));
    listen_for_connect(iat, 1337, resp);
    listen_for_connect(iat, 1338, resp);
    listen_for_connect(iat, 1339, resp);
    return 0;
}
