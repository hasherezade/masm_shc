#include <Windows.h>
#include "peb_lookup.h"

#define LOCALHOST_ROT13 ">?D;=;=;>"

typedef struct
{
    HMODULE(WINAPI * _LoadLibraryA)(LPCSTR lpLibFileName);
    FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
} t_mini_iat;

typedef struct
{
    int (PASCAL FAR *_WSAStartup)(
        _In_ WORD wVersionRequired,
        _Out_ LPWSADATA lpWSAData);

    SOCKET(PASCAL FAR *_socket)(
        _In_ int af,
        _In_ int type,
        _In_ int protocol);

    unsigned long (PASCAL FAR *_inet_addr)(_In_z_ const char FAR * cp);

    int (PASCAL FAR *_bind)(
        _In_ SOCKET s,
        _In_reads_bytes_(namelen) const struct sockaddr FAR *addr,
        _In_ int namelen);

    int (PASCAL FAR *_listen)(
        _In_ SOCKET s,
        _In_ int backlog);

    SOCKET(PASCAL FAR *_accept)(
        _In_ SOCKET s,
        _Out_writes_bytes_opt_(*addrlen) struct sockaddr FAR *addr,
        _Inout_opt_ int FAR *addrlen);

    int (PASCAL FAR *_recv)(
        _In_ SOCKET s,
        _Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR * buf,
        _In_ int len,
        _In_ int flags);

    int (PASCAL FAR *_send)(
        _In_ SOCKET s,
        _In_reads_bytes_(len) const char FAR * buf,
        _In_ int len,
        _In_ int flags);

    int (PASCAL FAR *_closesocket)(IN SOCKET s);

    u_short(PASCAL FAR *_htons)(_In_ u_short hostshort);

    int (PASCAL FAR *_WSACleanup)(void);

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

    iat._LoadLibraryA = (HMODULE(WINAPI*)(LPCSTR)) load_lib;
    iat._GetProcAddress = (FARPROC(WINAPI*)(HMODULE, LPCSTR)) get_proc;
    return true;
}

bool init_socket_iat(t_mini_iat &iat, t_socket_iat &sIAT)
{
    LPVOID WS232_dll = iat._LoadLibraryA("WS2_32.dll");

    sIAT._WSAStartup = (int (PASCAL FAR *)(
        _In_ WORD,
        _Out_ LPWSADATA)) iat._GetProcAddress((HMODULE)WS232_dll, "WSAStartup");

    sIAT._socket = (SOCKET(PASCAL FAR *)(
        _In_ int af,
        _In_ int type,
        _In_ int protocol)) iat._GetProcAddress((HMODULE)WS232_dll, "socket");

    sIAT._inet_addr
        = (unsigned long (PASCAL FAR *)(_In_z_ const char FAR * cp))
        iat._GetProcAddress((HMODULE)WS232_dll, "inet_addr");

    sIAT._bind = (int (PASCAL FAR *)(
        _In_ SOCKET s,
        _In_reads_bytes_(namelen) const struct sockaddr FAR *addr,
        _In_ int namelen)) iat._GetProcAddress((HMODULE)WS232_dll, "bind");

    sIAT._listen = (int (PASCAL FAR *)(
        _In_ SOCKET s,
        _In_ int backlog)) iat._GetProcAddress((HMODULE)WS232_dll, "listen");

    sIAT._accept = (SOCKET(PASCAL FAR *)(
        _In_ SOCKET s,
        _Out_writes_bytes_opt_(*addrlen) struct sockaddr FAR *addr,
        _Inout_opt_ int FAR *addrlen)) iat._GetProcAddress((HMODULE)WS232_dll, "accept"); ;

    sIAT._recv = (int (PASCAL FAR *)(
        _In_ SOCKET s,
        _Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR * buf,
        _In_ int len,
        _In_ int flags)) iat._GetProcAddress((HMODULE)WS232_dll, "recv"); ;

    sIAT._send = (int (PASCAL FAR *)(
        _In_ SOCKET s,
        _In_reads_bytes_(len) const char FAR * buf,
        _In_ int len,
        _In_ int flags)) iat._GetProcAddress((HMODULE)WS232_dll, "send");

    sIAT._closesocket
        = (int (PASCAL FAR *)(IN SOCKET s)) iat._GetProcAddress((HMODULE)WS232_dll, "closesocket");

    sIAT._htons
        = (u_short(PASCAL FAR *)(_In_ u_short hostshort)) iat._GetProcAddress((HMODULE)WS232_dll, "htons");

    sIAT._WSACleanup
        = (int (PASCAL FAR *)(void)) iat._GetProcAddress((HMODULE)WS232_dll, "WSACleanup");

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


    int (WINAPI * _MessageBoxW)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCWSTR lpText,
        _In_opt_ LPCWSTR lpCaption,
        _In_ UINT uType) = (int (WINAPI*)(
            _In_opt_ HWND,
            _In_opt_ LPCWSTR,
            _In_opt_ LPCWSTR,
            _In_ UINT)) iat._GetProcAddress((HMODULE)u32_dll, "MessageBoxW");

    bool got_resp = false;
    WSADATA wsaData;
    SecureZeroMemory(&wsaData, sizeof(wsaData));
    /// code:
    if (sIAT._WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    struct sockaddr_in sock_config;
    SecureZeroMemory(&sock_config, sizeof(sock_config));
    SOCKET listen_socket = 0;
    if ((listen_socket = sIAT._socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
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
