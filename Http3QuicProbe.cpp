/*
 * Http3QuicProbe - Detecteur de support HTTP/3 et QUIC
 * Auteur: Ayi NEDJIMI
 * Description: Teste le support HTTP/3 sur des hosts distants,
 *              verifie ALPN et effectue des probes QUIC sur UDP 443
 * Version: 1.0
 * Date: 2025-10-20
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <fstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

// Constantes
#define WM_PROBE_COMPLETE (WM_USER + 1)
#define ID_LISTVIEW 1001
#define ID_EDIT_URL 1002
#define ID_BTN_PROBE 1003
#define ID_BTN_EXPORT 1004
#define ID_BTN_CLEAR 1005
#define ID_STATUS 1006
#define ID_LABEL_URL 1007

// Structure pour un resultat de probe
struct ProbeResult {
    std::wstring url;
    std::wstring http3Support;
    std::wstring alpnProtocol;
    std::wstring notes;
};

// Variables globales
HWND g_hMainWindow = nullptr;
HWND g_hListView = nullptr;
HWND g_hEditUrl = nullptr;
HWND g_hStatus = nullptr;
std::vector<ProbeResult> g_results;
std::mutex g_resultMutex;
bool g_probing = false;

// Classe RAII pour handles
template<typename T>
class AutoHandle {
private:
    T handle;
public:
    AutoHandle(T h = nullptr) : handle(h) {}
    ~AutoHandle() {
        if (handle) {
            if constexpr (std::is_same_v<T, HINTERNET>) {
                WinHttpCloseHandle(handle);
            } else if constexpr (std::is_same_v<T, HANDLE>) {
                CloseHandle(handle);
            } else if constexpr (std::is_same_v<T, SOCKET>) {
                if (handle != INVALID_SOCKET) closesocket(handle);
            }
        }
    }
    operator T() const { return handle; }
    T* operator&() { return &handle; }
    T get() const { return handle; }
    void reset(T h = nullptr) {
        if (handle && handle != h) {
            if constexpr (std::is_same_v<T, HINTERNET>) {
                WinHttpCloseHandle(handle);
            } else if constexpr (std::is_same_v<T, HANDLE>) {
                CloseHandle(handle);
            } else if constexpr (std::is_same_v<T, SOCKET>) {
                if (handle != INVALID_SOCKET) closesocket(handle);
            }
        }
        handle = h;
    }
};

// Fonction de logging
void LogMessage(const std::wstring& message) {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring logFile = std::wstring(tempPath) + L"WinTools_Http3QuicProbe_log.txt";

    std::wofstream log(logFile, std::ios::app);
    if (log.is_open()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        log << std::setfill(L'0')
            << std::setw(4) << st.wYear << L"-"
            << std::setw(2) << st.wMonth << L"-"
            << std::setw(2) << st.wDay << L" "
            << std::setw(2) << st.wHour << L":"
            << std::setw(2) << st.wMinute << L":"
            << std::setw(2) << st.wSecond << L" - "
            << message << std::endl;
        log.close();
    }
}

// Extraire hostname et port d'une URL
bool ParseUrl(const std::wstring& url, std::wstring& hostname, std::wstring& path, INTERNET_PORT& port) {
    URL_COMPONENTSW urlComp = { 0 };
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t hostnameBuf[256];
    wchar_t pathBuf[1024];

    urlComp.lpszHostName = hostnameBuf;
    urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = pathBuf;
    urlComp.dwUrlPathLength = 1024;

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp)) {
        return false;
    }

    hostname = hostnameBuf;
    path = pathBuf;
    port = urlComp.nPort;

    return true;
}

// Tester QUIC via UDP probe
bool ProbeQuic(const std::wstring& hostname) {
    LogMessage(L"Probe QUIC UDP pour: " + hostname);

    // Convertir hostname en char*
    int hostnameLen = WideCharToMultiByte(CP_UTF8, 0, hostname.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::vector<char> hostnameUtf8(hostnameLen);
    WideCharToMultiByte(CP_UTF8, 0, hostname.c_str(), -1, hostnameUtf8.data(), hostnameLen, nullptr, nullptr);

    // Resoudre l'adresse
    struct addrinfo hints = { 0 };
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    struct addrinfo* result = nullptr;
    if (getaddrinfo(hostnameUtf8.data(), "443", &hints, &result) != 0) {
        LogMessage(L"Echec resolution DNS pour QUIC probe");
        return false;
    }

    // Creer socket UDP
    AutoHandle<SOCKET> sock = socket(result->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock.get() == INVALID_SOCKET) {
        freeaddrinfo(result);
        return false;
    }

    // Timeout de 2 secondes
    DWORD timeout = 2000;
    setsockopt(sock.get(), SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    // Packet QUIC Initial minimal (version negotiation)
    // Format: Header (1 byte) | Version (4 bytes) | DCID Len (1) | SCID Len (1)
    unsigned char quicPacket[] = {
        0xC0,                           // Header: Long header, Initial packet
        0x00, 0x00, 0x00, 0x01,        // Version (QUIC v1)
        0x00,                           // DCID Length (0)
        0x08,                           // SCID Length (8)
        0x01, 0x02, 0x03, 0x04,        // SCID (random)
        0x05, 0x06, 0x07, 0x08
    };

    // Envoyer le packet
    int sent = sendto(sock.get(), (char*)quicPacket, sizeof(quicPacket), 0,
                      result->ai_addr, (int)result->ai_addrlen);

    if (sent == SOCKET_ERROR) {
        freeaddrinfo(result);
        return false;
    }

    // Attendre une reponse
    char buffer[1500];
    int received = recvfrom(sock.get(), buffer, sizeof(buffer), 0, nullptr, nullptr);

    freeaddrinfo(result);

    if (received > 0) {
        LogMessage(L"Reponse QUIC recue");
        return true;
    }

    return false;
}

// Tester HTTP/3 via WinHTTP
ProbeResult ProbeHttp3(const std::wstring& url) {
    ProbeResult result;
    result.url = url;
    result.http3Support = L"Non";
    result.alpnProtocol = L"N/A";
    result.notes = L"";

    LogMessage(L"Probe HTTP/3 pour: " + url);

    std::wstring hostname, path;
    INTERNET_PORT port;

    if (!ParseUrl(url, hostname, path, port)) {
        result.notes = L"URL invalide";
        return result;
    }

    // Initialiser WinHTTP
    AutoHandle<HINTERNET> hSession = WinHttpOpen(
        L"Http3QuicProbe/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession.get()) {
        result.notes = L"Echec WinHttpOpen";
        return result;
    }

    // Essayer d'activer HTTP/3 (Windows 11+ avec support HTTP/3)
    DWORD http3Enabled = WINHTTP_PROTOCOL_FLAG_HTTP3;
    WinHttpSetOption(hSession.get(), WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL,
                     &http3Enabled, sizeof(http3Enabled));

    // Connecter
    AutoHandle<HINTERNET> hConnect = WinHttpConnect(
        hSession.get(),
        hostname.c_str(),
        port,
        0
    );

    if (!hConnect.get()) {
        result.notes = L"Echec WinHttpConnect";
        return result;
    }

    // Creer requete
    DWORD flags = WINHTTP_FLAG_SECURE;
    AutoHandle<HINTERNET> hRequest = WinHttpOpenRequest(
        hConnect.get(),
        L"HEAD",
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags
    );

    if (!hRequest.get()) {
        result.notes = L"Echec WinHttpOpenRequest";
        return result;
    }

    // Envoyer requete
    if (!WinHttpSendRequest(hRequest.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        result.notes = L"Echec WinHttpSendRequest";

        // Essayer probe QUIC
        if (ProbeQuic(hostname)) {
            result.http3Support = L"Probable (QUIC repond)";
            result.notes = L"Pas de HTTP/3 via WinHTTP, mais QUIC repond sur UDP 443";
        }

        return result;
    }

    // Recevoir reponse
    if (!WinHttpReceiveResponse(hRequest.get(), nullptr)) {
        result.notes = L"Echec WinHttpReceiveResponse";
        return result;
    }

    // Verifier le protocole utilise
    DWORD protocolUsed = 0;
    DWORD protocolSize = sizeof(protocolUsed);

    if (WinHttpQueryOption(hRequest.get(), WINHTTP_OPTION_HTTP_PROTOCOL_USED,
                          &protocolUsed, &protocolSize)) {

        if (protocolUsed & WINHTTP_PROTOCOL_FLAG_HTTP3) {
            result.http3Support = L"Oui";
            result.alpnProtocol = L"h3";
            result.notes = L"HTTP/3 disponible et utilise";
        } else if (protocolUsed & WINHTTP_PROTOCOL_FLAG_HTTP2) {
            result.http3Support = L"Non";
            result.alpnProtocol = L"h2";
            result.notes = L"HTTP/2 utilise, HTTP/3 non disponible";

            // Essayer probe QUIC quand meme
            if (ProbeQuic(hostname)) {
                result.notes += L" (mais QUIC repond)";
            }
        } else {
            result.http3Support = L"Non";
            result.alpnProtocol = L"http/1.1";
            result.notes = L"HTTP/1.1 utilise";
        }
    } else {
        result.notes = L"Impossible de determiner le protocole";
    }

    return result;
}

// Thread de probe
void ProbeThread(const std::wstring& url) {
    g_probing = true;

    SendMessageW(g_hStatus, SB_SETTEXTW, 0, (LPARAM)L"Probe en cours...");
    LogMessage(L"Debut du probe: " + url);

    ProbeResult result = ProbeHttp3(url);

    {
        std::lock_guard<std::mutex> lock(g_resultMutex);
        g_results.push_back(result);
    }

    LogMessage(L"Probe termine");
    PostMessageW(g_hMainWindow, WM_PROBE_COMPLETE, 0, 0);
    g_probing = false;
}

// Mettre a jour le ListView
void UpdateListView() {
    ListView_DeleteAllItems(g_hListView);

    std::lock_guard<std::mutex> lock(g_resultMutex);

    for (size_t i = 0; i < g_results.size(); i++) {
        const auto& res = g_results[i];

        LVITEMW lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = static_cast<int>(i);

        // URL
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(res.url.c_str());
        ListView_InsertItem(g_hListView, &lvi);

        // HTTP3 Support
        lvi.iSubItem = 1;
        lvi.pszText = const_cast<LPWSTR>(res.http3Support.c_str());
        ListView_SetItem(g_hListView, &lvi);

        // ALPN Protocol
        lvi.iSubItem = 2;
        lvi.pszText = const_cast<LPWSTR>(res.alpnProtocol.c_str());
        ListView_SetItem(g_hListView, &lvi);

        // Notes
        lvi.iSubItem = 3;
        lvi.pszText = const_cast<LPWSTR>(res.notes.c_str());
        ListView_SetItem(g_hListView, &lvi);
    }

    SendMessageW(g_hStatus, SB_SETTEXTW, 0, (LPARAM)L"Probe termine");
}

// Exporter en CSV
void ExportToCSV() {
    wchar_t fileName[MAX_PATH] = L"";
    OPENFILENAMEW ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWindow;
    ofn.lpstrFilter = L"Fichiers CSV (*.csv)\0*.csv\0Tous les fichiers (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"csv";
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (!GetSaveFileNameW(&ofn)) {
        return;
    }

    std::wofstream csv(fileName, std::ios::binary);
    if (!csv.is_open()) {
        MessageBoxW(g_hMainWindow, L"Impossible de creer le fichier CSV", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    // BOM UTF-8
    const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
    csv.write(reinterpret_cast<const wchar_t*>(bom), sizeof(bom));

    // En-tetes
    csv << L"URL;HTTP3Support;ALPNProtocol;Notes\n";

    std::lock_guard<std::mutex> lock(g_resultMutex);
    for (const auto& res : g_results) {
        csv << res.url << L";"
            << res.http3Support << L";"
            << res.alpnProtocol << L";"
            << res.notes << L"\n";
    }

    csv.close();
    LogMessage(std::wstring(L"Export CSV: ") + fileName);
    MessageBoxW(g_hMainWindow, L"Export CSV termine avec succes", L"Information", MB_OK | MB_ICONINFORMATION);
}

// Creer le ListView
void CreateListViewControl(HWND hwnd) {
    g_hListView = CreateWindowExW(
        0,
        WC_LISTVIEWW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
        10, 60, 960, 450,
        hwnd,
        (HMENU)ID_LISTVIEW,
        GetModuleHandle(nullptr),
        nullptr
    );

    ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    // Colonnes
    LVCOLUMNW lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;

    lvc.pszText = const_cast<LPWSTR>(L"URL");
    lvc.cx = 350;
    ListView_InsertColumn(g_hListView, 0, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"HTTP/3 Support");
    lvc.cx = 150;
    ListView_InsertColumn(g_hListView, 1, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"ALPN Protocol");
    lvc.cx = 120;
    ListView_InsertColumn(g_hListView, 2, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Notes");
    lvc.cx = 340;
    ListView_InsertColumn(g_hListView, 3, &lvc);
}

// Procedure de fenetre
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
        CreateWindowExW(0, L"STATIC", L"URL a tester:",
                       WS_CHILD | WS_VISIBLE,
                       10, 15, 100, 20, hwnd, (HMENU)ID_LABEL_URL,
                       GetModuleHandle(nullptr), nullptr);

        g_hEditUrl = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"https://www.cloudflare.com",
                                    WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                    110, 12, 550, 25, hwnd, (HMENU)ID_EDIT_URL,
                                    GetModuleHandle(nullptr), nullptr);

        CreateWindowExW(0, L"BUTTON", L"Tester",
                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                       670, 12, 80, 25, hwnd, (HMENU)ID_BTN_PROBE,
                       GetModuleHandle(nullptr), nullptr);

        CreateListViewControl(hwnd);

        CreateWindowExW(0, L"BUTTON", L"Exporter CSV",
                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                       10, 520, 120, 30, hwnd, (HMENU)ID_BTN_EXPORT,
                       GetModuleHandle(nullptr), nullptr);

        CreateWindowExW(0, L"BUTTON", L"Effacer",
                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                       140, 520, 100, 30, hwnd, (HMENU)ID_BTN_CLEAR,
                       GetModuleHandle(nullptr), nullptr);

        g_hStatus = CreateWindowExW(0, STATUSCLASSNAMEW, L"Pret - Entrez une URL HTTPS",
                                   WS_CHILD | WS_VISIBLE,
                                   0, 0, 0, 0, hwnd, (HMENU)ID_STATUS,
                                   GetModuleHandle(nullptr), nullptr);
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_BTN_PROBE:
            if (!g_probing) {
                wchar_t url[1024];
                GetWindowTextW(g_hEditUrl, url, 1024);

                if (wcslen(url) > 0) {
                    std::thread(ProbeThread, std::wstring(url)).detach();
                } else {
                    MessageBoxW(hwnd, L"Veuillez entrer une URL", L"Erreur", MB_OK | MB_ICONWARNING);
                }
            }
            break;
        case ID_BTN_EXPORT:
            ExportToCSV();
            break;
        case ID_BTN_CLEAR:
            ListView_DeleteAllItems(g_hListView);
            {
                std::lock_guard<std::mutex> lock(g_resultMutex);
                g_results.clear();
            }
            SendMessageW(g_hStatus, SB_SETTEXTW, 0, (LPARAM)L"Liste effacee");
            break;
        }
        break;

    case WM_PROBE_COMPLETE:
        UpdateListView();
        break;

    case WM_SIZE:
        SendMessageW(g_hStatus, WM_SIZE, 0, 0);
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

// Point d'entree
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    // Initialiser WinSock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        MessageBoxW(nullptr, L"Echec WSAStartup", L"Erreur", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Initialiser Common Controls
    INITCOMMONCONTROLSEX icc = { 0 };
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    LogMessage(L"Demarrage de Http3QuicProbe");

    // Enregistrer la classe de fenetre
    WNDCLASSEXW wc = { 0 };
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"Http3QuicProbeClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);

    RegisterClassExW(&wc);

    // Creer la fenetre
    g_hMainWindow = CreateWindowExW(
        0,
        L"Http3QuicProbeClass",
        L"Http3QuicProbe - Detecteur de support HTTP/3 et QUIC",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1000, 630,
        nullptr, nullptr, hInstance, nullptr
    );

    ShowWindow(g_hMainWindow, nCmdShow);
    UpdateWindow(g_hMainWindow);

    // Boucle de messages
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    WSACleanup();
    LogMessage(L"Fermeture de Http3QuicProbe");
    return static_cast<int>(msg.wParam);
}
