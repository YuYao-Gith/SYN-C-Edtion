# SYN-C-Edtion

一个由 C 语言编写的 SYN 洪水攻击工具（教学版），支持 Windows 与类 Unix（Linux/macOS）双平台。

> **⚠️ 重要声明**
>
> 本项目**仅用于教学用途**，用于学习 TCP 协议、原始套接字（Raw Socket）编程以及网络安全原理。
> 本项目**不可用于任何恶意用途**，严禁用于任何未经授权的攻击行为。
>
> **使用者需对自身行为承担全部法律责任。** 请仅在**自有设备**或**获得明确书面授权的系统**上进行测试，并在测试前通知相关网络管理员。任何未经授权使用本工具的行为都可能构成违法行为。

## 项目简介

SYN 洪水（SYN Flood）是一种经典的拒绝服务（DoS）攻击方式，其原理是利用 TCP 三次握手协议的设计缺陷：

1. 攻击者向目标发送大量伪造源地址的 SYN 包；
2. 目标服务器响应 SYN-ACK 并为其分配半开连接（Half-Open Connection）资源；
3. 由于源地址是伪造的，服务器永远等不到最终的 ACK，连接队列被迅速耗尽，导致合法用户无法建立连接。

本项目通过原始套接字（Raw Socket）手工构造 IP/TCP 报文头，以多线程方式向目标全端口（1–65535）发送 SYN 数据包，用于教学演示这一攻击原理。

## 功能特性

- **手工构造报文**：自行构造 IP 头与 TCP 头，不依赖系统协议栈
- **全端口遍历**：默认遍历目标全部 65535 个端口
- **多线程发送**：8 个线程并发发送数据包，提高发送速率
- **实时统计**：实时显示已发送数据包数、攻击持续时间与平均发送速率（包/秒）
- **双平台支持**：Windows（Winsock）与类 Unix（POSIX Socket）双版本
- **内置法律声明**：程序启动时显示法律声明，提醒使用者仅限授权测试

## 目录结构

```
SYN-C-Edtion/
├── README.md                    # 项目说明
├── Windows/
│   ├── syn.c                    # Windows 版源码（Winsock + 原始套接字）
│   └── Windows Compiler.bat     # Windows 编译脚本
└── 类Unix/
    ├── syn.c                    # 类 Unix 版源码（POSIX Socket）
    └── Unix C.sh                # 类 Unix 编译脚本
```

## 环境要求

### Windows

- Windows 10/11 或 Windows Server
- MinGW-w64（提供 `gcc`）或 MSVC
- 需要以**管理员身份**运行（创建原始套接字需要管理员权限）
- 可选：WinPcap/Npcap（部分环境用于原始套接字支持）

### 类 Unix（Linux/macOS）

- Linux 或 macOS
- `gcc` 及 `pthread` 库
- 需要 **root 权限**运行（创建原始套接字需要特权）

## 编译与运行

### Windows

双击运行 `Windows/Windows Compiler.bat`，或手动执行：

```bat
gcc -o syn_flood.exe syn.c -lws2_32 -liphlpapi -O3 -Wall
```

然后**以管理员身份**运行 `syn_flood.exe`：

```bat
syn_flood.exe
```

### 类 Unix（Linux/macOS）

```bash
cd 类Unix
gcc -o syn_flood syn.c -O3 -Wall -pthread
```

以 root 权限运行：

```bash
sudo ./syn_flood
```

### 使用步骤

1. 启动程序后，程序会显示法律声明；
2. 输入目标 IP 地址（仅限自有设备或已获授权的系统）；
3. 程序自动确定本地 IP 并创建原始套接字；
4. 攻击开始后：
   - **Windows**：按任意键停止攻击
   - **类 Unix**：按 `Ctrl+C` 停止攻击
5. 停止后显示统计信息（总时间、发送包数、平均速率）。

## 注意事项

- 本工具构造的报文使用**随机源端口**与随机序列号，以模拟真实攻击场景；
- 目标 IP 必须填写合法格式（`XXX.XXX.XXX.XXX`），否则程序会提示重新输入；
- 若无法创建原始套接字，请确认已以管理员/root 身份运行；
- 攻击仅在按下停止键前持续，停止后线程会安全退出并释放资源。

## 免责声明

- 本项目**仅用于教学与安全研究**，展示 SYN Flood 攻击原理与防御思路；
- 作者与贡献者**不对**任何因使用本项目而产生的直接或间接损失负责；
- 使用者必须遵守所在地法律法规，**仅限测试自有服务器或获得明确授权的系统**；
- 禁止将本项目用于任何非法攻击活动。

## 许可证

本项目采用 **GNU Affero General Public License v3.0（AGPL-3.0）** 许可。

AGPL-3.0 是 GPL 协议的强化版本：不仅要求修改与分发衍生作品时开源，还要求**通过网络提供服务**的衍生作品同样向用户开放源代码。

详见 [GNU AGPL v3.0 官方全文](https://www.gnu.org/licenses/agpl-3.0.html)。
