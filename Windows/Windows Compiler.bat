chcp 65001
echo 需安装前置WinPcap
echo 即将编译Windows版本SYN工具
gcc -o syn_flood.exe syn_flood.c -lws2_32 -liphlpapi -O3 -Wall
echo 编译已完成
pause
