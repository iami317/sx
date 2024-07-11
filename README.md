是一个用Go编写的端口扫描工具，快速可靠的方式枚举主机的有效端口, 这是一个非常简单的工具，可以对主机/主机列表进行快速SYN/CONNECT/UDP扫描，并列出所有返回回复的端口
基于[naabu](https://github.com/projectdiscovery/naabu)进行二开

## 特性
- 快速简单的基于SYN/CONNECT/UDP探头的扫描
- DNS端口扫描
- 用于DNS端口扫描的自动IP重复数据删除
- IPv4/IPv6端口扫描（实验性）
- 被动端口枚举使用ShodanInternetdb
- 主机发现扫描
- 扫描进度暴露
- 针对易用性和资源轻量级进行了优化

## 使用参考_example目录