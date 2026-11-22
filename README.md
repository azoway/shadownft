在 Linux 服务器上安装 [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)，并用 nftables 做敲门加白。

端口 B 跑 Shadowsocks。敲门端口不监听任何程序，只记录谁发过包。默认不查 ip-api，发包的 IPv4 直接写入本机白名单。`IP_API=yes` 时才查 ip-api，并且只有重庆或 `mobile` 为 true 才加白。白名单最多留最新 100 条。

访问 SSH、80、443 这些默认放行端口，或者访问敲门端口、Shadowsocks 端口，不会被拉黑。先连 Shadowsocks 端口再去敲门，仍然可以加白。访问了这三类以外的 TCP 或 UDP 端口，会立刻移出白名单并进入黑名单，默认 24 小时内再敲门也不会加白。重复访问会重新计算这 24 小时。内网地址和已经建立的连接不触发拉黑。

在客户端配置SS时, 需要配置2个, 建议同时配置fallbacks：

加白专用: ss://MjAyZrTS9uQT09@1.2.3.4:探测端口A (此链接用于触发加白，节点用不可用）
真实链接: ss://MjAyZrTS9uQT09@1.2.3.4:真实端口B


## 服务器要求

- Linux，x86_64 或 aarch64
- systemd
- root
- apt 或 dnf
- 能访问 GitHub，以及 `http://ip-api.com`
- 云厂商安全组放行 SSH、80、443，再放行敲门端口和 Shadowsocks 端口的 TCP、UDP

## 部署

在服务器上执行：

```bash
curl -fsSL https://raw.githubusercontent.com/azoway/shadownft/main/install.sh | bash
```

要在安装时关掉 ufw、firewalld 和系统自带的 nftables 服务，执行：

```bash
curl -fsSL https://raw.githubusercontent.com/azoway/shadownft/main/install.sh | confirm=yes bash
```

没有加 `confirm=yes` 时，如果发现这些防火墙，脚本会在终端问一句。输入 `y` 才清理，直接回车就保留。重复执行不会删掉已经写入的白名单，也不会重抽已有的端口和密码。

安装过程会：

1. 安装 `nftables`、`python3`、`curl`、`xz`
2. 从 shadowsocks-rust 的 GitHub release 下载 `ssserver`，并核对 sha256
3. 没有指定密码时，用 `ssservice genkey` 生成密钥
4. 没有指定端口时，Shadowsocks 端口和敲门端口都在 10000–20000 之间随机。敲门端口默认 1 个
5. 写入 nftables 表 `inet shadownft`，并启动 `shadowsocks-rust`、`shadownft` 两个服务

装完后的连接信息在终端里，也写在 `/etc/shadownft/client.txt`，权限 600：

```bash
sudo cat /etc/shadownft/client.txt
```

内容是公网地址、加密方法、密码、Shadowsocks 端口、敲门端口，以及一条 `ss://` 链接。

客户端先向任一敲门端口发一个包，再连 Shadowsocks 端口。敲门端口没有服务，TCP 超时或被拒绝是正常的。

```bash
nc -vz -w 3 服务器地址 端口A
```

UDP 也可以：

```bash
nc -uzv -w 3 服务器地址 端口A
```

等一两秒，再让 Shadowsocks 客户端连端口 B。可以看白名单和日志：

```bash
sudo nft list set inet shadownft whitelist
sudo journalctl -u shadownft -n 50 --no-pager
```

默认 `IP_API=no`。要按归属地筛选时：

```bash
curl -fsSL https://raw.githubusercontent.com/azoway/shadownft/main/install.sh | IP_API=yes bash
```

ip-api 在中文结果里把重庆标成 region `CQ`、地区名「重庆市」。比较前会去掉末尾的「市」或「省」，所以 `CQ` 和「重庆」都能对上。`mobile` 为 true 的地址即使不在重庆也会加白。免费接口走 HTTP，每分钟 45 次，并且声明不用于商用。查询失败或对不上时不加白。要换成带密钥的 HTTPS，把 `IP_API_URL` 设成仍然包含 `{ip}` 的地址。

2022 加密要求服务器和客户端的时钟差在 30 秒以内。安装时如果时钟还没同步，会尝试打开 `systemd-timesyncd`。

默认加密是 `2022-blake3-aes-128-gcm`。密码是 16 字节密钥的 Base64，不是任意字符串。

## 变量

变量写在 `bash` 前面。`/etc/shadownft/config.env` 里已有的值会保留；这次命令里显式传入的同名变量覆盖它们。

```bash
curl -fsSL https://raw.githubusercontent.com/azoway/shadownft/main/install.sh | SS_PORT=18000 PUBLIC_IP=203.0.113.10 bash
```

| 变量 | 默认 | 作用 |
|---|---|---|
| `SS_METHOD` | `2022-blake3-aes-128-gcm` | 加密方法 |
| `SS_PASSWORD` | 空则生成 | 设为 `generate` 时重新生成 |
| `SS_PORT` | 10000–20000 间随机 | Shadowsocks 端口 |
| `KNOCK_COUNT` | `1` | 敲门端口个数，在 10000–20000 间随机 |
| `KNOCK_PORTS` | 空则按个数随机 | 逗号分隔。已有旧的 `PORT_A` 时继续用它。设为 `generate` 会按个数重抽 |
| `PORT_MIN` / `PORT_MAX` | `10000` / `20000` | 随机端口的范围 |
| `SS_BIND` | `0.0.0.0` | Shadowsocks 监听地址 |
| `SS_MODE` | `tcp_and_udp` | 也可设 `tcp_only` 或 `udp_only` |
| `SS_VERSION` | 空则装当前最新 release，并记入配置 | `latest` 强制重新取最新版 |
| `SSH_PORT` | 读 `sshd -T`，否则 `22` | 用来避开端口 A、B，并作为默认额外放行端口之一 |
| `ALLOW_PORTS` | SSH 端口、`80`、`443` | 这些端口的 TCP 和 UDP 对所有来源放行。访问清单以外、且不是敲门或 Shadowsocks 的端口，会拉黑 |
| `PUBLIC_IP` | 向 ip-api 查询 | 写进连接信息 |
| `INTRANET_V4` | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8` | 直接放行的 IPv4 |
| `INTRANET_V6` | `::1,fc00::/7,fe80::/10` | 直接放行的 IPv6 |
| `IP_API` | `no` | `yes` 时敲门后才查 ip-api |
| `ALLOW_REGIONS` | `CQ,重庆` | 只在 `IP_API=yes` 时使用 |
| `ALLOW_MOBILE` | `true` | 只在 `IP_API=yes` 时，`mobile` 为 true 也加白 |
| `BLACKLIST_TIMEOUT` | `86400` | 黑名单秒数，默认 24 小时 |
| `WHITELIST_MAX` | `100` | 只保留最新的这些 /32 |
| `WHITELIST_SCOPE` | `dport_b` | 目前只支持这个值：白名单只能访问端口 B |
| `IP_API_URL` | `http://ip-api.com/json/{ip}?...&lang={lang}` | 必须包含 `{ip}` |
| `IP_API_LANG` | `zh-CN` | 替换 URL 里的 `{lang}` |
| `IP_API_RATE` | `40` | 每分钟最多查询这么多次 |
| `KNOCK_COOLDOWN` | `600` | 不匹配的地址多少秒内不再查询 |
| `NEGATIVE_TTL` | `600` | 查询失败后的冷却秒数 |
| `QUEUE_MAX` | `50` | 排队中的敲门上限，满了就丢掉新的 |
| `confirm` | 空 | 设为 `yes` 时关闭 ufw、firewalld，并停用系统 `nftables` 服务。不设时如果发现这些防火墙，会询问；输入 `y` 才清理 |

服务器上如果 ufw 或 firewalld 正在运行，或者系统 `nftables` 服务已启用，安装仍会继续。默认不清理它们。要清理时：

```bash
curl -fsSL https://raw.githubusercontent.com/azoway/shadownft/main/install.sh | confirm=yes bash
```

`REPLACE_FIREWALL=1` 同样表示清理。清理后如果还剩别的 input drop 链，脚本会打印链名并继续加载自己的规则，不会自动把 ufw 打开。

命令行里传入的密码会出现在 shell 历史里。轮换密码用：

```bash
curl -fsSL https://raw.githubusercontent.com/azoway/shadownft/main/install.sh | SS_PASSWORD=generate bash
```

## 回滚

手动撤掉这次加上的防火墙和服务，程序和配置还留着：

```bash
/usr/local/sbin/shadownft rollback
```

这会停止并禁用 `shadowsocks-rust` 和 `shadownft`，删除 `inet shadownft`，并清掉确认标记。白名单文件 `/var/lib/shadownft/whitelist.order` 还在。下次安装会把它填回去。

## 卸载

```bash
/usr/local/sbin/shadownft uninstall
```

会删掉：

- `shadowsocks-rust` 和 `shadownft` 服务
- `inet shadownft`
- `/etc/shadownft`、`/etc/shadowsocks-rust`、`/var/lib/shadownft`
- `/usr/local/sbin/shadownft`
- `/usr/local/lib/shadownft`
- `/usr/local/bin/ssserver`、`/usr/local/bin/ssservice`
- 系统用户 `shadowsocks`

不会卸掉 `nftables`、`python3`、`curl`。`ufw` 和 `firewalld` 如果在安装时被关掉，也不会自动打开。需要的话自己执行 `sudo ufw enable`，或 `sudo systemctl enable --now firewalld`。

服务文件已经不在时，可以手工做同样的事：

```bash
sudo systemctl disable --now shadownft shadowsocks-rust
sudo nft delete table inet shadownft
sudo rm -f /etc/systemd/system/shadownft.service /etc/systemd/system/shadowsocks-rust.service
sudo systemctl daemon-reload
sudo rm -rf /etc/shadownft /etc/shadowsocks-rust /var/lib/shadownft /usr/local/lib/shadownft
sudo rm -f /usr/local/sbin/shadownft /usr/local/bin/ssserver /usr/local/bin/ssservice
sudo userdel shadowsocks
sudo groupdel shadowsocks
```

`nft delete` 或 `userdel` 提示不存在时，可以忽略。
