# Landlock 是什么、能做什么、原理是什么

一个用 Go 写的、**可以真跑起来**的 Landlock 教学项目。不依赖任何第三方库，直接调内核的三个系统调用。

```
ll abi      探测内核支持到什么程度
ll fs       文件系统权限：三组对照实验
ll net      TCP bind/connect 限制
ll escape   哪些绕过手法无效，哪些真能绕过去
ll run      把任意命令关进 Landlock 沙箱里执行
```

---

## 0. 先说你的机器能不能跑

**结论：macOS 上跑不了 Landlock，但你这台机器上的 Docker 可以跑，实测通过了。**

Landlock 不是一个用户态库，而是 **Linux 内核里的 LSM（Linux Security Module）**，检查点在内核的 VFS 和 socket 层。macOS 内核（XNU）里没有这个东西，也没法在用户态模拟。所以：

| 环境 | 能不能跑 | 说明 |
| --- | --- | --- |
| macOS 15.8.1 原生 | ❌ | 内核里没有 Landlock，本项目能编译，运行会打印「当前不是 Linux」 |
| **你这台机器的 Docker** | ✅ | Docker Desktop 内核 `7.0.14-linuxkit`，Landlock **ABI 8**，实测通过 |
| Linux 真机 | ✅ | 需要 5.13+（ABI 1）；建议 6.12+（ABI 6） |

本机实测（在 `alpine:3.18` 容器里，内核即 Docker 的 linuxkit 内核）：

```
== 环境 ==
  平台          : linux/amd64
  内核 release  : 7.0.14-linuxkit
  Landlock ABI  : 8
== 本内核可接管的文件系统权限（handled_access_fs 掩码 = 0xffff） ==
== 本内核可接管的网络权限（handled_access_net 掩码 = 0x03） ==
== 本内核支持的 scope（0x03） ==
```

ABI 8 正好是 Linux 7.0 引入的（见 §2.6），所以 `7.0.14-linuxkit` 报 ABI 8 完全对得上 —— 这也是「查 ABI 比猜内核版本可靠」的现成例子。

所以**不用再找 Linux 机器**了，直接：

```bash
make abi        # 或者 make all
```

如果需要一台真 Linux 机器，任何 5.13+ 内核都行。自检三件事：

```bash
uname -r                                   # >= 5.13
cat /sys/kernel/security/lsm               # 应包含 landlock（某些容器里没挂 securityfs，看不到也不代表没有）
grep -i landlock /boot/config-$(uname -r)  # CONFIG_SECURITY_LANDLOCK=y
```

最可靠的自检是直接问内核 ABI 号 —— 这正是 `ll abi` 干的活（见下文）。

---

## 1. Landlock 是什么

一句话：

> **Landlock 让任何进程（包括非 root 进程）给自己和所有子孙进程戴上一套不可撤销、不可放宽的访问控制规则，作用范围是文件系统（按 inode 层级）、TCP 端口，以及（ABI 6+）信号和抽象 unix socket。**

它解决的问题不是「防止 root 干坏事」（那是 SELinux/AppArmor 的活），而是 **「让程序给自己上枷锁」**：一个解析不可信 PDF 的进程、一个跑用户提交代码的 CI worker、一个容器运行时，可以在不需要任何特权的前提下，把「我接下来只能读这几个目录、只能写这个临时目录、只能连这个端口」写进内核，然后放心地去处理不可信输入。

和常见机制的区别：

| 机制 | 授权对象 | 谁能用 | 拦在哪 | 主要局限 |
| --- | --- | --- | --- | --- |
| `chroot` / `pivot_root` | 路径前缀 | root | 路径解析 | root 可逃逸；只管「看到什么」 |
| user + mount namespace | 挂载视图 | 非特权（需 userns） | 路径解析 | 只改视图，不改权限判断 |
| **seccomp-bpf** | 系统调用号/参数值 | 非特权 | syscall 入口 | 只看到数字参数，不知道路径/inode |
| AppArmor | 路径（LSM） | root 配置 profile | VFS 等 | 要管理员预先写策略，绑定到程序 |
| SELinux | 安全标签（LSM） | root 配置策略 | VFS 等 | 要打标签、写策略，体系重 |
| **Landlock** | **inode 层级 + 端口** | **进程自己（无需特权）** | **VFS + socket + ioctl** | 只能收紧不能放宽；覆盖范围有限（见 §4） |

---

## 2. 原理

### 2.1 只有三个系统调用

Landlock 的用户态接口极简，编号在所有架构上一致（在 `asm-generic/unistd.h` 里定义）：

| 编号 | 系统调用 | 作用 |
| --- | --- | --- |
| 444 | `landlock_create_ruleset(attr, size, flags)` | 建一个「规则集」；`size=0, flags=1` 时只回问 ABI 版本 |
| 445 | `landlock_add_rule(fd, rule_type, attr, flags)` | 往规则集里加一条规则（**没有 size 参数**，见 §7） |
| 446 | `landlock_restrict_self(fd, flags)` | 把规则集钉到当前进程上，立即生效，不可撤销 |

代码在 [`internal/landlock/landlock_linux.go`](internal/landlock/landlock_linux.go)：

- `ABI()` [`landlock_linux.go:122`](internal/landlock/landlock_linux.go) — 用「size=0 的 create_ruleset」问版本号；返回 `ENOSYS` 说明内核没有这些调用，`EOPNOTSUPP` 说明有但没启用
- `CreateRuleset()` [`landlock_linux.go:148`](internal/landlock/landlock_linux.go) — 结构体尺寸协商（老内核不认识新字段）
- `AllowPath()` [`landlock_linux.go:199`](internal/landlock/landlock_linux.go) — 用 `O_PATH` 打开目录/文件，加一条 `PATH_BENEATH` 规则
- `Restrict()` [`landlock_linux.go:248`](internal/landlock/landlock_linux.go) — 先 `PR_SET_NO_NEW_PRIVS`，再 `restrict_self`

### 2.2 数据模型：ruleset → domain → layer

```
handled_access_fs  = 0x...  「我要接管哪些权限」（位掩码，必须显式声明）
handled_access_net = 0x...
scoped             = 0x...
       │
       ▼
  ruleset: { handled 集合 } + [ (路径/inode, 允许的权限位) ... ]
       │  landlock_restrict_self()
       ▼
  当前进程的 Landlock domain ──fork/exec──► 所有子孙进程都继承
       │
       │  再次 restrict_self 会再挂一层
       ▼
  layer 1 ─ layer 2 ─ ... （最多 16 层，判定时逐层都要通过 = 交集）
```

- **规则集本身不生效**，`restrict_self` 之后才变成进程上的 domain。
- 一旦生效，**没有撤销接口**，也没有「放宽」接口。
- 子进程 exec 之后，即使 exec 的是 setuid 程序，domain 也照样跟着（因为 `PR_SET_NO_NEW_PRIVS=1`，提权通道已关闭）。

### 2.3 内核里挂在哪

Landlock 是 LSM，核心代码在 `security/landlock/`。它挂在这些 hook 上：

| 场景 | 检查点 | 对应的权限位 |
| --- | --- | --- |
| 打开文件/目录 | VFS `security_file_open`（`open(2)` 的那一刻） | `READ_FILE` / `WRITE_FILE` / `READ_DIR` / `TRUNCATE` / `IOCTL_DEV` / `EXECUTE` |
| 创建/删除/重命名/链接 | inode 系列 hook（`inode_mkdir`、`inode_unlink`、`inode_rename`…） | `MAKE_*` / `REMOVE_*` / `REFER` |
| TCP `bind` / `connect` | `socket_bind` / `socket_connect` | `BIND_TCP` / `CONNECT_TCP` |
| `ioctl` | 文件 ioctl hook（ABI 5+） | `IOCTL_DEV` |

规则在内核里按 **inode** 组织成一棵树。检查时从目标 inode 沿父目录链往上找「最近的一条规则」，用它的 `allowed_access` 判定；一条都找不到就拒绝。

这解释了为什么绕过手法基本无效：**它判的是 inode，不是路径字符串**。`..`、符号链接、`/proc/self/root`、bind mount 绕一圈，最后落到的还是同一个 inode。

### 2.4 四条必须记住的语义

1. **只有声明过的权限才会被管。** `handled_access_fs` 里没写的位，Landlock 一眼都不看（等于全放行）。
   所以「随手写个 READ_FILE 就以为安全了」是经典误解 —— 见 `ll fs` 实验 1。
2. **声明了就是默认拒绝。** 同一个位：`handled` 里有、`allowed_access` 里没有 → `EACCES`。
   这是 fail-closed 模型，白名单式。
3. **一条路径规则覆盖整棵子树；多条规则取并集。**
   「全盘只读 + `/tmp/work` 可写」= 两条规则叠加 —— 见 `ll fs` 实验 3。
4. **多层 domain 取交集；只能收紧，不能放宽。**
   沙箱里的进程再调一次 `restrict_self` 挂一个更宽松的规则集也没用 —— 见 `ll escape` 第二节。

> 唯一的历史例外：`LANDLOCK_ACCESS_FS_REFER`（跨目录 rename/link）**即使没有写进 handled 也是默认拒绝**，但要用它又必须显式写进 handled。这是 ABI 1 为了向后兼容留下的坑。

### 2.5 为什么沙箱里的程序逃不出去

| 尝试 | 结果 | 原因 |
| --- | --- | --- |
| 直接 `open` 被拒的文件 | ❌ `EACCES` | 没有对应规则 |
| `chdir` 到目录再用相对路径 | ❌ `EACCES` | 判的是 inode，与路径写法无关 |
| 走 `/proc/self/root/...` | ❌ `EACCES` | 解析完还是同一个 inode |
| 建符号链接指向它 | ❌ `EACCES` | 链接可以建，但打开时按最终 inode 判 |
| `exec` 一个 `cat` 去读 | ❌ `EACCES` | domain 被 exec 继承 |
| 再挂一层更宽松的规则集 | ❌ `EACCES` | 层之间取交集 |
| exec 一个 setuid 程序提权 | ❌ | `PR_SET_NO_NEW_PRIVS=1` |
| **读 `restrict_self` 之前就打开的 fd** | ✅ **成功** | 检查点在 `open(2)`，已打开的 fd 不再检查 |
| 用 `/proc/self/fd/N` 重新 open 一遍 | ❌ `EACCES` | 重新 open 会重新检查 |

最后那条 ✅ 是最重要的实践教训：**实现沙箱时必须在 `restrict_self` 之前关掉所有不需要的 fd**（包括传进来的 socket、日志、`/dev/null` 等）。`ll escape` 的第三节就是现场演示。

### 2.6 ABI 版本化

内核能力在长，但**已发布的行为永不改变**，只往上加位。所以必须查 ABI 再决定用哪些位：

| ABI | 引入 | 新增 |
| --- | --- | --- |
| 1 | Linux 5.13 | 文件系统基础 13 个权限位 |
| 2 | Linux 5.19 | `REFER`（跨目录 rename/link） |
| 3 | Linux 6.2 | `TRUNCATE` |
| 4 | Linux 6.7 | `BIND_TCP` / `CONNECT_TCP` |
| 5 | Linux 6.10 | `IOCTL_DEV` |
| 6 | Linux 6.12 | `scoped`：抽象 unix socket、跨域发信号 |
| 7 | Linux 6.15 | `restrict_self` 的 flags：审计日志开关 |
| 8 | Linux 7.0 | `RESTRICT_SELF_TSYNC`：一次套到本进程所有线程 |
| 9 | Linux 7.1 | `RESOLVE_UNIX`：限制连接「路径名」unix socket |
| 10 | 更新内核 | UDP：`BIND_UDP` / `CONNECT_SEND_UDP`；以及按对象关闭审计日志 |
| 11 | 更新内核 | `RESTRICT_SELF_NO_NEW_PRIVS`：不必自己先 prctl |
| 12 | 更新内核 | capability / namespace 限制（新的 rule 类型） |

对照表 1~9 取自 man-pages 6.19 的 `landlock(7)`；10 以后尚无公开对照表。
本项目只实现到 ABI 8 —— 也就是本机实测过的那一版。

注意：**「内核版本」和「ABI 版本」不是一回事**（发行版会 backport）。代码里只能信 `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` 的返回值 —— 这就是 `landlock.SupportedFSAccess(abi)` 存在的理由。

---

## 3. 能做什么（真实用法）

Landlock 的典型使用者都是「要处理不可信输入」的场景：

- **沙箱执行器 / 容器运行时**：给容器里的进程再加一层文件系统与端口白名单（不需要 root、不需要 namespace）。
- **不可信文件解析**：图片/文档/字体/媒体解码器，只允许读输入文件、写临时目录，别的全禁。
- **跑用户代码的 CI / 判题系统**：编译器和被编译的代码都关进「只读工具链 + 一个可写目录」。
- **插件 / 扩展系统**：宿主进程 fork 出插件进程，直接限制成只能访问自己的数据目录。
- **服务加固**：把自己限制成「只读 `/usr`、只写 `/var/lib/myapp`、只 bind 一个端口」。

`ll run` 就是这种用法的最小实现：

```bash
# 全盘只读，只有 /tmp/sb 可写
make run ARGS="-ro / -rw /tmp/sb -- sh -c 'cat /etc/hostname; echo hi > /tmp/sb/a.txt; cat /tmp/sb/a.txt'"

[ll] Landlock ABI 8 已生效：只读 [/]，可写 [/tmp/sb]
17e482f70e10
hi
```

把写目标从 `/tmp/sb/a.txt` 换成 `/tmp/b.txt`，就会得到 `sh: can't create /tmp/b.txt: Permission denied`。

它做了四件事，和任何生产级沙箱执行器一样：

1. 算出手臂（`SupportedFSAccess(abi)`）→ `CreateRuleset`
2. 每个 `-ro` 路径加一条「读+列目录+执行」规则
3. 每个 `-rw` 路径加一条「全部权限」规则
4. `Restrict()` 之后 `execve` 目标程序（程序本身也是沙箱进程）

---

## 4. 不能做什么

Landlock 不是完整沙箱，以下都**不在**它的管辖范围（前几条在 `ll escape` 里实测过）：

- **已经打开的 fd**（终端、日志、socket、共享内存、`/dev/null`）—— 权限在 `open` 时就定了。
- **`chdir` / `stat` / `flock` / `chmod` / `chown` / `setxattr` / `utime` / `access` / `fcntl`** —— 这些操作至今没有对应的权限位，管不了（你不能阻止沙箱里读文件元信息）。
- **网络只覆盖 TCP 端口**（ABI 4~9）；UDP 要到 ABI 10，ICMP / raw socket 至今不管；**完全不看 IP 和域名**。
- **没有资源限制**：CPU、内存、进程数、打开文件数都不管（用 cgroup / rlimit / seccomp）。
- **不能审计和告警**（ABI 7 只提供日志开关，不是完整的审计策略）。
- **不能强制别的进程**：它只能自缚 + 被子孙继承；你不能用它去限制一个已经在跑的进程。
- **不是「防 root」**：root 进程照样可以用 `ptrace` 等手段（除非配合其它机制）。

一句话：**Landlock 是「文件/端口维度的最小权限」，是 seccomp、namespace、cgroup 的补充，不是替代品。** 真实沙箱一般四件套一起上：namespaces（隔离视图）+ cgroups（限资源）+ seccomp（限 syscall）+ Landlock（限文件与端口语义）。

---

## 5. 代码导览

```
internal/landlock/            核心库：三个系统调用的薄封装（无第三方依赖）
  landlock.go                 跨平台的权限位常量、ABI 表、位运算
  landlock_linux.go           Linux 实现：真正调 444/445/446
  landlock_other.go           非 Linux 桩（macOS 上能编译，运行报不支持）
  landlock_test.go            纯逻辑单测（任何平台都能跑）
cmd/ll/
  main.go                     命令分发；子进程入口拦截
  probe.go                    「换进程做实验」的框架 + 输出辅助
  cmd_abi.go                  探测 ABI 与可用权限位
  cmd_fs.go                   文件系统三组对照实验
  cmd_net.go                  网络两组实验
  cmd_escape.go               绕过手法与边界
  cmd_run.go                  沙箱执行器（最实用）
Makefile                      make abi / fs / net / escape / all / run
```

### 关键设计：为什么每个实验都要换进程

`landlock_restrict_self` 不可撤销。如果三组实验都在同一个进程里做，第二组会被第一组的规则污染。所以 `probe.go` 的套路是：

```
父进程（干净）── fork/exec 自己，环境变量里带上实验名 ──► 子进程
                                                          应用 Landlock
                                                          做试探
                                                          退出
```

父进程全程不受限，所以能干净地展示「有/没有沙箱」的对比。子进程必须在 `main` 里被**最早拦截**（[`main.go`](cmd/ll/main.go) 的第一行逻辑），否则它会把父进程的编排代码再跑一遍。

### 实验清单

| 实验 | 配置 | 看点 |
| --- | --- | --- |
| `fs-1` | handled = `READ_FILE`，只放行系统目录 | 没声明的写/列目录/执行**完全不受管** |
| `fs-2` | handled = 全部，只放行 `work/` | 真正的默认拒绝：白名单外全部 `EACCES` |
| `fs-3` | `/` 只读 + `work/` 全权限 | 规则取并集；`REMOVE`/`TRUNCATE` 单独受管 |
| `net-1` | handled = TCP 全部，0 条端口规则 | connect/bind 全拒；**UDP 和 unix socket 照旧** |
| `net-2` | 只放行 8080 的 `CONNECT_TCP` | 8080 变成 `ECONNREFUSED`（说明请求真的发出去了） |
| `escape` | 系统目录只读 + `work/` 全权限 | 七种绕过手法，只有「继承的 fd」成功 |

`fs` 的实测输出（节选）：

```
== 实验 2/3：handled = 全部文件系统权限，只放行 /tmp/landlock-demo/work ==
  [拦截] 读 outside.txt（白名单外）      open ...: permission denied
  [拦截] 列目录 /（白名单外）            open /: permission denied
  [放行] 写 work/f2.txt（白名单内）
  [拦截] 写 demoRoot 下的新文件（白名单外）
```

`escape` 的实测输出（节选）：

```
== 一、常规硬读：全部失败 ==
  [拦截] 直接 open(secret.txt)
  [拦截] 先 chdir 到 secret 所在目录，再用相对路径打开
  [拦截] 借道 /proc/self/root 读（绕路解析到同一个 inode）
  [拦截] 在 work 里建符号链接指向 secret，再读链接
  [拦截] exec /bin/cat 让子进程去读（domain 被继承）
== 三、真正能绕过去的：restrict 之前就打开的 fd ==
  [放行] 直接读继承来的 fd 3（父进程在 restrict 前打开）
  [拦截] 用 /proc/self/fd/3 重新打开同一个文件
```

---

## 6. 怎么跑

### macOS（就用你现在的机器）

```bash
make abi        # 探测
make all        # 跑完 abi + fs + net + escape
make fs         # 单个演示
make run ARGS="-ro / -rw /tmp/sb -- sh -c 'id; touch /tmp/sb/x'"
make shell      # 进容器手动玩（项目挂在 /w）
```

原理：`GOOS=linux GOARCH=amd64 go build` 交叉编译出一个**静态二进制**，再丢进 `alpine:3.18` 容器里跑。Landlock 用的是容器内核，跟宿主机是 macOS 无关。

> 如果 Docker 的 seccomp 策略挡了 landlock 系统调用（老版本 Docker），加 `--security-opt seccomp=unconfined`。Docker 29 / linuxkit 7.x 实测默认允许，不需要。

### Linux 真机

```bash
go build -o bin/ll ./cmd/ll
./bin/ll all             # 不需要 root，也不需要任何 capability
```

### 自己写代码

```go
r, err := landlock.CreateRuleset(landlock.SupportedFSAccess(abi), 0, 0)
if err != nil { return err }
r.AllowPath("/usr", landlock.AccessFSReadFile|landlock.AccessFSReadDir|landlock.AccessFSExecute)
r.AllowPath("/tmp/work", landlock.SupportedFSAccess(abi))
if err := r.Restrict(); err != nil { return err }   // 从这里开始不可逆
```

---

## 7. 踩过的坑（都是真的）

1. **`landlock_add_rule` 的第 4 个参数是 `flags`，不是 `size`。**
   它没有 size 参数，内核按固定 `sizeof` 拷贝结构体。手滑传个 12 进去，`flags != 0` → 一律 `EINVAL`，而且看起来像是「规则非法」，很难查。
2. **Go 的 `os/exec` 在 `Stdin == nil` 时会去打开 `/dev/null`。**
   沙箱里没放行 `/dev/null`，于是 exec 直接失败并报 `open /dev/null: permission denied` —— 看起来像是「exec 被拦了」，其实程序根本没启动。`ll fs` 的 `execEcho` 里显式赋值 `cmd.Stdin = os.Stdin` 就是为了避开它。
3. **`exec` 一个程序需要 `READ_FILE` + `EXECUTE` 两个权限。**
   只放行 `EXECUTE` 是不够的，加载二进制和动态库要读文件。
4. **`landlock_ruleset_attr` 会随 ABI 长大。**
   老内核收到超出自己认知的 size 会返回 `E2BIG`，所以要按 24 → 16 → 8 降级重试（见 `CreateRuleset`）。
5. **`PR_SET_NO_NEW_PRIVS` 是 `restrict_self` 的前置条件。**
   忘了它会得到 `EPERM`；设置之后，沙箱里所有 exec 都不再能通过 setuid 提权（这正是我们要的）。
6. **演示必须换进程。**
   `restrict_self` 不可撤销，同一进程里连着做几组实验会互相污染；而且不换进程时，`net` 的「对照组」会跑在 sandbox 里，结论全错。

---

## 8. 参考资料

- 内核文档：<https://docs.kernel.org/userspace-api/landlock.html>（ABI 与语义的权威来源）
- UAPI 头文件：`include/uapi/linux/landlock.h`
- 内核实现：`security/landlock/`（`syscalls.c` 是三个系统调用的入口）
- 官方示例：`samples/landlock/sandboxer.c`
- LWN 系列文章：*Landlock: unprivileged access control*（设计动机与演进）
