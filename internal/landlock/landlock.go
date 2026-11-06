// Package landlock 是对 Linux Landlock LSM 的一层极薄封装。
//
// 这里刻意不做「高级抽象」：内核提供了哪三个系统调用、参数结构体长什么样，
// 都直接摊在代码里，方便配合 cmd/ll 的演示来理解 Landlock 是什么、能做什么、原理如何。
//
// 本文件只放「跨平台通用」的东西（权限位常量、ABI 版本表、位运算工具），
// 真正的系统调用在 landlock_linux.go，其它平台在 landlock_other.go 里给出桩实现，
// 这样在 macOS 上 `go build ./...` 也能过，只是运行时会告诉你「不支持」。
package landlock

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnsupported 表示当前平台或内核不支持 Landlock。
var ErrUnsupported = errors.New("landlock 不可用：需要 Linux 5.13+ 且内核启用了 Landlock LSM")

// ---------------------------------------------------------------------------
// 权限位
//
// Landlock 的一切都建立在这套「位掩码」上：
//   - handled_access_*：这个规则集「打算管哪些权限」。声明了才受管，没声明的一律不管（完全放行）。
//   - allowed_access  ：某条路径/端口规则「额外放开哪些权限」。
//
// 位定义来自 include/uapi/linux/landlock.h，属于内核 ABI，永不改变。
// 新权限只能追加新位，所以老程序在新内核上依然正确。
// ---------------------------------------------------------------------------

// FSAccess 是文件系统访问权限位。
type FSAccess uint64

const (
	// ABI 1（Linux 5.13）就有的 13 个权限位。
	AccessFSExecute    FSAccess = 1 << iota // 执行文件
	AccessFSWriteFile                       // 打开文件可写（O_WRONLY / O_RDWR）
	AccessFSReadFile                        // 打开文件可读（O_RDONLY / O_RDWR）
	AccessFSReadDir                         // 列目录（getdents）
	AccessFSRemoveDir                       // rmdir
	AccessFSRemoveFile                      // unlink
	AccessFSMakeChar                        // mknod 字符设备
	AccessFSMakeDir                         // mkdir
	AccessFSMakeReg                         // O_CREAT 普通文件（常规文件（Regular File）：也就是我们平时最常接触的，用来存文本、图片、代码、可执行程序的那种普通文件）
	AccessFSMakeSock                        // bind unix socket（创建 socket 文件）
	AccessFSMakeFifo                        // mkfifo（FIFO（命名管道）：通过 mkfifo() 创建，会在文件系统里留下一个特殊文件。任何进程只要知道路径，就能打开它进行通信）
	// Pipe（匿名管道）：通常指 pipe() 系统调用创建的对象，只能用于有亲缘关系的进程（如父子进程）之间通信。它没有文件系统路径，用完即毁
	AccessFSMakeBlock // mknod 块设备
	AccessFSMakeSym   // symlink

	AccessFSRefer    // ABI 2（Linux 5.19）：跨目录 rename/link
	AccessFSTruncate // ABI 3（Linux 6.2）：truncate / ftruncate / O_TRUNC
	AccessFSIoctlDev // ABI 5（Linux 6.10）：对设备文件做 ioctl
)

// NetAccess 是网络访问权限位（只针对 TCP，UDP 至今不受 Landlock 管理）。
type NetAccess uint64

const (
	AccessNetBindTCP    NetAccess = 1 << iota // ABI 4（Linux 6.7）：bind 本地 TCP 端口
	AccessNetConnectTCP                       // ABI 4（Linux 6.7）：connect 远端 TCP 端口
)

// Scope 是「作用域」限制位，用于处理那些不属于某个文件路径的访问。
type Scope uint64

const (
	ScopeAbstractUnixSocket Scope = 1 << iota // ABI 6（Linux 6.12）：抽象命名空间的 unix socket（不允许沙箱里的进程连接到沙箱外部创建的“抽象 Unix 套接字”）
	// 抽象 Unix 套接字：一种不依赖文件系统的本地通信方式，只需要一个名字，常用于服务端程序（比如数据库、容器运行时）与客户端程序之间的数据交换
	// 服务端示例===================================================
	// import socket
	// import os

	// # 创建套接字
	// sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

	// # 关键点：用 \0 开头！这就是抽象命名空间
	// # 注意：Python中不能用普通的字符串，必须用 bytes (b"\0...")
	// abstract_address = b'\0my_abstract_service'

	// # 绑定
	// sock.bind(abstract_address)
	// sock.listen(1)

	// print("服务端启动，监听抽象地址...")
	// conn, _ = sock.accept()
	// print("收到:", conn.recv(1024).decode())
	// conn.close()
	// ===========================================================
	// 客户端示例===================================================
	// import socket

	// sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

	// # 连接到同一个抽象地址
	// sock.connect(b'\0my_abstract_service')

	// sock.sendall(b"Hello from Python!")
	// sock.close()
	// ===========================================================

	ScopeSignal // ABI 6（Linux 6.12）：给沙箱内外进程发信号
)

type fsAccessInfo struct {
	flag FSAccess
	name string
	abi  int
}

// 顺序即打印顺序。
var fsAccessInfos = []fsAccessInfo{
	{AccessFSExecute, "EXECUTE", 1},
	{AccessFSWriteFile, "WRITE_FILE", 1},
	{AccessFSReadFile, "READ_FILE", 1},
	{AccessFSReadDir, "READ_DIR", 1},
	{AccessFSRemoveDir, "REMOVE_DIR", 1},
	{AccessFSRemoveFile, "REMOVE_FILE", 1},
	{AccessFSMakeChar, "MAKE_CHAR", 1},
	{AccessFSMakeDir, "MAKE_DIR", 1},
	{AccessFSMakeReg, "MAKE_REG", 1},
	{AccessFSMakeSock, "MAKE_SOCK", 1},
	{AccessFSMakeFifo, "MAKE_FIFO", 1},
	{AccessFSMakeBlock, "MAKE_BLOCK", 1},
	{AccessFSMakeSym, "MAKE_SYM", 1},
	{AccessFSRefer, "REFER", 2},
	{AccessFSTruncate, "TRUNCATE", 3},
	{AccessFSIoctlDev, "IOCTL_DEV", 5},
}

var netAccessInfos = []struct {
	flag NetAccess
	name string
	abi  int
}{
	{AccessNetBindTCP, "BIND_TCP", 4},
	{AccessNetConnectTCP, "CONNECT_TCP", 4},
}

var scopeInfos = []struct {
	flag Scope
	name string
	abi  int
}{
	{ScopeAbstractUnixSocket, "ABSTRACT_UNIX_SOCKET", 6},
	{ScopeSignal, "SIGNAL", 6},
}

// Has 判断 a 是否包含 x 中的全部位。
func (a FSAccess) Has(x FSAccess) bool { return a&x == x }

// Names 返回 a 里包含的权限名，用来打印成人能读的样子。
func (a FSAccess) Names() []string {
	var out []string
	for _, i := range fsAccessInfos {
		if a.Has(i.flag) {
			out = append(out, i.name)
		}
	}
	return out
}

func (a FSAccess) String() string { return strings.Join(a.Names(), "|") }

// String 打印成 "BIND_TCP|CONNECT_TCP"。
func (n NetAccess) String() string {
	var out []string
	for _, i := range netAccessInfos {
		if n&i.flag != 0 {
			out = append(out, i.name)
		}
	}
	return strings.Join(out, "|")
}

// String 打印成 "ABSTRACT_UNIX_SOCKET|SIGNAL"。
func (s Scope) String() string {
	var out []string
	for _, i := range scopeInfos {
		if s&i.flag != 0 {
			out = append(out, i.name)
		}
	}
	return strings.Join(out, "|")
}

// SupportedFSAccess 返回某个 ABI 版本的内核「认识」的全部 FS 权限位。
//
// 这是最容易踩的坑：给老内核传它不认识的位，landlock_create_ruleset 会直接
// 返回 EINVAL。所以正确姿势永远是：先查 ABI，再用这个函数算出掩码。
func SupportedFSAccess(abi int) FSAccess {
	var a FSAccess
	for _, i := range fsAccessInfos {
		if abi >= i.abi {
			a |= i.flag
		}
	}
	return a
}

// SupportedNetAccess 返回某个 ABI 版本支持的网络权限位。
func SupportedNetAccess(abi int) NetAccess {
	var a NetAccess
	for _, i := range netAccessInfos {
		if abi >= i.abi {
			a |= i.flag
		}
	}
	return a
}

// SupportedScopes 返回某个 ABI 版本支持的 scope 位。
func SupportedScopes(abi int) Scope {
	var a Scope
	for _, i := range scopeInfos {
		if abi >= i.abi {
			a |= i.flag
		}
	}
	return a
}

// ABIChange 描述某个 Landlock ABI 版本相对上一版新增了什么。
type ABIChange struct {
	ABI    int    // Landlock ABI 版本号
	Kernel string // 首次引入该 ABI 的 Linux 版本
	Desc   string // 新增能力
}

// ABIChanges 是 ABI 演进史。注意「内核版本」和「ABI 版本」不是一回事：
// 发行版会把 Landlock 的补丁回合（backport）到老内核上，所以代码里必须查 ABI，
// 不能靠 uname 猜。
//
// 内核版本一列取自 man-pages 的 landlock(7) VERSIONS 对照表（收至 ABI 9）；
// 更新内核上的 ABI 10+ 尚无公开对照表，只能查 ABI。
func ABIChanges() []ABIChange {
	return []ABIChange{
		{1, "5.13", "文件系统基础权限：EXECUTE / WRITE_FILE / READ_FILE / READ_DIR / REMOVE_* / MAKE_*"},
		{2, "5.19", "REFER：允许（显式放行时）跨目录 rename、link"},
		{3, "6.2", "TRUNCATE：truncate/ftruncate/O_TRUNC 也算写权限"},
		{4, "6.7", "网络：BIND_TCP / CONNECT_TCP"},
		{5, "6.10", "IOCTL_DEV：设备文件的 ioctl"},
		{6, "6.12", "scoped：抽象 unix socket、跨域发信号"},
		{7, "6.15", "restrict_self 的 flags：控制是否为被拒行为记录审计日志"},
		{8, "7.0", "LANDLOCK_RESTRICT_SELF_TSYNC：一次把规则套到本进程所有线程"},
	}
}

// FSAccessTable 返回每个 FS 权限位及其所需的最低 ABI，供打印帮助/表格用。
func FSAccessTable() [][3]string {
	out := make([][3]string, 0, len(fsAccessInfos))
	for _, i := range fsAccessInfos {
		out = append(out, [3]string{i.name, fmt.Sprint(i.abi), fmt.Sprintf("0x%04x", uint64(i.flag))})
		// 把数字转成十六进制，如果不足 4 位，前面用 0 补齐，最小宽度是4
	}
	return out
}
