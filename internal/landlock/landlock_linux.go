//go:build linux

package landlock

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// Landlock 只提供三个系统调用（Linux 5.13+），编号在 asm-generic/unistd.h 里统一定义，
// 因此 x86_64 / arm64 / riscv64 全都是同一组数字，可以直接写死。
//
//	444 landlock_create_ruleset(u64 *attr, size_t size, u32 flags)
//	445 landlock_add_rule(int ruleset_fd, enum rule_type, void *attr, u32 flags)
//	446 landlock_restrict_self(int ruleset_fd, u32 flags)
const (
	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446
)

const (
	// createRulesetVersion：size=0、flags=1 时不建规则集，只回问内核「你的 Landlock ABI 是第几版」。
	createRulesetVersion = 1 << 0

	ruleTypePathBeneath = 1 // LANDLOCK_RULE_PATH_BENEATH：按「目录/文件」授权
	ruleTypeNetPort     = 2 // LANDLOCK_RULE_NET_PORT      ：按「端口」授权（ABI 4+）

	prSetNoNewPrivs = 38 // PR_SET_NO_NEW_PRIVS

	// O_PATH：只取文件「身份」不取读写权限的打开方式。Landlock 加规则时用它引用父目录。
	oPath = 0x200000
)

// ---------------------------------------------------------------------------
// 内核结构体
// ---------------------------------------------------------------------------

// rulesetAttr 对应 struct landlock_ruleset_attr。
// 它随 ABI 长大：ABI1 只有第 1 个字段，ABI4 加网络，ABI6 加 scope。
// 新内核允许传大结构，老内核只认识前 N 字节，所以下面按 size 做降级重试。
type rulesetAttr struct {
	handledAccessFS  uint64
	handledAccessNet uint64 // ABI 4+
	scoped           uint64 // ABI 6+
}

// pathBeneathAttr 对应 struct landlock_path_beneath_attr，
// C 里是 __attribute__((packed)) { __u64 allowed_access; __s32 parent_fd; }，共 12 字节。
// Go 的 struct 会在末尾补 4 字节对齐（sizeof = 16），但前 12 字节布局与 C 完全一致，
// 所以调用时把 size 显式写成 12 就行。
type pathBeneathAttr struct {
	allowedAccess uint64
	parentFD      int32
}

// netPortAttr 对应 struct landlock_net_port_attr（ABI 4+）。
type netPortAttr struct {
	allowedAccess uint64
	port          uint64
}

// ---------------------------------------------------------------------------
// 探测
// ---------------------------------------------------------------------------

// Support 汇总「这台机器上 Landlock 到底能用吗、能用哪些」。
type Support struct {
	GOOS   string
	GOARCH string
	Kernel string   // uname -r
	LSMs   []string // /sys/kernel/security/lsm 里的 LSM 列表
	ABI    int      // Landlock ABI 版本，0 表示不可用
	ABIErr error    // 查 ABI 失败的原因（通常是 ENOSYS -> 内核太老或没编译）
}

// Enabled 表示 Landlock 是否可用。
func (s Support) Enabled() bool { return s.ABIErr == nil && s.ABI > 0 }

// Detect 探测当前环境。这个函数本身不会修改任何状态，可以随便调。
func Detect() Support {
	s := Support{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}

	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		s.Kernel = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		// 形如 "capability,landlock,yama,apparmor"
		s.LSMs = strings.Split(strings.TrimSpace(string(b)), ",")
	}

	s.ABI, s.ABIErr = ABI()
	if s.ABIErr != nil {
		s.ABI = 0
	}
	return s
}

// InLSMList 表示 landlock 是否出现在启用的 LSM 列表里。
// 有 /sys/kernel/security 挂载时才有意义（容器里常常没有）。
func (s Support) InLSMList() bool {
	for _, l := range s.LSMs {
		if strings.TrimSpace(l) == "landlock" {
			return true
		}
	}
	return false
}

// ABI 返回内核的 Landlock ABI 版本号。
//
// 玩法很巧：landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
// 不创建任何东西，只把 ABI 版本号当作返回值吐出来。
//
// 返回 ENOSYS  -> 内核根本没有这几个系统调用（< 5.13）
// 返回 EOPNOTSUPP -> 内核有系统调用，但 Landlock 没启用（CONFIG 没开或 lsm= 里被关掉）
func ABI() (int, error) {
	r, _, errno := syscall.Syscall(sysLandlockCreateRuleset, 0, 0, createRulesetVersion)
	if errno != 0 {
		return 0, os.NewSyscallError("landlock_create_ruleset(VERSION)", errno)
	}
	return int(r), nil
}

// ---------------------------------------------------------------------------
// 规则集
// ---------------------------------------------------------------------------

// Ruleset 是一组「handled 权限 + 若干允许项」的描述，本身还不生效。
// 只有把它 Restrict() 到进程上，才会变成不可撤销的 sandbox domain（沙箱域）。
type Ruleset struct {
	fd int
}

// CreateRuleset 创建规则集。
//
// handledFS / handledNet / handledScoped 是「我要接管哪些权限」的掩码：
//   - 只有被声明的权限才可能被拒绝；
//   - 没声明的权限，Landlock 完全不看（相当于全放行）。
//
// 这是 Landlock 最核心的语义，也是新手最容易误解的地方：
// 它不是一个「默认全禁」的笼子，而是「你点名要管的权限，默认全禁，再按规则放行」。
func CreateRuleset(handledFS FSAccess, handledNet NetAccess, handledScoped Scope) (*Ruleset, error) {
	attr := rulesetAttr{
		handledAccessFS:  uint64(handledFS),
		handledAccessNet: uint64(handledNet),
		scoped:           uint64(handledScoped),
	}

	// 结构体尺寸协商：老内核只认识小尺寸，遇到不认识的尺寸返回 E2BIG/EINVAL。
	// 所以先从完整尺寸试起，失败就退到更小的尺寸（字段更少的老结构）。
	sizes := []int{24, 16, 8}
	if handledScoped != 0 {
		sizes = []int{24} // 只有 24 字节的结构才装得下 scoped 字段
	} else if handledNet != 0 {
		sizes = []int{24, 16} // 至少 16 字节才装得下 handled_access_net
	}

	var lastErr error
	for _, size := range sizes {
		fd, _, errno := syscall.Syscall6(sysLandlockCreateRuleset,
			uintptr(unsafe.Pointer(&attr)), uintptr(size), 0, 0, 0, 0)
		if errno == 0 {
			return &Ruleset{fd: int(fd)}, nil
		}
		lastErr = os.NewSyscallError(fmt.Sprintf("landlock_create_ruleset(size=%d)", size), errno)
		if errno != syscall.E2BIG && errno != syscall.EINVAL {
			return nil, lastErr
		}
	}
	return nil, lastErr
}

// FD 返回底层文件描述符（调试用）。
func (r *Ruleset) FD() int { return r.fd }

// Close 释放规则集。已经 Restrict 过的规则集不受影响（内核里有独立引用计数）。
func (r *Ruleset) Close() error {
	if r.fd < 0 {
		return nil
	}
	err := syscall.Close(r.fd)
	r.fd = -1
	return err
}

// AllowPath 给 path 放行 access 里的权限。
//
// 语义要点：
//   - path 可以是目录，也可以是单个文件（比如 /dev/null）；
//   - 一条规则的放行范围是「该路径及其整棵子树」；
//   - 多条规则之间是「取并集」，所以「全局只读 + 某个目录可写」= 两条规则叠加；
//   - allowed 里的位必须都在 handled 里出现过，否则 EINVAL。
func (r *Ruleset) AllowPath(path string, access FSAccess) error {
	// 用 O_PATH 打开：只要目录的「身份」，不需要读写权限，也不需要额外权限。
	fd, err := syscall.Open(path, oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open(O_PATH)", Path: path, Err: err}
	}
	defer syscall.Close(fd)

	attr := pathBeneathAttr{allowedAccess: uint64(access), parentFD: int32(fd)}
	// 注意：landlock_add_rule 的签名是 (fd, rule_type, rule_attr, flags)，
	// 第 4 个参数是 flags 而不是 size —— 它没有 size 参数，内核按固定 sizeof 拷贝结构体。
	// 这里很容易手滑写成 12，结果是 EINVAL（flags 只允许 0 或 LANDLOCK_ADD_RULE_QUIET）。
	_, _, errno := syscall.Syscall6(sysLandlockAddRule,
		uintptr(r.fd), ruleTypePathBeneath, uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
	if errno != 0 {
		return os.NewSyscallError("landlock_add_rule(PATH_BENEATH "+path+")", errno)
	}
	return nil
}

// AllowPort 放行端口 port 上的 TCP 操作（ABI 4+，UDP 不在管辖范围内）。
//
// 语义：BIND_TCP 匹配被 bind 的本地端口；CONNECT_TCP 匹配 connect 的目标端口。
// 也就是说「只允许连 8080」确实可以表达出来。但要注意规则是「端口 → 许可」的白名单，
// 一个规则集里没列出的端口全部被拒。
func (r *Ruleset) AllowPort(port uint16, access NetAccess) error {
	attr := netPortAttr{allowedAccess: uint64(access), port: uint64(port)}
	_, _, errno := syscall.Syscall6(sysLandlockAddRule,
		uintptr(r.fd), ruleTypeNetPort, uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
	if errno != 0 {
		return os.NewSyscallError(fmt.Sprintf("landlock_add_rule(NET_PORT %d)", port), errno)
	}
	return nil
}

// Restrict 把规则集「钉」到当前进程上，从此不可撤销。
//
// 两个必须先理解的细节：
//
//  1. 先设置 PR_SET_NO_NEW_PRIVS=1。Landlock 要求进程不能再通过 setuid/setgid 或
//     文件 capability 提权，否则「沙箱里 exec 一个 setuid root 的程序」就成了逃逸通道。
//     这也意味着沙箱内的一切 exec 都不再提权。
//
//  2. restrict_self 只会「叠加」规则：新 domain 与已有 domain 是取交集的关系。
//     所以沙箱内的进程哪怕再调一次 restrict_self 加一个更宽松的规则集，
//     也绝不可能拿回第一层拒绝掉的权限。唯一能改变规则的是 fork 出子进程之前，
//     或者一开始就少管点——没有「解除」接口，这是 by design。
//
// 生效后，当前进程以及它 fork/exec 出来的所有子孙进程都受同一套规则约束。
func (r *Ruleset) Restrict() error {
	if r.fd < 0 {
		return errors.New("landlock: 规则集已关闭")
	}
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return os.NewSyscallError("prctl(PR_SET_NO_NEW_PRIVS)", errno)
	}
	if _, _, errno := syscall.Syscall(sysLandlockRestrictSelf, uintptr(r.fd), 0, 0); errno != 0 {
		return os.NewSyscallError("landlock_restrict_self", errno)
	}
	// 规则集一旦挂上，内核已经持有引用，用户态这份 fd 可以关掉。
	return r.Close()
}

// NoNewPrivs 读取 /proc/self/status 里的 NoNewPrivs 字段。
func NoNewPrivs() (bool, error) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "NoNewPrivs:"); ok {
			return strings.TrimSpace(v) == "1", nil
		}
	}
	return false, errors.New("NoNewPrivs 字段不存在")
}
