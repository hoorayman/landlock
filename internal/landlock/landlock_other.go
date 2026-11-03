//go:build !linux

package landlock

import "runtime"

// 非 Linux 平台（macOS / Windows）的桩实现：只为让代码能编译通过。
//
// Landlock 是 Linux 内核的安全模块（LSM），由内核在 VFS 打开文件、bind/connect、
// ioctl 等路径上做检查，用户态无法在别的操作系统上模拟。所以 macOS 上只能
// 「编译过、运行说不行」，真正跑演示需要 Linux 5.13+ 内核（容器/虚拟机/真机都行）。

// Support 在非 Linux 平台恒为「不可用」。
type Support struct {
	GOOS   string
	GOARCH string
	Kernel string
	LSMs   []string
	ABI    int
	ABIErr error
}

// Enabled 恒为 false。
func (s Support) Enabled() bool { return false }

// InLSMList 恒为 false。
func (s Support) InLSMList() bool { return false }

// Detect 在非 Linux 平台返回不可用。
func Detect() Support {
	return Support{
		GOOS:   runtime.GOOS,
		GOARCH: runtime.GOARCH,
		Kernel: runtime.GOOS,
		ABIErr: ErrUnsupported,
	}
}

// ABI 在非 Linux 平台返回 ErrUnsupported。
func ABI() (int, error) { return 0, ErrUnsupported }

// Ruleset 是空壳。
type Ruleset struct{}

// CreateRuleset 在非 Linux 平台返回 ErrUnsupported。
func CreateRuleset(FSAccess, NetAccess, Scope) (*Ruleset, error) { return nil, ErrUnsupported }

// FD 恒为 -1。
func (r *Ruleset) FD() int { return -1 }

// Close 什么也不做。
func (r *Ruleset) Close() error { return nil }

// AllowPath 在非 Linux 平台返回 ErrUnsupported。
func (r *Ruleset) AllowPath(string, FSAccess) error { return ErrUnsupported }

// AllowPort 在非 Linux 平台返回 ErrUnsupported。
func (r *Ruleset) AllowPort(uint16, NetAccess) error { return ErrUnsupported }

// Restrict 在非 Linux 平台返回 ErrUnsupported。
func (r *Ruleset) Restrict() error { return ErrUnsupported }

// NoNewPrivs 在非 Linux 平台返回 ErrUnsupported。
func NoNewPrivs() (bool, error) { return false, ErrUnsupported }
