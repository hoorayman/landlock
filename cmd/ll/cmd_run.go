package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"landlock/internal/landlock"
)

// pathList 是一个可以重复出现的字符串 flag，例如 -ro /usr -ro /lib。
type pathList []string

func (p *pathList) String() string { return strings.Join(*p, ",") }

func (p *pathList) Set(v string) error {
	*p = append(*p, v)
	return nil
}

// cmdRun 把 Landlock 做成人能用的形态：给一个命令，加上路径白名单，然后执行。
//
// 这就是容器运行时、systemd 的 ProtectSystem=、以及各种「沙箱执行器」
// 使用 Landlock 的基本姿势。
func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var ro, rw pathList
	fs.Var(&ro, "ro", "该路径可读+可执行（可重复，包含整棵子树）")
	fs.Var(&rw, "rw", "该路径拥有全部权限（可重复，包含整棵子树）")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "用法: ll run [-ro PATH]... [-rw PATH]... -- CMD [ARGS...]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	cmdline := fs.Args()
	if len(cmdline) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	if len(ro) == 0 && len(rw) == 0 {
		fmt.Fprintln(os.Stderr, "至少给一个 -ro 或 -rw，否则沙箱里什么都打不开（这是「默认拒绝」的正常表现）。")
		os.Exit(2)
	}

	abi := requireLandlock()
	supported := landlock.SupportedFSAccess(abi)
	readOnly := landlock.AccessFSReadFile | landlock.AccessFSReadDir | landlock.AccessFSExecute

	r, err := landlock.CreateRuleset(supported, 0, 0)
	if err != nil {
		fatal(err)
	}
	for _, p := range ro {
		if err := r.AllowPath(p, readOnly); err != nil {
			fatal(err)
		}
	}
	for _, p := range rw {
		// 目录不存在就没法加规则，这里替用户建好（此时还没限制，建得出来）。
		if err := os.MkdirAll(p, 0o755); err != nil {
			fatal(err)
		}
		if err := r.AllowPath(p, supported); err != nil {
			fatal(err)
		}
	}

	// 先解析出可执行文件的绝对路径（在某些 -ro 配置下，PATH 里只有部分目录可读）。
	bin, err := exec.LookPath(cmdline[0])
	if err != nil {
		fatal(err)
	}

	if err := r.Restrict(); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "[ll] Landlock ABI %d 已生效：只读 %v，可写 %v\n", abi, ro, rw)

	// 用 execve 直接替换当前进程，这样被执行的程序就是沙箱进程本身。
	if err := syscall.Exec(bin, cmdline, os.Environ()); err != nil {
		fatal(err)
	}
}
