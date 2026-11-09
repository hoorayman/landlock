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
// 标准 flag 一个名字只能绑一个值（fs.String("ro", ...) 只能拿到最后一次）。要“可重复”就得让目标类型自己实现 flag.Value 接口（String() + Set(string)）
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
	// NewFlagSet 给 run 单独一套flag。
	// flag.ExitOnError 的含义：解析出错时直接 os.Exit(2) 并打印 usage
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var ro, rw pathList
	fs.Var(&ro, "ro", "该路径可读+可执行（可重复，包含整棵子树）") // 注册：名字 "ro" 绑定到 &ro
	fs.Var(&rw, "rw", "该路径拥有全部权限（可重复，包含整棵子树）")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "用法: ll run [-ro PATH]... [-rw PATH]... -- CMD [ARGS...]")
		fs.PrintDefaults() // 这是 Go flag 包自带的“帮助文本生成器”：遍历这个 FlagSet 里注册过的所有 flag
	}
	if err := fs.Parse(args); err != nil { // fs.Parse(args)解析：args 是 os.Args[2:]
		fatal(err)
	}
	cmdline := fs.Args() // fs.Args()是剩余：非 flag 的那些参数
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

	// execve 不做 PATH 查找，所以要先把 "sh" 这种裸名字解析成 "/bin/sh"。
	// （Landlock 不管 stat，这一步放 Restrict 前后都能用；放前面更符合「先准备、后收窄」。）
	// 注意：LookPath 按 $PATH 顺序搜索，PATH 里有可写目录时可能选中不该执行的二进制。
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
