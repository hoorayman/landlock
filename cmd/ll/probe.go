package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"landlock/internal/landlock"
)

// errDenied 用来标记「我们知道这是权限被拒，但错误不是直接的 errno」的情况
// （典型场景：exec 出去的子进程自己打印了 permission denied）。
var errDenied = errors.New("permission denied")

// ---------------------------------------------------------------------------
// 演示用的目录
// ---------------------------------------------------------------------------

func demoRoot() string    { return filepath.Join(os.TempDir(), "landlock-demo") }
func workDir() string     { return filepath.Join(demoRoot(), "work") }        // 白名单目录：放行
func secretFile() string  { return filepath.Join(demoRoot(), "secret.txt") }  // 白名单外：应被拒
func outsideFile() string { return filepath.Join(demoRoot(), "outside.txt") } // 白名单外：应被拒

// prepareDirs 由父进程（还没有任何限制时）调用，准备好演示用的文件和目录。
func prepareDirs() error {
	if err := os.MkdirAll(workDir(), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(secretFile(), []byte("TOP-SECRET\n"), 0o644); err != nil {
		return err
	}
	return os.WriteFile(outsideFile(), []byte("outside\n"), 0o644)
}

// ---------------------------------------------------------------------------
// 在「独立子进程」里应用 Landlock 并做实验
// ---------------------------------------------------------------------------

// sandbox 描述一次实验：apply 建规则集并 restrict_self，test 在沙箱里做试探。
//
// 为什么必须换进程：restrict_self 对当前进程永久生效、没有撤销接口。
// 如果在同一个进程里连着做几组实验，后一组会被前一组的规则污染，结论就不可信了。
type sandbox struct {
	stage string     // 暗号：写进环境变量，子进程据此知道自己该跑哪一组实验
	extra []*os.File // 额外传给子进程的 fd（从 3 开始），演示「继承的 fd 不受限」
	apply func() error
	test  func()
}

// run 在父进程里调用：fork/exec 自己，把 apply+test 交给子进程。
func (s sandbox) run() {
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), stageEnv+"="+s.stage)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	if len(s.extra) > 0 {
		cmd.ExtraFiles = s.extra
	}
	if err := cmd.Run(); err != nil {
		fmt.Printf("  !! 子进程异常退出: %v\n", err)
	}
}

// runChild 在子进程里调用：应用沙箱 → 做实验 → 退出。
func (s sandbox) runChild() {
	if err := s.apply(); err != nil {
		fmt.Printf("  !! 应用 Landlock 失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  -- 沙箱已生效（restrict_self 之后对本进程永久生效）--\n")
	s.test()
	os.Exit(0)
}

// childStage 是子进程的唯一入口：直接构造对应的实验，不去执行演示的编排代码
// （否则子进程会把父进程的打印、以及其它实验的 run() 再跑一遍，越套越深）。
func childStage(name string) {
	abi, err := landlock.ABI()
	if err != nil {
		fmt.Fprintf(os.Stderr, "子进程里 Landlock 不可用: %v\n", err)
		os.Exit(1)
	}
	switch name {
	case "fs-1":
		fs1().runChild()
	case "fs-2":
		fs2(abi).runChild()
	case "fs-3":
		fs3(abi).runChild()
	case "net-1":
		net1().runChild()
	case "net-2":
		net2().runChild()
	case "escape":
		escape(abi).runChild()
	default:
		fmt.Fprintf(os.Stderr, "未知的实验: %q\n", name)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// 输出辅助
// ---------------------------------------------------------------------------

func section(format string, a ...any) {
	fmt.Printf("\n== %s ==\n", fmt.Sprintf(format, a...))
}

func note(format string, a ...any) {
	fmt.Printf("  %s\n", fmt.Sprintf(format, a...))
}

// probe 执行一个动作，并报告 Landlock 有没有拦住它。
func probe(label string, fn func() error) {
	err := fn()
	switch {
	case err == nil:
		fmt.Printf("  [放行] %s\n", label)
	case isDenied(err):
		fmt.Printf("  [拦截] %s\n           %v\n", label, oneLine(err))
	default:
		// 比如「端口没人监听 → connection refused」，说明请求真的发出去了。
		fmt.Printf("  [放行] %s\n           （错误与 Landlock 无关：%v）\n", label, oneLine(err))
	}
}

func isDenied(err error) bool {
	return errors.Is(err, errDenied) ||
		errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EPERM) ||
		errors.Is(err, os.ErrPermission)
}

// oneLine 把 exec 带回来的多行错误压成一行，便于阅读。
func oneLine(err error) string {
	s := strings.TrimSpace(strings.ReplaceAll(err.Error(), "\n", " | "))
	const max = 160
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "错误: %v\n", err)
	os.Exit(1)
}

// ---------------------------------------------------------------------------
// 支持性检查
// ---------------------------------------------------------------------------

// requireLandlock 在 Landlock 不可用时打印诊断信息并退出。
func requireLandlock() int {
	abi, err := landlock.ABI()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Landlock 不可用：%v\n", err)
		fmt.Fprintln(os.Stderr, explainUnavailable(err))
		os.Exit(1)
	}
	return abi
}

func explainUnavailable(err error) string {
	switch {
	case errors.Is(err, landlock.ErrUnsupported):
		return "  → 当前不是 Linux。Landlock 是 Linux 内核特性，macOS 上没有，\n" +
			"    可以用 Docker 跑一个 Linux 5.13+ 内核（见 README / make docker）。"
	case errors.Is(err, syscall.ENOSYS):
		return "  → 内核里没有 landlock 这三个系统调用：Linux 版本低于 5.13。"
	case errors.Is(err, syscall.EOPNOTSUPP):
		return "  → 内核有这个系统调用，但 Landlock LSM 没启用（CONFIG_LSM / lsm= 启动参数）。"
	default:
		return "  → " + err.Error()
	}
}
