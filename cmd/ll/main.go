package main

import (
	"fmt"
	"os"
	"os/exec"
)

// stageEnv 是「子进程复用自己」的暗号。
//
// 为什么要 re-exec？因为 landlock_restrict_self 对当前进程永久生效、不可撤销，
// 一个进程里做完第一组实验就再也回不到「没有沙箱」的状态了。
// 所以每个演示都：父进程 → fork/exec 自己（带上环境变量）→ 子进程里应用规则并做实验。
const stageEnv = "LL_DEMO_STAGE"

const usage = `ll —— 用一个能跑的小工具讲清楚 Linux Landlock

用法:
  ll abi      探测：内核版本、LSM 列表、Landlock ABI、可用权限位
  ll fs       演示：文件系统权限是怎么被限制的（3 组对照实验）
  ll net      演示：TCP bind/connect 限制（需要 ABI >= 4）
  ll escape   演示：哪些绕过手法无效，哪些真的能绕过
  ll run      把任意命令关进 Landlock 沙箱里执行
  ll all      依次运行 abi / fs / net / escape

ll run 用法:
  ll run [-ro PATH]... [-rw PATH]... -- CMD [ARGS...]
    -ro PATH   该路径可读可执行（可重复，范围含整棵子树）
    -rw PATH   该路径全部权限（可重复，范围含整棵子树）
  没有被 -ro/-rw 覆盖的路径，全部拒绝。

  例：ll run -ro / -rw /tmp/sandbox -- sh -c 'cat /etc/hostname > /tmp/sandbox/a'

注意:
  Landlock 是 Linux 5.13+ 的内核 LSM，macOS/Windows 上没有，macOS 上请用
  make docker 在容器里跑（容器内核 >= 5.13 即可）。
`

func main() {
	// 父进程的run会设置好环境变量，所以子进程会走到这个if分支。子进程只做一件事：跑指定的那组实验，跑完退出。
	// 必须在分发命令之前拦截，否则子进程会把父进程的编排逻辑再跑一遍。
	if stage := os.Getenv(stageEnv); stage != "" {
		childStage(stage)
		return
	}

	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "abi":
		cmdABI()
	case "fs":
		cmdFS()
	case "net":
		cmdNet()
	case "escape":
		cmdEscape()
	case "run":
		cmdRun(os.Args[2:])
	case "all":
		runAll()
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n", os.Args[1])
		fmt.Print(usage)
		os.Exit(2)
	}
}

// runAll 依次执行每个演示。每个演示自己负责 fork 子进程，互不影响。
func runAll() {
	for _, name := range []string{"abi", "fs", "net", "escape"} {
		c := exec.Command(os.Args[0], name)
		c.Stdout, c.Stderr = os.Stdout, os.Stderr // 因为 os/exec 默认不继承父进程的 stdio —— Stdout 为 nil 时，子进程的 stdout 会被接到 /dev/null。所以加这行，父进程就能看到每个演示的输出。
		if err := c.Run(); err != nil {
			fmt.Printf("\n(命令 %q 退出：%v)\n", name, err)
		}
	}
	fmt.Println()
}
