package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"landlock/internal/landlock"
)

// cmdEscape 专门回答两个问题：
//   - 「沙箱里的程序能不能自己想办法绕出去？」
//   - 「Landlock 到底防不住什么？」
func cmdEscape() {
	abi := requireLandlock()
	if err := prepareDirs(); err != nil {
		fatal(err)
	}

	sb := escape(abi)

	// 父进程（尚未受限）先把 secret 打开，把 fd 交给子进程：
	// 用来演示「restrict 之前就打开的 fd」这个缺口。
	f, err := os.Open(secretFile())
	if err != nil {
		fatal(err)
	}
	sb.extra = []*os.File{f} // 到了子进程里它是 fd 3

	note("沙箱配置：handled = 全部文件系统权限")
	note("  放行：%s → 只读+执行", strings.Join(systemDirs, " "))
	note("  放行：/proc → 只读+执行（为了演示 /proc 相关绕过手法）")
	note("  放行：%s → 全部权限", workDir())
	note("  目标：读 %s（它所在的目录不在白名单里）", secretFile())

	sb.run()

	section("小结")
	note("前三类全都失败：Landlock 的检查在 VFS 层，路径怎么绕、进程怎么 fork 都躲不开。")
	note("最后一类成功：fd 一旦打开，权限就已经定了 —— 这是实现沙箱时必须堵的口子。")
}

// escape 的沙箱配置：系统目录只读，work 目录可写，secret 所在目录不在白名单里。
func escape(abi int) sandbox {
	supported := landlock.SupportedFSAccess(abi)
	readOnly := readOnlyFS()
	allow := append(append([]string{}, systemDirs...), "/proc")

	return sandbox{
		stage: "escape",
		apply: func() error {
			r, err := landlock.CreateRuleset(supported, 0, 0)
			if err != nil {
				return err
			}
			for _, p := range allow {
				if _, statErr := os.Stat(p); statErr != nil {
					continue // 这个发行版没有这个目录
				}
				if err := r.AllowPath(p, readOnly); err != nil {
					return err
				}
			}
			if err := r.AllowPath(workDir(), supported); err != nil {
				return err
			}
			return r.Restrict()
		},
		test: testEscape,
	}
}

func testEscape() {
	// -----------------------------------------------------------------
	section("一、常规硬读：全部失败")
	// -----------------------------------------------------------------
	probe("直接 open(secret.txt)", readFile(secretFile()))

	probe("先 chdir 到 secret 所在目录，再用相对路径打开", func() error {
		if err := os.Chdir(demoRoot()); err != nil {
			return err
		}
		_, err := os.Open("secret.txt")
		return err
	})

	probe("借道 /proc/self/root 读（绕路解析到同一个 inode）", func() error {
		_, err := os.ReadFile("/proc/self/root" + secretFile())
		return err
	})

	probe("在 work 里建符号链接指向 secret，再读链接", func() error {
		link := filepath.Join(workDir(), "link-to-secret")
		os.Remove(link)
		if err := os.Symlink(secretFile(), link); err != nil {
			return err // 建链接本身允许（work 有 MAKE_SYM），失败说明是别的问题
		}
		_, err := os.ReadFile(link)
		return err
	})

	probe("exec /bin/cat 让子进程去读（domain 被继承）", func() error {
		cmd := exec.Command("/bin/cat", secretFile())
		cmd.Stdin = os.Stdin // 避免 os/exec 去打开 /dev/null（那个 open 也会被检查）
		out, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		msg := strings.TrimSpace(string(out))
		if strings.Contains(strings.ToLower(msg), "permission denied") {
			return fmt.Errorf("%w: %s", errDenied, msg)
		}
		return fmt.Errorf("%v: %s", err, msg)
	})

	// -----------------------------------------------------------------
	section("二、试图解除或放宽限制：做不到")
	// -----------------------------------------------------------------
	probe("再 Restrict 一层「允许读 secret」的规则集，然后重试", func() error {
		r, err := landlock.CreateRuleset(landlock.AccessFSReadFile, 0, 0)
		if err != nil {
			return err
		}
		// 用 O_PATH 打开被拒绝的文件是允许的（只取 inode 身份、不要读权限），
		// 所以这一层规则集能建、也能挂上去 —— 但它不可能放开第一层的拒绝。
		if err := r.AllowPath(secretFile(), landlock.AccessFSReadFile); err != nil {
			return err
		}
		if err := r.Restrict(); err != nil {
			return err
		}
		_, err = os.ReadFile(secretFile())
		return err
	})
	note("→ 多层规则集是「取交集」：新的 domain 只能更严，永远不能更松。")
	note("→ 内核也没有提供任何「卸载规则集」的接口，restrict_self 是单向门。")
	note("→ 最多叠 16 层，再多就 E2BIG。")

	if nnp, err := landlock.NoNewPrivs(); err == nil {
		note("→ NoNewPrivs = %v（Landlock 强制为 1：setuid/setgid/文件 capability 全部失效）", nnp)
	}

	// -----------------------------------------------------------------
	section("三、真正能绕过去的：restrict 之前就打开的 fd")
	// -----------------------------------------------------------------
	probe("直接读继承来的 fd 3（父进程在 restrict 前打开）", func() error {
		f := os.NewFile(3, "inherited-secret")
		if f == nil {
			return errors.New("没有继承到 fd 3")
		}
		// 故意不 Close：下面那个 /proc/self/fd/3 的探测还要用它。
		b, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		if len(b) == 0 {
			return errors.New("fd 3 是空的")
		}
		return nil
	})

	probe("用 /proc/self/fd/3 重新打开同一个文件", readFile("/proc/self/fd/3"))

	note("→ 因为检查点在 open(2)，不是 read(2)：fd 一旦打开，权限就已经定了。")
	note("→ 想拿 /proc/self/fd/N 重新 open 一遍也没用，内核会重新做一次检查。")
	note("→ 所以真正的沙箱要在 restrict_self 之前关掉所有不需要的 fd。")

	// -----------------------------------------------------------------
	section("四、Landlock 管不到的东西")
	// -----------------------------------------------------------------
	note("· 没写进 handled_* 的权限完全不拦（ABI 1~3 连网络都没有）。")
	note("· ABI 4~9 只管 TCP 的 bind/connect；UDP、ICMP、raw socket 不管。")
	note("· 已经打开的一切 fd（终端、日志、socket、共享内存）。")
	note("· chdir/stat/chmod/chown/setxattr/utime/access —— 这些至今不在权限位里。")
	note("· ptrace、进程间发信号（ABI 6 的 scoped 管一部分）、namespace、cgroup、资源用量。")
	note("· 单个进程的「自我约束」：沙箱里的程序只能被限制得更严，出不去。")
}
