package main

import (
	"os"
	"os/exec"
	"path/filepath"

	"landlock/internal/landlock"
)

// readOnlyFS 是「只读」的权限组合：能读文件内容、能列目录、能执行，
// 不含任何写 / 建 / 删 / truncate 权限。
func readOnlyFS() landlock.FSAccess {
	return landlock.AccessFSReadFile | landlock.AccessFSReadDir | landlock.AccessFSExecute
}

// systemDirs 是让程序能正常跑起来所需的那批系统目录。
var systemDirs = []string{"/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc"}

// cmdFS 用三组对照实验讲文件系统权限。
func cmdFS() {
	abi := requireLandlock()
	if err := prepareDirs(); err != nil {
		fatal(err)
	}

	note("演示目录：")
	note("  白名单目录 = %s", workDir())
	note("  白名单之外 = %s", outsideFile())

	// -------- 实验 1 --------
	section("实验 1/3：handled = READ_FILE 一个位")
	note("要点：Landlock 只拦「你点名要管」的权限。没点名的写文件、列目录、执行，一点不受影响。")
	fs1().run()

	// -------- 实验 2 --------
	section("实验 2/3：handled = 全部文件系统权限，只放行 %s", workDir())
	note("这才是安全意义上的「沙箱」：默认全禁，白名单之外一律 EACCES。")
	fs2(abi).run()

	// -------- 实验 3 --------
	section("实验 3/3：全盘只读 + %s 可读写", workDir())
	note("规则之间是「取并集」：\"/\" 给只读，workDir 给全部，合起来就是「到处能读，只有这里能写」。")
	fs3(abi).run()

	section("三组实验的结论")
	note("1) handled 之外的权限 = 完全不限制。所以「只写了 READ_FILE 就以为万事大吉」是常见误解。")
	note("2) handled 之内的权限 = 默认拒绝，只能被 AllowPath 逐个放开（fail-closed）。")
	note("3) 多条规则取并集；不同的规则集（多次 Restrict）取交集。前者放松，后者只能收紧。")
	note("4) exec 一个外部程序要同时满足：READ_FILE（读二进制和动态库）+ EXECUTE（执行权限）。")
}

// ---------------------------------------------------------------------------
// 三组实验的定义（父进程和子进程共用）
// ---------------------------------------------------------------------------

func fs1() sandbox {
	return sandbox{
		stage: "fs-1",
		apply: func() error {
			// 只声明「我要管 READ_FILE」，别的权限一概不管。
			r, err := landlock.CreateRuleset(landlock.AccessFSReadFile, 0, 0)
			if err != nil {
				return err
			}
			// 给系统目录放行 READ_FILE：够程序启动、够读二进制，
			// 但 demoRoot 一个字节都不放开。
			for _, p := range systemDirs {
				if _, statErr := os.Stat(p); statErr != nil {
					continue
				}
				if err := r.AllowPath(p, landlock.AccessFSReadFile); err != nil {
					return err
				}
			}
			return r.Restrict()
		},
		test: func() {
			probe("读 outside.txt（READ_FILE 被管、该路径没放行）", readFile(outsideFile()))
			probe("读 /etc/hostname（该路径放行了 READ_FILE）", readFile("/etc/hostname"))
			probe("写 work/f1.txt（WRITE_FILE 没声明 → 不受管）", writeFile(filepath.Join(workDir(), "f1.txt")))
			probe("列目录 work（READ_DIR 没声明 → 不受管）", readDir(workDir()))
			probe("执行 /bin/echo（EXECUTE 没声明 → 不受管）", execEcho)
		},
	}
}

func fs2(abi int) sandbox {
	supported := landlock.SupportedFSAccess(abi)
	return sandbox{
		stage: "fs-2",
		apply: func() error {
			r, err := landlock.CreateRuleset(supported, 0, 0)
			if err != nil {
				return err
			}
			if err := r.AllowPath(workDir(), supported); err != nil {
				return err
			}
			return r.Restrict()
		},
		test: func() {
			probe("读 outside.txt（白名单外）", readFile(outsideFile()))
			probe("列目录 /（白名单外）", readDir("/"))
			probe("写 work/f2.txt（白名单内）", writeFile(filepath.Join(workDir(), "f2.txt")))
			probe("读 work/f2.txt（白名单内）", readFile(filepath.Join(workDir(), "f2.txt")))
			probe("mkdir work/sub（白名单内）", func() error {
				return os.MkdirAll(filepath.Join(workDir(), "sub"), 0o755)
			})
			probe("删除 work/f2.txt（白名单内）", func() error {
				return os.Remove(filepath.Join(workDir(), "f2.txt"))
			})
			probe("写 demoRoot 下的新文件（白名单外）", writeFile(filepath.Join(demoRoot(), "f2-escape.txt")))
			probe("执行 /bin/echo（EXECUTE 未对任何路径放行）", execEcho)
		},
	}
}

func fs3(abi int) sandbox {
	supported := landlock.SupportedFSAccess(abi)
	return sandbox{
		stage: "fs-3",
		apply: func() error {
			r, err := landlock.CreateRuleset(supported, 0, 0)
			if err != nil {
				return err
			}
			// 规则一：整个文件系统只读。
			if err := r.AllowPath("/", readOnlyFS()); err != nil {
				return err
			}
			// 规则二：work 目录全部权限。两条规则取并集。
			if err := r.AllowPath(workDir(), supported); err != nil {
				return err
			}
			return r.Restrict()
		},
		test: func() {
			probe("读 outside.txt（/ 只读 → 可以读）", readFile(outsideFile()))
			probe("列目录 /etc（/ 放行了 READ_DIR）", readDir("/etc"))
			probe("读 /etc/hostname", readFile("/etc/hostname"))
			probe("执行 /bin/echo（/ 放行了 EXECUTE）", execEcho)
			probe("写 work/f3.txt（workDir 全部权限）", writeFile(filepath.Join(workDir(), "f3.txt")))
			probe("写 demoRoot 下的新文件（/ 只给了只读）", writeFile(filepath.Join(demoRoot(), "f3-escape.txt")))
			probe("删除 outside.txt（REMOVE_FILE 对 / 未放行）", func() error {
				return os.Remove(outsideFile())
			})
			probe("truncate outside.txt（对 / 未放行 TRUNCATE）", func() error {
				return os.Truncate(outsideFile(), 0)
			})
		},
	}
}

// ---------------------------------------------------------------------------
// 动作集合
// ---------------------------------------------------------------------------

func readFile(path string) func() error {
	return func() error {
		_, err := os.ReadFile(path)
		return err
	}
}

func writeFile(path string) func() error {
	return func() error {
		return os.WriteFile(path, []byte("hello\n"), 0o644)
	}
}

func readDir(path string) func() error {
	return func() error {
		_, err := os.ReadDir(path)
		return err
	}
}

// execEcho 演示「exec 一个外部程序」。
//
// 这里必须显式给 Stdin 赋值：os/exec 在 Stdin 为 nil 时会打开 /dev/null，
// 而那个 open(2) 同样会被 Landlock 检查。踩过这个坑就会看到莫名其妙的
// "open /dev/null: permission denied"，而其实要 exec 的程序根本没启动。
func execEcho() error {
	cmd := exec.Command("/bin/echo", "echo 被执行了")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}
