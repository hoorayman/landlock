package main

import (
	"fmt"
	"os"
	"strings"

	"landlock/internal/landlock"
)

// cmdABI 只做只读探测：这个环境能不能用 Landlock、能用到什么程度。
func cmdABI() {
	sup := landlock.Detect()

	section("环境")
	note("平台          : %s/%s", sup.GOOS, sup.GOARCH)
	note("内核 release  : %s", sup.Kernel)
	if len(sup.LSMs) > 0 {
		note("已启用 LSM    : %s", strings.Join(sup.LSMs, ","))
		note("landlock 在列 : %v", sup.InLSMList())
	} else {
		note("已启用 LSM    : 读不到 /sys/kernel/security/lsm（容器里常见，不影响使用）")
	}

	if !sup.Enabled() {
		note("Landlock ABI  : 不可用（%v）", sup.ABIErr)
		fmt.Println(explainUnavailable(sup.ABIErr))
		os.Exit(1)
	}
	note("Landlock ABI  : %d", sup.ABI)

	section("ABI 演进：每一版新增的能力")
	for _, c := range landlock.ABIChanges() {
		state := "[不可用]"
		if c.ABI <= sup.ABI {
			state = "[ 可用 ]"
		}
		fmt.Printf("  %s ABI %d   Linux %-5s  %s\n", state, c.ABI, c.Kernel, c.Desc)
	}

	section("本内核可接管的文件系统权限（handled_access_fs 掩码 = 0x%04x）",
		uint64(landlock.SupportedFSAccess(sup.ABI)))
	fmt.Printf("  %s\n", landlock.SupportedFSAccess(sup.ABI))

	fmt.Println("\n  每个权限位：")
	fmt.Println("    名称           最低ABI   位")
	for _, row := range landlock.FSAccessTable() {
		fmt.Printf("    %-14s %-9s %s\n", row[0], row[1], row[2])
	}

	section("本内核可接管的网络权限（handled_access_net 掩码 = 0x%02x）",
		uint64(landlock.SupportedNetAccess(sup.ABI)))
	if n := landlock.SupportedNetAccess(sup.ABI); n == 0 {
		note("无（需要 ABI >= 4 / Linux 6.7+）")
	} else {
		fmt.Printf("  %s\n", n)
	}

	if s := landlock.SupportedScopes(sup.ABI); s != 0 {
		section("本内核支持的 scope（0x%02x）", uint64(s))
		fmt.Printf("  %s\n", s)
	}

	section("一句话总结")
	note("Landlock 是「非特权进程自己给自己戴的紧箍咒」：")
	note("  1) 你声明要管哪些权限（handled_*），只有这些权限会被拦；")
	note("  2) 声明了但没放行的，一律拒绝 —— 默认拒绝，不是默认放行；")
	note("  3) 一旦 restrict_self，不可撤销，且对子进程全部继承。")
}
