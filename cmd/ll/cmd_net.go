package main

import (
	"net"
	"os"
	"path/filepath"
	"time"

	"landlock/internal/landlock"
)

// cmdNet 演示 ABI 4（Linux 6.7）起的网络规则：只覆盖 TCP 的 bind / connect。
func cmdNet() {
	abi := requireLandlock()
	if abi < 4 {
		section("网络规则需要 ABI >= 4（Linux 6.7+）")
		note("当前 ABI = %d，这台机器的 Landlock 管不了网络。", abi)
		note("文件系统部分仍然可用：ll fs")
		return
	}

	section("对照组：没有 Landlock 时")
	note("注意 connect 的结果：端口没人监听 → connection refused，说明请求确实发出去了。")
	probe("connect 127.0.0.1:1", dialTCP("127.0.0.1:1"))
	probe("listen 127.0.0.1:0（随机端口）", listenTCP())
	probe("UDP 发送到 127.0.0.1:9", udpSend())

	section("实验 1/2：handled = BIND_TCP|CONNECT_TCP，没有放行任何端口")
	note("要点：网络规则是「按端口白名单」，没列出的端口全部拒绝。")
	net1().run()

	section("实验 2/2：只放行 127.0.0.1:8080 的 connect")
	note("放行后 8080 会变成 connection refused（请求发出去了），其它端口仍然是 permission denied。")
	net2().run()

	section("结论与边界")
	note("1) ABI 4~9 的网络能力只有两个位：BIND_TCP / CONNECT_TCP，而且只认端口。")
	note("2) UDP 要等到 ABI 10 才有 BIND_UDP / CONNECT_SEND_UDP；ICMP、raw socket 至今不管。")
	note("3) unix socket 走的是文件系统（MAKE_SOCK）和 ABI 6 的 scoped，不在网络规则里。")
	note("4) 想按 IP / 域名 / 协议限制？Landlock 做不到，它连 IP 都不看，得靠 netns + 防火墙。")
}

// ---------------------------------------------------------------------------
// 实验定义
// ---------------------------------------------------------------------------

func net1() sandbox {
	return sandbox{
		stage: "net-1",
		apply: func() error {
			r, err := landlock.CreateRuleset(0, landlock.AccessNetBindTCP|landlock.AccessNetConnectTCP, 0)
			if err != nil {
				return err
			}
			return r.Restrict() // 一条端口规则都不加 → 全部拒绝
		},
		test: func() {
			probe("connect 127.0.0.1:1", dialTCP("127.0.0.1:1"))
			probe("connect 127.0.0.1:8080", dialTCP("127.0.0.1:8080"))
			probe("listen 127.0.0.1:0", listenTCP())
			probe("UDP 发送到 127.0.0.1:9（这版 ABI 不管 UDP）", udpSend())
			probe("unix socket listen（走文件系统规则，不走网络规则）", unixListen())
		},
	}
}

func net2() sandbox {
	return sandbox{
		stage: "net-2",
		apply: func() error {
			r, err := landlock.CreateRuleset(0, landlock.AccessNetBindTCP|landlock.AccessNetConnectTCP, 0)
			if err != nil {
				return err
			}
			if err := r.AllowPort(8080, landlock.AccessNetConnectTCP); err != nil {
				return err
			}
			return r.Restrict()
		},
		test: func() {
			probe("connect 127.0.0.1:1（未放行）", dialTCP("127.0.0.1:1"))
			probe("connect 127.0.0.1:8080（已放行）", dialTCP("127.0.0.1:8080"))
			probe("listen 127.0.0.1:8080（放行的只是 CONNECT_TCP）", listenTCPPort("127.0.0.1:8080"))
		},
	}
}

// ---------------------------------------------------------------------------
// 网络动作
// ---------------------------------------------------------------------------

func dialTCP(addr string) func() error {
	return func() error {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			return err
		}
		return c.Close()
	}
}

func listenTCP() func() error { return listenTCPPort("127.0.0.1:0") }

func listenTCPPort(addr string) func() error {
	return func() error {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		return l.Close()
	}
}

func udpSend() func() error {
	return func() error {
		c, err := net.Dial("udp", "127.0.0.1:9")
		if err != nil {
			return err
		}
		defer c.Close()
		_, err = c.Write([]byte("ping"))
		return err
	}
}

func unixListen() func() error {
	return func() error {
		path := filepath.Join(demoRoot(), "demo.sock")
		os.Remove(path)
		if err := os.MkdirAll(demoRoot(), 0o755); err != nil {
			return err
		}
		l, err := net.Listen("unix", path)
		if err != nil {
			return err
		}
		// Close 时 Go 会自动 unlink 掉 socket 文件，所以这里不用再删。
		return l.Close()
	}
}
