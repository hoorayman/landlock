package landlock

import "testing"

// 这些测试只验证「纯逻辑」部分（权限位掩码），任何平台都能跑。
// 真正的系统调用行为需要 Linux 5.13+，见 cmd/ll 的演示（make abi 等）。

func TestSupportedFSAccess(t *testing.T) {
	tests := []struct {
		abi  int
		want FSAccess
	}{
		{1, 0x1fff}, // 13 个基础位
		{2, 0x3fff}, // + REFER
		{3, 0x7fff}, // + TRUNCATE
		{4, 0x7fff}, // 网络，不影响 FS
		{5, 0xffff}, // + IOCTL_DEV
		{6, 0xffff},
		{8, 0xffff},
	}
	for _, tc := range tests {
		if got := SupportedFSAccess(tc.abi); got != tc.want {
			t.Errorf("SupportedFSAccess(%d) = 0x%04x, want 0x%04x", tc.abi, uint64(got), uint64(tc.want))
		}
	}
}

func TestSupportedNetAccess(t *testing.T) {
	if got := SupportedNetAccess(3); got != 0 {
		t.Errorf("ABI 3 不该有网络权限，得到 %s", got)
	}
	if got := SupportedNetAccess(4); got != AccessNetBindTCP|AccessNetConnectTCP {
		t.Errorf("ABI 4 应该有 BIND_TCP|CONNECT_TCP，得到 %s", got)
	}
}

func TestSupportedScopes(t *testing.T) {
	if got := SupportedScopes(5); got != 0 {
		t.Errorf("ABI 5 不该有 scope，得到 %s", got)
	}
	if got := SupportedScopes(6); got != ScopeAbstractUnixSocket|ScopeSignal {
		t.Errorf("ABI 6 应该有两个 scope，得到 %s", got)
	}
}

func TestFSAccessString(t *testing.T) {
	got := (AccessFSReadFile | AccessFSWriteFile | AccessFSMakeReg).String()
	want := "WRITE_FILE|READ_FILE|MAKE_REG"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// ABI 表必须是单调递增的，且不能有洞 —— 因为 SupportedFSAccess 依赖 abi 比较。
func TestABIChangesMonotonic(t *testing.T) {
	changes := ABIChanges()
	for i, c := range changes {
		if c.ABI != i+1 {
			t.Fatalf("ABIChanges()[%d].ABI = %d, want %d", i, c.ABI, i+1)
		}
		if c.Desc == "" {
			t.Errorf("ABI %d 缺少描述", c.ABI)
		}
	}
}
