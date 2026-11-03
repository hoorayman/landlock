# 目标架构：Intel Mac 上的 Docker 默认是 linux/amd64；如果是 Apple Silicon 改成 arm64。
ARCH ?= amd64
IMAGE ?= alpine:3.18

GO ?= go
BIN := bin/ll-linux-$(ARCH)

# 容器里跑演示时的公共参数（挂载当前目录，工作目录设为 /w）
DOCKER := docker run --rm -v "$(CURDIR)":/w -w /w $(IMAGE)

.PHONY: help all abi fs net escape run shell linux darwin check clean

help:
	@echo "make abi        # 探测：内核 / LSM / Landlock ABI / 可用权限位"
	@echo "make fs         # 演示：文件系统权限（3 组对照实验）"
	@echo "make net        # 演示：TCP bind/connect 限制"
	@echo "make escape     # 演示：什么样绕不过去，什么样真能绕过"
	@echo "make all        # 依次跑上面四个"
	@echo "make run        # 用法: make run ARGS=\"-ro / -rw /tmp/sb -- sh -c 'id'\""
	@echo "make shell      # 进容器手动玩（容器内已挂载本项目到 /w）"
	@echo "make check      # gofmt + vet + 测试 + 双平台编译"
	@echo ""
	@echo "Linux 真机上可以直接: go build -o bin/ll ./cmd/ll && ./bin/ll all"

# 在 Linux 容器里跑（macOS 上最省事的方式；容器内核 5.13+ 即可）
abi fs net escape all: linux
	$(DOCKER) /w/$(BIN) $@

run: linux
	$(DOCKER) /w/$(BIN) run $(ARGS)

shell: linux
	docker run --rm -it -v "$(CURDIR)":/w -w /w $(IMAGE) sh

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) $(GO) build -trimpath -o $(BIN) ./cmd/ll

# macOS 上能编译，但运行时会告诉你「不支持」（Landlock 是 Linux 内核特性）
darwin:
	$(GO) build -trimpath -o bin/ll-darwin ./cmd/ll

check:
	gofmt -l .
	$(GO) vet ./...
	$(GO) test ./...
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) $(GO) build -trimpath -o /dev/null ./cmd/ll
	$(GO) build -trimpath -o /dev/null ./cmd/ll

clean:
	rm -rf bin
