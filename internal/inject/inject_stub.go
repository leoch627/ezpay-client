//go:build !windows

package inject

import (
	"fmt"

	"wxhook/internal/model"
)

// stub 是给非 Windows 目标的实现。
//
// 存在的意义不是"功能降级"，而是让 go build ./... 在任意平台都能过：
// 本项目的表单层（httpapi / monitor / store）与平台无关，
// 只有 DLL 调用这一段需要 Windows。CI 上跑 go vet / 单元测试时走这里。
//
// 所有方法都返回明确 error，绝不返回零值假装成功 ——
// 上层能靠 error 判断"这个平台没有注入能力"，而不是看到一个 attached=false 的假状态。
type stub struct{}

func open(string) (Injector, error) {
	return stub{}, nil
}

func (stub) Available() bool   { return false }
func (stub) DLLPath() string   { return "" }

func (stub) InjectDLL(pid uint32, dllPath string) error {
	return fmt.Errorf("%w: InjectDLL(pid=%d, %s)", ErrUnsupported, pid, dllPath)
}

func (stub) FindProcessByName(exeName string) ([]uint32, error) {
	return nil, fmt.Errorf("%w: FindProcessByName(%s)", ErrUnsupported, exeName)
}

func (stub) GetModuleBase(pid uint32, moduleName string) (uint64, error) {
	return 0, fmt.Errorf("%w: GetModuleBase(pid=%d, %s)", ErrUnsupported, pid, moduleName)
}

func (stub) FindWeChatExe() (string, error) {
	return "", fmt.Errorf("%w: FindWeChatExe", ErrUnsupported)
}

func (stub) ReadHookStatus() (model.HookStatus, error) {
	return model.HookStatus{}, fmt.Errorf("%w: ReadHookStatus", ErrUnsupported)
}
