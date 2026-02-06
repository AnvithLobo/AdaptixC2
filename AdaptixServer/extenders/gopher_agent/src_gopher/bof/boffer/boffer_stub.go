//go:build !windows

package boffer

var (
	RegisterJobFunc func(taskId uint32, hProcess uintptr, pid uint16, hPipeRead uintptr, hPipeWrite uintptr) bool
	CurrentTaskID   uint32 = 0
)
