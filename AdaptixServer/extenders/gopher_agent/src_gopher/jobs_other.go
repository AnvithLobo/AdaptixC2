//go:build !windows
// +build !windows

package main

import "gopher/utils"

// ProcessJobs stub for non-Windows platforms
var ProcessJobs []utils.ProcessJobData

// registerProcessJob stub for non-Windows platforms
func registerProcessJob(taskId uint32, hProcess uintptr, pid uint16, hPipeRead uintptr, hPipeWrite uintptr) bool {
	// Process jobs are Windows-specific
	return false
}

// IsProcessJobRunning stub for non-Windows platforms
func IsProcessJobRunning(taskId uint32) bool {
	return false
}

// PollProcessJobs stub for non-Windows platforms
func PollProcessJobs() [][]byte {
	// Process jobs are Windows-specific
	return nil
}

// killProcessJob stub for non-Windows platforms
func killProcessJob(taskId string) bool {
	return false
}
