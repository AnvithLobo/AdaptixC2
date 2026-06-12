// Ref: https://github.com/praetorian-inc/goffloader

package coffer

import (
	_ "embed"
	"fmt"
	"gopher/utils"
	"strings"
	"syscall"
	"unsafe"

	"gopher/bof/binutil"
	"gopher/bof/boffer"
	"gopher/bof/defwin"
	"gopher/bof/memory"

	"golang.org/x/sys/windows"
)

const (
	MEM_COMMIT             = windows.MEM_COMMIT
	MEM_RESERVE            = windows.MEM_RESERVE
	MEM_TOP_DOWN           = windows.MEM_TOP_DOWN
	PAGE_EXECUTE_READWRITE = windows.PAGE_EXECUTE_READWRITE
	// PAGE_EXECUTE_READ is a Windows constant used with Windows API calls
	PAGE_EXECUTE_READ = windows.PAGE_EXECUTE_READ
	// PAGE_READWRITE is a Windows constant used with Windows API calls
	PAGE_READWRITE = windows.PAGE_READWRITE
)

var (
	kernel32                = syscall.MustLoadDLL("kernel32.dll")
	procVirtualAlloc        = kernel32.MustFindProc("VirtualAlloc")
	procVirtualFree         = kernel32.MustFindProc("VirtualFree")
	procVirtualProtect      = kernel32.MustFindProc("VirtualProtect")
	procCreateThread        = kernel32.MustFindProc("CreateThread")
	procWaitForSingleObject = kernel32.MustFindProc("WaitForSingleObject")
	procCloseHandle         = kernel32.MustFindProc("CloseHandle")
)

const (
	MEM_RELEASE = 0x8000
)

type AsyncContext struct {
	WakeupFunc func()
	StopEvent  windows.Handle
}

func resolveExternalAddress(symbolName string, outChannel chan<- interface{}, asyncCtx *AsyncContext) uintptr {
	if strings.HasPrefix(symbolName, "__imp_") {
		symbolName = symbolName[6:]
		// 32 bit import names are __imp__
		symbolName = strings.TrimPrefix(symbolName, "_")

		libName := ""
		procName := ""

		// If we're following Dynamic Function Resolution Naming Conventions
		if len(strings.Split(symbolName, "$")) == 2 {
			libName = strings.Split(symbolName, "$")[0] + ".dll"
			procName = strings.Split(symbolName, "$")[1]
		} else {
			procName = symbolName

			switch procName {
			case "FreeLibrary", "LoadLibraryA", "GetProcAddress", "GetModuleHandleA", "GetModuleFileNameA":
				libName = "kernel32.dll"
			case "MessageBoxA":
				libName = "user32.dll"
			case string("BeaconOutput"):
				return windows.NewCallback(boffer.GetCoffOutputForChannel(outChannel))
			case string("BeaconDataParse"):
				return windows.NewCallback(boffer.DataParse)
			case string("BeaconDataInt"):
				return windows.NewCallback(boffer.DataInt)
			case string("BeaconDataShort"):
				return windows.NewCallback(boffer.DataShort)
			case string("BeaconDataLength"):
				return windows.NewCallback(boffer.DataLength)
			case string("BeaconDataExtract"):
				return windows.NewCallback(boffer.DataExtract)
			case string("BeaconPrintf"):
				return windows.NewCallback(boffer.GetCoffPrintfForChannel(outChannel))
			case string("BeaconAddValue"):
				return windows.NewCallback(boffer.AddValue)
			case string("BeaconGetValue"):
				return windows.NewCallback(boffer.GetValue)
			case string("BeaconRemoveValue"):
				return windows.NewCallback(boffer.RemoveValue)
			case string("BeaconFormatAlloc"):
				return windows.NewCallback(boffer.FormatAllocate)
			case string("BeaconFormatReset"):
				return windows.NewCallback(boffer.FormatReset)
			case string("BeaconFormatAppend"):
				return windows.NewCallback(boffer.FormatAppend)
			case string("BeaconFormatFree"):
				return windows.NewCallback(boffer.FormatFree)
			case string("BeaconFormatInt"):
				return windows.NewCallback(boffer.FormatInt)
			case string("BeaconFormatPrintf"):
				return windows.NewCallback(boffer.FormatPrintfFunc)
			case string("BeaconFormatToString"):
				return windows.NewCallback(boffer.FormatToString)
			case string("BeaconUseToken"):
				return windows.NewCallback(boffer.UseToken)
			case string("BeaconRevertToken"):
				return windows.NewCallback(boffer.RevertToken)
			case string("BeaconIsAdmin"):
				return windows.NewCallback(boffer.IsAdmin)
			case string("toWideChar"):
				return windows.NewCallback(boffer.ToWideChar)
			case string("BeaconGetSpawnTo"):
				fallthrough
			case string("BeaconGetSpawnTemporaryProcess"):
				fallthrough
			case string("BeaconInjectProcess"):
				fallthrough
			case string("BeaconInjectTemporaryProcess"):
				fallthrough
			case string("BeaconCleanupProcess"):
				fallthrough
			case string("AxAddScreenshot"):
				return windows.NewCallback(boffer.AxAddScreenshot(outChannel))
			case string("AxDownloadMemory"):
				return windows.NewCallback(boffer.AxDownloadMemory(outChannel))
			case string("BeaconWakeup"):
				if asyncCtx != nil {
					return windows.NewCallback(boffer.GetBeaconWakeup(asyncCtx.WakeupFunc))
				}
				return windows.NewCallback(func() uintptr { return 0 })
			case string("BeaconGetStopJobEvent"):
				if asyncCtx != nil {
					return windows.NewCallback(boffer.GetBeaconGetStopJobEvent(asyncCtx.StopEvent))
				}
				return windows.NewCallback(func() uintptr { return 0 })
			default:
				fmt.Printf("Unknown symbol: %s\n", procName)
				return 0
			}
		}

		libStringPtr, _ := syscall.LoadLibrary(libName)
		procAddress, _ := syscall.GetProcAddress(libStringPtr, procName)
		return procAddress
	}
	return 0
}

func virtualAlloc(lpAddress uintptr, dwSize uintptr, flAllocationType uint32, flProtect uint32) (uintptr, error) {
	ret, _, err := procVirtualAlloc.Call(
		lpAddress,
		dwSize,
		uintptr(flAllocationType),
		uintptr(flProtect),
	)
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

func isSpecialSymbol(sym *SymbolParsed) bool {
	return sym.StorageClass == defwin.IMAGE_SYM_CLASS_EXTERNAL && sym.SectionNumber == 0
}

func isImportSymbol(sym *SymbolParsed) bool {
	return strings.HasPrefix(sym.NameString(), "__imp_")
}

func processRelocation(symbolDefAddress uintptr, sectionAddress uintptr, reloc defwin.Relocation, symbol *SymbolParsed) {
	symbolOffset := (uintptr)(reloc.VirtualAddress)

	absoluteSymbolAddress := symbolOffset + sectionAddress

	segmentValue := *(*uint32)(unsafe.Pointer(absoluteSymbolAddress))

	if (symbol.StorageClass == defwin.IMAGE_SYM_CLASS_STATIC && symbol.Value != 0) ||
		(symbol.StorageClass == defwin.IMAGE_SYM_CLASS_EXTERNAL && symbol.SectionNumber != 0) {
		symbolOffset = (uintptr)(symbol.Value)
	} else {
		symbolDefAddress += (uintptr)(segmentValue)
	}

	symbolRefAddress := sectionAddress

	//TODO: Handle x86 cases as well
	switch reloc.Type {
	case defwin.IMAGE_REL_AMD64_ADDR64:
		addr := (*uint64)(unsafe.Pointer(absoluteSymbolAddress))
		fmt.Sprintf("Symbol Ref Address: 0x%x\n", addr)
		*addr = uint64(symbolDefAddress)
	case defwin.IMAGE_REL_AMD64_ADDR32NB:
		addr := (*uint32)(unsafe.Pointer(absoluteSymbolAddress))
		valueToWrite := symbolDefAddress - (symbolRefAddress + 4 + symbolOffset)
		fmt.Sprintf("Symbol Ref Address: 0x%x\n", addr)
		*addr = uint32(valueToWrite)
	case defwin.IMAGE_REL_AMD64_REL32, defwin.IMAGE_REL_AMD64_REL32_1, defwin.IMAGE_REL_AMD64_REL32_2, defwin.IMAGE_REL_AMD64_REL32_3, defwin.IMAGE_REL_AMD64_REL32_4, defwin.IMAGE_REL_AMD64_REL32_5:
		relativeSymbolDefAddress := symbolDefAddress - (uintptr)(reloc.Type-4) - (absoluteSymbolAddress + 4)
		addr := (*uint32)(unsafe.Pointer(absoluteSymbolAddress))
		fmt.Sprintf("Symbol Ref Address: 0x%x\n", addr)
		*addr = uint32(relativeSymbolDefAddress)
	default:
		fmt.Printf("Unsupported relocation type: %d\n", reloc.Type)
	}
}

type CoffSection struct {
	Section *Section
	Address uintptr
}

func Load(coffBytes []byte, argBytes []byte) ([]utils.BofMsg, error) {
	return LoadWithMethod(coffBytes, argBytes, "go")
}

func LoadWithMethod(coffBytes []byte, argBytes []byte, method string) ([]utils.BofMsg, error) {
	output := make(chan interface{})

	parsedCoff := Explore(binutil.WrapByteSlice(coffBytes))
	parsedCoff.ReadAll()
	parsedCoff.Seal()

	sections := make(map[string]CoffSection, parsedCoff.Sections.Len())

	gotBaseAddress := uintptr(0)
	gotOffset := 0
	gotSize := uint32(0)
	var gotMap = make(map[string]uintptr)

	bssBaseAddress := uintptr(0)
	bssOffset := 0
	bssSize := uint32(0)

	for _, symbol := range parsedCoff.Symbols {
		if isSpecialSymbol(symbol) {
			if isImportSymbol(symbol) {
				gotSize += 8
			} else {
				bssSize += symbol.Value + 8 //leave room for null bytes
			}
		}
	}

	for _, section := range parsedCoff.Sections.Array() {
		// Use the larger of SizeOfRawData and VirtualSize.
		// This is critical for .bss sections which have VirtualSize > 0 but SizeOfRawData = 0.
		allocationSize := uintptr(section.SizeOfRawData)
		if uintptr(section.VirtualSize) > allocationSize {
			allocationSize = uintptr(section.VirtualSize)
		}
		// For .bss sections with Common symbols, use bssSize if larger
		if strings.HasPrefix(section.NameString(), ".bss") && uintptr(bssSize) > allocationSize {
			allocationSize = uintptr(bssSize)
		}

		if allocationSize == 0 {
			continue
		}

		addr, err := virtualAlloc(0, allocationSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
		if err != nil {
			return []utils.BofMsg{}, fmt.Errorf("VirtualAlloc failed: %s", err.Error())
		}

		if strings.HasPrefix(section.NameString(), ".bss") {
			bssBaseAddress = addr
		}

		copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:], section.RawData())

		allocatedSection := CoffSection{
			Section: section,
			Address: addr,
		}

		sections[section.NameString()] = allocatedSection
	}

	// If we have Common symbols (bssSize > 0) but no .bss section was found, we must allocate it now.
	if bssBaseAddress == 0 && bssSize > 0 {
		addr, err := virtualAlloc(0, uintptr(bssSize), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
		if err != nil {
			return []utils.BofMsg{}, fmt.Errorf("VirtualAlloc (implicit bss) failed: %s", err.Error())
		}
		bssBaseAddress = addr
	}

	gotBaseAddress, err := virtualAlloc(0, uintptr(gotSize), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return []utils.BofMsg{}, fmt.Errorf("VirtualAlloc failed: %s", err.Error())
	}

	for _, section := range parsedCoff.Sections.Array() {
		sectionVirtualAddr := sections[section.NameString()].Address
		fmt.Sprintf("Section: %s\n", section.NameString())

		for _, reloc := range section.Relocations() {

			symbol := parsedCoff.Symbols[reloc.SymbolTableIndex]

			if symbol.StorageClass > 3 {
				continue
			}

			symbolTypeString := defwin.MAP_IMAGE_SYM_CLASS[symbol.StorageClass]
			fmt.Sprintf("0x%08X %s %s\n", reloc.VirtualAddress, symbolTypeString, symbol.NameString())
			symbolDefAddress := uintptr(0)

			if isSpecialSymbol(symbol) {
				if isImportSymbol(symbol) {
					externalAddress := resolveExternalAddress(symbol.NameString(), output, nil)

					if externalAddress == 0 {
						return []utils.BofMsg{}, fmt.Errorf("failed to resolve external address for symbol: %s", symbol.NameString())
					}

					if existingGotAddress, exists := gotMap[symbol.NameString()]; exists {
						symbolDefAddress = existingGotAddress
					} else {
						symbolDefAddress = gotBaseAddress + uintptr(gotOffset*8)
						gotOffset += 1
						gotMap[symbol.NameString()] = symbolDefAddress
					}
					copy((*[8]byte)(unsafe.Pointer(symbolDefAddress))[:], (*[8]byte)(unsafe.Pointer(&externalAddress))[:])
				} else {
					symbolDefAddress = bssBaseAddress + uintptr(bssOffset)
					bssOffset += int(symbol.Value) + 8
				}
			} else {
				targetSection := parsedCoff.Sections.Array()[symbol.SectionNumber-1]
				symbolDefAddress = sections[targetSection.NameString()].Address + uintptr(symbol.Value)
			}

			fmt.Sprintf("Symbol Def Address: 0x%x\n", symbolDefAddress)
			processRelocation(symbolDefAddress, sectionVirtualAddr, reloc, symbol)
		}

		if section.Characteristics&defwin.IMAGE_SCN_MEM_EXECUTE != 0 {
			oldProtect := PAGE_READWRITE
			_, _, errVirtualProtect := procVirtualProtect.Call(sectionVirtualAddr, uintptr(section.SizeOfRawData), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
			if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
				return []utils.BofMsg{}, fmt.Errorf("Error calling VirtualProtect:\r\n%s", errVirtualProtect.Error())
			}
		}
	}

	// Call the entry point
	go invokeMethod(method, argBytes, parsedCoff, sections, output, nil)

	var msgs []utils.BofMsg

	bofMsg := utils.BofMsg{}
	for msg := range output {
		switch msg.(type) {

		case int:
			bofMsg.Type = msg.(int)

		case []byte:
			bofMsg.Data = msg.([]byte)
			msgs = append(msgs, bofMsg)
			bofMsg = utils.BofMsg{}

		default:
			bofMsg = utils.BofMsg{}
		}
	}

	boffer.ClearExtractedBuffers()

	return msgs, nil
}

func invokeMethod(methodName string, argBytes []byte, parsedCoff *File, sectionMap map[string]CoffSection, outChannel chan<- interface{}, asyncBof *AsyncBof) {
	defer close(outChannel)

	// Catch unexpected panics and propagate them to the output channel
	// This prevents the host program from terminating unexpectedly
	defer func() {
		if r := recover(); r != nil {
			// Panic caught, silently return or pass to channel if needed
			// errorMsg := fmt.Sprintf("Panic occurred when executing COFF: %v\n%s", r, debug.Stack())
			// outChannel <- errorMsg
		}
	}()

	// Call the entry point
	for _, symbol := range parsedCoff.Symbols {
		if symbol.NameString() == methodName {
			mainSection := parsedCoff.Sections.Array()[symbol.SectionNumber-1]
			entryPoint := sectionMap[mainSection.NameString()].Address + uintptr(symbol.Value)

			if len(argBytes) == 0 {
				argBytes = make([]byte, 1)
			}

			// Allocate arguments in unmanaged memory to prevent Go pointer usage in native thread
			argsSize := uintptr(len(argBytes))
			argsBuf, _, _ := procVirtualAlloc.Call(0, argsSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
			if argsBuf == 0 {
				return
			}
			memory.MemCpy(argsBuf, uintptr(unsafe.Pointer(&argBytes[0])), uint32(len(argBytes)))

			// Trampoline stub (x64) to adapt CreateThread(Context*) -> go(char* args, int len)
			trampoline := []byte{
				0x48, 0x8B, 0x01, // mov rax, [rcx]      ; func_ptr (offset 0)
				0x48, 0x8B, 0x51, 0x10, // mov rdx, [rcx+16]   ; len (offset 16)
				0x48, 0x8B, 0x49, 0x08, // mov rcx, [rcx+8]    ; args (offset 8)
				0x48, 0x83, 0xEC, 0x28, // sub rsp, 40         ; shadow space
				0xFF, 0xD0, // call rax
				0x48, 0x83, 0xC4, 0x28, // add rsp, 40
				0xC3, // ret
			}

			// Context structure: { func_ptr, args_ptr, len_low, len_high }
			ctxSize := 24
			ctxBuf, _, _ := procVirtualAlloc.Call(0, uintptr(ctxSize), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
			if ctxBuf == 0 {
				return
			}

			// Fill context
			*(*uintptr)(unsafe.Pointer(ctxBuf)) = entryPoint
			*(*uintptr)(unsafe.Pointer(ctxBuf + 8)) = argsBuf
			*(*uintptr)(unsafe.Pointer(ctxBuf + 16)) = argsSize

			// Allocate executable memory for trampoline
			trampolineBuf, _, _ := procVirtualAlloc.Call(0, uintptr(len(trampoline)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
			if trampolineBuf == 0 {
				return
			}
			memory.MemCpy(trampolineBuf, uintptr(unsafe.Pointer(&trampoline[0])), uint32(len(trampoline)))

			// Create native thread to execute the BOF
			hThread, _, _ := procCreateThread.Call(0, 0, trampolineBuf, ctxBuf, 0, 0)
			if hThread == 0 {
				return
			}

			if asyncBof != nil {
				asyncBof.hThread = hThread
			}

			const INFINITE = 0xFFFFFFFF
			procWaitForSingleObject.Call(hThread, INFINITE)

			// Cleanup resources
			procCloseHandle.Call(hThread)

			if argsBuf != 0 {
				procVirtualFree.Call(argsBuf, 0, MEM_RELEASE)
			}
			if ctxBuf != 0 {
				procVirtualFree.Call(ctxBuf, 0, MEM_RELEASE)
			}
			if trampolineBuf != 0 {
				procVirtualFree.Call(trampolineBuf, 0, MEM_RELEASE)
			}
		}
	}
}

func virtualFree(addr uintptr) {
	if addr != 0 {
		procVirtualFree.Call(addr, 0, uintptr(0x8000)) // MEM_RELEASE
	}
}

func freeSections(sections map[string]CoffSection, gotBase uintptr) {
	for _, cs := range sections {
		virtualFree(cs.Address)
	}
	virtualFree(gotBase)
}

type AsyncBof struct {
	Output    chan interface{}
	Done      chan struct{}
	StopEvent windows.Handle
	hThread   uintptr
	sections  map[string]CoffSection
	gotBase   uintptr
}

func (a *AsyncBof) Stop() {
	if a.StopEvent != 0 {
		windows.SetEvent(a.StopEvent)
	}
	if a.hThread != 0 {
		// Wait up to 200ms for thread to exit cleanly (for processes that check StopEvent)
		ret, _, _ := procWaitForSingleObject.Call(a.hThread, 200)
		if ret != 0 { // WAIT_OBJECT_0 == 0
			// Thread didn't exit, force kill it (for in-process assembly execution)
			procTerminateThread := windows.NewLazySystemDLL("kernel32.dll").NewProc("TerminateThread")
			procTerminateThread.Call(a.hThread, 0)
		}
	}
}

func (a *AsyncBof) Cleanup() {
	if a.StopEvent != 0 {
		windows.CloseHandle(a.StopEvent)
		a.StopEvent = 0
	}
	freeSections(a.sections, a.gotBase)
	boffer.ClearExtractedBuffers()
}

func LoadAsync(coffBytes []byte, argBytes []byte, wakeupFunc func()) (*AsyncBof, error) {
	return LoadAsyncWithMethod(coffBytes, argBytes, "go", wakeupFunc)
}

func LoadAsyncWithMethod(coffBytes []byte, argBytes []byte, method string, wakeupFunc func()) (*AsyncBof, error) {
	output := make(chan interface{}, 64)

	stopEvent, err := windows.CreateEvent(nil, 1, 0, nil) // manual-reset, initially non-signaled
	if err != nil {
		return nil, fmt.Errorf("CreateEvent failed: %s", err.Error())
	}

	asyncCtx := &AsyncContext{
		WakeupFunc: wakeupFunc,
		StopEvent:  stopEvent,
	}

	parsedCoff := Explore(binutil.WrapByteSlice(coffBytes))
	parsedCoff.ReadAll()
	parsedCoff.Seal()

	sections := make(map[string]CoffSection, parsedCoff.Sections.Len())

	gotBaseAddress := uintptr(0)
	gotOffset := 0
	gotSize := uint32(0)
	var gotMap = make(map[string]uintptr)

	bssBaseAddress := uintptr(0)
	bssOffset := 0
	bssSize := uint32(0)

	for _, symbol := range parsedCoff.Symbols {
		if isSpecialSymbol(symbol) {
			if isImportSymbol(symbol) {
				gotSize += 8
			} else {
				bssSize += symbol.Value + 8
			}
		}
	}

	for _, section := range parsedCoff.Sections.Array() {
		// Use the larger of SizeOfRawData and VirtualSize.
		// This is critical for .bss sections which have VirtualSize > 0 but SizeOfRawData = 0.
		allocationSize := uintptr(section.SizeOfRawData)
		if uintptr(section.VirtualSize) > allocationSize {
			allocationSize = uintptr(section.VirtualSize)
		}
		// For .bss sections with Common symbols, use bssSize if larger
		if strings.HasPrefix(section.NameString(), ".bss") && uintptr(bssSize) > allocationSize {
			allocationSize = uintptr(bssSize)
		}

		if allocationSize == 0 {
			continue
		}

		addr, err := virtualAlloc(0, allocationSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
		if err != nil {
			freeSections(sections, gotBaseAddress)
			windows.CloseHandle(stopEvent)
			return nil, fmt.Errorf("VirtualAlloc failed: %s", err.Error())
		}

		if strings.HasPrefix(section.NameString(), ".bss") {
			bssBaseAddress = addr
		}

		copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:], section.RawData())

		allocatedSection := CoffSection{
			Section: section,
			Address: addr,
		}

		sections[section.NameString()] = allocatedSection
	}

	// If we have Common symbols (bssSize > 0) but no .bss section was found, we must allocate it now.
	if bssBaseAddress == 0 && bssSize > 0 {
		addr, err := virtualAlloc(0, uintptr(bssSize), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
		if err != nil {
			freeSections(sections, 0)
			windows.CloseHandle(stopEvent)
			return nil, fmt.Errorf("VirtualAlloc (implicit bss) failed: %s", err.Error())
		}
		bssBaseAddress = addr
	}

	gotBaseAddress, err = virtualAlloc(0, uintptr(gotSize), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		freeSections(sections, 0)
		windows.CloseHandle(stopEvent)
		return nil, fmt.Errorf("VirtualAlloc failed: %s", err.Error())
	}

	for _, section := range parsedCoff.Sections.Array() {
		sectionVirtualAddr := sections[section.NameString()].Address

		for _, reloc := range section.Relocations() {
			symbol := parsedCoff.Symbols[reloc.SymbolTableIndex]

			if symbol.StorageClass > 3 {
				continue
			}

			symbolDefAddress := uintptr(0)

			if isSpecialSymbol(symbol) {
				if isImportSymbol(symbol) {
					externalAddress := resolveExternalAddress(symbol.NameString(), output, asyncCtx)

					if externalAddress == 0 {
						freeSections(sections, gotBaseAddress)
						windows.CloseHandle(stopEvent)
						return nil, fmt.Errorf("failed to resolve external address for symbol: %s", symbol.NameString())
					}

					if existingGotAddress, exists := gotMap[symbol.NameString()]; exists {
						symbolDefAddress = existingGotAddress
					} else {
						symbolDefAddress = gotBaseAddress + uintptr(gotOffset*8)
						gotOffset += 1
						gotMap[symbol.NameString()] = symbolDefAddress
					}
					copy((*[8]byte)(unsafe.Pointer(symbolDefAddress))[:], (*[8]byte)(unsafe.Pointer(&externalAddress))[:])
				} else {
					symbolDefAddress = bssBaseAddress + uintptr(bssOffset)
					bssOffset += int(symbol.Value) + 8
				}
			} else {
				targetSection := parsedCoff.Sections.Array()[symbol.SectionNumber-1]
				symbolDefAddress = sections[targetSection.NameString()].Address + uintptr(symbol.Value)
			}

			processRelocation(symbolDefAddress, sectionVirtualAddr, reloc, symbol)
		}

		if section.Characteristics&defwin.IMAGE_SCN_MEM_EXECUTE != 0 {
			oldProtect := PAGE_READWRITE
			_, _, errVirtualProtect := procVirtualProtect.Call(sectionVirtualAddr, uintptr(section.SizeOfRawData), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
			if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
				freeSections(sections, gotBaseAddress)
				windows.CloseHandle(stopEvent)
				return nil, fmt.Errorf("Error calling VirtualProtect:\r\n%s", errVirtualProtect.Error())
			}
		}
	}

	asyncBof := &AsyncBof{
		Output:    output,
		Done:      make(chan struct{}),
		StopEvent: stopEvent,
		sections:  sections,
		gotBase:   gotBaseAddress,
	}

	go func() {
		defer close(asyncBof.Done)
		invokeMethod(method, argBytes, parsedCoff, sections, output, asyncBof)
	}()

	return asyncBof, nil
}
