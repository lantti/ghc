from ctypes import *
from ctypes.wintypes import *

ULONG_PTR = c_size_t
SIZE_T = ULONG_PTR
PULONG_PTR = POINTER(ULONG_PTR)
ULONGLONG = c_uint64
PVOID = c_void_p
JOBOBJECTINFOCLASS = c_int
LPOVERLAPPED = PULONG_PTR

#JobObjectInfoClass
associateCompletionPortInformation = 7
basicLimitInformation = 2
basicUIRestrictions = 4
endOfJobTimeInformation = 6
extendedLimitInformation = 9
securityLimitInformation = 5
groupInformation = 11

#QueuedCompletionStatus
JOB_OBJECT_MSG_BOGUS = 0
JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO = 4

#LimitFlags
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

#HandleFlags
HANDLE_FLAG_INHERIT = 0x00000001
HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x00000002

#CreationFlags
CREATE_SUSPENDED = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400

#StartupFlags
STARTF_USESTDHANDLES = 0x00000100

INVALID_HANDLE_VALUE = -1

class STARTUPINFOA(Structure):
    _fields_ = [("cb", DWORD),
            ("lpReserved", LPSTR),
            ("lpDesktop", LPSTR),
            ("lpTitle", LPSTR),
            ("dwX", DWORD),
            ("dwY", DWORD),
            ("dwXSize", DWORD),
            ("dwYSize", DWORD),
            ("dwXCountChars", DWORD),
            ("dwYCountChars", DWORD),
            ("dwFillAttribute", DWORD),
            ("dwFlags", DWORD),
            ("wShowWindow", WORD),
            ("cbReserved2", WORD),
            ("lpReserved2", LPBYTE),
            ("hStdInput", HANDLE),
            ("hStdOutput", HANDLE),
            ("hStdError", HANDLE)]

class STARTUPINFOW(Structure):
    _fields_ = [("cb", DWORD),
            ("lpReserved", LPWSTR),
            ("lpDesktop", LPWSTR),
            ("lpTitle", LPWSTR),
            ("dwX", DWORD),
            ("dwY", DWORD),
            ("dwXSize", DWORD),
            ("dwYSize", DWORD),
            ("dwXCountChars", DWORD),
            ("dwYCountChars", DWORD),
            ("dwFillAttribute", DWORD),
            ("dwFlags", DWORD),
            ("wShowWindow", WORD),
            ("cbReserved2", WORD),
            ("lpReserved2", LPBYTE),
            ("hStdInput", HANDLE),
            ("hStdOutput", HANDLE),
            ("hStdError", HANDLE)]

class PROCESS_INFORMATION(Structure):
    _fields_ = [("hProcess", HANDLE),
            ("hThread", HANDLE),
            ("dwProcessId", DWORD),
            ("dwThreadId", DWORD)]

class IO_COUNTERS(Structure):
    _fields_ = [("ReadOperationCount", ULONGLONG),
            ("WriteOperationCount", ULONGLONG),
            ("OtherOperationCount", ULONGLONG),
            ("ReadTransferCount", ULONGLONG),
            ("WriteTransferCount", ULONGLONG),
            ("OtherTransferCount", ULONGLONG)] 

class JOBOBJECT_BASIC_LIMIT_INFORMATION(Structure):
    _fields_ = [("PerProcessUserTimeLimit", LARGE_INTEGER),
            ("PerJobUserTimeLimit", LARGE_INTEGER),
            ("LimitFlags", DWORD),
            ("MinimumWorkingSetSize", SIZE_T),
            ("MaximumWorkingSetSize", SIZE_T),
            ("ActiveProcessLimit", DWORD),
            ("Affinity", ULONG_PTR),
            ("PriorityClass", DWORD),
            ("SchedulingClass", DWORD)] 

class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(Structure):
    _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", SIZE_T),
            ("JobMemoryLimit", SIZE_T),
            ("PeakProcessMemoryUsed", SIZE_T),
            ("PeakJobMemoryUsed", SIZE_T)] 

class JOBOBJECT_ASSOCIATE_COMPLETION_PORT(Structure):
    _fields_ = [("CompletionKey", PVOID),
            ("CompletionPort", HANDLE)] 

class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [("nLength", DWORD),
            ("lpSecurityDescriptor", LPVOID),
            ("bInheritHandle", BOOL)]

LPSTARTUPINFOA = POINTER(STARTUPINFOA)
LPSTARTUPINFOW = POINTER(STARTUPINFOW)
LPPROCESS_INFORMATION = POINTER(PROCESS_INFORMATION)
LPSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)

def errcheck(result, func, args):
    if not result:
        raise WinError()
    return args

prototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, DWORD)
paramflags = (1, "hObject"), (1, "dwMask", 0), (1, "dwFlags", 0) 
setHandleInformation = prototype(("SetHandleInformation", windll.kernel32),
    paramflags)
setHandleInformation.errcheck = errcheck

prototype = WINFUNCTYPE(BOOL, PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD)
paramflags = ((2, "hReadPipe"), (2, "hWritePipe"),
        (1, "lpPipeAttributes", None), (1, "nSize", 0)) 
createPipe = prototype(("CreatePipe", windll.kernel32), paramflags)
createPipe.errcheck = errcheck

prototype = WINFUNCTYPE(BOOL, HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)
paramflags = ((1, "hFile"), (1, "lpBuffer"), (1, "nNumberOfBytesToRead"),
        (2, "lpNumberOfBytesRead"), (1,"lpOverlapped", None))
readFile = prototype(("ReadFile", windll.kernel32), paramflags)
readFile.errcheck = errcheck


prototype = WINFUNCTYPE(BOOL, HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)
paramflags = ((1, "hFile"), (1, "lpBuffer"), (1, "nNumberOfBytesToWrite"),
        (2, "lpNumberOfBytesWritten"), (1,"lpOverlapped", None))
writeFile = prototype(("WriteFile", windll.kernel32), paramflags)
writeFile.errcheck = errcheck

prototype = WINFUNCTYPE(HANDLE, LPSECURITY_ATTRIBUTES, LPCSTR)
paramflags = (1, "lpJobAttributes", None), (1, "lpName", None)
createJobObjectA = prototype(("CreateJobObjectA", windll.kernel32), paramflags)
createJobObjectA.errcheck = errcheck

prototype = WINFUNCTYPE(BOOL, HANDLE, JOBOBJECTINFOCLASS, LPVOID, DWORD)
paramflags = ((1, "hJob"), (1, "JobObjectInfoClass"), (1, "lpJobObjectInfo"),
        (1, "JobObjectInfoLength"))
setInformationJobObject = prototype(("SetInformationJobObject",
    windll.kernel32), paramflags)
setInformationJobObject.errcheck = errcheck

prototype = WINFUNCTYPE(BOOL, HANDLE, HANDLE)
paramflags = (1, "hJob"), (1, "hProcess")
assignProcessToJobObject  = prototype(("AssignProcessToJobObject",
    windll.kernel32), paramflags)
assignProcessToJobObject.errcheck = errcheck

prototype = WINFUNCTYPE(BOOL, HANDLE, UINT)
paramflags = (1, "hJob"), (1, "uExitCode")
terminateJobObject  = prototype(("TerminateJobObject", windll.kernel32),
        paramflags)
terminateJobObject.errcheck = errcheck

prototype = WINFUNCTYPE(HANDLE, HANDLE, HANDLE, ULONG_PTR, DWORD)
paramflags = ((1, "FileHandle", INVALID_HANDLE_VALUE),
        (1, "ExistingCompletionPort", None), (1, "CompletionKey", 0),
        (1, "NumberOfConcurrentThreads", 0))
createIoCompletionPort = prototype(("CreateIoCompletionPort", windll.kernel32),
        paramflags)
createIoCompletionPort.errcheck = errcheck

prototype = WINFUNCTYPE(BOOL, HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED, DWORD)
paramflags = ((1, "CompletionPort"), (2, "lpNumberOfBytes"),
        (2, "lpCompletionKey"), (2, "lpOverlapped"),
        (1, "dwMilliseconds"))
getQueuedCompletionStatus = prototype(("GetQueuedCompletionStatus",
    windll.kernel32), paramflags)

prototype = WINFUNCTYPE(BOOL, HANDLE)
paramflags = (1, "hObject"),
closeHandle = prototype(("CloseHandle", windll.kernel32), paramflags)
closeHandle.errcheck = errcheck

prototype = WINFUNCTYPE(BOOL, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
        LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA,
        LPPROCESS_INFORMATION)
paramflags = ((1, "lpApplicationName", None), (1, "lpCommandLine", None),
        (1, "lpProcessAttributes", None), (1, "lpThreadAttributes", None),
        (1, "bInheritHandles", False), (1, "dwCreationFlags", 0),
        (1, "lpEnvironment", None), (1, "lpCurrentDirectory", None),
        (1, "lpStartupInfo", STARTUPINFOA()), (2, "lpProcessInformation"))
createProcessA  = prototype(("CreateProcessA", windll.kernel32),
        paramflags)
createProcessA.errcheck = errcheck

prototype = WINFUNCTYPE(BOOL, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
        LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW,
        LPPROCESS_INFORMATION)
paramflags = ((1, "lpApplicationName", None), (1, "lpCommandLine", None),
        (1, "lpProcessAttributes", None), (1, "lpThreadAttributes", None),
        (1, "bInheritHandles", False), (1, "dwCreationFlags", 0),
        (1, "lpEnvironment", None), (1, "lpCurrentDirectory", None),
        (1, "lpStartupInfo", STARTUPINFOW()), (2, "lpProcessInformation"))
createProcessW  = prototype(("CreateProcessW", windll.kernel32),
        paramflags)
createProcessW.errcheck = errcheck

prototype = WINFUNCTYPE(DWORD, HANDLE)
paramflags = (1, "hThread"),
resumeThread = prototype(("ResumeThread", windll.kernel32), paramflags)

prototype = WINFUNCTYPE(BOOL, HANDLE, LPDWORD)
paramflags = (1, "hProcess"), (2, 'lpExitCode')
getExitCodeProcess = prototype(("GetExitCodeProcess", windll.kernel32),
        paramflags)
getExitCodeProcess.errcheck = errcheck

def makeWinEnvBlock(env, wide=False):
    if env == None:
        return None
    s = ""
    for k,v in env.items():
        s += k + '=' + v + '\0'
    s += '\0'
    if wide:
        b = ctypes.create_unicode_buffer(s)
    else:
        b = ctypes.create_string_buffer(s.encode('ascii'))
    return ctypes.cast(b, ctypes.c_void_p)

def readWinPipe(handle, target, buffer_size=4096):
    buf = ctypes.create_string_buffer(buffer_size)
    n = buffer_size
    try:
        while n != 0:
            n = readFile(handle, buf, buffer_size)
            target.write(buf[:n])
            #print("got: " + str(buf[:n]))
    except BrokenPipeError:
        pass

def writeWinPipe(handle, source, buffer_size=4096):
    buf = ctypes.create_string_buffer(buffer_size)
    try:
        n = source.readinto(buf)
        while n != 0:
            writeFile(handle, buf, n)
            #print("put: " + str(buf[:n]))
            n = source.readinto(buf)
    except BrokenPipeError:
        pass

def newJobWithRedirectedIo(cmd, env=None, combine_output=False):
    bInfo = JOBOBJECT_BASIC_LIMIT_INFORMATION(
            LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
    eInfo = JOBOBJECT_EXTENDED_LIMIT_INFORMATION(BasicLimitInformation=bInfo)
    pipeAttr = SECURITY_ATTRIBUTES(nLength=sizeof(SECURITY_ATTRIBUTES),
            lpSecurityDescriptor=None, bInheritHandle=True)

    jobObject = INVALID_HANDLE_VALUE
    completionPort = INVALID_HANDLE_VALUE
    inpipeR = INVALID_HANDLE_VALUE
    inpipeW = INVALID_HANDLE_VALUE
    outpipeR = INVALID_HANDLE_VALUE
    outpipeW = INVALID_HANDLE_VALUE
    errpipeR = INVALID_HANDLE_VALUE
    errpipeW = INVALID_HANDLE_VALUE
    pInfo = None

    try:
        jobObject = createJobObjectA()
        completionPort = createIoCompletionPort()
        cPortAssoc = JOBOBJECT_ASSOCIATE_COMPLETION_PORT(
                CompletionKey=jobObject, CompletionPort=completionPort)
        setInformationJobObject(jobObject, extendedLimitInformation,
                cast(byref(eInfo), LPVOID), sizeof(eInfo))
        setInformationJobObject(jobObject, associateCompletionPortInformation,
                cast(byref(cPortAssoc), LPVOID), sizeof(cPortAssoc))

        inpipeR, inpipeW = createPipe(lpPipeAttributes=pipeAttr)
        outpipeR, outpipeW = createPipe(lpPipeAttributes=pipeAttr)

        setHandleInformation(inpipeW, HANDLE_FLAG_INHERIT, 0)
        setHandleInformation(outpipeR, HANDLE_FLAG_INHERIT, 0)
        
        if combine_output:
            hStdErr = outpipeW
        else:
            errpipeR, errpipeW = createPipe(lpPipeAttributes=pipeAttr)
            setHandleInformation(errpipeR, HANDLE_FLAG_INHERIT, 0)
            hStdErr = errpipeW

        creationFlags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT

        envBlock = makeWinEnvBlock(env, wide=True)

        cmdLine = create_unicode_buffer(cmd)

        sInfo = STARTUPINFOW(cb=sizeof(STARTUPINFOA), 
                dwFlags=STARTF_USESTDHANDLES, hStdOutput=outpipeW,
                hStdError=hStdErr, hStdInput=inpipeR)

        pInfo = createProcessW(lpCommandLine=cmdLine, bInheritHandles=True,
                dwCreationFlags=creationFlags, lpEnvironment=envBlock,
                lpStartupInfo=sInfo)

        assignProcessToJobObject(jobObject, pInfo.hProcess)
        resumeThread(pInfo.hThread)

    except:
        if completionPort != INVALID_HANDLE_VALUE:
            closeHandle(completionPort)
        if jobObject != INVALID_HANDLE_VALUE:
            terminateJobObject(jobObject, 98)
            closeHandle(jobObject)
        if inpipeW != INVALID_HANDLE_VALUE:
            closeHandle(inpipeW)
        if outpipeR != INVALID_HANDLE_VALUE:
            closeHandle(outpipeR)
        if errpipeR != INVALID_HANDLE_VALUE:
            closeHandle(errpipeR)
        raise

    finally:
        if inpipeR != INVALID_HANDLE_VALUE:
            closeHandle(inpipeR)
        if outpipeW != INVALID_HANDLE_VALUE:
            closeHandle(outpipeW)
        if errpipeW != INVALID_HANDLE_VALUE:
            closeHandle(errpipeW)
    return (pInfo.hProcess, pInfo.hThread, jobObject, completionPort, inpipeW, 
            outpipeR, errpipeR)

def waitForZeroActiveProcesses(completionPort, timeout, interval=1000):
    nB = JOB_OBJECT_MSG_BOGUS
    t = 0
    while nB != JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO and t < timeout*1000:
        if nB == JOB_OBJECT_MSG_BOGUS:
            t += interval
        nB, cKey, oL = getQueuedCompletionStatus(CompletionPort=completionPort,
                dwMilliseconds=interval)
    return nB == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO

