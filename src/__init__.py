SeCreateTokenPrivilege = se_create_token_privilege = 1
SeAssignPrimaryTokenPrivilege = se_assign_primary_token_privilege = 2
SeLockMemoryPrivilege = se_lock_memory_privilege = 3
SeIncreaseQuotaPrivilege = se_increase_quota_privilege = 4
SeUnsolicitedInputPrivilege = se_unsolicited_input_privilege = 5
SeMachineAccountPrivilege = se_machine_account_privilege = 6
SeTcbPrivilege = se_tcb_privilege = 7
SeSecurityPrivilege = se_security_privilege = 8
SeTakeOwnershipPrivilege = se_take_ownership_privilege = 9
SeLoadDriverPrivilege = se_load_driver_privilege = 10
SeSystemProfilePrivilege = se_system_profile_privilege = 11
SeSystemtimePrivilege = se_system_time_privilege = 12
SeProfileSingleProcessPrivilege = se_profile_single_process_privilege = 13
SeIncreaseBasePriorityPrivilege = se_increase_base_priority_privilege = 14
SeCreatePagefilePrivilege = se_create_pagefile_privilege = 15
SeCreatePermanentPrivilege = se_create_permanent_privilege = 16
SeBackupPrivilege = se_backup_privilege = 17
SeRestorePrivilege = se_restore_privilege = 18
SeShutdownPrivilege = se_shutdown_privilege = 19
SeDebugPrivilege = se_debug_privilege = 20
SeAuditPrivilege = se_audit_privilege = 21
SeSystemEnvironmentPrivilege = se_system_environment_privilege = 22
SeChangeNotifyPrivilege = se_change_notify_privilege = 23
SeRemoteShutdownPrivilege = se_remote_shutdown_privilege = 24
SeUndockPrivilege = se_undock_privilege = 25
SeSyncAgentPrivilege = se_sync_agent_privilege = 26
SeEnableDelegationPrivilege = se_enable_delegation_privilege = 27
SeManageVolumePrivilege = se_manage_volume_privilege = 28
SeImpersonatePrivilege = se_impersonate_privilege = 29
SeCreateGlobalPrivilege = se_create_global_privilege = 30
SeTrustedCredManAccessPrivilege = se_trusted_cred_man_access_privilege = 31
SeRelabelPrivilege = se_relabel_privilege = 32
SeIncreaseWorkingSetPrivilege = se_increase_working_set_privilege = 33
SeTimeZonePrivilege = se_time_zone_privilege = 34
SeCreateSymbolicLinkPrivilege = se_create_symbolic_link_privilege = 35

ProcessBasicInformation = 0x00
ProcessDebugPort = 0x07
ProcessExceptionPort = 0x08
ProcessAccessToken = 0x09
ProcessWow64Information = 0x1A
ProcessImageFileName = 0x1B
ProcessDebugObjectHandle = 0x1E
ProcessDebugFlags = 0x1F
ProcessExecuteFlags = 0x22
ProcessInstrumentationCallback = 0x28
MaxProcessInfoClass = 0x64

process_info_class = ProcessInfoClass = PROCESSINFOCLASS

SysDbgQueryModuleInformation = 0
SysDbgQueryTraceInformation = 1
SysDbgSetTracepoint = 2
SysDbgSetSpecialCall = 3
SysDbgClearSpecialCalls = 4
SysDbgQuerySpecialCalls = 5
SysDbgBreakPoint = 6
SysDbgQueryVersion = 7
SysDbgReadVirtual = 8
SysDbgWriteVirtual = 9
SysDbgReadPhysical = 10
SysDbgWritePhysical = 11
SysDbgReadControlSpace = 12
SysDbgWriteControlSpace = 13
SysDbgReadIoSpace = 14
SysDbgWriteIoSpace = 15
SysDbgReadMsr = 16
SysDbgWriteMsr = 17
SysDbgReadBusData = 18
SysDbgWriteBusData = 19
SysDbgCheckLowMemory = 20
SysDbgEnableKernelDebugger = 21
SysDbgDisableKernelDebugger = 22
SysDbgGetAutoKdEnable = 23
SysDbgSetAutoKdEnable = 24
SysDbgGetPrintBufferSize = 25
SysDbgSetPrintBufferSize = 26
SysDbgGetKdUmExceptionEnable = 27
SysDbgSetKdUmExceptionEnable = 28
SysDbgGetTriageDump = 29
SysDbgGetKdBlockEnable = 30
SysDbgSetKdBlockEnable = 31

import ctypes
from ctypes import wintypes
from ctypes.wintypes import *

def RtlNtStatusToDosError(Status):
    return ctypes.windll.ntdll.RtlNtStatusToDosError(Status)
rtl_nt_status_to_dos_error = RtlNtStatusToDosError

def NtErrorCheck(func):
    def f(*args, **kwargs):
        res = func(*args, **kwargs)
        if res[0]:
            raise NtError(res[0])
        return res[1]
    return f
nt_error_check = NtErrorCheck

class NtError(Exception):
    def __init__(self, code):
        dos_error = RtlNtStatusToDosError(code)
        message = '[{}] '.format(dos_error) + ctypes.FormatError(dos_error)
        super().__init__(message)
nt_error = NtError

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2", ctypes.c_void_p * 2),
        ("UniqueProcessId", ctypes.c_void_p),
        ("Reserved3", ctypes.c_void_p),
    ]

@NtErrorCheck
def RtlAdjustPrivilege(Privilege: NtPrivilege, Enable: bool, CurrentThread: bool) -> bool:
    '''
    Enables or disables a privilege from the calling thread or process.
      Privilege     - Privilege to adjust, chosen from the privilege enum
      Enable        - Whether the privilege should be enabled our disabled
      CurrentThread - Whether the currents threads privilege should be targeted instead of the whole process
    '''
    PrivilegeState = ctypes.c_bool()
    return ctypes.windll.ntdll.RtlAdjustPrivilege(Privilege, Enable, CurrentThread, ctypes.pointer(PrivilegeState)), bool(PrivilegeState)
rtl_adjust_privilege = RtlAdjustPrivilege

@NtErrorCheck
def NtSetSystemPowerState(SystemPowerState, NoResumeAlarm, ForcePowerDown):
    return ctypes.windll.ntdll.NtSetSystemPowerState(SystemPowerState, NoResumeAlarm, ForcePowerDown), None
nt_set_system_power_state = NtSetSystemPowerState

@NtErrorCheck
def NtRaiseHardError(ErrorStatus: int, NumberOfParameters: int, UnicodeStringParameterMask: int, Parameters: int, ResponseOption: int):
    ErrorResponse = ctypes.c_ulong()
    return ctypes.windll.ntdll.NtRaiseHardError(ErrorStatus, NumberOfParameters, UnicodeStringParameterMask, Parameters, ResponseOption, ctypes.byref(ErrorResponse)), ErrorResponse
nt_raise_hard_error = NtRaiseHardError

@NtErrorCheck
def NtSetInformationProcess(ProcessHandle: int, ProcessInformationClass: int, ProcessInformation: int):
    ProcessHandle = wintypes.HANDLE(int(ProcessHandle))
    NtSe = ctypes.windll.ntdll.NtSetInformationProcess
    ProcessInformation = ctypes.c_ulong(ProcessInformation) 
    ProcessInformationLength = ctypes.sizeof(ctypes.c_ulong)
    NtSe.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_ulong
    )
    r = NtSe(ProcessHandle, ProcessInformationClass, ctypes.byref(ProcessInformation), ProcessInformationLength)
    ctypes.windll.Kernel32.CloseHandle(ProcessHandle)
    return r, None
nt_set_information_process = NtSetInformationProcess

def RtlDowncaseUnicodeChar(SourceCharacter):
    return chr(ctypes.windll.ntdll.RtlDowncaseUnicodeChar(ctypes.c_wchar(SourceCharacter)))
rtl_downcase_unicode_char = RtlDowncaseUnicodeChar

def RtlUpcaseUnicodeChar(SourceCharacter):
    return chr(ctypes.windll.ntdll.RtlUpcaseUnicodeChar(ctypes.c_wchar(SourceCharacter)))
rtl_upcase_unicode_char = RtlUpcaseUnicodeChar

@NtErrorCheck
def RtlCharToInteger(String, Base=10):
    Value = ctypes.c_ulong()
    return ctypes.windll.ntdll.RtlCharToInteger(ctypes.c_wchar_p(String), ctypes.c_ulong(Base), ctypes.pointer(Value)), Value.value
rtl_char_to_integer = RtlCharToInteger

@NtErrorCheck
def NtClose(Handle):
    return ctypes.windll.ntdll.NtClose(Handle), None
nt_close = NtClose

@NtErrorCheck
def NtQuerySystemTime():
    SystemTime = wintypes.LARGE_INTEGER(0)
    return ctypes.windll.ntdll.NtQuerySystemTime(ctypes.pointer(SystemTime)), SystemTime.value
nt_query_system_time = NtQuerySystemTime

def RtlUniform(Seed):
    uSeed = ctypes.c_ulong(Seed)
    return ctypes.windll.ntdll.RtlUniform(ctypes.pointer(uSeed))
rtl_uniform = RtlUniform

def RtlTimeToSecondsSince1970(Time=None):
    if Time==None:
        Time = NtQuerySystemTime()

    Time = wintypes.LARGE_INTEGER(Time)
    ElapsedSeconds = ctypes.c_ulong()
    if not ctypes.windll.ntdll.RtlTimeToSecondsSince1970(ctypes.pointer(Time), ctypes.pointer(ElapsedSeconds)):
        raise NtError("The function did not succeed.")
    return ElapsedSeconds.value
rtl_time_to_seconds_since_1970 = RtlTimeToSecondsSince1970

@NtErrorCheck
def NtQueryInformationProcess(ProcessHandle, ProcessInformationClass):
    out = PROCESS_BASIC_INFORMATION()
    NtQ = ctypes.windll.ntdll.NtQueryInformationProcess
    length = ctypes.sizeof(PROCESS_BASIC_INFORMATION)
    NtQ.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG, wintypes.PULONG]
    result = NtQ(ProcessHandle, ProcessInformationClass, ctypes.byref(out), length, ctypes.byref(wintypes.DWORD(0)))
    return result, out

@NtErrorCheck
def NtSystemDebugControl(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength):
    return ctypes.windll.ntdll.NtSystemDebugControl(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength), None

class _SYSDBG_VIRTUAL(ctypes.Structure):
    _fields_ = [
        ("Address", ctypes.c_void_p),
        ("Buffer", ctypes.c_void_p),
        ("Request", ctypes.c_ulong)
    ]
SYSDBG_VIRTUAL = _SYSDBG_VIRTUAL
PSYSDBG_VIRTUAL = _SYSDBG_VIRTUAL
class _DBGKD_GET_VERSION64(ctypes.Structure):
    _fields_ = [
        ("MajorVersion", WORD),
        ("MinorVersion", WORD),
        ("ProtocolVersion", WORD),
        ("Flags", WORD),
        ("MachineType", WORD),
        ("MaxPacketType", BYTE),
        ("MaxStateChange", BYTE),
        ("MaxManipulate", BYTE),
        ("Simulation", BYTE),
        ("Unused", WORD),
        ("KernBase", ctypes.c_uint64),
        ("PsLoadedModuleList", ctypes.c_uint64),
        ("DebuggerDataList", ctypes.c_uint64)
    ]
DBGKD_GET_VERSION64 = _DBGKD_GET_VERSION64
PDBGKD_GET_VERSION64 = _DBGKD_GET_VERSION64

@NtErrorCheck
def RtlSetProcessIsCritical(NewValue, CheckFlag=0):
    OldValue = ctypes.c_bool()
    res = ctypes.windll.ntdll.RtlSetProcessIsCritical(NewValue, ctypes.pointer(OldValue), CheckFlag)
    return res, OldValue.value
