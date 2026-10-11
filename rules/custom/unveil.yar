/*
   Unveil custom rules - evasion tradecraft that family signatures miss.
   Author: HaiND from the Post and Telecommunication Institute of Technology
*/

import "pe"

rule UNV_Direct_Syscall_Stubs
{
    meta:
        description = "Several x64 syscall stubs outside ntdll/win32u: direct syscalls (SysWhispers, Hell's Gate, custom loaders)"
        author = "HaiND"
        score = 70
        mitre = "T1106"
    strings:
        // mov r10, rcx; mov eax, <ssn>; syscall; ret
        $stub = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 }
        // mov r10, rcx; mov eax, <ssn>; ... syscall (with test/jne for SharedUserData check in between)
        $stub2 = { 4C 8B D1 B8 ?? ?? 00 00 F6 04 25 08 03 FE 7F 01 75 03 0F 05 C3 }
    condition:
        (#stub + #stub2) >= 3
        and not (uint16(0) == 0x5A4D and pe.is_pe and
                 (pe.exports("NtCreateFile") or pe.exports("NtUserGetMessage")))
}

rule UNV_Indirect_Syscall_Gadget_Search
{
    meta:
        description = "Code that scans ntdll for 'syscall; ret' gadgets to perform indirect syscalls"
        author = "HaiND"
        score = 60
        mitre = "T1106"
    strings:
        $g1 = { 80 3? 0F 75 ?? 80 7? 01 05 75 ?? 80 7? 02 C3 }   // cmp byte [r],0F; jne; cmp [r+1],05; jne; cmp [r+2],C3
        $g2 = { 66 81 3? 0F 05 75 }                              // cmp word [r], 0x050F; jne
        $n1 = "ntdll.dll" ascii wide nocase
    condition:
        any of ($g*) and $n1
}

rule UNV_AMSI_Patch_Code
{
    meta:
        description = "Code that resolves AmsiScanBuffer and writes a return-early patch (E_INVALIDARG / xor eax,eax)"
        author = "HaiND"
        score = 80
        mitre = "T1562.001"
    strings:
        $f1 = "AmsiScanBuffer" ascii wide
        $f2 = "amsi.dll" ascii wide nocase
        $vp = "VirtualProtect" ascii wide
        $p1 = { B8 57 00 07 80 C3 }
        $p2 = { 31 C0 C3 }
        $p3 = { 48 31 C0 C3 }
        $p4 = { C7 ?? 57 00 07 80 }
    condition:
        $f1 and ($f2 or $vp) and any of ($p*)
}

rule UNV_ETW_Patch_Code
{
    meta:
        description = "Code that resolves EtwEventWrite/NtTraceEvent and patches it to return"
        author = "HaiND"
        score = 75
        mitre = "T1562.006"
    strings:
        $f1 = "EtwEventWrite" ascii wide
        $f2 = "NtTraceEvent" ascii wide
        $vp1 = "VirtualProtect" ascii wide
        $vp2 = "NtProtectVirtualMemory" ascii wide
        $wp1 = "WriteProcessMemory" ascii wide
        $p1 = { 48 33 C0 C3 }
        $p2 = { C2 14 00 }
        $p3 = { 33 C0 C3 }
    condition:
        any of ($f*) and any of ($vp*, $wp1) and any of ($p*)
}

rule UNV_Reflective_Loader_Export
{
    meta:
        description = "PE exporting a reflective loader routine (Stephen Fewer RDI and derivatives)"
        author = "HaiND"
        score = 80
        mitre = "T1620"
    condition:
        uint16(0) == 0x5A4D and pe.is_pe and
        (pe.exports("ReflectiveLoader") or pe.exports("_ReflectiveLoader@4") or pe.exports("_ReflectiveLoader@0"))
}

rule UNV_Unhooking_Fresh_Ntdll
{
    meta:
        description = "Loader that maps a clean ntdll from disk/KnownDlls/suspended process to remove EDR hooks"
        author = "HaiND"
        score = 65
        mitre = "T1562.001"
    strings:
        $k1 = "\\KnownDlls\\ntdll.dll" ascii wide nocase
        $k2 = "\\??\\C:\\Windows\\System32\\ntdll.dll" ascii wide nocase
        $s1 = "NtMapViewOfSection" ascii wide
        $s2 = "NtOpenSection" ascii wide
        $s3 = "MapViewOfFile" ascii wide
        $t1 = ".text" ascii
        $vp = "VirtualProtect" ascii wide
    condition:
        any of ($k*) and any of ($s*) and $t1 and $vp
}

rule UNV_Process_Hollowing_API_Chain
{
    meta:
        description = "Suspended process creation + unmap + remote write + context hijack (process hollowing toolkit)"
        author = "HaiND"
        score = 60
        mitre = "T1055.012"
    strings:
        $a1 = "NtUnmapViewOfSection" ascii wide
        $a2 = "ZwUnmapViewOfSection" ascii wide
        $b1 = "WriteProcessMemory" ascii wide
        $b2 = "NtWriteVirtualMemory" ascii wide
        $c1 = "SetThreadContext" ascii wide
        $c2 = "NtSetContextThread" ascii wide
        $d1 = "ResumeThread" ascii wide
        $d2 = "NtResumeThread" ascii wide
    condition:
        any of ($a*) and any of ($b*) and any of ($c*) and any of ($d*)
}

rule UNV_Sleep_Obfuscation_Timer_Rop
{
    meta:
        description = "Sleep-mask tradecraft (Ekko/Foliage/Cronos): timer queue or APC driving NtContinue with SystemFunction032 encryption"
        author = "HaiND"
        score = 70
        mitre = "T1027"
    strings:
        $a1 = "NtContinue" ascii wide
        $a2 = "SystemFunction032" ascii wide
        $b1 = "CreateTimerQueueTimer" ascii wide
        $b2 = "NtQueueApcThread" ascii wide
        $b3 = "RtlCreateTimer" ascii wide
        $c1 = "RtlCaptureContext" ascii wide
    condition:
        all of ($a*) and any of ($b*) and $c1
}
