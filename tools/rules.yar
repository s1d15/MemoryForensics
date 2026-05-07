rule Credential_Theft_Indicators {
    meta:
        description = "Detects credential dumping tools and strings"
    strings:
        $m1 = "lsass" nocase
        $m2 = "mimikatz" nocase
        $m3 = "sekurlsa" nocase
        $m4 = "procdump" nocase
    condition: 2 of them
}

rule Fileless_Powershell {
    meta:
        description = "Detect fileless Powershell execution"
    strings:
        $p1 = "IEX(" nocase
        $p2 = "DownloadString" nocase
        $p3 = "Invoke-WebRequest" nocase
        $p4 = "-ep bypass" nocase
    condition: 2 of them
}

rule Process_Injection {
    meta:
        description = "Detects common process injection patterns"
    strings:
        $i1 = "VirtualAlloc" nocase
        $i2 = "WriteProcessMemory" nocase
        $i3 = "CreateRemoteThread" nocase
    condition: 2 of them
}