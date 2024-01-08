$srvsysPatched = '0'
$srvsysVersion = "0"
Write-Host "============================================================" -ForegroundColor Green
Write-Host "A Script to determine if a machine is patched with MS17-010" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
[reflection.assembly]::LoadWithPartialName("System.Version")
$os = Get-WmiObject -class Win32_OperatingSystem
$osName = $os.Caption
$s = "%systemroot%\system32\drivers\srv.sys"
$s2 = "%systemroot%\system32\drivers\srv2.sys"
$v = [System.Environment]::ExpandEnvironmentVariables($s)
$v2 = [System.Environment]::ExpandEnvironmentVariables($s2)
If (Test-Path "$v")
    {
    Try
        {
        $versionInfo = (Get-Item $v).VersionInfo

        
        if ($osName.Contains("Windows 10")) {
            $fileVersion = New-Object System.Version($versionInfo.ProductVersionRaw)
        }
        elseif ($osName.Contains("2016")) {
            $fileVersion = New-Object System.Version($versionInfo.ProductVersionRaw)
        }
        else {
            $versionString = "$($versionInfo.FileMajorPart).$($versionInfo.FileMinorPart).
$($versionInfo.FileBuildPart).$($versionInfo.FilePrivatePart)"
            $fileVersion = New-Object System.Version($versionString)
        }

        Write-Host $versionInfo
        Write-Host $fileVersion
        
        
        }
    Catch
        {
        $srvsysPatched = '0'
        $srvsysVersion = "Unable to retrieve file version info, please verify vulnerability state manually."
        Write-Host "Error. Unable to retrieve file version info, please verify vulnerability state manually." -ForegroundColor Yellow
	Read-Host "Press ENTER"
        Return
        }
    }

elseif(Test-Path "$v2")
{

	$currentOS = "$osName"
	$versionInfo = (Get-Item $v2).VersionInfo
	$fileVersion = New-Object System.Version($versionInfo.ProductVersionRaw)
	Write-Host $versionInfo
        Write-Host $fileVersion
	Write-Host "`nCurrent OS: $currentOS (Build Number $($os.BuildNumber))" -ForegroundColor Cyan
	Write-Host "`nVersion of srv2.sys: $($fileVersion.ToString())" -ForegroundColor Cyan
	Write-Host "`nSystem is patched with MS17-010 and is therefore not vulnerable to EternalBlue." -ForegroundColor Green
	Read-Host "`nPress ENTER"
	break

}

Else
    {
    $srvsysPatched = '0'
    $srvsysVersion = "Srv.sys does not exist, please verify vulnerability state via Patch KB number."
    Write-Host "Error. Unable to locate Srv.sys/file does not exist, please verify vulnerability state via Patch KB number." -ForegroundColor Yellow
    Read-Host "Press ENTER"
    Return
    }
if ($osName.Contains("Vista") -or ($osName.Contains("2008") -and -not $osName.Contains("R2")))
    {
    if ($versionString.Split('.')[3][0] -eq "1")
        {
        $currentOS = "$osName GDR"
        $expectedVersion = New-Object System.Version("6.0.6002.19743")
        } 
    elseif ($versionString.Split('.')[3][0] -eq "2")
        {
        $currentOS = "$osName LDR"
        $expectedVersion = New-Object System.Version("6.0.6002.24067")
        }
    else
        {
        $currentOS = "$osName"
        $expectedVersion = New-Object System.Version("9.9.9999.99999")
        }
    }
elseif ($osName.Contains("Windows 7") -or ($osName.Contains("2008 R2")))
    {
    $currentOS = "$osName LDR"
    $expectedVersion = New-Object System.Version("6.1.7601.23689")
    }
elseif ($osName.Contains("Windows 8.1") -or $osName.Contains("2012 R2"))
    {
    $currentOS = "$osName LDR"
    $expectedVersion = New-Object System.Version("6.3.9600.18604")
    }
elseif ($osName.Contains("Windows 8") -or $osName.Contains("2012"))
    {
    $currentOS = "$osName LDR"
    $expectedVersion = New-Object System.Version("6.2.9200.22099")
    }
elseif ($osName.Contains("Windows 10"))
    {
    if ($os.BuildNumber -eq "10240")
        {
        $currentOS = "$osName TH1"
        $expectedVersion = New-Object System.Version("10.0.10240.17319")
        }
    elseif ($os.BuildNumber -eq "10586")
        {
        $currentOS = "$osName TH2"
        $expectedVersion = New-Object System.Version("10.0.10586.839")
        }
    elseif ($os.BuildNumber -eq "14393")
        {
        $currentOS = "$($osName) RS1"
        $expectedVersion = New-Object System.Version("10.0.14393.953")
        }
    
    ## Builds 10240, 10586 and 14393 could be afftected and hence those have been added above.
    ## Please note that if the Windows 10 Build is 1703 or later, there will be an error. We need to add 2-3 more build versions so that the code 
    ## can break from there by simply showing a line that the system is patched. 
    elseif ($os.BuildNumber -eq "16299")
        {
        $currentOS = "$osName"
        $srvsysPatched = '1'
	Write-Host "`nCurrent OS: $currentOS (Build Number $($os.BuildNumber))" -ForegroundColor Cyan
        Write-Host "`nSystem is patched with MS17-010 and is therefore not vulnerable to EternalBlue." -ForegroundColor Green
	Read-Host "`nPress ENTER"
        return
        }

    elseif ($os.BuildNumber -eq "15063")
        {
        $currentOS = "$osName"
        $srvsysPatched = '1'
	Write-Host "`nCurrent OS: $currentOS (Build Number $($os.BuildNumber))" -ForegroundColor Cyan
        Write-Host "`nSystem is patched with MS17-010 and is therefore not vulnerable to EternalBlue." -ForegroundColor Green
	Read-Host "`nPress ENTER"
        return
        }
    }
elseif ($osName.Contains("2016"))
    {
    $currentOS = "$osName"
    $expectedVersion = New-Object System.Version("10.0.14393.953")
    }
elseif ($osName.Contains("Windows XP"))
    {
    $currentOS = "$osName"
    $expectedVersion = New-Object System.Version("5.1.2600.7208")
    }
elseif ($osName.Contains("Server 2003"))
    {
    $currentOS = "$osName"
    $expectedVersion = New-Object System.Version("5.2.3790.6021")
    }
else
    {
    $srvsysPatched = '0'
    $srvsysVersion = "Unable to determine OS applicability, please verify vulnerability state via Patch KB number."
    Write-Host "Error. Unable to determine OS applicability, please verify vulnerability state manually." -ForegroundColor Yellow
    $currentOS = "$osName"
    $expectedVersion = New-Object System.Version("9.9.9999.99999")
    Read-Host "Press ENTER"
    }
    
    Write-Host "`nCurrent OS: $currentOS (Build Number $($os.BuildNumber))" -ForegroundColor Cyan
    Write-Host "`nExpected Version of srv.sys: $($expectedVersion.ToString())" -ForegroundColor Cyan
    Write-Host "`nActual Version of srv.sys: $($fileVersion.ToString())" -ForegroundColor Cyan
If ($($fileVersion.CompareTo($expectedVersion)) -lt 0)
    {
    
    Write-Host "`nSystem is NOT Patched with MS17-010 and is therefore vulnerable to EternalBlue!" -ForegroundColor Red
    $srvsysPatched = '0'
    $srvsysVersion = "System does not appear to be patched, please verify vulnerability state via Patch KB number. Version of srv.sys: $($fileVersion.ToString()), Expected version: 
$expectedVersion or higher."
    
    Read-Host "`nPress ENTER"
    }
Else
    {
    Write-Host "`n"
    Write-Host "System is Patched with MS17-010 and is therefore not Vulerable to EternalBlue" -ForegroundColor Green
    $srvsysPatched = '1'
    $srvsysVersion = "System is patched with MS17-010 and is therefore not Vulnerable to EternalBlue. Version of srv.sys: $($fileVersion.ToString()). Expected version: $expectedVersion or higher."
    Read-Host "Press ENTER"
    }
#
