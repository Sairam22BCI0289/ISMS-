$ErrorActionPreference = "Stop"

$BackendDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceDir = Join-Path $BackendDir "data\public_datasets\host_public_raw\evtx_tmp"
$DestDir = Join-Path $BackendDir "data\public_datasets\host_public_raw\evtx_attack_samples"
$VenvPythonPath = Join-Path $BackendDir ".venv\Scripts\python.exe"

function Find-CommandPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {
        $cmd = Get-Command $Name -ErrorAction Stop
        return $cmd.Source
    }
    catch {
        return $null
    }
}

function Find-LocalPythonConverter {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SearchRoot
    )

    $candidateNames = @(
        "evtx2json.py",
        "evtx_to_json.py",
        "convert_evtx_to_json.py",
        "evtx_dump_json.py",
        "evtx_dump.py"
    )

    foreach ($name in $candidateNames) {
        $found = Get-ChildItem -Path $SearchRoot -Recurse -File -Filter $name -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($found) {
            return $found.FullName
        }
    }

    return $null
}

function Convert-WithEvtx2Json {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConverterPath,
        [Parameter(Mandatory = $true)]
        [string]$InputPath,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $output = & $ConverterPath $InputPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "evtx2json failed: $output"
    }

    [System.IO.File]::WriteAllLines($OutputPath, $output)
}

function Convert-WithPythonScript {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonPath,
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        [Parameter(Mandatory = $true)]
        [string]$InputPath,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $scriptName = [System.IO.Path]::GetFileName($ScriptPath).ToLowerInvariant()

    $argSets = @(
        @($ScriptPath, $InputPath, $OutputPath),
        @($ScriptPath, "-i", $InputPath, "-o", $OutputPath),
        @($ScriptPath, "--input", $InputPath, "--output", $OutputPath),
        @($ScriptPath, $InputPath)
    )

    $firstMeaningfulErrorText = $null
    $lastErrorText = $null

    foreach ($args in $argSets) {
        try {
            $result = & $PythonPath @args 2>&1
            $exitCode = $LASTEXITCODE

            if ($exitCode -ne 0) {
                $errorText = ($result | Out-String).Trim()
                if (-not [string]::IsNullOrWhiteSpace($errorText)) {
                    if (-not $firstMeaningfulErrorText) {
                        $firstMeaningfulErrorText = $errorText
                    }
                    $lastErrorText = $errorText
                }
                continue
            }

            if (Test-Path -LiteralPath $OutputPath) {
                return
            }

            if ($args.Count -eq 2 -and $result) {
                [System.IO.File]::WriteAllLines($OutputPath, $result)
                return
            }

            if (Test-Path -LiteralPath $OutputPath) {
                return
            }
        }
        catch {
            $errorText = $_.Exception.Message
            if (-not [string]::IsNullOrWhiteSpace($errorText)) {
                if (-not $firstMeaningfulErrorText) {
                    $firstMeaningfulErrorText = $errorText
                }
                $lastErrorText = $errorText
            }
        }
    }

    $errorToReport = $firstMeaningfulErrorText
    if (-not $errorToReport) {
        $errorToReport = $lastErrorText
    }
    if (-not $errorToReport) {
        $errorToReport = "unknown error"
    }

    throw "python converter failed for script '$scriptName': $errorToReport"
}

New-Item -ItemType Directory -Force -Path $DestDir | Out-Null

if (-not (Test-Path -LiteralPath $SourceDir)) {
    Write-Host "[ERROR] Source folder not found: $SourceDir"
    exit 1
}

$EvtxFiles = Get-ChildItem -Path $SourceDir -Filter *.evtx -File -ErrorAction SilentlyContinue
$TotalFound = $EvtxFiles.Count
$Converted = 0
$Failed = 0

$Evtx2JsonPath = Find-CommandPath -Name "evtx2json"
$PythonPath = $null
if (Test-Path -LiteralPath $VenvPythonPath) {
    $PythonPath = $VenvPythonPath
}
else {
    $PythonPath = Find-CommandPath -Name "python"
}
$LocalPythonConverter = $null

if (-not $Evtx2JsonPath -and $PythonPath) {
    $LocalPythonConverter = Find-LocalPythonConverter -SearchRoot $BackendDir
}

if (-not $Evtx2JsonPath -and (-not $PythonPath -or -not $LocalPythonConverter)) {
    Write-Host "[WARN] No supported EVTX converter found."
    Write-Host "[WARN] Checked for:"
    Write-Host "       - evtx2json"
    Write-Host "       - python plus a local converter script such as evtx2json.py / evtx_to_json.py"
    Write-Host "[INFO] Source folder: $SourceDir"
    Write-Host "[INFO] Destination folder: $DestDir"
    Write-Host "[INFO] Total .evtx files found: $TotalFound"
    Write-Host "[INFO] Total converted successfully: 0"
    Write-Host "[INFO] Total failed: $TotalFound"
    exit 1
}

if ($Evtx2JsonPath) {
    Write-Host "[INFO] Using converter: evtx2json ($Evtx2JsonPath)"
}
elseif ($PythonPath -and $LocalPythonConverter) {
    Write-Host "[INFO] Using converter: python ($PythonPath) + $LocalPythonConverter"
}

foreach ($file in $EvtxFiles) {
    $outputName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name) + ".json"
    $outputPath = Join-Path $DestDir $outputName

    Write-Host "[INFO] Input:  $($file.Name)"
    Write-Host "[INFO] Output: $outputName"

    if (Test-Path -LiteralPath $outputPath) {
        Write-Host "[SKIP] Output already exists."
        continue
    }

    try {
        if ($Evtx2JsonPath) {
            Convert-WithEvtx2Json -ConverterPath $Evtx2JsonPath -InputPath $file.FullName -OutputPath $outputPath
        }
        else {
            Convert-WithPythonScript -PythonPath $PythonPath -ScriptPath $LocalPythonConverter -InputPath $file.FullName -OutputPath $outputPath
        }

        if (Test-Path -LiteralPath $outputPath) {
            $Converted += 1
            Write-Host "[OK] Converted successfully."
        }
        else {
            $Failed += 1
            Write-Host "[FAIL] Converter finished but no output file was created."
        }
    }
    catch {
        $Failed += 1
        Write-Host "[FAIL] $($_.Exception.Message)"
    }
}

Write-Host "[INFO] Total .evtx files found: $TotalFound"
Write-Host "[INFO] Total converted successfully: $Converted"
Write-Host "[INFO] Total failed: $Failed"
