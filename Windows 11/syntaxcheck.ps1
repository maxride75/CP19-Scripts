$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path .\Windows11_Hardening.ps1),
    [ref]$tokens,
    [ref]$errors
) | Out-Null
$errors
