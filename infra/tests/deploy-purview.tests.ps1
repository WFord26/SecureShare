#Requires -Version 7.2
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot '../deploy.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors -join "`n") }
$definition = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Resolve-DelegatedScopes'
}, $true)
. ([scriptblock]::Create($definition.Extent.Text))
$scopes = @(
    [pscustomobject]@{ value = 'Content.Process.User'; id = 'content-id'; isEnabled = $true },
    [pscustomobject]@{ value = 'ProtectionScopes.Compute.User'; id = 'compute-id'; isEnabled = $true },
    [pscustomobject]@{ value = 'Content.Process.All'; id = 'broad-id'; isEnabled = $true }
)
$requested = @('Content.Process.User', 'ProtectionScopes.Compute.User')
$result = Resolve-DelegatedScopes $scopes $requested
if ($result.Count -ne 2 -or $result['Content.Process.User'] -ne 'content-id' -or
    $result['ProtectionScopes.Compute.User'] -ne 'compute-id') { throw 'Incorrect permission resolution.' }
foreach ($available in @(@($scopes[0]), @($scopes + $scopes[0]))) {
    $rejected = $false
    try { Resolve-DelegatedScopes $available $requested | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Missing or ambiguous permission was accepted.' }
}
$scopes[0].isEnabled = $false
$rejected = $false
try { Resolve-DelegatedScopes $scopes $requested | Out-Null } catch { $rejected = $true }
if (-not $rejected) { throw 'Disabled permission was accepted.' }
Write-Output 'PASS: Purview delegated permissions resolved; missing, disabled and duplicate permissions rejected.'
