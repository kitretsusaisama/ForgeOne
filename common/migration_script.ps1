# Migration Script for ForgeOne Common Module Restructuring
# This PowerShell script implements the folder structure reorganization plan

# Set error action preference to stop on any error
$ErrorActionPreference = "Stop"

# Define the root directory
$rootDir = "c:/Users/Victo/Downloads/TERO/common"
$srcDir = "$rootDir/src"
$testsDir = "$rootDir/tests"
$dataDir = "$rootDir/data"
$docsDir = "$rootDir/docs"
$examplesDir = "$rootDir/examples"

# Function to create directory if it doesn't exist
function EnsureDirectory {
    param(
        [string]$path
    )
    
    if (-not (Test-Path -Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        Write-Host "Created directory: $path"
    }
}

# Function to create a mod.rs file
function CreateModFile {
    param(
        [string]$directory,
        [string]$moduleName
    )
    
    $modPath = "$directory/mod.rs"
    if (-not (Test-Path -Path $modPath)) {
        $content = "//! $moduleName module for ForgeOne Common\n\n// Re-export all public items\n"
        Set-Content -Path $modPath -Value $content
        Write-Host "Created mod.rs file: $modPath"
    }
}

# Function to move a file and update its imports
function MoveFile {
    param(
        [string]$sourcePath,
        [string]$destPath
    )
    
    if (Test-Path -Path $sourcePath) {
        # Create the destination directory if it doesn't exist
        $destDir = Split-Path -Path $destPath -Parent
        EnsureDirectory -path $destDir
        
        # Copy the file to the new location
        Copy-Item -Path $sourcePath -Destination $destPath -Force
        Write-Host "Moved file: $sourcePath -> $destPath"
    } else {
        Write-Host "Source file not found: $sourcePath" -ForegroundColor Yellow
    }
}

# Phase 1: Module Reorganization
Write-Host "\nPhase 1: Module Reorganization" -ForegroundColor Cyan

# Create module directories and mod.rs files
$modules = @(
    @{Name = "bootstrap"; DisplayName = "Bootstrap"},
    @{Name = "config"; DisplayName = "Configuration"},
    @{Name = "crypto"; DisplayName = "Cryptography"},
    @{Name = "db"; DisplayName = "Database"},
    @{Name = "error"; DisplayName = "Error Handling"},
    @{Name = "identity"; DisplayName = "Identity"},
    @{Name = "trust"; DisplayName = "Trust"},
    @{Name = "policy"; DisplayName = "Policy"},
    @{Name = "telemetry"; DisplayName = "Telemetry"},
    @{Name = "observer"; DisplayName = "Observer"},
    @{Name = "diagnostics"; DisplayName = "Diagnostics"},
    @{Name = "audit"; DisplayName = "Audit"},
    @{Name = "model"; DisplayName = "Model"},
    @{Name = "macros"; DisplayName = "Macros"}
)

foreach ($module in $modules) {
    $moduleDir = "$srcDir/$($module.Name)"
    EnsureDirectory -path $moduleDir
    CreateModFile -directory $moduleDir -moduleName $module.DisplayName
}

# Define submodule structure
$submodules = @{
    "bootstrap" = @("init", "shutdown")
    "config" = @("loader", "validator", "signed")
    "crypto" = @("keys", "signatures", "encryption", "hashing", "random")
    "db" = @("access", "crypto", "indxdb", "integrity", "metrics", "model", "recovery", "redb", "schema", "snapshot", "sharding", "vault")
    "error" = @("types", "traceable", "predictor")
    "identity" = @("context", "trust")
    "trust" = @("graph", "node", "evaluation")
    "policy" = @("effect", "rule", "set")
    "telemetry" = @("metrics", "tracing", "health", "profiling")
    "observer" = @("types", "severity", "llm")
    "diagnostics" = @("health", "predictive", "reporting")
    "audit" = @("event", "log", "policy", "compliance")
    "model" = @("syscall", "execution", "resource")
    "macros" = @("logging", "tracing", "policy", "audit")
}

# Create submodule files
foreach ($module in $modules) {
    $moduleName = $module.Name
    $moduleDir = "$srcDir/$moduleName"
    
    if ($submodules.ContainsKey($moduleName)) {
        foreach ($submodule in $submodules[$moduleName]) {
            $submodulePath = "$moduleDir/$submodule.rs"
            if (-not (Test-Path -Path $submodulePath)) {
                $content = "//! $submodule functionality for the $moduleName module\n"
                Set-Content -Path $submodulePath -Value $content
                Write-Host "Created submodule file: $submodulePath"
            }
        }
    }
}

# Move existing module files to their new locations
foreach ($module in $modules) {
    $moduleName = $module.Name
    $sourceFile = "$srcDir/$moduleName.rs"
    $destFile = "$srcDir/$moduleName/mod.rs"
    
    if (Test-Path -Path $sourceFile) {
        # Read the content of the source file
        $content = Get-Content -Path $sourceFile -Raw
        
        # Set the content to the destination file
        Set-Content -Path $destFile -Value $content
        Write-Host "Moved module content: $sourceFile -> $destFile"
    }
}

# Phase 2: Test Reorganization
Write-Host "\nPhase 2: Test Reorganization" -ForegroundColor Cyan

# Create test directories
$testDirs = @(
    "$testsDir/common",
    "$testsDir/unit",
    "$testsDir/integration",
    "$testsDir/performance"
)

foreach ($dir in $testDirs) {
    EnsureDirectory -path $dir
}

# Create common test utilities
$commonTestFiles = @(
    @{Path = "$testsDir/common/mod.rs"; Content = "//! Common test utilities for ForgeOne Common\n"},
    @{Path = "$testsDir/common/fixtures.rs"; Content = "//! Test fixtures for ForgeOne Common\n"},
    @{Path = "$testsDir/common/helpers.rs"; Content = "//! Test helpers for ForgeOne Common\n"}
)

foreach ($file in $commonTestFiles) {
    if (-not (Test-Path -Path $file.Path)) {
        Set-Content -Path $file.Path -Value $file.Content
        Write-Host "Created common test file: $file.Path"
    }
}

# Create unit test directories for each module
foreach ($module in $modules) {
    $unitTestDir = "$testsDir/unit/$($module.Name)"
    EnsureDirectory -path $unitTestDir
}

# Move existing test files to their new locations
$testFiles = Get-ChildItem -Path $testsDir -Filter "*.rs"
foreach ($testFile in $testFiles) {
    $fileName = $testFile.Name
    $moduleName = $fileName -replace "_test\.rs$", ""
    
    # Skip files that don't match the module pattern
    if (-not ($modules | Where-Object { $_.Name -eq $moduleName })) {
        # Check if it's an integration test
        if ($fileName -match "_integration\.rs$") {
            $destFile = "$testsDir/integration/$fileName"
            MoveFile -sourcePath $testFile.FullName -destPath $destFile
        }
        # Check if it's a performance test
        elseif ($fileName -match "_performance\.rs$") {
            $destFile = "$testsDir/performance/$fileName"
            MoveFile -sourcePath $testFile.FullName -destPath $destFile
        }
        continue
    }
    
    $destFile = "$testsDir/unit/$moduleName/$fileName"
    MoveFile -sourcePath $testFile.FullName -destPath $destFile
}

# Phase 3: Data Reorganization
Write-Host "\nPhase 3: Data Reorganization" -ForegroundColor Cyan

# Create data directories
$dataDirs = @(
    "$dataDir/vault",
    "$dataDir/backups",
    "$dataDir/backups/system",
    "$dataDir/backups/logs",
    "$dataDir/backups/blobs",
    "$dataDir/backups/events"
)

foreach ($dir in $dataDirs) {
    EnsureDirectory -path $dir
}

# Create placeholder for vault
$vaultFile = "$dataDir/vault/secrets.vault"
if (-not (Test-Path -Path $vaultFile)) {
    Set-Content -Path $vaultFile -Value "# Placeholder for encrypted secrets vault"
    Write-Host "Created placeholder vault file: $vaultFile"
}

# Phase 4: Examples
Write-Host "\nPhase 4: Examples" -ForegroundColor Cyan

# Create examples directory
EnsureDirectory -path $examplesDir

# Create example files
$exampleFiles = @(
    @{Path = "$examplesDir/basic_usage.rs"; Content = "//! Basic usage example for ForgeOne Common\n\nfn main() {\n    println!(\"Basic usage example for ForgeOne Common\");\n}\n"},
    @{Path = "$examplesDir/audit_example.rs"; Content = "//! Audit example for ForgeOne Common\n\nfn main() {\n    println!(\"Audit example for ForgeOne Common\");\n}\n"},
    @{Path = "$examplesDir/policy_example.rs"; Content = "//! Policy example for ForgeOne Common\n\nfn main() {\n    println!(\"Policy example for ForgeOne Common\");\n}\n"},
    @{Path = "$examplesDir/db_example.rs"; Content = "//! Database example for ForgeOne Common\n\nfn main() {\n    println!(\"Database example for ForgeOne Common\");\n}\n"}
)

foreach ($file in $exampleFiles) {
    if (-not (Test-Path -Path $file.Path)) {
        Set-Content -Path $file.Path -Value $file.Content
        Write-Host "Created example file: $file.Path"
    }
}

Write-Host "\nMigration completed successfully!" -ForegroundColor Green
Write-Host "Please review the changes and update imports in all files to reflect the new structure."