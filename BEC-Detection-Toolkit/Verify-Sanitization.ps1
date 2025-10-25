# Verify-Sanitization.ps1
# Quick script to verify all hardcoded domains have been removed

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  BEC Toolkit Sanitization Verifier" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$rootPath = $PSScriptRoot
$scriptsPath = Join-Path $rootPath "Scripts"

# Check for hardcoded domains
$searchTerms = @("ecentria.com", "ecentria", "@ecentria")

$foundIssues = $false

Write-Host "Scanning for hardcoded references...`n" -ForegroundColor Yellow

Get-ChildItem -Path $scriptsPath -Filter "*.ps1" | ForEach-Object {
    $file = $_
    Write-Host "Checking: $($file.Name)" -ForegroundColor Cyan
    
    foreach ($term in $searchTerms) {
        $matches = Select-String -Path $file.FullName -Pattern $term -CaseSensitive:$false
        
        if ($matches) {
            $foundIssues = $true
            Write-Host "  [!] Found '$term' in:" -ForegroundColor Red
            foreach ($match in $matches) {
                Write-Host "      Line $($match.LineNumber): $($match.Line.Trim())" -ForegroundColor Yellow
            }
        }
    }
    
    if (-not $foundIssues) {
        Write-Host "  [✓] Clean - no hardcoded references" -ForegroundColor Green
    }
    Write-Host ""
    $foundIssues = $false
}

# Also check README and other docs
Write-Host "Checking documentation files...`n" -ForegroundColor Yellow

Get-ChildItem -Path $rootPath -Filter "*.md" | ForEach-Object {
    $file = $_
    
    # Skip SANITIZATION_COMPLETE.md as it contains the word "ecentria" in the changelog
    if ($file.Name -eq "SANITIZATION_COMPLETE.md") {
        Write-Host "Skipping: $($file.Name) (changelog document)" -ForegroundColor Gray
        return
    }
    
    Write-Host "Checking: $($file.Name)" -ForegroundColor Cyan
    
    foreach ($term in $searchTerms) {
        $matches = Select-String -Path $file.FullName -Pattern $term -CaseSensitive:$false
        
        if ($matches) {
            $foundIssues = $true
            Write-Host "  [!] Found '$term' in:" -ForegroundColor Red
            foreach ($match in $matches) {
                Write-Host "      Line $($match.LineNumber): $($match.Line.Trim())" -ForegroundColor Yellow
            }
        }
    }
    
    if (-not $foundIssues) {
        Write-Host "  [✓] Clean" -ForegroundColor Green
    }
    Write-Host ""
    $foundIssues = $false
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Verification Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`nIf all files show [✓] Clean, you're ready to publish!" -ForegroundColor Green
Write-Host "If any [!] Found messages appear, review those lines." -ForegroundColor Yellow
