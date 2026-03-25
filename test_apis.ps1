$output = @()
$output += "--- Testing Invite API ---"
try {
    $inviteBody = @{ username = "test_inv10"; password = "pwd"; email = "test10@example.com" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "http://localhost:8080/api/users/invite" -Method Post -Body $inviteBody -ContentType "application/json"
    $output += ($res | ConvertTo-Json)
} catch {
    $output += $_.Exception.Message
}

$output += "`n--- Testing Rule API ---"
try {
    $ruleBody = @{ name = "test rule 10"; description = "desc"; action = "BLOCK" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "http://localhost:8080/api/rules" -Method Post -Body $ruleBody -ContentType "application/json"
    $output += ($res | ConvertTo-Json)
} catch {
    $output += $_.Exception.Message
}

$output += "`n--- Testing Scan API ---"
try {
    $scanBody = @{ content = "http://google.com" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "http://localhost:8080/api/analysis/scan" -Method Post -Body $scanBody -ContentType "application/json"
    $output += ($res | ConvertTo-Json)
} catch {
    $output += $_.Exception.Message
}

$output | Out-File -FilePath "C:\Users\NKUNIM\Desktop\Enterprise Fraud Intelligence & Threat Analysis Platform\test_out3.txt" -Encoding utf8
