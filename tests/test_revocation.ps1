
$baseUrl = "http://127.0.0.1:8001"

# 1. Login
$loginData = @{ username="testuser2"; password="testpassword123" }
try {
    $resp = Invoke-RestMethod -Uri "$baseUrl/api/auth/login" -Method Post -Body $loginData
} catch {
    $regData = @{ username="testuser2"; email="test2@example.com"; full_name="Test User"; password="testpassword123" } | ConvertTo-Json
    Invoke-RestMethod -Uri "$baseUrl/api/auth/register" -Method Post -Body $regData -ContentType "application/json"
    $resp = Invoke-RestMethod -Uri "$baseUrl/api/auth/login" -Method Post -Body $loginData
}

$token = $resp.access_token
$headers = @{ "Authorization" = "Bearer $token"; "Content-Type" = "application/json" }

Write-Host "--- Test: Revocation Blockchain Verification ---"

# Register Doc
$rand = Get-Random
$docData = @{ doc_type="national_id"; fields=@{ id_number="789-$rand"; name="Check-$rand" } } | ConvertTo-Json
$doc = Invoke-RestMethod -Uri "$baseUrl/api/identity/documents" -Method Post -Body $docData -Headers $headers
$docId = $doc.id
Write-Host "Registered doc: $docId"

# Create Grant
$grantData = @{ document_id=$docId; grantee_identifier="checker@test.com"; fields_allowed=@("name"); expires_hours=1 } | ConvertTo-Json
$grant = Invoke-RestMethod -Uri "$baseUrl/api/access/grants" -Method Post -Body $grantData -Headers $headers
$grantId = $grant.id
Write-Host "Created grant: $grantId"

# Revoke Grant
Write-Host "Revoking grant..."
Invoke-RestMethod -Uri "$baseUrl/api/access/grants/$grantId" -Method Delete -Headers $headers

# Check ALL blocks
$blocks = Invoke-RestMethod -Uri "$baseUrl/api/chain/blocks" -Method Get -Headers $headers
Write-Host "Total Blocks: $($blocks.Count)"

$found = $false
foreach ($block in $blocks) {
    foreach ($tx in $block.transactions) {
        Write-Host "Block $($block.index) - Action: $($tx.action)"
        if ($tx.action -eq "REVOKE_GRANT" -and $tx.metadata.grant_id -eq $grantId) {
            $found = $true
        }
    }
}

if ($found) {
    Write-Host "`nSUCCESS: REVOKE_GRANT found on blockchain!"
} else {
    Write-Host "`nFAILURE: REVOKE_GRANT NOT found on blockchain."
    exit 1
}
