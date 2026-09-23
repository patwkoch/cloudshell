#!/bin/bash
set -u

REGION="us-east-1"
HOME_ACCOUNT="472466695190"
ROLE_NAME="EC2-Restart-Orchestrator-Role"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT="iis-cert-cross-account-${TIMESTAMP}.csv"

# Environment|AccountId
ACCOUNTS=(
  "DEV-QA|185560503223"
  "STG-TRN-UAT|598767860971"
  "PROD|472466695190"
)

echo '"Environment","AccountId","InstanceId","Hostname","Binding","Subject","Template","Thumbprint","Expiration","DaysRemaining","Status"' > "$REPORT"

CURRENT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)
echo "Current AWS account: $CURRENT_ACCOUNT"
if [ "$CURRENT_ACCOUNT" != "$HOME_ACCOUNT" ]; then
  echo "WARNING: Expected to start in PROD account $HOME_ACCOUNT. Continuing, but cross-account trust may differ."
fi

run_aws() {
  if [ "$USE_ASSUMED" = "true" ]; then
    AWS_ACCESS_KEY_ID="$ASSUMED_ACCESS_KEY" \
    AWS_SECRET_ACCESS_KEY="$ASSUMED_SECRET_KEY" \
    AWS_SESSION_TOKEN="$ASSUMED_SESSION_TOKEN" \
    aws "$@"
  else
    aws "$@"
  fi
}

for ENTRY in "${ACCOUNTS[@]}"; do
  ENVIRONMENT="${ENTRY%%|*}"
  ACCOUNT_ID="${ENTRY##*|}"
  # Excel opens CSV numeric-looking fields as numbers even when CSV-quoted.
  # This constant text formula preserves the fixed, trusted 12-digit account ID.
  ACCOUNT_ID_CSV="\"=\"\"${ACCOUNT_ID}\"\"\""
  USE_ASSUMED="false"

  echo
  echo "======================================================"
  echo " $ENVIRONMENT - $ACCOUNT_ID"
  echo "======================================================"

  if [ "$ACCOUNT_ID" != "$CURRENT_ACCOUNT" ]; then
    echo "Assuming role $ROLE_NAME..."
    CREDS=$(aws sts assume-role \
      --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}" \
      --role-session-name "IISCertInventory" \
      --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
      --output text 2>/dev/null) || {
        echo "ERROR: Unable to assume role in $ACCOUNT_ID"
        echo "\"$ENVIRONMENT\",$ACCOUNT_ID_CSV,\"\",\"\",\"\",\"ASSUME ROLE FAILED\",\"\",\"\",\"\",\"\",\"ERROR\"" >> "$REPORT"
        continue
      }
    read -r ASSUMED_ACCESS_KEY ASSUMED_SECRET_KEY ASSUMED_SESSION_TOKEN <<< "$CREDS"
    USE_ASSUMED="true"
  else
    echo "Using current CloudShell credentials."
  fi

  INSTANCE_IDS=$(run_aws ssm describe-instance-information \
    --region "$REGION" \
    --filters "Key=PlatformTypes,Values=Windows" \
    --query 'InstanceInformationList[].InstanceId' \
    --output text 2>/dev/null || true)

  if [ -z "$INSTANCE_IDS" ] || [ "$INSTANCE_IDS" = "None" ]; then
    echo "No SSM-managed Windows instances found."
    continue
  fi

  INSTANCE_COUNT=$(echo "$INSTANCE_IDS" | wc -w | tr -d ' ')
  echo "Found $INSTANCE_COUNT Windows instances."
  echo "Submitting read-only IIS certificate inventory..."

  COMMAND_ID=$(run_aws ssm send-command \
    --region "$REGION" \
    --instance-ids $INSTANCE_IDS \
    --document-name "AWS-RunPowerShellScript" \
    --comment "Read-only IIS HTTPS certificate inventory" \
    --parameters 'commands=[
"Import-Module WebAdministration -ErrorAction SilentlyContinue",
"if (-not (Get-Module WebAdministration)) { [PSCustomObject]@{Hostname=$env:COMPUTERNAME;Binding=\"\";Subject=\"\";Template=\"\";Thumbprint=\"\";Expiration=\"\";DaysRemaining=\"\";Status=\"NO_IIS\"} | ConvertTo-Csv -NoTypeInformation; exit 0 }",
"# Prefer v2 template information, then the legacy template-name extension.",
"function Get-InventoryTemplate($Cert) {",
" $Fallback=\"UNKNOWN\"",
" foreach ($Oid in @(\"1.3.6.1.4.1.311.21.7\",\"1.3.6.1.4.1.311.20.2\")) {",
"  foreach ($Ext in @($Cert.Extensions | Where-Object { $_.Oid.Value -eq $Oid })) {",
"   try { $Text=$Ext.Format($false).Trim() } catch { continue }",
"   if (-not $Text) { continue }",
"   # Resolve known fleet template OIDs even when Windows cannot resolve their names.",
"   if ($Text -match \"1\\.3\\.6\\.1\\.4\\.1\\.311\\.21\\.8\\.10987005\\.6455535\\.6243231\\.9307925\\.11114365\\.15\\.961358\\.10389579(?![\\d.])\") { return \"Standard SSL Certificate\" }",
"   if ($Text -match \"1\\.3\\.6\\.1\\.4\\.1\\.311\\.21\\.8\\.10987005\\.6455535\\.6243231\\.9307925\\.11114365\\.15\\.7040614\\.1412261(?![\\d.])\") { return \"Serco CMS Web Server\" }",
"   $Name=$Text",
"   if ($Text -match \"Template\\s*=\\s*([^\\r\\n,]+)\") { $Name=$Matches[1].Trim() }",
"   elseif ($Oid -eq \"1.3.6.1.4.1.311.21.7\") { $Fallback=$Text; continue }",
"   $Name=($Name -replace \"\\s*\\([\\d.]+\\)\\s*$\",\"\").Trim()",
"   switch -Regex ($Name) {",
"    \"^Standard\\s*SSL\\s*Certificate$\" { return \"Standard SSL Certificate\" }",
"    \"^Web\\s*Server$\" { return \"WebServer\" }",
"    \"^Serco\\s*CMS\\s*Web\\s*Server$\" { return \"Serco CMS Web Server\" }",
"   }",
"   if ($Name -match \"^\\d+(\\.\\d+)+$\") { $Fallback=$Name; continue }",
"   if ($Name) { return $Name }",
"  }",
" }",
" return $Fallback",
"}",
"# Single-status precedence: EXPIRED, MISSING_CN, RENEW_SOON, LEGACY_TEMPLATE, OK.",
"# Unrecognized templates retain their name/OID; only known legacy templates are flagged.",
"$Now=Get-Date",
"$Results=Get-WebBinding -Protocol https | ForEach-Object {",
" $Binding=$_",
" $Hash=if ($Binding.CertificateHash -is [byte[]]) { ([BitConverter]::ToString($Binding.CertificateHash)).Replace(\"-\",\"\") } else { ([string]$Binding.CertificateHash -replace \"\\s\",\"\").ToUpperInvariant() }",
" if (-not $Hash) { return }",
" $Cert=Get-ChildItem Cert:\\LocalMachine\\My | Where-Object { ($_.Thumbprint -replace \" \",\"\").ToUpper() -eq $Hash } | Select-Object -First 1",
" if ($Cert) {",
"  $Days=[math]::Floor(($Cert.NotAfter-$Now).TotalDays)",
"  $Template=Get-InventoryTemplate $Cert",
"  $HasCN=$Cert.Subject -match \"(?:^|,|;)\\s*CN\\s*=\\s*[^\\s,;]+\"",
"  $Status=if($Cert.NotAfter -le $Now){\"EXPIRED\"}elseif(-not $HasCN){\"MISSING_CN\"}elseif($Days -le 90){\"RENEW_SOON\"}elseif($Template -in @(\"WebServer\",\"Serco CMS Web Server\")){\"LEGACY_TEMPLATE\"}else{\"OK\"}",
"  [PSCustomObject]@{Hostname=$env:COMPUTERNAME;Binding=$Binding.BindingInformation;Subject=$Cert.Subject;Template=$Template;Thumbprint=$Cert.Thumbprint;Expiration=$Cert.NotAfter.ToString(\"yyyy-MM-dd HH:mm:ss\");DaysRemaining=$Days;Status=$Status}",
" } else {",
"  [PSCustomObject]@{Hostname=$env:COMPUTERNAME;Binding=$Binding.BindingInformation;Subject=\"CERTIFICATE NOT FOUND\";Template=\"UNKNOWN\";Thumbprint=$Hash;Expiration=\"\";DaysRemaining=\"\";Status=\"ORPHANED_BINDING\"}",
" }",
"}",
"if($Results){$Results | ConvertTo-Csv -NoTypeInformation}else{[PSCustomObject]@{Hostname=$env:COMPUTERNAME;Binding=\"\";Subject=\"\";Template=\"\";Thumbprint=\"\";Expiration=\"\";DaysRemaining=\"\";Status=\"NO_HTTPS_BINDINGS\"} | ConvertTo-Csv -NoTypeInformation}"
]' \
    --query 'Command.CommandId' \
    --output text 2>/dev/null) || {
      echo "ERROR: Unable to submit SSM command."
      echo "\"$ENVIRONMENT\",$ACCOUNT_ID_CSV,\"\",\"\",\"\",\"SEND COMMAND FAILED\",\"\",\"\",\"\",\"\",\"ERROR\"" >> "$REPORT"
      continue
    }

  echo "Command ID: $COMMAND_ID"
  echo "Waiting for all invocations to finish..."

  while true; do
    STATUSES=$(run_aws ssm list-command-invocations \
      --region "$REGION" \
      --command-id "$COMMAND_ID" \
      --query 'CommandInvocations[].Status' \
      --output text 2>/dev/null || true)
    TOTAL=$(echo "$STATUSES" | wc -w | tr -d ' ')
    PENDING=$(echo "$STATUSES" | tr '\t' '\n' | grep -E '^(Pending|InProgress|Delayed)$' | wc -l | tr -d ' ' || true)
    echo "  Completed: $((TOTAL-PENDING)) / $TOTAL"
    if [ "$TOTAL" -gt 0 ] && [ "$PENDING" -eq 0 ]; then break; fi
    sleep 5
  done

  echo "Collecting $ENVIRONMENT results..."
  for ID in $INSTANCE_IDS; do
    INVOCATION=$(run_aws ssm get-command-invocation \
      --region "$REGION" \
      --command-id "$COMMAND_ID" \
      --instance-id "$ID" \
      --output json 2>/dev/null || true)

    if [ -z "$INVOCATION" ]; then
      echo "\"$ENVIRONMENT\",$ACCOUNT_ID_CSV,\"$ID\",\"\",\"\",\"NO INVOCATION RESULT\",\"\",\"\",\"\",\"\",\"ERROR\"" >> "$REPORT"
      continue
    fi

    STATUS=$(echo "$INVOCATION" | jq -r '.Status // "UNKNOWN"')
    OUTPUT=$(echo "$INVOCATION" | jq -r '.StandardOutputContent // ""')

    if [ "$STATUS" != "Success" ]; then
      ERR=$(echo "$INVOCATION" | jq -r '.StandardErrorContent // ""' | tr '\n' ' ' | sed 's/"/""/g')
      echo "\"$ENVIRONMENT\",$ACCOUNT_ID_CSV,\"$ID\",\"\",\"\",\"SSM COMMAND FAILED\",\"\",\"\",\"\",\"\",\"$STATUS: $ERR\"" >> "$REPORT"
      continue
    fi

    if echo "$OUTPUT" | grep -q '^NO_IIS$'; then continue; fi
    if echo "$OUTPUT" | grep -q '^NO_HTTPS_BINDINGS$'; then continue; fi

    echo "$OUTPUT" | grep -v '^"Hostname"' | sed '/^[[:space:]]*$/d' | while IFS= read -r LINE; do
      echo "\"$ENVIRONMENT\",$ACCOUNT_ID_CSV,\"$ID\",$LINE" >> "$REPORT"
    done
  done
done

echo
echo "======================================================"
echo " CROSS-ACCOUNT REPORT COMPLETE"
echo "======================================================"
echo "Report: $REPORT"
echo
echo "Certificates requiring attention (expiration, template, CN, orphaned binding, or error):"
python3 - "$REPORT" <<'PYCSV'
import csv
import sys

with open(sys.argv[1], newline="", encoding="utf-8-sig") as report:
    rows = csv.DictReader(report)
    writer = csv.DictWriter(sys.stdout, fieldnames=rows.fieldnames)
    writer.writeheader()
    for row in rows:
        if row["Status"] not in {"OK", "NO_IIS", "NO_HTTPS_BINDINGS"}:
            writer.writerow(row)
PYCSV
echo
echo "Full report:"
cat "$REPORT"
