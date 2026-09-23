#!/bin/bash
set -u

# Inventory only: never renews, rebinds, deletes, or exports private keys.
# Includes LocalMachine\My certificates even on servers without IIS.
# NO_REFERENCE_FOUND means no match in completed checks, NOT safe to delete.
# Kofax/application settings, scheduled scripts, automatic selection, CCS,
# and certificate stores other than LocalMachine\My are not inspected.
# UsageCheckCoverage records failures and these scope limits on each row.

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

echo '"Environment","AccountId","InstanceId","Hostname","Binding","Subject","DNSNames","Template","Thumbprint","Expiration","DaysRemaining","Status","RecordType","CertificateStore","IISBindingStatus","DetectedUsage","UsageStatus","UsageCheckCoverage"' > "$REPORT"

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
        echo "\"$ENVIRONMENT\",$ACCOUNT_ID_CSV,\"\",\"\",\"\",\"ASSUME ROLE FAILED\",\"\",\"\",\"\",\"\",\"\",\"ERROR\",\"ERROR\",\"\",\"\",\"\",\"CHECKS_INCOMPLETE\",\"NOT_RUN\"" >> "$REPORT"
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
"# Read-only scope: LocalMachine\\My. References indicate configuration, not live use.",
"function Normalize-Hash($Value) {",
" if ($Value -is [byte[]]) { return ([BitConverter]::ToString($Value)).Replace(\"-\",\"\") }",
" return ([string]$Value -replace \"[\\s\\u200e\\u200f]\", \"\").ToUpperInvariant()",
"}",
"$Usage=@{}",
"$Coverage=[ordered]@{}",
"function Add-Usage($Hash,$Label) {",
" $Key=Normalize-Hash $Hash",
" if ($Key -match \"^[A-F0-9]{40}$\") { $Usage[$Key]=@($Usage[$Key])+@($Label) }",
"}",
"$Bindings=@()",
"$IisChecked=$false",
"$IisState=\"ERROR\"",
"try {",
" if (Get-Module -ListAvailable WebAdministration) {",
"  Import-Module WebAdministration -ErrorAction Stop",
"  $Bindings=@(Get-WebBinding -Protocol https -ErrorAction Stop)",
"  $IisChecked=$true",
"  $IisState=if ($Bindings.Count) { \"PRESENT\" } else { \"NO_HTTPS_BINDINGS\" }",
"  $Coverage[\"IIS\"]=\"CHECKED\"",
"  foreach ($B in $Bindings) { Add-Usage $B.CertificateHash (\"IIS: \"+$B.BindingInformation) }",
" } elseif (-not (Test-Path \"$env:windir\\System32\\inetsrv\\config\\applicationHost.config\")) {",
"  $IisChecked=$true; $IisState=\"NO_IIS\"; $Coverage[\"IIS\"]=\"NOT_INSTALLED\"",
" } else { $Coverage[\"IIS\"]=\"FAILED_MODULE_UNAVAILABLE\" }",
"} catch { $Coverage[\"IIS\"]=\"FAILED\" }",
"try {",
" $HttpText=(& netsh.exe http show sslcert 2>&1 | Out-String)",
" if ($LASTEXITCODE -ne 0) { throw \"HTTP.sys query failed\" }",
" # Label parsing is English-only. Other locales are explicitly incomplete.",
" if ($HttpText -notmatch \"SSL Certificate bindings\") { throw \"Unrecognized HTTP.sys output\" }",
" $MatchesHttp=[regex]::Matches($HttpText,\"(?im)^\\s*Certificate Hash\\s*:\\s*([a-f0-9]{40})\\s*$\")",
" foreach ($M in $MatchesHttp) { Add-Usage $M.Groups[1].Value \"HTTP.sys SSL registration\" }",
" $Coverage[\"HTTP.sys\"]=\"CHECKED_STATIC_HASHES_ONLY\"",
"} catch { $Coverage[\"HTTP.sys\"]=\"FAILED_OR_UNSUPPORTED_OUTPUT\" }",
"try {",
" $Listeners=@(Get-CimInstance -Namespace \"root\\cimv2\\TerminalServices\" -ClassName Win32_TSGeneralSetting -ErrorAction Stop)",
" $Coverage[\"RDP\"]=\"CHECKED\"",
" foreach ($Listener in $Listeners) {",
"  $RdpHash=Normalize-Hash $Listener.SSLCertificateSHA1Hash",
"  if ($RdpHash -match \"^[A-F0-9]{40}$\") { Add-Usage $RdpHash (\"RDP: \"+$Listener.TerminalName) }",
"  else { $Coverage[\"RDP\"]=\"INCOMPLETE_UNRESOLVED_LISTENER\" }",
" }",
"} catch { $Coverage[\"RDP\"]=\"FAILED_OR_UNAVAILABLE\" }",
"try {",
" $WsListeners=@(Get-ChildItem WSMan:\\localhost\\Listener -ErrorAction Stop)",
" $Coverage[\"WinRM\"]=\"CHECKED\"",
" foreach ($Listener in $WsListeners) {",
"  if ($Listener.Keys -contains \"Transport=HTTPS\") {",
"   $WsHash=Normalize-Hash (Get-Item ($Listener.PSPath+\"\\CertificateThumbprint\") -ErrorAction Stop).Value",
"   if ($WsHash -match \"^[A-F0-9]{40}$\") { Add-Usage $WsHash \"WinRM HTTPS listener\" }",
"   else { $Coverage[\"WinRM\"]=\"INCOMPLETE_UNRESOLVED_LISTENER\" }",
"  }",
" }",
"} catch { $Coverage[\"WinRM\"]=\"FAILED_OR_UNAVAILABLE\" }",
"$Coverage[\"Kofax_Applications_ScheduledScripts\"]=\"NOT_CHECKED\"",
"$Coverage[\"AutomaticSelection_CentralCertificateStore_OtherStores\"]=\"NOT_CHECKED\"",
"$CoverageText=($Coverage.GetEnumerator() | ForEach-Object { $_.Key+\"=\"+$_.Value }) -join \"; \"",
"$ChecksIncomplete=@($Coverage.Values | Where-Object { $_ -match \"FAILED|INCOMPLETE\" }).Count -gt 0",
"$Now=Get-Date",
"function New-ReportRow($Cert,$Binding,$Hash,$RowType,$ForcedStatus) {",
" $Row=[ordered]@{Hostname=$env:COMPUTERNAME;Binding=$Binding;Subject=\"\";DNSNames=\"\";Template=\"\";Thumbprint=$Hash;Expiration=\"\";DaysRemaining=\"\";Status=$ForcedStatus;RecordType=$RowType;CertificateStore=\"LocalMachine\\My\";IISBindingStatus=\"\";DetectedUsage=\"\";UsageStatus=\"\";UsageCheckCoverage=$CoverageText}",
" if ($RowType -eq \"SERVER\") { $Row.CertificateStore=\"\"; return [PSCustomObject]$Row }",
" $Row.IISBindingStatus=if ($RowType -eq \"IIS_BINDING\") { \"BOUND_TO_IIS\" } elseif ($IisChecked) { \"NOT_BOUND_TO_IIS\" } else { \"UNKNOWN\" }",
" $Refs=@($Usage[$Hash] | Where-Object { $_ } | Select-Object -Unique)",
" $Row.DetectedUsage=$Refs -join \"`n\"",
" $Row.UsageStatus=if ($Refs.Count) { \"REFERENCE_FOUND\" } elseif ($ChecksIncomplete) { \"CHECKS_INCOMPLETE\" } else { \"NO_REFERENCE_FOUND\" }",
" if ($Cert) {",
"  $Row.Subject=$Cert.SubjectName.Decode([System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseNewLines -bor [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::Reversed).Trim()",
"  if ($Cert.Extensions | Where-Object { $_.Oid.Value -eq \"2.5.29.17\" }) { $Row.DNSNames=(@($Cert.DnsNameList | ForEach-Object { $_.Unicode } | Where-Object { $_ } | Select-Object -Unique) -join \"`n\") }",
"  $Row.Template=Get-InventoryTemplate $Cert",
"  $Row.Expiration=$Cert.NotAfter.ToString(\"yyyy-MM-dd HH:mm:ss\")",
"  $Row.DaysRemaining=[math]::Floor(($Cert.NotAfter-$Now).TotalDays)",
"  # CN and legacy-template requirements apply to IIS, not unrelated client/RDP certificates.",
"  $Row.Status=if ($Cert.NotAfter -le $Now) { \"EXPIRED\" } elseif ($RowType -eq \"IIS_BINDING\" -and $Cert.Subject -notmatch \"(?:^|,|;)\\s*CN\\s*=\\s*[^\\s,;]+\") { \"MISSING_CN\" } elseif ($Row.DaysRemaining -le 90) { \"RENEW_SOON\" } elseif ($RowType -eq \"IIS_BINDING\" -and $Row.Template -in @(\"WebServer\",\"Serco CMS Web Server\")) { \"LEGACY_TEMPLATE\" } else { \"OK\" }",
" } elseif ($ForcedStatus -eq \"ORPHANED_BINDING\") { $Row.Subject=\"CERTIFICATE NOT FOUND\"; $Row.Template=\"UNKNOWN\" }",
" return [PSCustomObject]$Row",
"}",
"$Results=@()",
"$Certificates=@()",
"$StoreChecked=$false",
"try { $Certificates=@(Get-ChildItem Cert:\\LocalMachine\\My -ErrorAction Stop); $StoreChecked=$true }",
"catch { $Results+=New-ReportRow $null \"\" \"\" \"SERVER\" \"CERT_STORE_READ_FAILED\" }",
"$Bound=@{}",
"foreach ($B in $Bindings) {",
" $Hash=Normalize-Hash $B.CertificateHash",
" if (-not $Hash) { $Results+=New-ReportRow $null $B.BindingInformation \"\" \"IIS_BINDING\" \"NO_CERTIFICATE_HASH\"; continue }",
" $Bound[$Hash]=$true",
" $Cert=$Certificates | Where-Object { (Normalize-Hash $_.Thumbprint) -eq $Hash } | Select-Object -First 1",
" $MissingStatus=if ($StoreChecked) { \"ORPHANED_BINDING\" } else { \"CERT_STORE_READ_FAILED\" }",
" $Results+=New-ReportRow $Cert $B.BindingInformation $Hash \"IIS_BINDING\" $MissingStatus",
"}",
"foreach ($Cert in $Certificates) {",
" $Hash=Normalize-Hash $Cert.Thumbprint",
" if (-not $Bound.ContainsKey($Hash)) { $Results+=New-ReportRow $Cert \"\" $Hash \"CERTIFICATE\" \"\" }",
"}",
"if ($IisState -ne \"PRESENT\") { $Results+=New-ReportRow $null \"\" \"\" \"SERVER\" $IisState }",
"$Results | ConvertTo-Csv -NoTypeInformation",
"# Detect SSM stdout truncation instead of accepting a partial inventory.",
"Write-Output (\"INVENTORY_COMPLETE=\"+$Results.Count)"
]' \
    --query 'Command.CommandId' \
    --output text 2>/dev/null) || {
      echo "ERROR: Unable to submit SSM command."
      echo "\"$ENVIRONMENT\",$ACCOUNT_ID_CSV,\"\",\"\",\"\",\"SEND COMMAND FAILED\",\"\",\"\",\"\",\"\",\"\",\"ERROR\",\"ERROR\",\"\",\"\",\"\",\"CHECKS_INCOMPLETE\",\"NOT_RUN\"" >> "$REPORT"
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
      echo "\"$ENVIRONMENT\",$ACCOUNT_ID_CSV,\"$ID\",\"\",\"\",\"NO INVOCATION RESULT\",\"\",\"\",\"\",\"\",\"\",\"ERROR\",\"ERROR\",\"\",\"\",\"\",\"CHECKS_INCOMPLETE\",\"NOT_RUN\"" >> "$REPORT"
      continue
    fi

    STATUS=$(echo "$INVOCATION" | jq -r '.Status // "UNKNOWN"')
    OUTPUT=$(echo "$INVOCATION" | jq -r '.StandardOutputContent // ""')

    if [ "$STATUS" != "Success" ]; then
      ERR=$(echo "$INVOCATION" | jq -r '.StandardErrorContent // ""' | tr '\n' ' ' | sed 's/"/""/g')
      echo "\"$ENVIRONMENT\",$ACCOUNT_ID_CSV,\"$ID\",\"\",\"\",\"SSM COMMAND FAILED\",\"\",\"\",\"\",\"\",\"\",\"$STATUS: $ERR\",\"ERROR\",\"\",\"\",\"\",\"CHECKS_INCOMPLETE\",\"NOT_RUN\"" >> "$REPORT"
      continue
    fi

    # Parse complete CSV records: Subject and DNSNames contain in-cell newlines.
    printf '%s\n' "$OUTPUT" | python3 -c '
import csv
import sys

fields = ["Hostname", "Binding", "Subject", "DNSNames", "Template", "Thumbprint", "Expiration", "DaysRemaining", "Status", "RecordType", "CertificateStore", "IISBindingStatus", "DetectedUsage", "UsageStatus", "UsageCheckCoverage"]
prefix = [sys.argv[1], "=\"" + sys.argv[2] + "\"", sys.argv[3]]
writer = csv.writer(sys.stdout, quoting=csv.QUOTE_ALL, lineterminator="\n")
try:
    # Validate the whole response before appending any records.
    records = list(csv.reader(sys.stdin, strict=True))
    if not records or records[0] != fields:
        raise ValueError("Unexpected SSM CSV header")
    if len(records[-1]) != 1 or not records[-1][0].startswith("INVENTORY_COMPLETE="):
        raise ValueError("Missing completion marker; SSM output may be truncated")
    expected_count = int(records[-1][0].split("=", 1)[1])
    data = records[1:-1]
    if len(data) != expected_count or any(len(row) != len(fields) for row in data):
        raise ValueError("Incomplete SSM CSV records")
    writer.writerows(prefix + row for row in data)
except (ValueError, csv.Error) as error:
    row = dict.fromkeys(fields, "")
    row.update(Subject=str(error), Status="INVENTORY_OUTPUT_ERROR", RecordType="ERROR", UsageStatus="CHECKS_INCOMPLETE", UsageCheckCoverage="OUTPUT_INCOMPLETE")
    writer.writerow(prefix + [row[field] for field in fields])
    print("Inventory output error for " + sys.argv[3] + ": " + str(error), file=sys.stderr)
' "$ENVIRONMENT" "$ACCOUNT_ID" "$ID" >> "$REPORT"

  done
done

echo
echo "======================================================"
echo " CROSS-ACCOUNT REPORT COMPLETE"
echo "======================================================"
echo "Report: $REPORT"
echo
echo "Certificates requiring review (health, no reference found, or incomplete checks):"
python3 - "$REPORT" <<'PYCSV'
import csv
import sys

with open(sys.argv[1], newline="", encoding="utf-8-sig") as report:
    rows = csv.DictReader(report)
    writer = csv.DictWriter(sys.stdout, fieldnames=rows.fieldnames)
    writer.writeheader()
    for row in rows:
        if (row["Status"] not in {"OK", "NO_IIS", "NO_HTTPS_BINDINGS"}
                or row["UsageStatus"] in {"NO_REFERENCE_FOUND", "CHECKS_INCOMPLETE"}
                or "FAILED" in row["UsageCheckCoverage"]
                or "INCOMPLETE" in row["UsageCheckCoverage"]):
            writer.writerow(row)
PYCSV
echo
echo "Full report:"
cat "$REPORT"
