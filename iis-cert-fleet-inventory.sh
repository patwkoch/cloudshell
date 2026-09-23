#!/bin/bash

set -euo pipefail

REGION="us-east-1"

# Optional S3 destination.
# Leave BUCKET="" if you do not want to upload.
BUCKET=""
PREFIX="iis-cert-reports"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT="iis-cert-report-${TIMESTAMP}.csv"

echo "======================================================"
echo " IIS CERTIFICATE FLEET INVENTORY"
echo " Region: $REGION"
echo "======================================================"
echo

echo "Finding SSM-managed Windows instances..."

INSTANCE_IDS=$(aws ssm describe-instance-information \
  --region "$REGION" \
  --filters "Key=PlatformTypes,Values=Windows" \
  --query 'InstanceInformationList[].InstanceId' \
  --output text)

if [ -z "$INSTANCE_IDS" ]; then
    echo "No SSM-managed Windows instances found."
    exit 1
fi

INSTANCE_COUNT=$(echo "$INSTANCE_IDS" | wc -w | tr -d ' ')

echo "Found $INSTANCE_COUNT Windows instances."
echo

echo "Submitting IIS certificate inventory command..."

COMMAND_ID=$(aws ssm send-command \
  --region "$REGION" \
  --instance-ids $INSTANCE_IDS \
  --document-name "AWS-RunPowerShellScript" \
  --comment "Inventory IIS HTTPS certificate expiration" \
  --parameters 'commands=[
"Import-Module WebAdministration -ErrorAction SilentlyContinue",
"if (-not (Get-Module WebAdministration)) {",
"  Write-Output \"NO_IIS\"",
"  exit 0",
"}",
"$Now = Get-Date",
"$Results = Get-WebBinding -Protocol https | ForEach-Object {",
"  $Binding = $_",
"  $Hash = ($Binding.CertificateHash -replace \" \", \"\").ToUpper()",
"  if (-not $Hash) { return }",
"  $Cert = Get-ChildItem Cert:\\LocalMachine\\My | Where-Object {",
"      ($_.Thumbprint -replace \" \", \"\").ToUpper() -eq $Hash",
"  } | Select-Object -First 1",
"  if ($Cert) {",
"    $Days = [math]::Floor(($Cert.NotAfter - $Now).TotalDays)",
"    $Status = if ($Days -lt 0) {",
"        \"EXPIRED\"",
"    } elseif ($Days -le 30) {",
"        \"CRITICAL\"",
"    } elseif ($Days -le 60) {",
"        \"WARNING\"",
"    } elseif ($Days -le 90) {",
"        \"RENEW_SOON\"",
"    } else {",
"        \"OK\"",
"    }",
"    [PSCustomObject]@{",
"      Server=$env:COMPUTERNAME;",
"      Binding=$Binding.BindingInformation;",
"      Subject=$Cert.Subject;",
"      Thumbprint=$Cert.Thumbprint;",
"      Expiration=$Cert.NotAfter.ToString(\"yyyy-MM-dd HH:mm:ss\");",
"      DaysRemaining=$Days;",
"      Status=$Status",
"    }",
"  } else {",
"    [PSCustomObject]@{",
"      Server=$env:COMPUTERNAME;",
"      Binding=$Binding.BindingInformation;",
"      Subject=\"CERTIFICATE NOT FOUND\";",
"      Thumbprint=$Hash;",
"      Expiration=\"\";",
"      DaysRemaining=\"\";",
"      Status=\"ERROR\"",
"    }",
"  }",
"}",
"if ($Results) {",
"  $Results | ConvertTo-Csv -NoTypeInformation",
"} else {",
"  Write-Output \"NO_HTTPS_BINDINGS\"",
"}"
]' \
  --query 'Command.CommandId' \
  --output text)

echo "Command ID: $COMMAND_ID"
echo

echo "Waiting for SSM command to complete..."

while true
do
    STATUS_COUNTS=$(aws ssm list-command-invocations \
      --region "$REGION" \
      --command-id "$COMMAND_ID" \
      --details \
      --query 'CommandInvocations[].Status' \
      --output text)

    TOTAL=$(echo "$STATUS_COUNTS" | wc -w | tr -d ' ')
    PENDING=$(echo "$STATUS_COUNTS" | tr '\t' '\n' | grep -E '^(Pending|InProgress|Delayed)$' | wc -l | tr -d ' ' || true)

    echo "  Completed: $((TOTAL - PENDING)) / $TOTAL"

    if [ "$TOTAL" -gt 0 ] && [ "$PENDING" -eq 0 ]; then
        break
    fi

    sleep 5
done

echo
echo "SSM command finished."
echo

echo "Collecting results..."

echo '"InstanceId","Server","Binding","Subject","Thumbprint","Expiration","DaysRemaining","Status"' > "$REPORT"

NO_IIS=0
NO_HTTPS=0
FAILED=0

for ID in $INSTANCE_IDS
do
    STATUS=$(aws ssm get-command-invocation \
      --region "$REGION" \
      --command-id "$COMMAND_ID" \
      --instance-id "$ID" \
      --query 'Status' \
      --output text 2>/dev/null || echo "UNKNOWN")

    if [ "$STATUS" != "Success" ]; then
        echo "WARNING: $ID returned status $STATUS"

        ERROR_TEXT=$(aws ssm get-command-invocation \
          --region "$REGION" \
          --command-id "$COMMAND_ID" \
          --instance-id "$ID" \
          --query 'StandardErrorContent' \
          --output text 2>/dev/null || true)

        ESCAPED_ERROR=$(echo "$ERROR_TEXT" | tr '\n' ' ' | sed 's/"/""/g')
        echo "\"$ID\",\"\",\"\",\"SSM COMMAND FAILED\",\"\",\"\",\"\",\"$STATUS: $ESCAPED_ERROR\"" >> "$REPORT"
        FAILED=$((FAILED + 1))
        continue
    fi

    OUTPUT=$(aws ssm get-command-invocation \
      --region "$REGION" \
      --command-id "$COMMAND_ID" \
      --instance-id "$ID" \
      --query 'StandardOutputContent' \
      --output text)

    if echo "$OUTPUT" | grep -q '^NO_IIS$'; then
        NO_IIS=$((NO_IIS + 1))
        continue
    fi

    if echo "$OUTPUT" | grep -q '^NO_HTTPS_BINDINGS$'; then
        NO_HTTPS=$((NO_HTTPS + 1))
        continue
    fi

    echo "$OUTPUT" \
      | grep -v '^"Server"' \
      | sed '/^[[:space:]]*$/d' \
      | while IFS= read -r LINE
        do
            echo "\"$ID\",$LINE"
        done \
      >> "$REPORT"
done

echo
echo "======================================================"
echo " REPORT COMPLETE"
echo "======================================================"
echo
echo "Report file:"
echo "  $REPORT"
echo
echo "Windows instances checked: $INSTANCE_COUNT"
echo "No IIS:                    $NO_IIS"
echo "IIS but no HTTPS binding:  $NO_HTTPS"
echo "SSM failures:              $FAILED"
echo

echo "Certificate summary:"
echo

awk -F',' '
NR > 1 {
    gsub(/"/,"",$8)
    count[$8]++
}
END {
    for (s in count) {
        printf "%-15s %d\n", s, count[s]
    }
}' "$REPORT" | sort

echo
echo "Certificates requiring attention:"
echo

awk -F',' '
NR == 1 {
    print
    next
}
{
    status=$8
    gsub(/"/,"",status)

    if (
        status == "EXPIRED" ||
        status == "CRITICAL" ||
        status == "WARNING" ||
        status == "RENEW_SOON" ||
        status == "ERROR"
    ) {
        print
    }
}' "$REPORT"

if [ -n "$BUCKET" ]; then
    echo
    echo "Uploading report to S3..."

    S3_PATH="s3://${BUCKET}/${PREFIX}/${REPORT}"

    aws s3 cp \
      "$REPORT" \
      "$S3_PATH" \
      --region "$REGION"

    echo
    echo "Uploaded:"
    echo "  $S3_PATH"
fi

echo
echo "Done."
