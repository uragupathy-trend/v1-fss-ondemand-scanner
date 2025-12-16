# Vision One File Security - OCI Ondemand Scanner

A serverless OCI Function for automated malware scanning of files in Oracle Cloud Infrastructure Object Storage buckets using Vision One File Security.

## Features

- **🔍 Batch Scanning**: Process up to 100 files per execution with concurrent scanning
- **📅 Scheduled + Manual**: Automated scheduling via OCI Resource Scheduler + on-demand invocation
- **🛡️ Three Scanner Modes**: `TAG_ONLY`, `MOVE_MALWARE_ONLY`, `MOVE_ALL`
- **⚡ High Performance**: Configurable batch sizes and concurrent processing (up to 8 parallel scans)
- **🔐 Enterprise Security**: OCI Vault API key storage, fail-fast error handling
- **📊 Comprehensive Logging**: Detailed execution tracking and security event monitoring

## Scanner Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `TAG_ONLY` | Only tag files with scan results, no file movement | Development/testing |
| `MOVE_MALWARE_ONLY` | Move only malware to quarantine, tag clean files in-place | **Production recommended** |
| `MOVE_ALL` | Move both clean and malware files to separate buckets | Full file segregation |

## Quick Start

### 1. Configure
Copy and update configuration:
```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
```

Essential configuration in `terraform.tfvars`:
```hcl
# Required
source_bucket_name = "my-source-bucket"
quarantine_bucket_name = "my-quarantine-bucket"
v1_scanner_endpoint = "antimalware.us-east-1.cloudone.trendmicro.com:443"
vision_one_api_key_secret_ocid = "ocid1.vaultsecret.oc1..."

# Scanner mode (production recommended)
v1_file_scanner_mode = "MOVE_MALWARE_ONLY"

# Optional: Enable scheduled scanning
enable_scheduled_scanning = true
```

### 2. Deploy
```bash
./deploy.sh
```

### 3. Test
```bash
# Get function ID from deployment output
FUNCTION_ID=$(cd terraform && terraform output -raw function_id)

# Manual invocation
oci fn function invoke --function-id $FUNCTION_ID

# Upload test file to trigger scanning
oci os object put --bucket-name my-source-bucket --file test-file.pdf
```

## Architecture

```
📅 OCI Resource Scheduler → 🖥️ Trigger Instance → 📡 OCI Events → ⚡ Function → 🛡️ Vision One
👤 Manual Invocation ────────────────────────────────────────────┘

🗂️ Source Bucket → 🔍 Batch Scan → 🏷️ Clean Files (tagged in-place)
                                   → 🦠 Malware Files (moved to quarantine)
```

## Configuration

### Performance Settings
```hcl
max_files = 100              # Files per batch (recommended: 50-100)
concurrent_scans = 5         # Parallel scans (recommended: 3-8)
function_memory_mb = 1024    # Memory allocation
function_timeout_seconds = 900  # 15 minutes timeout
```

### Scheduling (Optional)
```hcl
enable_scheduled_scanning = true
recurrence_details = "FREQ=MONTHLY;BYMONTHDAY=1;BYHOUR=2;BYMINUTE=0"  # Monthly at 2 AM
```

### Logging
```hcl
enable_logging = true
log_level = "INFO"  # DEBUG, INFO, WARNING, ERROR
```

## Prerequisites

- **Terraform** >= 1.0
- **Docker** (running daemon)
- **OCI CLI** configured
- **Vision One API Key** stored in OCI Vault
- **OCI Resources**: VCN, Subnet, Compartment

## Deployment Commands

```bash
# Deploy infrastructure
./deploy.sh

# Destroy infrastructure
./deploy.sh destroy

# Force destroy (no prompts)
./deploy.sh destroy --force
```

## Testing & Monitoring

### Manual Testing
```bash
# Test function directly
oci fn function invoke --function-id $(terraform output -raw function_id)

# Test with custom parameters
echo '{"max_files": 50}' | oci fn function invoke --function-id $FUNCTION_ID --file -

# Upload test file
oci os object put --bucket-name source-bucket --file test.pdf
```

### Monitor Scheduled Scans
```bash
# Check scheduler status
oci resource-scheduler schedule list --compartment-id $COMPARTMENT_ID

# View function logs
oci logging log list --log-group-id $(terraform output -raw log_group_id)
```

## Security Features

- ✅ **Critical Security Fix Applied**: Prevents false "clean" results when Vision One is unreachable
- ✅ **Fail-Fast Connection**: Health check ensures scanner connectivity before processing
- ✅ **Secure API Key Storage**: Vision One API keys stored in OCI Vault
- ✅ **Error Isolation**: Files with scan errors are not processed as "clean"
- ✅ **IAM Integration**: Resource principals for secure OCI service access

## Production Recommendations

```hcl
# terraform.tfvars for production
v1_file_scanner_mode = "MOVE_MALWARE_ONLY"
enable_scheduled_scanning = true
recurrence_details = "FREQ=MONTHLY;BYMONTHDAY=1;BYHOUR=2;BYMINUTE=0"
max_files = 100
concurrent_scans = 5
function_memory_mb = 1024
enable_logging = true
log_level = "INFO"
```

## Support & Documentation

- **Function Code**: `function/func.py` - Core scanning logic
- **Infrastructure**: `terraform/` - Complete OCI resource definitions
- **Deployment**: `deploy.sh` - Automated deployment script

For troubleshooting and advanced configuration, see the Terraform outputs after deployment for resource details and quick test commands.
