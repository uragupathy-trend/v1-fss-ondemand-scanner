# Vision One File Security Ondemand Scanner

A serverless OCI Function that provides on-demand and scheduled batch scanning of files in Oracle Cloud Infrastructure (OCI) Object Storage buckets using Vision One File Security SDK.

## Overview

This application creates a comprehensive malware scanning solution with both manual on-demand and automated scheduled scanning capabilities. It uses a hybrid architecture combining OCI Resource Scheduler, OCI Events, and OCI Functions for reliable, scalable file security scanning.

## Features

- **🔍 Batch File Scanning**: Process up to 100 files in a single function invocation for improved efficiency
- **📅 Hybrid Scheduling**: OCI Resource Scheduler for automated scanning + manual invocation on-demand
- **🛡️ Three Scanner Modes**: Configure how files are handled after scanning (MOVE_ALL, MOVE_MALWARE_ONLY, TAG_ONLY)
- **⚡ Performance Optimization**: Configurable batch sizes and concurrent scanning (up to 8 concurrent scans)
- **🤖 Automated Scanning**: Scheduled scanning (hourly minimum, monthly for production)
- **👤 Manual Invocation**: Direct function calls via OCI CLI, Console, or API anytime
- **🔐 Enterprise Security**: Uses OCI Vault for API key management and IAM for service permissions
- **📊 Comprehensive Logging**: Full function execution and event tracking

## Scanner Modes

| Mode | Description |
|------|-------------|
| `MOVE_ALL` | Move both clean and malware files to separate buckets |
| `MOVE_MALWARE_ONLY` | Move only malware to quarantine, tag clean files in-place |
| `TAG_ONLY` | Only tag files with scan results, no file movement |

## Quick Start

1. **Configure** your environment in `terraform/terraform.tfvars`:
   ```bash
   # Update with your actual values
   source_bucket_name = "my-source-bucket"
   quarantine_bucket_name = "my-quarantine-bucket"
   v1_file_scanner_mode = "MOVE_MALWARE_ONLY"
   ```

2. **Deploy** the infrastructure:
   ```bash
   ./deploy.sh
   ```

3. **Test** the function:
   ```bash
   # Method 1: Upload a file to your source bucket to trigger scanning
   oci os object put --bucket-name my-source-bucket --file test-file.pdf

   # Method 2: Direct function invocation with test event
   oci fn function invoke --function-id [FUNCTION_ID] --file test-event.json

   # Or with inline body
   oci fn function invoke --function-id [FUNCTION_ID] --body '{"test": "batch-scan"}'

   # Get your function ID from terraform output
   cd terraform && terraform output -raw function_id
   ```

## Hybrid Scheduler Architecture

The application uses a **hybrid scheduler architecture** combining OCI Resource Scheduler, Events, and Functions for reliable automated scanning plus manual invocation capabilities.

### How the Hybrid Architecture Works

```
🕐 OCI Resource Scheduler → 🖥️ Trigger Instance → 📡 OCI Events → ⚡ OCI Function → 🛡️ Malware Scan
        ↓                        ↓                    ↓              ↓               ↓
   Cron Schedule           Always Free Instance    Instance Start    Batch Scan     Auto Quarantine
   (hourly/monthly)        (Lightweight trigger)     Event Rule     (100 files)    (MOVE_MALWARE_ONLY)
```

1. **OCI Resource Scheduler** starts a lightweight trigger instance on schedule
2. **Instance start event** fires automatically in OCI Events
3. **Event rule** triggers the malware scanning function
4. **Function scans** up to 100 files from the source bucket
5. **Results processed** - malware moved to quarantine, clean files tagged

## Scheduled Scanning Configuration

### Enable Scheduled Scanning

Set this in `terraform.tfvars`:
```hcl
# Enable automated scheduled malware scanning
enable_scheduled_scanning = true
enable_logging = true  # Recommended for monitoring

# Scanner mode (as requested)
v1_file_scanner_mode = "MOVE_MALWARE_ONLY"

# Schedule options (OCI Resource Scheduler minimum: hourly)
scan_schedule_expression = "0 * * * *"    # Testing: hourly
# scan_schedule_expression = "0 2 1 * *"  # Production: monthly on 1st at 2AM
```

### Schedule Options

| Schedule | Expression | Use Case |
|----------|------------|----------|
| **Hourly** | `"0 * * * *"` | Testing, high-security environments |
| **Daily** | `"0 2 * * *"` | Regular scanning (2 AM daily) |
| **Weekly** | `"0 2 * * 1"` | Weekly scans (Monday 2 AM) |
| **Monthly** | `"0 2 1 * *"` | **Production recommended** (1st of month 2 AM) |

### Manual Invocation

The function supports manual invocation anytime alongside scheduled scanning:

```bash
# Get function ID
FUNCTION_ID=$(cd terraform && terraform output -raw function_id)

# Manual scan NOW
oci fn function invoke --function-id $FUNCTION_ID

# Manual scan with custom parameters
echo '{"max_files": 50}' | oci fn function invoke --function-id $FUNCTION_ID --file -

# Manual scan via OCI Console
# Navigate to Functions → Applications → v1-fss-ondemand-application → Invoke
```

### Monitoring Scheduled Scans

```bash
# View scheduler status
oci resource-scheduler schedule list --compartment-id [COMPARTMENT_ID]

# View trigger instance
oci compute instance list --compartment-id [COMPARTMENT_ID] --display-name "v1-fss-scheduler-trigger"

# View event rule
oci events rule list --compartment-id [COMPARTMENT_ID] --display-name "v1-fss-scheduler-function-trigger"

# View function logs (if logging enabled)
oci logging log list --log-group-id [LOG_GROUP_ID]

# Test manual invocation
oci fn function invoke --function-id [FUNCTION_ID] --body '{}'
```

### Benefits of Hybrid Architecture

- **🤖 Automated**: Scheduled scans without manual intervention
- **👤 Manual Override**: Immediate scanning when needed
- **💰 Cost Effective**: Always Free trigger instance + serverless function
- **🔄 Reliable**: Native OCI service integration with proper error handling
- **📊 Scalable**: Handles high-volume file processing efficiently
- **🔐 Secure**: IAM-based permissions and encrypted API key storage

## Performance Configuration

Configure these settings in `terraform.tfvars` based on your requirements:

```hcl
# Batch Processing
max_files = 100              # Files per batch (recommended: 50-100)
concurrent_scans = 5         # Parallel scans (recommended: 3-8)

# Function Resources
function_memory_mb = 1024    # Memory allocation
function_timeout_seconds = 900  # 15 minutes timeout
```

### Performance Recommendations

| Batch Size | Memory | Timeout | Use Case |
|------------|---------|---------|----------|
| < 50 files | 512MB | 5 min | Small batches |
| 50-100 files | 1024MB | 15 min | **Recommended** |
| 100+ files | 2048MB | 30 min | Large batches |

## Prerequisites

- Terraform >= 1.0
- Docker (running daemon)
- OCI CLI configured
- Vision One File Security API key (stored in OCI Vault)

## Architecture

### Hybrid Scheduler Architecture
```
📅 OCI Resource Scheduler ─┐
                           ├─→ 🖥️ Trigger Instance → 📡 OCI Events → ⚡ OCI Function → 🛡️ Vision One Scanner
👤 Manual CLI Invocation ─┘                                                ↓
                                                                   📊 Batch Processing
                                                                           ↓
🗂️ Source Bucket ←────────────────────────────────────── 🏷️ Tag Clean Files
                                                                           ↓
🦠 Quarantine Bucket ←──────────────────────────── 🚨 Move Malware Files (MOVE_MALWARE_ONLY)
```

### Component Details
- **Resource Scheduler**: Cron-based scheduling (minimum hourly frequency)
- **Trigger Instance**: Always Free VM.Standard.E2.1.Micro for event generation
- **Event Rule**: com.oraclecloud.computeapi.launchinstance trigger
- **Function**: Serverless batch processing with configurable concurrency
- **Vision One Integration**: Direct SDK connection to scanner endpoint

## Deployment Commands

```bash
# Full deployment
./deploy.sh

# Deploy with custom variables
./deploy.sh --var-file custom.tfvars

# Destroy infrastructure (with confirmation)
./deploy.sh destroy

# Force destroy without prompts
./deploy.sh destroy --force

# Show usage information
./deploy.sh --help

# Manual terraform commands
cd terraform
terraform plan -var-file="terraform.tfvars"
terraform apply -var-file="terraform.tfvars"
terraform destroy -var-file="terraform.tfvars"
```

## Testing & Troubleshooting

### Test Manual Invocation
```bash
# Get function details
cd terraform
FUNCTION_ID=$(terraform output -raw function_id)
FUNCTION_INVOKE_ENDPOINT=$(terraform output -raw function_invoke_endpoint)

# Test function invocation
oci fn function invoke --function-id $FUNCTION_ID

# Test with debug logging
echo '{"log_level": "DEBUG"}' | oci fn function invoke --function-id $FUNCTION_ID --file -
```

### Monitor Scheduled Scans
```bash
# Check scheduler status
oci resource-scheduler schedule get --schedule-id $(terraform output -raw scheduler_id)

# View trigger instance status
oci compute instance get --instance-id $(terraform output -raw trigger_instance_id)

# Monitor function logs
oci logging log list --log-group-id $(terraform output -raw log_group_id)
```

### Common Issues

| Issue | Solution |
|-------|----------|
| Scheduler frequency too high | Use minimum `"0 * * * *"` (hourly) |
| Function timeout | Increase `function_timeout_seconds` to 900+ |
| Memory errors | Increase `function_memory_mb` to 1024+ |
| Bucket access denied | Check IAM policies and bucket permissions |
| API key issues | Verify OCI Vault secret configuration |

## Configuration Files

| File | Purpose |
|------|---------|
| `terraform/terraform.tfvars` | **Main configuration** - buckets, scheduling, performance |
| `terraform/main.tf` | Infrastructure as code - resources and dependencies |
| `terraform/variables.tf` | Variable definitions and validation |
| `terraform/outputs.tf` | Resource outputs for testing and monitoring |
| `function/func.py` | **Function logic** - batch scanning and file processing |
| `function/Dockerfile` | Container image configuration |
| `function/requirements.txt` | Python dependencies (oci-sdk, vision-one-sdk) |
| `deploy.sh` | **Deployment script** - automated build and deploy |

## Production Deployment Guide

### 1. Configure Production Settings
```hcl
# terraform/terraform.tfvars
v1_file_scanner_mode = "MOVE_MALWARE_ONLY"
scan_schedule_expression = "0 2 1 * *"  # Monthly on 1st at 2AM
max_files = 100
concurrent_scans = 5
function_memory_mb = 1024
enable_scheduled_scanning = true
enable_logging = true
```

### 2. Deploy and Verify
```bash
# Deploy production
./deploy.sh

# Verify deployment
terraform output

# Test manual scan
oci fn function invoke --function-id $(terraform output -raw function_id)

# Monitor first scheduled scan (starts 5 minutes after deployment)
```

### 3. Production Monitoring
- **Scheduler**: Runs monthly on 1st at 2 AM
- **Manual**: Available 24/7 via OCI CLI or Console
- **Logging**: Enabled for compliance and troubleshooting
- **Cost**: Always Free instance + serverless function charges

## Support

This implementation provides enterprise-grade malware scanning with:
- **Proven Architecture**: Based on v1-fss-scanner with hybrid scheduler enhancements
- **Production Ready**: Monthly scheduling with manual override capabilities  
- **Cost Optimized**: Always Free compute + pay-per-use function execution
- **Highly Scalable**: Batch processing up to 100 files with 8x concurrency
- **Secure by Design**: OCI Vault integration and IAM-based permissions
