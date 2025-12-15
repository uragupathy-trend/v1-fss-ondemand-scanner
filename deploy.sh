#!/bin/bash
# Vision One File Security Ondemand Scanner - OCI Deployment Script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$SCRIPT_DIR/terraform"
OPERATION="deploy"
FORCE_MODE=false

# Colors
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; NC='\033[0m'

log() { echo -e "${2:-$G}[${3:-INFO}]$NC $1"; }
die() { log "$1" "$R" "ERROR"; exit 1; }

usage() {
    cat << EOF
Usage: $0 [deploy|destroy] [--force]

Commands:
  deploy    Deploy infrastructure (default)
  destroy   Destroy infrastructure
  help      Show this help

Options:
  --force   Skip confirmations (destroy only)

Examples:
  $0                  # Deploy
  $0 destroy          # Destroy with prompts
  $0 destroy --force  # Destroy without prompts

Scanner Modes (configure in terraform.tfvars):
  MOVE_ALL            # Move both clean and malware files to separate buckets
  MOVE_MALWARE_ONLY   # Move only malware to quarantine, tag clean files  
  TAG_ONLY            # Only tag files, no movement
EOF
}

check_prereqs() {
    log "Checking prerequisites..."
    
    # Check required tools
    for tool in terraform docker oci; do
        command -v "$tool" >/dev/null || die "$tool not found in PATH. Please install $tool first."
    done
    
    # Check Docker daemon
    docker info >/dev/null 2>&1 || die "Docker daemon not running. Please start Docker."
    
    # Check terraform.tfvars exists
    [[ -f "$TERRAFORM_DIR/terraform.tfvars" ]] || die "terraform.tfvars not found. Copy from terraform.tfvars.example and configure."
    
    # Check for placeholder values
    if grep -qE "(your-|example|aaaaaaaa|aa:bb:cc)" "$TERRAFORM_DIR/terraform.tfvars" 2>/dev/null; then
        log "terraform.tfvars contains placeholder values. Please update with actual configuration." "$Y" "WARN"
        log "Key values to update: tenancy_ocid, user_ocid, fingerprint, private_key_path, compartment_id, subnet_id" "$Y" "WARN"
    fi
    
    # Check function code exists
    [[ -f "$SCRIPT_DIR/function/func.py" ]] || die "Function code not found. Please ensure func.py exists in function/ directory."
    
    log "All prerequisite checks passed"
}

deploy() {
    log "Deploying Vision One Ondemand Scanner infrastructure..." "$B"
    cd "$TERRAFORM_DIR"
    
    log "Initializing Terraform..."
    terraform init
    
    log "Creating deployment plan..."
    terraform plan -out=tfplan
    
    log "Applying infrastructure changes..."
    terraform apply tfplan
    rm -f tfplan
    
    log "Deployment Summary:" "$G"
    echo "=========================="
    echo "Function App: $(terraform output -raw application_id 2>/dev/null || echo "N/A")"
    echo "Function ID: $(terraform output -raw function_id 2>/dev/null || echo "N/A")"
    echo "Function Endpoint: $(terraform output -raw function_invoke_endpoint 2>/dev/null || echo "N/A")"
    echo "OCIR Repository: $(terraform output -raw container_repository_url 2>/dev/null || echo "N/A")"
    echo "Dynamic Group: $(terraform output -raw dynamic_group_id 2>/dev/null || echo "N/A")"
    echo "Scanner Mode: $(terraform output -json scanner_configuration 2>/dev/null | jq -r '.scanner_mode' 2>/dev/null || echo "N/A")"
    echo "=========================="
    
    # Show performance recommendations if available
    if terraform output -json performance_recommendations >/dev/null 2>&1; then
        echo
        log "Performance Recommendations:" "$B"
        terraform output -json performance_recommendations | jq -r '.message' 2>/dev/null || echo "Configuration looks good"
    fi
    
    echo
    log "Deployment complete!" "$G"
    log "You can now invoke the function using: oci fn function invoke --function-id \$(terraform output -raw function_id)" "$G"
    
    # Show quick test command
    echo
    log "Quick test command:" "$B"
    terraform output -raw function_invoke_command 2>/dev/null || echo "oci fn function invoke --function-id [FUNCTION_ID]"
}

destroy() {
    log "WARNING: This will destroy ALL infrastructure!" "$Y" "WARN"
    echo "Resources to be destroyed:"
    echo "  - OCI Function and Application"
    echo "  - Container Repository and Images"
    echo "  - IAM Policies and Dynamic Groups"
    echo "  - Event Rules (if scheduled scanning enabled)"
    echo "  - Log Groups (if logging enabled)"
    
    if [[ "$FORCE_MODE" != "true" ]]; then
        echo
        read -p "Type 'yes' to confirm destruction: " confirm
        [[ "$confirm" == "yes" ]] || { log "Operation cancelled"; exit 0; }
        
        echo
        read -p "Type 'DELETE' for final confirmation: " final
        [[ "$final" == "DELETE" ]] || { log "Operation cancelled"; exit 0; }
    fi
    
    log "Destroying infrastructure..." "$Y" "WARN"
    cd "$TERRAFORM_DIR"
    
    # Initialize if needed
    [[ -d ".terraform" ]] || terraform init
    
    log "Creating destroy plan..."
    terraform plan -destroy -out=destroy.tfplan
    
    log "Applying destruction..."
    terraform apply destroy.tfplan
    rm -f destroy.tfplan
    
    log "All resources have been destroyed" "$Y" "WARN"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        deploy) OPERATION="deploy"; shift ;;
        destroy) OPERATION="destroy"; shift ;;
        --force) FORCE_MODE=true; shift ;;
        help|--help|-h) usage; exit 0 ;;
        *) die "Unknown option: $1. Use --help for usage."; ;;
    esac
done

# Handle interrupts gracefully
trap 'die "Operation interrupted"' INT TERM

log "Starting $OPERATION operation..." "$B"
check_prereqs

case $OPERATION in
    deploy) deploy ;;
    destroy) destroy ;;
    *) die "Invalid operation: $OPERATION" ;;
esac
