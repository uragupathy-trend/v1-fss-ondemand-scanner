# Function Outputs
output "function_id" {
  description = "OCID of the Vision One Ondemand Scanner function"
  value       = oci_functions_function.v1_fss_ondemand_function.id
}

output "function_invoke_endpoint" {
  description = "Function invoke endpoint URL"
  value       = oci_functions_function.v1_fss_ondemand_function.invoke_endpoint
}

output "application_id" {
  description = "OCID of the function application"
  value       = oci_functions_application.v1_fss_ondemand_application.id
}

output "function_image_uri" {
  description = "Complete container image URI used by the function"
  value       = oci_functions_function.v1_fss_ondemand_function.image
}

output "function_image_digest" {
  description = "Container image digest used by the function"
  value       = oci_functions_function.v1_fss_ondemand_function.image_digest
}

# OCIR Repository Outputs
output "container_repository_url" {
  description = "Container repository URL"
  value       = "${var.ocir_region}/${var.tenancy_namespace}/${oci_artifacts_container_repository.v1_fss_ondemand_repo.display_name}"
}

# IAM Outputs
output "dynamic_group_id" {
  description = "OCID of the dynamic group for the function"
  value       = oci_identity_dynamic_group.v1_fss_ondemand_function_dynamic_group.id
}

output "policy_id" {
  description = "OCID of the IAM policy for the function"
  value       = oci_identity_policy.v1_fss_ondemand_function_policy.id
}

# Configuration Summary
output "scanner_configuration" {
  description = "Scanner configuration summary"
  value = {
    scanner_mode           = var.v1_file_scanner_mode
    source_bucket         = var.source_bucket_name
    production_bucket     = var.production_bucket_name
    quarantine_bucket     = var.quarantine_bucket_name
    max_files            = var.max_files
    concurrent_scans     = var.concurrent_scans
    memory_mb            = var.function_memory_mb
    timeout_seconds      = var.function_timeout_seconds
    logging_enabled      = var.enable_logging
    scheduled_scanning   = var.enable_scheduled_scanning
  }
}

output "vision_one_config" {
  description = "Vision One configuration (sensitive data masked)"
  value = {
    region              = var.vision_one_region
    scanner_endpoint    = var.v1_scanner_endpoint
    api_key_configured  = var.vision_one_api_key_secret_ocid != null && var.vision_one_api_key_secret_ocid != ""
  }
  sensitive = false
}

output "deployment_info" {
  description = "Deployment information"
  value = {
    region           = var.region
    compartment_id   = var.compartment_id
    environment      = var.environment
    deployment_time  = timestamp()
  }
}

# Log Group Outputs (conditional)
output "log_group_id" {
  description = "OCID of the log group (if logging is enabled)"
  value       = var.enable_logging ? oci_logging_log_group.v1_fss_ondemand_log_group[0].id : null
}

output "function_log_id" {
  description = "OCID of the function invocation log (if logging is enabled)"
  value       = var.enable_logging ? oci_logging_log.v1_fss_ondemand_function_log[0].id : null
}

# Scheduled Scanning Outputs (conditional) - Monitoring Alarm Based
output "monitoring_alarm_id" {
  description = "OCID of the monitoring alarm for scheduled scanning (if enabled)"
  value       = var.enable_scheduled_scanning ? oci_monitoring_alarm.v1_fss_ondemand_schedule_alarm[0].id : null
}

output "alarm_topic_id" {
  description = "OCID of the ONS topic for alarm notifications (if scheduled scanning is enabled)"
  value       = var.enable_scheduled_scanning ? oci_ons_notification_topic.v1_fss_ondemand_alarm_topic[0].topic_id : null
}

output "alarm_repeat_duration" {
  description = "Alarm repeat schedule configuration"
  value       = var.enable_scheduled_scanning ? var.alarm_repeat_duration : null
}

output "event_rule_id" {
  description = "OCID of the event rule that triggers function from alarm (if scheduled scanning is enabled)"
  value       = var.enable_scheduled_scanning ? oci_events_rule.alarm_function_trigger[0].id : null
}

# Quick Reference Commands
output "function_invoke_command" {
  description = "OCI CLI command to invoke the function manually"
  value = "oci fn function invoke --function-id ${oci_functions_function.v1_fss_ondemand_function.id}"
}

output "function_logs_command" {
  description = "OCI CLI command to view function logs"
  value = var.enable_logging ? "oci logging-search search-logs --compartment-id ${var.compartment_id} --search-query \"search \\\"${var.compartment_id}\\\" | where oracle.resourceid=\\\"${oci_functions_function.v1_fss_ondemand_function.id}\\\"\"" : "Logging not enabled"
}

output "docker_push_command" {
  description = "Command to manually push updated container image"
  value = "cd ../function && docker build --platform linux/amd64 -t ${var.ocir_region}/${var.tenancy_namespace}/${oci_artifacts_container_repository.v1_fss_ondemand_repo.display_name}:${var.image_tag} . && docker push ${var.ocir_region}/${var.tenancy_namespace}/${oci_artifacts_container_repository.v1_fss_ondemand_repo.display_name}:${var.image_tag}"
}

# Performance Insights
output "performance_recommendations" {
  description = "Performance recommendations based on configuration"
  value = {
    message = var.max_files > 50 && var.function_memory_mb < 1024 ? "Consider increasing memory allocation for processing ${var.max_files} files" : "Configuration looks good for current batch size"
    memory_recommendation = var.max_files > 100 ? "Consider 2048MB+ for batches over 100 files" : "Current memory allocation should be sufficient"
    timeout_recommendation = var.max_files * 10 > var.function_timeout_seconds ? "Consider increasing timeout - estimated ${var.max_files * 10}s needed for ${var.max_files} files" : "Timeout looks sufficient"
  }
}
