terraform {
  required_version = ">= 1.0"
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }
}

provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
  region           = var.region
}

# Data source for object storage namespace
data "oci_objectstorage_namespace" "ns" {
  compartment_id = var.compartment_id
}

# Bucket validation logic based on scanner mode
locals {
  # Check if required buckets are provided based on scanner mode
  production_bucket_required = var.v1_file_scanner_mode == "MOVE_ALL"
  quarantine_bucket_required = contains(["MOVE_ALL", "MOVE_MALWARE_ONLY"], var.v1_file_scanner_mode)
  
  # Validation checks
  production_bucket_valid = local.production_bucket_required ? var.production_bucket_name != "" : true
  quarantine_bucket_valid = local.quarantine_bucket_required ? var.quarantine_bucket_name != "" : true
  
  # Error messages for validation failures
  validation_errors = compact([
    !local.production_bucket_valid ? "Production bucket name is required when v1_file_scanner_mode is 'MOVE_ALL'" : "",
    !local.quarantine_bucket_valid ? "Quarantine bucket name is required when v1_file_scanner_mode is 'MOVE_ALL' or 'MOVE_MALWARE_ONLY'" : ""
  ])
  
  # Common tags
  common_tags = {
    "Project"     = "VisionOneFileSecurity"
    "Environment" = var.environment
    "Type"        = "BatchScanner"
  }
}

# Validation check - this will cause terraform to fail if buckets are missing
data "external" "bucket_validation" {
  count = length(local.validation_errors) > 0 ? 1 : 0
  program = ["echo", jsonencode({
    error = join("; ", local.validation_errors)
  })]
}

# This resource will fail if validation errors exist
resource "null_resource" "bucket_validation_check" {
  count = length(local.validation_errors) > 0 ? 1 : 0
  
  provisioner "local-exec" {
    command = "echo 'Validation Error: ${join("; ", local.validation_errors)}' && exit 1"
  }
  
  depends_on = [data.external.bucket_validation]
}

# Dynamic Group for Function
resource "oci_identity_dynamic_group" "v1_fss_ondemand_function_dynamic_group" {
  compartment_id = var.tenancy_ocid
  name           = "v1-fss-ondemand-function-dynamic-group"
  description    = "Dynamic group for Vision One File Security Ondemand Scanner function"
  
  matching_rule = "ALL {resource.type = 'fnfunc', resource.compartment.id = '${var.compartment_id}'}"
  
  freeform_tags = local.common_tags
}

# IAM Policy for Function
resource "oci_identity_policy" "v1_fss_ondemand_function_policy" {
  compartment_id = var.compartment_id
  name           = "v1-fss-ondemand-function-policy"
  description    = "Policy for Vision One File Security Ondemand Scanner function"
  
  statements = [
    "Allow dynamic-group v1-fss-ondemand-function-dynamic-group to manage objects in compartment id ${var.compartment_id}",
    "Allow dynamic-group v1-fss-ondemand-function-dynamic-group to manage buckets in compartment id ${var.compartment_id}",
    "Allow dynamic-group v1-fss-ondemand-function-dynamic-group to use fn-function in compartment id ${var.compartment_id}",
    "Allow dynamic-group v1-fss-ondemand-function-dynamic-group to use fn-invocation in compartment id ${var.compartment_id}",
    "Allow dynamic-group v1-fss-ondemand-function-dynamic-group to manage repos in compartment id ${var.compartment_id}",
    "Allow dynamic-group v1-fss-ondemand-function-dynamic-group to read repos in compartment id ${var.compartment_id}",
    "Allow dynamic-group v1-fss-ondemand-function-dynamic-group to use object-family in compartment id ${var.compartment_id}",
    "Allow dynamic-group v1-fss-ondemand-function-dynamic-group to manage functions-family in compartment id ${var.compartment_id}",
    "Allow service objectstorage-${var.region} to manage objects in compartment id ${var.compartment_id}",
    "Allow dynamic-group v1-fss-ondemand-function-dynamic-group to manage log-groups in compartment id ${var.compartment_id}",
    "Allow dynamic-group v1-fss-ondemand-function-dynamic-group to read secret-family in compartment id ${var.compartment_id}",
    "Allow dynamic-group v1-fss-ondemand-function-dynamic-group to use keys in compartment id ${var.compartment_id}",
    "Allow service cloudevents to use fn-function in compartment id ${var.compartment_id}",
    "Allow service cloudevents to use fn-invocation in compartment id ${var.compartment_id}"
  ]
  
  freeform_tags = local.common_tags
  depends_on = [oci_identity_dynamic_group.v1_fss_ondemand_function_dynamic_group]
}

# OCIR Repository
resource "oci_artifacts_container_repository" "v1_fss_ondemand_repo" {
  compartment_id = var.compartment_id
  display_name   = var.function_image_name
  is_public      = true

  freeform_tags = {
    "Project"     = "VisionOneFileSecurity"
    "Environment" = var.environment
  }
}

# Docker build and push automation
resource "null_resource" "docker_build_push" {
  triggers = {
    function_code = filesha256("${path.module}/../function/func.py")
    dockerfile    = filesha256("${path.module}/../function/Dockerfile")
  }
  
  provisioner "local-exec" {
  command = <<-EOT
      echo "${var.docker_auth_token}" | docker login ${var.ocir_region} -u "${var.tenancy_namespace}/${var.docker_username}" --password-stdin
      
      cd ${path.module}/../function
      docker build --platform linux/amd64 -t ${var.ocir_region}/${var.tenancy_namespace}/${oci_artifacts_container_repository.v1_fss_ondemand_repo.display_name}:${var.image_tag} .
      docker push ${var.ocir_region}/${var.tenancy_namespace}/${oci_artifacts_container_repository.v1_fss_ondemand_repo.display_name}:${var.image_tag}
    EOT
  }
  depends_on = [oci_artifacts_container_repository.v1_fss_ondemand_repo]
}

# Function Application
resource "oci_functions_application" "v1_fss_ondemand_application" {
  compartment_id = var.compartment_id
  display_name   = "v1-fss-ondemand-application"
  
  subnet_ids = [var.subnet_id]
  
  # Use x86_64 shape to match Docker image architecture
  shape = "GENERIC_X86"
  
  # Function configuration with scanner mode-based bucket settings
  config = merge(
    {
      SOURCE_BUCKET_NAME    = var.source_bucket_name
      V1_REGION            = var.vision_one_region
      V1_SCANNER_ENDPOINT  = var.v1_scanner_endpoint
      VAULT_SECRET_OCID    = var.vision_one_api_key_secret_ocid
      V1_FILE_SCANNER_MODE = var.v1_file_scanner_mode
      MAX_FILES            = tostring(var.max_files)
      CONCURRENT_SCANS     = tostring(var.concurrent_scans)
      LOG_LEVEL           = var.log_level
    },
    # Conditionally add production bucket if required
    var.v1_file_scanner_mode == "MOVE_ALL" ? {
      PRODUCTION_BUCKET_NAME = var.production_bucket_name
    } : {},
    # Conditionally add quarantine bucket if required
    contains(["MOVE_ALL", "MOVE_MALWARE_ONLY"], var.v1_file_scanner_mode) ? {
      QUARANTINE_BUCKET_NAME = var.quarantine_bucket_name
    } : {}
  )

  freeform_tags = local.common_tags
  depends_on    = [oci_identity_policy.v1_fss_ondemand_function_policy]
}

# Function
resource "oci_functions_function" "v1_fss_ondemand_function" {
  application_id = oci_functions_application.v1_fss_ondemand_application.id
  display_name   = "v1-fss-ondemand-scanner"
  image          = "${var.ocir_region}/${var.tenancy_namespace}/${oci_artifacts_container_repository.v1_fss_ondemand_repo.display_name}:${var.image_tag}"
  memory_in_mbs  = var.function_memory_mb
  timeout_in_seconds = var.function_timeout_seconds

  freeform_tags = local.common_tags
  depends_on = [null_resource.docker_build_push]
}

# OCI Monitoring Alarm for scheduled function invocation
# This creates an alarm that fires based on a schedule to trigger the function
resource "oci_monitoring_alarm" "v1_fss_ondemand_schedule_alarm" {
  count                         = var.enable_scheduled_scanning ? 1 : 0
  compartment_id                = var.compartment_id
  display_name                  = "v1-fss-ondemand-schedule-alarm"
  metric_compartment_id         = var.compartment_id
  namespace                     = "oci_computeagent"
  
  # Use a simple metric query that will always evaluate to trigger on schedule
  query = "CpuUtilization[1m].mean() >= 0"
  
  # Alarm severity
  severity = "INFO"
  
  # Enable the alarm
  is_enabled = true
  
  # Schedule configuration - alarm will fire repeatedly based on schedule
  repeat_notification_duration = var.alarm_repeat_duration
  
  # Alarm will transition from OK to FIRING state, triggering the event
  destinations = [oci_ons_notification_topic.v1_fss_ondemand_alarm_topic[0].topic_id]
  
  # Alarm body message
  body = "Scheduled trigger for Vision One File Security malware scanning"
  
  freeform_tags = merge(local.common_tags, {
    "Purpose"      = "ScheduledTrigger"
    "Architecture" = "DirectAlarmScheduler"
  })
}

# ONS Topic for alarm notifications (required for alarm to function)
resource "oci_ons_notification_topic" "v1_fss_ondemand_alarm_topic" {
  count          = var.enable_scheduled_scanning ? 1 : 0
  compartment_id = var.compartment_id
  name           = "v1-fss-ondemand-alarm-topic"
  description    = "Topic for Vision One File Security scheduling alarm notifications"
  
  freeform_tags = local.common_tags
}

# Event rule that triggers function when the alarm fires
resource "oci_events_rule" "alarm_function_trigger" {
  count          = var.enable_scheduled_scanning ? 1 : 0
  compartment_id = var.compartment_id
  display_name   = "v1-fss-alarm-function-trigger"
  description    = "Triggers malware scanning function when monitoring alarm fires"
  is_enabled     = true

  # Event condition: when the monitoring alarm changes state to FIRING
  condition = jsonencode({
    "eventType": ["com.oraclecloud.monitoring.alarm.fired"],
    "data": {
      "alarmId": oci_monitoring_alarm.v1_fss_ondemand_schedule_alarm[0].id
    }
  })

  actions {
    actions {
      action_type = "FAAS"
      is_enabled  = true
      function_id = oci_functions_function.v1_fss_ondemand_function.id
    }
  }

  freeform_tags = merge(local.common_tags, {
    "Purpose"      = "DirectSchedulerTrigger"
    "TriggerType"  = "AlarmFired"
  })
}

# Optional Log Group for Function (only created if logging is enabled)
resource "oci_logging_log_group" "v1_fss_ondemand_log_group" {
  count          = var.enable_logging ? 1 : 0
  compartment_id = var.compartment_id
  display_name   = "v1-fss-ondemand-log-group"
  description    = "Log group for Vision One File Security Ondemand Scanner"

  freeform_tags = local.common_tags
}

# Optional Function Invocation Log (only created if logging is enabled)
resource "oci_logging_log" "v1_fss_ondemand_function_log" {
  count          = var.enable_logging ? 1 : 0
  display_name   = "v1-fss-ondemand-function-log"
  log_group_id   = oci_logging_log_group.v1_fss_ondemand_log_group[0].id
  log_type       = "SERVICE"

  configuration {
    source {
      category    = "invoke"
      resource    = oci_functions_application.v1_fss_ondemand_application.id
      service     = "functions"
      source_type = "OCISERVICE"
    }
  }

  freeform_tags = local.common_tags
}
