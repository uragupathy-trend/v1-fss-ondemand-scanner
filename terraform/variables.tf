# OCI Provider Configuration
variable "tenancy_ocid" {
  description = "The OCID of the tenancy"
  type        = string
}

variable "user_ocid" {
  description = "The OCID of the user"
  type        = string
}

variable "fingerprint" {
  description = "The fingerprint of the public key"
  type        = string
}

variable "private_key_path" {
  description = "The path to the private key file"
  type        = string
}

variable "region" {
  description = "The OCI region"
  type        = string
  default     = "ap-sydney-1"
}

# Compartment and Network Configuration
variable "compartment_id" {
  description = "The OCID of the compartment where resources will be created"
  type        = string
}

variable "vcn_id" {
  description = "The OCID of the VCN where the function will be deployed"
  type        = string
}

variable "subnet_id" {
  description = "The OCID of the public subnet where the function will be deployed"
  type        = string
}

# Bucket Configuration (existing buckets)
variable "source_bucket_name" {
  description = "Name of the existing source bucket where files are scanned"
  type        = string
}

variable "production_bucket_name" {
  description = "Name of the existing production bucket for clean files. Required only when v1_file_scanner_mode is 'MOVE_ALL'"
  type        = string
  default     = ""
}

variable "quarantine_bucket_name" {
  description = "Name of the existing quarantine bucket for files with malware. Required when v1_file_scanner_mode is 'MOVE_ALL' or 'MOVE_MALWARE_ONLY'"
  type        = string
  default     = ""
}

# Vision One Configuration
variable "vision_one_region" {
  description = "Vision One region"
  type        = string
  default     = "ap-southeast-2"
}

variable "v1_scanner_endpoint" {
  description = "Vision One File Security scanner endpoint"
  type        = string
}

variable "vision_one_api_key_secret_ocid" {
  description = "OCI Vault Secret OCID containing Vision One API key"
  type        = string
}

# Scanner Mode Configuration
variable "v1_file_scanner_mode" {
  description = "File scanner mode that controls file movement behavior. Valid values: MOVE_ALL (move both clean and malware files), MOVE_MALWARE_ONLY (move only malware files, retain clean files), TAG_ONLY (update tags only, don't move any files)"
  type        = string
  default     = "MOVE_MALWARE_ONLY"
  
  validation {
    condition = contains(["MOVE_ALL", "MOVE_MALWARE_ONLY", "TAG_ONLY"], var.v1_file_scanner_mode)
    error_message = "File scanner mode must be one of: MOVE_ALL, MOVE_MALWARE_ONLY, TAG_ONLY."
  }
}

# Performance Configuration for Batch Scanning
variable "max_files" {
  description = "Maximum number of files to process per batch execution"
  type        = number
  default     = 100
}

variable "concurrent_scans" {
  description = "Number of concurrent file scans to perform"
  type        = number
  default     = 5
}

# Function Configuration
variable "function_image_name" {
  description = "Function container image name"
  type        = string
  default     = "v1-fss-ondemand-scanner"
}

variable "environment" {
  description = "Environment name (e.g., dev, test, prod)"
  type        = string
  default     = "dev"
}

variable "function_memory_mb" {
  description = "Memory allocation for the function in MB (batch scanning may need more memory)"
  type        = number
  default     = 1024
}

variable "function_timeout_seconds" {
  description = "Timeout for the function in seconds (batch scanning may take longer)"
  type        = number
  default     = 900
}

# Docker/OCIR Configuration
variable "docker_username" {
  description = "Docker username for OCIR authentication (tenancy-namespace/username)"
  type        = string
}

variable "docker_auth_token" {
  description = "Docker auth token for OCIR authentication"
  type        = string
  sensitive   = true
}

variable "image_tag" {
  description = "Docker image tag"
  type        = string
  default     = "latest"
}

variable "ocir_region" {
  description = "OCIR region (e.g., syd.ocir.io, iad.ocir.io)"
  type        = string
  default     = "syd.ocir.io"
}

variable "tenancy_namespace" {
  description = "OCI tenancy namespace for OCIR"
  type        = string
}

# Optional: Scheduled Scanning Configuration
variable "enable_scheduled_scanning" {
  description = "Enable scheduled batch scanning at regular intervals"
  type        = bool
  default     = false
}

variable "recurrence_details" {
  description = "ICAL recurrence pattern for scheduled scanning"
  type        = string
  default     = "FREQ=MONTHLY;BYMONTHDAY=1;BYHOUR=2;BYMINUTE=0"
}

variable "recurrence_type" {
  description = "Recurrence type for scheduled scanning"
  type        = string
  default     = "ICAL"
}

# Logging Configuration
variable "enable_logging" {
  description = "Enable logging for events and function execution"
  type        = bool
  default     = false
}

variable "log_level" {
  description = "Logging level for the function (DEBUG, INFO, WARNING, ERROR)"
  type        = string
  default     = "INFO"
  
  validation {
    condition = contains(["DEBUG", "INFO", "WARNING", "ERROR"], var.log_level)
    error_message = "Log level must be one of: DEBUG, INFO, WARNING, ERROR."
  }
}
