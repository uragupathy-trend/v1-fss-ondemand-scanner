#!/usr/bin/env python3
"""
Vision One OCI Bucket Batch Scanner
On-demand scanning for Oracle Cloud Infrastructure Object Storage buckets
using Trend Micro Vision One File Security SDK with support for all scanner modes.
"""

import json
import logging
import os
import time
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any

import oci
from oci.vault import VaultsClient
from oci.secrets import SecretsClient
import amaas.grpc
from fdk import response

# Configure logging
logging.basicConfig(
    level=os.getenv('LOG_LEVEL', 'INFO'),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global cache for secrets to avoid repeated vault calls
_secret_cache = {}

def get_secret_from_vault(secret_ocid: str, signer) -> str:
    """Retrieve secret from OCI Vault with caching"""
    
    # Check cache first
    if secret_ocid in _secret_cache:
        logger.info(f"Using cached secret for OCID: {secret_ocid[:20]}...")
        return _secret_cache[secret_ocid]
    
    try:
        logger.info(f"Retrieving secret from vault: {secret_ocid[:20]}...")
        
        # Initialize secrets client
        secrets_client = SecretsClient(config={}, signer=signer)
        
        # Get secret bundle (current version)
        secret_bundle = secrets_client.get_secret_bundle(secret_id=secret_ocid)
        
        # Decode the secret content
        secret_content = secret_bundle.data.secret_bundle_content.content
        
        # Cache the secret
        _secret_cache[secret_ocid] = secret_content
        
        logger.info("Secret retrieved and cached successfully")
        return secret_content
        
    except Exception as e:
        logger.error(f"Error retrieving secret from vault: {str(e)}")
        raise ValueError(f"Failed to retrieve secret from vault: {str(e)}")

@dataclass
class ScanResult:
    """Batch scan result tracking"""
    total: int = 0
    scanned: int = 0
    clean: int = 0
    malware: int = 0
    errors: int = 0
    skipped: int = 0
    duration: float = 0

class BatchScanner:
    """OCI bucket batch scanner with Vision One File Security integration"""
    
    def __init__(self):
        # Initialize signer FIRST before configuration
        self.signer = oci.auth.signers.get_resource_principals_signer()
        self.config = self._get_configuration()
        self.storage_client = oci.object_storage.ObjectStorageClient(config={}, signer=self.signer)
        self.namespace = self.storage_client.get_namespace().data
        self.v1_handle = None

    def _get_configuration(self) -> Dict[str, str]:
        """Get configuration from environment variables and OCI Vault"""
        
        # Always required variables
        required_vars = [
            'SOURCE_BUCKET_NAME',
            'V1_REGION',
            'V1_SCANNER_ENDPOINT',
            'V1_FILE_SCANNER_MODE'
        ]
        
        # Vault-based variables (sensitive)
        vault_vars = [
            'VAULT_SECRET_OCID'
        ]
        
        config = {}
        
        # Get required configuration from environment variables
        for var in required_vars:
            value = os.environ.get(var)
            if not value:
                raise ValueError(f"Missing required environment variable: {var}")
            config[var.lower()] = value
        
        # Validate and set default for scanner mode
        scanner_mode = config.get('v1_file_scanner_mode', 'MOVE_ALL')
        valid_modes = ['MOVE_ALL', 'MOVE_MALWARE_ONLY', 'TAG_ONLY']
        
        if scanner_mode not in valid_modes:
            logger.warning(f"Invalid scanner mode '{scanner_mode}', falling back to 'MOVE_ALL'")
            config['v1_file_scanner_mode'] = 'MOVE_ALL'
            scanner_mode = 'MOVE_ALL'
        else:
            logger.info(f"Scanner mode set to: {scanner_mode}")
        
        # Get bucket configuration based on scanner mode
        if scanner_mode == 'MOVE_ALL':
            # Both production and quarantine buckets required
            for bucket_var in ['PRODUCTION_BUCKET_NAME', 'QUARANTINE_BUCKET_NAME']:
                value = os.environ.get(bucket_var)
                if not value:
                    raise ValueError(f"Missing required environment variable for MOVE_ALL mode: {bucket_var}")
                config[bucket_var.lower()] = value
        
        elif scanner_mode == 'MOVE_MALWARE_ONLY':
            # Only quarantine bucket required
            value = os.environ.get('QUARANTINE_BUCKET_NAME')
            if not value:
                raise ValueError(f"Missing required environment variable for MOVE_MALWARE_ONLY mode: QUARANTINE_BUCKET_NAME")
            config['quarantine_bucket_name'] = value
            
            # Production bucket is optional
            prod_value = os.environ.get('PRODUCTION_BUCKET_NAME')
            if prod_value:
                config['production_bucket_name'] = prod_value
        
        elif scanner_mode == 'TAG_ONLY':
            # No additional buckets required, but get them if available for logging
            for bucket_var in ['PRODUCTION_BUCKET_NAME', 'QUARANTINE_BUCKET_NAME']:
                value = os.environ.get(bucket_var)
                if value:
                    config[bucket_var.lower()] = value
        
        # Get sensitive configuration from OCI Vault
        for var in vault_vars:
            secret_ocid = os.environ.get(var)
            if not secret_ocid:
                raise ValueError(f"Missing required environment variable: {var}")
            
            if var == 'VAULT_SECRET_OCID':
                # Retrieve Vision One API key from vault
                api_key = get_secret_from_vault(secret_ocid, self.signer)
                config['v1_api_key'] = api_key
        
        # Performance configuration (optional)
        config['max_files'] = int(os.environ.get('MAX_FILES', '100'))
        config['concurrent_scans'] = int(os.environ.get('CONCURRENT_SCANS', '5'))
        
        return config

    def _init_vision_one(self):
        """Initialize Vision One scanner connection"""
        if not self.v1_handle:
            logger.info("Initializing Vision One connection")
            self.v1_handle = amaas.grpc.init(
                host=self.config['v1_scanner_endpoint'],
                api_key=self.config['v1_api_key'],
                enable_tls=False
            )

    def _scan_file(self, bucket: str, object_name: str) -> Dict:
        """Download and scan a single file"""
        try:
            # Get object
            obj_response = self.storage_client.get_object(
                namespace_name=self.namespace,
                bucket_name=bucket,
                object_name=object_name
            )
            
            # Create temp file for scanning
            temp_file_path = f"/tmp/{os.path.basename(object_name)}"
            with open(temp_file_path, 'wb') as temp_file:
                for chunk in obj_response.data.raw.stream(1024 * 1024, decode_content=False):
                    temp_file.write(chunk)
            
            logger.info(f"File downloaded to: {temp_file_path}")
            
            # Scan with Vision One
            result = amaas.grpc.scan_file(
                channel=self.v1_handle,
                file_name=temp_file_path,
                verbose=True,
                tags=["oci-function","batch-scanner"]
            )
            
            # Parse scan result
            scan_data = json.loads(result)
            is_malware_detected = False

            logger.info(f"Scan result for the file {temp_file_path} : {scan_data}")
            
            atse_result = scan_data.get('result', {}).get('atse', {})
            if atse_result:
                malware_count = atse_result.get('malwareCount', 0)
                logger.info(f"Malware Count: {malware_count}")
                malware_list = atse_result.get('malware', [])
                logger.info(f"Malware List: {malware_list}")
                is_malware_detected = malware_count > 0
                logger.info(f"Is Malware Detected: {is_malware_detected}")
                
            else:
                logger.info(f"No atse result found in scan data for the object {object_name}")
            
            return {
                "object_name": object_name,
                "is_malware_detected": is_malware_detected,
                "scan_id": scan_data.get('scanId'),
                "file_sha256": scan_data.get('fileSHA256'),
                "scanner_version": scan_data.get('scannerVersion')
            }
            
        except Exception as e:
            logger.error(f"Error scanning {object_name}: {e}")
            return {'object_name': object_name, 'error': str(e)}

    def move_file_based_on_scan(self, scan_result: Dict) -> str:
        """Process file based on scan results and configured scanner mode"""
        if 'error' in scan_result:
            logger.error(f"Scan failed: {scan_result['error']}")
            return 'error'
        
        object_name = scan_result['object_name']
        is_malware = scan_result['is_malware_detected']
        mode = self.config['v1_file_scanner_mode']
        
        logger.info(f"Processing file with scanner mode: {mode}")
        logger.info(f"Malware detected: {is_malware}")
        
        # Prepare scan result metadata
        metadata = {
            "filescanned": "true",
            "ismalwaredetected": str(is_malware).lower(),
            "ondemand_scantimestamp": str(int(time.time())),
            "scanid": scan_result.get('scan_id', ''),
            "scannerversion": scan_result.get('scanner_version', '')
        }
        
        if is_malware and scan_result.get('malware_names'):
            metadata["malwarenames"] = ','.join(scan_result['malware_names'][:3])  # Limit size
        
        # MODE 1: TAG_ONLY - Always tag files in-place, never move
        if mode == 'TAG_ONLY':
            logger.info("TAG_ONLY mode: Updating file metadata in-place")
            return self._update_file_metadata_in_place(object_name, metadata)
        
        # MODE 2: MOVE_MALWARE_ONLY - Move only malware to quarantine, tag clean files in-place
        elif mode == 'MOVE_MALWARE_ONLY':
            if is_malware and self.config.get('quarantine_bucket_name'):
                logger.info("MOVE_MALWARE_ONLY mode: Moving infected file to quarantine")
                return self._move_file_to_bucket(
                    object_name, self.config['quarantine_bucket_name'], metadata
                )
            else:
                logger.info("MOVE_MALWARE_ONLY mode: Clean file detected, updating metadata in-place")
                return self._update_file_metadata_in_place(object_name, metadata)
        
        # MODE 3: MOVE_ALL - Move all files to appropriate buckets
        else:  # MOVE_ALL or any other value falls back to this mode
            target_bucket = (self.config.get('quarantine_bucket_name') if is_malware 
                           else self.config.get('production_bucket_name'))
            if target_bucket:
                logger.info(f"MOVE_ALL mode: Moving file to {'quarantine' if is_malware else 'production'} bucket: {target_bucket}")
                return self._move_file_to_bucket(object_name, target_bucket, metadata)
            else:
                # Fallback: tag in place
                logger.warning(f"MOVE_ALL mode: No target bucket configured, tagging in place")
                return self._update_file_metadata_in_place(object_name, metadata)

    def _update_file_metadata_in_place(self, object_name: str, metadata: Dict) -> str:
        """Update file metadata/tags in-place without moving the file"""
        try:
            source_bucket = self.config['source_bucket_name']
            
            # Get the original object content and details
            get_object_response = self.storage_client.get_object(
                namespace_name=self.namespace,
                bucket_name=source_bucket,
                object_name=object_name
            )
            
            # Get existing metadata
            existing_meta = {}
            try:
                object_details = self.storage_client.head_object(
                    namespace_name=self.namespace,
                    bucket_name=source_bucket,
                    object_name=object_name
                )
                existing_meta = object_details.headers.get('opc-meta-data', {})
                if isinstance(existing_meta, str):
                    existing_meta = json.loads(existing_meta)
            except:
                existing_meta = {}

            # Merge existing metadata with scan tags
            updated_meta = {**existing_meta, **metadata}
            
            # Update the object in-place with new metadata
            logger.info(f"Updating metadata for object {object_name} in bucket {source_bucket}")
            
            self.storage_client.put_object(
                namespace_name=self.namespace,
                bucket_name=source_bucket,
                object_name=object_name,
                put_object_body=get_object_response.data.content,
                content_type=get_object_response.headers.get('content-type'),
                opc_meta=updated_meta
            )
            
            logger.info(f"Metadata successfully updated for object in {source_bucket}")
            return "metadata_updated"
            
        except Exception as e:
            logger.error(f"Error updating metadata: {str(e)}")
            return "metadata_update_failed"

    def _move_file_to_bucket(self, object_name: str, target_bucket: str, metadata: Dict) -> str:
        """Move file from source bucket to target bucket with scan metadata"""
        try:
            source_bucket = self.config['source_bucket_name']
            
            # Get the original object
            get_object_response = self.storage_client.get_object(
                namespace_name=self.namespace,
                bucket_name=source_bucket,
                object_name=object_name
            )
            
            # Get existing metadata from source object
            existing_meta = {}
            try:
                object_details = self.storage_client.head_object(
                    namespace_name=self.namespace,
                    bucket_name=source_bucket,
                    object_name=object_name
                )
                existing_meta = object_details.headers.get('opc-meta-data', {})
                if isinstance(existing_meta, str):
                    existing_meta = json.loads(existing_meta)
            except:
                existing_meta = {}

            # Add origin bucket to metadata
            metadata["originalbucket"] = source_bucket
            
            
            # Merge existing metadata with scan tags
            updated_meta = {**existing_meta, **metadata}
       
            try:
                # Copy object to target bucket with updated metadata
                logger.info(f"Copying object from {source_bucket} to {target_bucket}")
                
                self.storage_client.put_object(
                    namespace_name=self.namespace,
                    bucket_name=target_bucket,
                    object_name=object_name,
                    put_object_body=get_object_response.data.content,
                    content_type=get_object_response.headers.get('content-type'),
                    opc_meta=updated_meta
                )
                
                logger.info(f"Object successfully copied to target bucket: {target_bucket}")
           
            except Exception as copy_error:
                logger.error(f"Error copying object: {str(copy_error)}")
                return "copy_failed"
            
            # Delete the object from the source bucket after successful copy
            logger.info(f"Deleting object from source bucket: {source_bucket}")
            self.storage_client.delete_object(
                namespace_name=self.namespace,
                bucket_name=source_bucket,
                object_name=object_name
            )
            logger.info(f"Object successfully deleted from source bucket")
            
            return "moved"
            
        except Exception as e:
            logger.error(f"Error moving file: {str(e)}")
            return "move_failed"

    def _update_object_metadata(self, bucket: str, object_name: str, metadata: Dict):
        """Update object metadata in place"""
        try:
            # Get existing metadata
            head_response = self.storage_client.head_object(
                namespace_name=self.namespace,
                bucket_name=bucket,
                object_name=object_name
            )
            
            existing_meta = head_response.headers.get('opc-meta', {})
            if isinstance(existing_meta, str):
                existing_meta = json.loads(existing_meta) if existing_meta else {}
            
            # Merge metadata
            updated_meta = {**existing_meta, **metadata}
            
            # Copy object with new metadata
            self.storage_client.copy_object(
                namespace_name=self.namespace,
                bucket_name=bucket,
                copy_object_details=oci.object_storage.models.CopyObjectDetails(
                    source_object_name=object_name,
                    destination_namespace=self.namespace,
                    destination_bucket=bucket,
                    destination_object_name=object_name,
                    metadata=updated_meta,
                    metadata_directive="REPLACE"
                )
            )
            
        except Exception as e:
            logger.error(f"Failed to update metadata for {object_name}: {e}")

    def _move_object(self, source_bucket: str, object_name: str, target_bucket: str, metadata: Dict):
        """Move object between buckets"""
        try:
            # Get source object
            obj_response = self.storage_client.get_object(
                namespace_name=self.namespace,
                bucket_name=source_bucket,
                object_name=object_name
            )
            
            # Put to target bucket with metadata
            self.storage_client.put_object(
                namespace_name=self.namespace,
                bucket_name=target_bucket,
                object_name=object_name,
                put_object_body=obj_response.data.content,
                opc_meta=metadata
            )
            
            # Delete from source
            self.storage_client.delete_object(
                namespace_name=self.namespace,
                bucket_name=source_bucket,
                object_name=object_name
            )
            
        except Exception as e:
            logger.error(f"Failed to move {object_name}: {e}")
            raise

    def scan_bucket(self) -> ScanResult:
        """Main scanning logic"""
        result = ScanResult()
        start_time = time.time()
        
        try:
            self._init_vision_one()
            
            # List objects
            objects_response = self.storage_client.list_objects(
                namespace_name=self.namespace,
                bucket_name=self.config['source_bucket_name'],
                limit=self.config['max_files']
            )
            
            objects = objects_response.data.objects
            result.total = len(objects)
            
            if not objects:
                logger.info("No objects found in bucket")
                return result
            
            logger.info(f"Processing {len(objects)} objects from {self.config['source_bucket_name']}")
            
            # Process files concurrently
            with ThreadPoolExecutor(max_workers=self.config['concurrent_scans']) as executor:
                # Submit scan tasks
                future_to_obj = {
                    executor.submit(self._scan_file, self.config['source_bucket_name'], obj.name): obj.name
                    for obj in objects
                }
                
                # Process results
                for future in as_completed(future_to_obj):
                    obj_name = future_to_obj[future]
                    try:
                        scan_result = future.result()
                        logger.info(f"Scan result for {obj_name}: {scan_result}")
                        logger.info(f"Calling move_file_based_on_scan()")

                        action = self.move_file_based_on_scan(scan_result)
                        
                        result.scanned += 1

                        if 'error' in scan_result:
                            result.errors += 1
                        elif scan_result.get('is_malware_detected'):
                            result.malware += 1
                        else:
                            result.clean += 1
                        
                        logger.info(f"✅ {obj_name}: {'MALWARE' if scan_result.get('is_malware_detected') else 'CLEAN'} -> {action}")
                        
                    except Exception as e:
                        result.errors += 1
                        logger.error(f"❌ {obj_name}: {e}")
            
            result.duration = time.time() - start_time
            
        finally:
            if self.v1_handle:
                amaas.grpc.quit(self.v1_handle)
        
        return result


def handler(ctx, data=None):
    """OCI Function handler for batch scanning"""
    try:
        logger.info("Starting OCI Function batch scanner")
        
        scanner = BatchScanner()
        result = scanner.scan_bucket()
        
        summary = {
            "status": "success",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "source_bucket": scanner.config['source_bucket_name'],
            "scanner_mode": scanner.config['v1_file_scanner_mode'],
            "results": asdict(result),
            "performance": {
                "files_per_second": round(result.scanned / result.duration, 2) if result.duration > 0 else 0,
                "duration_seconds": round(result.duration, 2)
            }
        }
        
        logger.info(f"Batch scan complete: {result.scanned} scanned, {result.clean} clean, {result.malware} malware, {result.errors} errors in {result.duration:.2f}s")
        
        return response.Response(
            ctx,
            response_data=json.dumps(summary, indent=2),
            headers={"Content-Type": "application/json"}
        )
        
    except Exception as e:
        logger.error(f"Fatal error in batch scanner: {e}")
        return response.Response(
            ctx,
            response_data=json.dumps({
                "status": "error",
                "error": str(e),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                "error_type": "batch_scanner_error"
            }),
            headers={"Content-Type": "application/json"},
            status_code=500
        )


# CLI entry point for testing
if __name__ == "__main__":
    import sys
    
    # Set test environment variables
    os.environ.setdefault('SOURCE_BUCKET_NAME', 'test-source-bucket')
    os.environ.setdefault('V1_REGION', 'us-east-1')
    os.environ.setdefault('V1_SCANNER_ENDPOINT', 'antimalware.us-east-1.cloudone.trendmicro.com:443')
    os.environ.setdefault('V1_FILE_SCANNER_MODE', 'TAG_ONLY')
    os.environ.setdefault('VAULT_SECRET_OCID', 'ocid1.vaultsecret.oc1.example...')
    os.environ.setdefault('LOG_LEVEL', 'DEBUG')
    
    print("Testing BatchScanner in CLI mode...")
    try:
        scanner = BatchScanner()
        result = scanner.scan_bucket()
        print(f"Scan Results: {asdict(result)}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
