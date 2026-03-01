import os
import boto3
from core.config import settings

def verify_s3():
    config = settings.AWS_CONFIG
    print("--- S3 Configuration Check ---")
    print(f"Region: {config['region']}")
    print(f"Bucket: {config['bucket_name']}")
    print(f"Access Key ID set: {bool(config['access_key'])}")
    print(f"Secret Access Key set: {bool(config['secret_key'])}")
    
    if not all(config.values()):
        print("\n[!] Error: One or more AWS configuration values are missing in .env")
        return

    try:
        s3 = boto3.client(
            "s3",
            aws_access_key_id=config["access_key"],
            aws_secret_access_key=config["secret_key"],
            region_name=config["region"]
        )
        # Try to list objects (standard connectivity check)
        s3.list_objects_v2(Bucket=config['bucket_name'], MaxKeys=1)
        print("\n[✓] Success: Connectivity to AWS S3 verified!")
    except Exception as e:
        print(f"\n[!] Error: Connectivity check failed: {e}")

if __name__ == "__main__":
    verify_s3()
