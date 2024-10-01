import boto3


def delete_s3_bucket(bucket_name: str) -> None:
    """Delete an S3 bucket and all objects inside."""
    s3 = boto3.resource("s3")
    bucket = s3.Bucket(bucket_name)
    bucket.objects.all().delete()
    bucket.delete()