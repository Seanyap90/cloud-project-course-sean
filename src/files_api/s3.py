import boto3

BUCKET_NAME = "cloud-course-bucket-sean"

session = boto3.Session(profile_name="sean-mlops-club")

s3_client = boto3.client("s3")

s3_client.put_object(Bucket=BUCKET_NAME, Key="folder/hello.txt", Body="Hello, World!", ContentType="text/plain")