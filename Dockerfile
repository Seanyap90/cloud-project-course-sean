FROM python:3.11-slim-bookworm

# copy/create the bare minimum files needed to install dependencies
WORKDIR /app
RUN mkdir -p /app/src/ \
    && touch /app/src/__init__.py
COPY pyproject.toml ./

# install dependencies
RUN pip install uvicorn
RUN pip install --editable ./

# copy the rest of the code
COPY src/ ./src/

# create the bucket (the idea is we're mocking AWS), and launch the fastapi app
CMD \
    python -c "import boto3; boto3.client('s3').create_bucket(Bucket='$S3_BUCKET_NAME')" \
    && uvicorn files_api.main:create_app --factory --host 0.0.0.0 --port 8000 --reload