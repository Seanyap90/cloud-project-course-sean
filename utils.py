import hashlib
import json
from functools import lru_cache
from time import sleep

import boto3
import httpx
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.config import Config
from botocore.credentials import ReadOnlyCredentials
from botocore.session import get_session
from botocore.signers import RequestSigner
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

################################
# --- CloudFormation utils --- #
################################


def get_stack_outputs(stack_name: str, aws_region: str) -> dict[str, str]:
    cloudformation = boto3.client("cloudformation", region_name=aws_region)
    stack_result = cloudformation.describe_stacks(StackName=stack_name)
    return {output["OutputKey"]: output["OutputValue"] for output in stack_result["Stacks"][0]["Outputs"]}


def stack_exists(cf_client, stack_name):
    try:
        cf_client.describe_stacks(StackName=stack_name)
        return True
    except cf_client.exceptions.ClientError as e:
        if "does not exist" in str(e):
            return False
        else:
            raise


def delete_stack_if_exists(cf_client, stack_name):
    try:
        cf_client.describe_stacks(StackName=stack_name)
        print(f"Stack {stack_name} exists. Deleting stack.")
        cf_client.delete_stack(StackName=stack_name)
        waiter = cf_client.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name)
        print(f"Stack {stack_name} deleted.")
    except cf_client.exceptions.ClientError as e:
        if "does not exist" in str(e):
            print(f"Stack {stack_name} does not exist, no need to delete.")
        else:
            raise


def create_cloudformation_stack(
    template_fpath: str,
    stack_name: str,
    aws_region: str,
    skip_if_exists: bool = True,
) -> dict[str, str]:
    template_body: str = load_template(template_path=template_fpath)
    console_url: str = get_cloudformation_console_url(stack_name=stack_name)
    print(f"View stack '{stack_name}' in the CloudFormation console at '{console_url}'.")
    return create_cloudformation_stack_from_template(
        template_body=template_body,
        stack_name=stack_name,
        aws_region=aws_region,
        skip_if_exists=skip_if_exists,
    )


def create_cloudformation_stack_from_template(
    template_body: str,
    stack_name: str,
    aws_region: str,
    skip_if_exists: bool = True,
) -> dict[str, str]:
    cloudformation = boto3.client("cloudformation", region_name=aws_region)
    if skip_if_exists:
        if stack_exists(cf_client=cloudformation, stack_name=stack_name):
            print(f"Stack {stack_name} exists. Skipping stack creation.")
            return get_stack_outputs(stack_name=stack_name, aws_region=aws_region)

    delete_stack_if_exists(cf_client=cloudformation, stack_name=stack_name)

    print(f"Creating stack {stack_name}.")
    cloudformation.create_stack(StackName=stack_name, TemplateBody=template_body, Capabilities=["CAPABILITY_IAM"])
    waiter = cloudformation.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name)

    stack_result = cloudformation.describe_stacks(StackName=stack_name)
    stack_status = stack_result["Stacks"][0]["StackStatus"]
    if stack_status != "CREATE_COMPLETE":
        raise Exception(f"Stack creation failed: {stack_status}")

    stack_outputs = get_stack_outputs(stack_name=stack_name, aws_region=aws_region)

    return stack_outputs


def load_template(template_path):
    with open(template_path, "r") as file:
        return file.read()


def get_cloudformation_console_url(stack_name):
    region = boto3.Session().region_name
    return f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks/stackinfo?filteringText=&filteringStatus=active&viewNested=true&hideStacks=false&stackId={stack_name}"


def lookup_api_key_value(api_key_id: str, aws_region: str):
    apigateway = boto3.client("apigateway", region_name=aws_region)
    response = apigateway.get_api_key(apiKey=api_key_id, includeValue=True)
    return response["value"]


###################################
# --- deep copy httpx request --- #
###################################

from copy import deepcopy

import httpx


def deepcopy_httpx_request(original_request: httpx.Request) -> httpx.Request:
    """Create a deep copy of an httpx.Request object."""
    # Deep copy the original request to avoid mutating it
    request_copy = deepcopy(original_request)

    # Create a new request with the copied data
    new_request = httpx.Request(
        method=request_copy.method,
        url=request_copy.url,
        headers=request_copy.headers.copy(),
        content=request_copy.content,
        extensions=deepcopy(request_copy.extensions),
    )

    return new_request


##############################################
# --- Pretty print SigV4 request details --- #
##############################################


def print_request_details(
    request: httpx.Request,
    aws_request: AWSRequest,
    region_name: str,
    service_name: str,
    credentials: ReadOnlyCredentials,
):
    console = Console()

    console.rule("SigV4 Signing Details")

    # Print the canonical request details
    canonical_table = Table(title="Canonical Request")
    canonical_table.add_column("Component", justify="left", style="white", no_wrap=True)
    canonical_table.add_column("Value", style="cyan")

    canonical_table.add_row("HTTP Method", request.method)
    canonical_table.add_row("Service", service_name)
    canonical_table.add_row("Region", region_name)
    canonical_table.add_row("Host", request.url.host)
    canonical_table.add_row("Canonical URI (path)", request.url.path)
    canonical_table.add_row(
        "Canonical Query (query params)", request.url.query.decode("utf-8")
    )  # Decode byte string to regular string
    canonical_table.add_row("Payload Hash", hashlib.sha256(request.content or b"").hexdigest())

    console.print(canonical_table)

    # Print the AWS credentials details
    credentials_table = Table(title="AWS Credentials")
    credentials_table.add_column("Component", justify="left", style="white", no_wrap=True)
    credentials_table.add_column("Value", style="cyan")

    credentials_table.add_row("Access Key", credentials.access_key)
    credentials_table.add_row("Secret Key", "(hidden for security)")
    credentials_table.add_row("Session Token", credentials.token or "None")

    console.print(credentials_table)

    # Print the signed headers
    headers_table = Table(title="Signed Request Headers")
    headers_table.add_column("Header", justify="left", style="white", no_wrap=True)
    headers_table.add_column("Value", style="cyan")

    for header, value in aws_request.headers.items():
        headers_table.add_row(header, value)

    console.print(headers_table)


def print_http_request(request: httpx.Request):
    # Initialize the Rich console
    console = Console()
    console.rule("HTTP Request")

    # Start constructing the HTTP request string
    request_lines = []

    # Add the request line (e.g., GET /path HTTP/1.1)
    request_line = f"{request.method} {request.url.path} HTTP/1.1"
    request_lines.append(request_line)

    # Add the headers
    for header, value in request.headers.items():
        request_lines.append(f"{header}: {value}")

    # Add a blank line to separate headers and body
    request_lines.append("")

    # Add the body if it exists
    if request.content:
        request_lines.append(request.content.decode("utf-8", errors="replace"))

    # Combine all lines into a single string
    request_text = "\n".join(request_lines)

    # Use Rich Syntax for highlighting
    syntax = Syntax(request_text, "http", theme="monokai", word_wrap=True)

    # Print the highlighted request
    console.print(syntax)


def print_http_response(response: httpx.Response):
    # Initialize the Rich console
    console = Console()
    console.rule("HTTP Response")

    # Start constructing the HTTP response string
    response_lines = []

    # Add the status line (e.g., HTTP/1.1 200 OK)
    status_line = f"{response.http_version} {response.status_code} {response.reason_phrase}"
    response_lines.append(status_line)

    # Add the headers
    for header, value in response.headers.items():
        response_lines.append(f"{header}: {value}")

    # Add a blank line to separate headers and body
    response_lines.append("")

    # Add the body if it exists
    if response.content:
        response_lines.append(response.text)

    # Combine all lines into a single string
    response_text = "\n".join(response_lines)

    # Use Rich Syntax for highlighting
    syntax = Syntax(response_text, "http", theme="monokai", word_wrap=True)

    # Print the highlighted response
    console.print(syntax)
