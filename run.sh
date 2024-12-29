#!/bin/bash

set -e

#####################
# --- Constants --- #
#####################

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
MINIMUM_TEST_COVERAGE_PERCENT=0

AWS_LAMBDA_FUNCTION_NAME="files-api-handler"
BUILD_DIR_REL_PATH="./build"
BUILD_DIR="${THIS_DIR}/${BUILD_DIR_REL_PATH}"


##########################
# --- Task Functions --- #
##########################

# install core and development Python dependencies into the currently activated venv
function install {
    python -m pip install --upgrade pip
    python -m pip install --editable "$THIS_DIR/[dev]"
}

# package and deploy the src/ code by updating an existing AWS Lambda function
# The function package consists of
# - deployment package: contents of the src/ folder
# - layer package: installed dependencies
# 
# Note, this function assumes that
# - a lambda function named $AWS_LAMBDA_FUNCTION_NAME already exists
# - docker 🐳 is required to run this function
function deploy-lambda {
    export AWS_PROFILE=sean-mlops-club
    export AWS_REGION=us-west-2
    deploy-lambda:cd
}

function deploy-lambda:cd {
    # Get the current user ID and group ID to run the docker command with so that
	# the generated lambda-env folder doesn't have root permissions, instead user level permission
	# This will help in library installation in the docker container and cleaning up the lambda-env folder later on.
	USER_ID=$(id -u)
	GROUP_ID=$(id -g)

    LAMBDA_LAYER_DIR_NAME="lambda-env"
    LAMBDA_LAYER_DIR="${BUILD_DIR}/${LAMBDA_LAYER_DIR_NAME}"
    LAMBDA_LAYER_ZIP_FPATH="${BUILD_DIR}/lambda-layer.zip"
    LAMBDA_HANDLER_ZIP_FPATH="${BUILD_DIR}/lambda.zip"
    SRC_DIR="${THIS_DIR}/src"

    # clean up artifacts
    rm -rf "$LAMBDA_LAYER_DIR" || true
    rm -f "$LAMBDA_LAYER_ZIP_FPATH" || true

    # install dependencies
    docker logout || true  # log out to use the public ecr
    docker pull public.ecr.aws/lambda/python:3.12-arm64

    # install dependencies in a docker container to ensure compatibility with AWS Lambda
    # 
    # Note: we remote boto3 and botocore because AWS lambda automatically
    # provides these. This saves us ~24MB in the final, uncompressed layer size.
    docker run --rm \
        --user $USER_ID:$GROUP_ID \
        --volume "${THIS_DIR}":/out \
        --entrypoint /bin/bash \
        public.ecr.aws/lambda/python:3.12-arm64 \
        -c " \
        pip install --root --upgrade pip \
        && pip install \
            --editable /out/[aws-lambda] \
            --target /out/${BUILD_DIR_REL_PATH}/${LAMBDA_LAYER_DIR_NAME}/python \
        && rm -rf /out/${BUILD_DIR_REL_PATH}/${LAMBDA_LAYER_DIR_NAME}/python/boto3 \
        && rm -rf /out/${BUILD_DIR_REL_PATH}/${LAMBDA_LAYER_DIR_NAME}/python/botocore \
        "

    sudo chown -R $(whoami):$(whoami) "$BUILD_DIR"
    chmod -R 777 ${BUILD_DIR}

    # bundle dependencies and handler in a zip file
    cd "$LAMBDA_LAYER_DIR"
    zip -r "$LAMBDA_LAYER_ZIP_FPATH" ./

    cd "$SRC_DIR"
    zip -r "$LAMBDA_HANDLER_ZIP_FPATH" ./

    cd "$THIS_DIR"

    # publish the lambda "deployment package" (the handler)
    aws lambda update-function-code \
        --function-name "$AWS_LAMBDA_FUNCTION_NAME" \
        --zip-file fileb://${LAMBDA_HANDLER_ZIP_FPATH} \
        --output json | cat

    # publish the lambda layer with a new version
    LAYER_VERSION_ARN=$(aws lambda publish-layer-version \
        --layer-name cloud-course-project-python-deps \
        --compatible-runtimes python3.12 \
        --zip-file fileb://${LAMBDA_LAYER_ZIP_FPATH} \
        --compatible-architectures arm64 \
        --query 'LayerVersionArn' \
        --output text | cat)

    # update the lambda function to use the new layer version
    aws lambda update-function-configuration \
        --function-name "$AWS_LAMBDA_FUNCTION_NAME" \
        --layers $LAYER_VERSION_ARN \
        --handler "files_api.aws_lambda_handler.handler" \
        --output json | cat
}

function install-generated-sdk {
    # setting editable_mode=strict fixes an issue with autocompletion
    # in VS Code when installing editable packages. See:
    # https://github.com/microsoft/pylance-release/issues/3473
    python -m pip install --editable "$THIS_DIR/files-api-sdk" \
        --config-settings editable_mode=strict
}

function generate-client-library {
    docker run --rm \
        -v ${PWD}:/local openapitools/openapi-generator-cli generate \
        --generator-name python-pydantic-v1 \
        --input-spec /local/openapi.json \
        --output /local/files-api-sdk \
        --package-name files_api_sdk
}

function run {
    AWS_PROFILE=cloud-course \
    S3_BUCKET_NAME="some-bucket" \
        uvicorn 'files_api.main:create_app' --reload
}

# start the FastAPI app, pointed at a mocked aws endpoint
function run-mock {
    set +e

    # Start moto.server in the background on localhost:5000
    python -m moto.server -p 5000 &
    MOTO_PID=$!

    # point the AWS CLI and boto3 to the mocked AWS server using mocked credentials
    export AWS_ENDPOINT_URL="http://localhost:5000"
    export AWS_SECRET_ACCESS_KEY="mock"
    export AWS_ACCESS_KEY_ID="mock"
    export S3_BUCKET_NAME="some-bucket"

    # create a bucket called "some-bucket" using the mocked aws server
    aws s3 mb "s3://$S3_BUCKET_NAME"

    # Trap EXIT signal to kill the moto.server process when uvicorn stops
    trap 'kill $MOTO_PID' EXIT

    # Set AWS endpoint URL and start FastAPI app with uvicorn in the foreground
    export LOGURU_LEVEL="INFO"
    uvicorn files_api.main:create_app --reload

    # Wait for the moto.server process to finish (this is optional if you want to keep it running)
    wait $MOTO_PID
}

function set-local-aws-env-vars {
    export AWS_PROFILE=sean-mlops-club
    export AWS_REGION=us-west-2
}

function run-docker {
    set-local-aws-env-vars
    aws configure export-credentials --profile $AWS_PROFILE --format env > .env
    docker compose up --build
}

function run-locust {
    set-local-aws-env-vars
    aws configure export-credentials --profile $AWS_PROFILE --format env > .env
    docker compose \
        --file docker-compose.yaml \
        --file docker-compose.locust.yaml \
        up \
        --build
}

# run linting, formatting, and other static code quality tools
function lint {
    pre-commit run --all-files
}

# same as `lint` but with any special considerations for CI
function lint:ci {
    # We skip no-commit-to-branch since that blocks commits to `main`.
    # All merged PRs are commits to `main` so this must be disabled.
    SKIP=no-commit-to-branch pre-commit run --all-files
}

# execute tests that are not marked as `slow`
function test:quick {
    run-tests -m "not slow" ${@:-"$THIS_DIR/tests/"}
}

# execute tests against the installed package; assumes the wheel is already installed
function test:ci {
    INSTALLED_PKG_DIR="$(python -c 'import files_api; print(files_api.__path__[0])')"
    # in CI, we must calculate the coverage for the installed package, not the src/ folder
    COVERAGE_DIR="$INSTALLED_PKG_DIR" run-tests
}

# (example) ./run.sh test tests/test_states_info.py::test__slow_add
function run-tests {
    PYTEST_EXIT_STATUS=0
    rm -rf "$THIS_DIR/test-reports" || true
    python -m pytest ${@:-"$THIS_DIR/tests/"} \
        --cov "${COVERAGE_DIR:-$THIS_DIR/src}" \
        --cov-report html \
        --cov-report term \
        --cov-report xml \
        --junit-xml "$THIS_DIR/test-reports/report.xml" \
        --cov-fail-under "$MINIMUM_TEST_COVERAGE_PERCENT" || ((PYTEST_EXIT_STATUS+=$?))
    mv coverage.xml "$THIS_DIR/test-reports/" || true
    mv htmlcov "$THIS_DIR/test-reports/" || true
    mv .coverage "$THIS_DIR/test-reports/" || true
    return $PYTEST_EXIT_STATUS
}

function test:wheel-locally {
    deactivate || true
    rm -rf test-env || true
    python -m venv test-env
    source test-env/bin/activate
    clean || true
    pip install build
    build
    pip install ./dist/*.whl pytest pytest-cov
    test:ci
    deactivate || true
}

# serve the html test coverage report on localhost:8000
function serve-coverage-report {
    python -m http.server --directory "$THIS_DIR/test-reports/htmlcov/" 8000
}

# build a wheel and sdist from the Python source code
function build {
    python -m build --sdist --wheel "$THIS_DIR/"
}

function release:test {
    lint
    clean
    build
    publish:test
}

function release:prod {
    release:test
    publish:prod
}

function publish:test {
    try-load-dotenv || true
    twine upload dist/* \
        --repository testpypi \
        --username=__token__ \
        --password="$TEST_PYPI_TOKEN"
}

function publish:prod {
    try-load-dotenv || true
    twine upload dist/* \
        --repository pypi \
        --username=__token__ \
        --password="$PROD_PYPI_TOKEN"
}

# remove all files generated by tests, builds, or operating this codebase
function clean {
    rm -rf dist build coverage.xml test-reports
    find . \
      -type d \
      \( \
        -name "*cache*" \
        -o -name "*.dist-info" \
        -o -name "*.egg-info" \
        -o -name "*htmlcov" \
      \) \
      -not -path "*env/*" \
      -exec rm -r {} + || true

    find . \
      -type f \
      -name "*.pyc" \
      -o -name "*.zip" \
      -o -name "*.DS_Store" \
      -not -path "*env/*" \
      -exec rm {} +
}

# export the contents of .env as environment variables
function try-load-dotenv {
    if [ ! -f "$THIS_DIR/.env" ]; then
        echo "no .env file found"
        return 1
    fi

    while read -r line; do
        export "$line"
    done < <(grep -v '^#' "$THIS_DIR/.env" | grep -v '^$')
}

# print all functions in this file
function help {
    echo "$0 <task> <args>"
    echo "Tasks:"
    compgen -A function | cat -n
}

TIMEFORMAT="Task completed in %3lR"
time ${@:-help}