from textwrap import dedent

import pydantic
from fastapi import FastAPI
from fastapi.routing import APIRoute

from files_api.errors import (
    handle_broad_exceptions,
    handle_pydantic_validation_errors,
)
from files_api.monitoring.logger import inject_lambda_context__middleware
from files_api.routes import ROUTER
from files_api.settings import Settings
from fastapi.exceptions import RequestValidationError
from files_api.route_handler import RouteHandler


def custom_generate_unique_id(route: APIRoute):
    """
    Generate prettier `operationId`s in the OpenAPI schema.

    These become the function names in generated client SDKs.
    """
    return f"{route.tags[0]}-{route.name}"


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create a FastAPI application."""
    settings = settings or Settings()

    app = FastAPI(
        title="Files API",
        summary="Store and retrieve files.",
        version="v1",  # a fancier version would read the semver from pkg metadata
        description=dedent(
            """\
        ![Maintained by](https://img.shields.io/badge/Maintained%20by-MLOps%20Club-05998B?style=for-the-badge)

        | Helpful Links | Notes |
        | --- | --- |
        | [Course Homepage](https://mlops-club.org) | |
        | [Course Student Portal](https://courses.mlops-club.org) | |
        | [Course Materials Repo](https://github.com/mlops-club/python-on-aws-course.git) | `mlops-club/python-on-aws-course` |
        | [Course Reference Project Repo](https://github.com/mlops-club/cloud-course-project.git) | `mlops-club/cloud-course-project` |
        | [FastAPI Documentation](https://fastapi.tiangolo.com/) | |
        | [Learn to make "badges"](https://shields.io/) | Example: <img alt="Awesome Badge" src="https://img.shields.io/badge/Awesome-😎-blueviolet?style=for-the-badge"> |
        """
        ),
        docs_url="/",  # its easier to find the docs when they live on the base url
        root_path='/prod',
        generate_unique_id_function=custom_generate_unique_id,
    )
    app.state.settings = settings

    app.router.route_class = RouteHandler
    app.include_router(ROUTER)
    app.add_exception_handler(
        exc_class_or_status_code=RequestValidationError,
        handler=handle_pydantic_validation_errors,
    )
    app.middleware("http")(handle_broad_exceptions)
    app.middleware("http")(inject_lambda_context__middleware)

    return app

def custom_generate_unique_id(route: APIRoute):
    """
    Generate prettier `operationId`s in the OpenAPI schema.

    These become the function names in generated client SDKs.
    """
    return f"{route.tags[0]}-{route.name}"


if __name__ == "__main__":
    import uvicorn

    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=8000)
