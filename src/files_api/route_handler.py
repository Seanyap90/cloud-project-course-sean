from typing import Callable

from fastapi import (
    Request,
    Response,
)
from fastapi.routing import APIRoute
from loguru import logger

from files_api.monitoring.logger import (
    log_request_info,
    log_response_info,
)


class RouteHandler(APIRoute):
    """Custom router to add FastAPI context to logs."""

    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def route_handler(request: Request) -> Response:

            request_context = {
                "path": request.url.path,
                "route": self.path,
                "method": request.method,
            }

            logger.configure(extra={"http": request_context})

            log_request_info(request)
            response: Response = await original_route_handler(request)
            log_response_info(response)
            return response

        return route_handler