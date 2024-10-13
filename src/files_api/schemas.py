####################################
# --- Request/response schemas --- #
####################################

from datetime import datetime
from typing import (
    List,
    Optional,
)

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)
from typing_extensions import Self

DEFAULT_GET_FILES_PAGE_SIZE = 10
DEFAULT_GET_FILES_MIN_PAGE_SIZE = 10
DEFAULT_GET_FILES_MAX_PAGE_SIZE = 100
DEFAULT_GET_FILES_DIRECTORY = ""


# read (cRud)
class FileMetadata(BaseModel):
    """Metadata of a file."""

    file_path: str = Field(
        description="The path of the file.",
        json_schema_extra={"example": "path/to/pyproject.toml"},
    )
    last_modified: datetime = Field(description="The last modified date of the file.")
    size_bytes: int = Field(description="The size of the file in bytes.")


# read (cRud)
class GetFilesResponse(BaseModel):
    """Response model for `GET /v1/files`."""

    files: List[FileMetadata]
    next_page_token: Optional[str]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "files": [
                    {
                        "file_path": "path/to/pyproject.toml",
                        "last_modified": "2022-01-01T00:00:00Z",
                        "size_bytes": 512,
                    },
                    {
                        "file_path": "path/to/Makefile",
                        "last_modified": "2022-01-01T00:00:00Z",
                        "size_bytes": 256,
                    },
                ],
                "next_page_token": "next_page_token_example",
            }
        }
    )


# read (cRud)
class GetFilesQueryParams(BaseModel):
    """Query parameters for `GET /v1/files`."""

    page_size: int = Field(
        DEFAULT_GET_FILES_PAGE_SIZE,
        ge=DEFAULT_GET_FILES_MIN_PAGE_SIZE,
        le=DEFAULT_GET_FILES_MAX_PAGE_SIZE,
    )
    directory: str = Field(
        DEFAULT_GET_FILES_DIRECTORY,
        description="The directory to list files from.",
    )
    page_token: Optional[str] = Field(
        None,
        description="The token for the next page.",
    )

    @model_validator(mode="after")
    def check_page_token_is_mutually_exclusive_with_page_size_and_directory(self) -> Self:
        if self.page_token:
            get_files_query_params: dict = self.model_dump(exclude_unset=True)
            page_size_set = "page_size" in get_files_query_params.keys()
            directory_set = "directory" in get_files_query_params.keys()
            if page_size_set or directory_set:
                raise ValueError("page_token is mutually exclusive with page_size and directory")
        return self


# delete (cruD)
class DeleteFileResponse(BaseModel):
    """Response model for `DELETE /v1/files/:file_path`."""

    message: str


# create/update (CrUd)
class PutFileResponse(BaseModel):
    """Response model for `PUT /v1/files/:file_path`."""

    file_path: str = Field(
        description="The path of the file.",
        json_schema_extra={"example": "path/to/pyproject.toml"},
    )
    message: str = Field(description="A message about the operation.")