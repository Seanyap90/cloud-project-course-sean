from fastapi import status
from fastapi.testclient import TestClient


# Constants for testing
TEST_FILE_PATH = "test.txt"
TEST_FILE_CONTENT = b"Hello, world!"
TEST_FILE_CONTENT_TYPE = "text/plain"


def test__upload_file__happy_path(client: TestClient):
    # create a file
    test_file_path = "some/nested/file.txt"
    test_file_content = b"some content"
    test_file_content_type = "text/plain"

    response = client.put(
        f"/v1/files/{test_file_path}",
        files={"file": (test_file_path, test_file_content, test_file_content_type)},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json() == {
        "file_path": test_file_path,
        "message": f"New file uploaded at path: /{test_file_path}",
    }

    # update an existing file
    updated_content = b"updated content"
    response = client.put(
        f"/v1/files/{test_file_path}",
        files={"file": (test_file_path, updated_content, test_file_content_type)},
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {
        "file_path": test_file_path,
        "message": f"Existing file updated at path: /{test_file_path}",
    }


def test_list_files_with_pagination(client: TestClient):
    # Upload files
    for i in range(15):
        client.put(
            f"/v1/files/file{i}.txt",
            files={"file": (f"file{i}.txt", TEST_FILE_CONTENT, TEST_FILE_CONTENT_TYPE)},
        )
    # List files with page size 10
    response = client.get("/v1/files?page_size=10")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert len(data["files"]) == 10
    assert "next_page_token" in data


def test_get_file_metadata(client: TestClient):
    # Upload a file
    client.put(
        f"/v1/files/{TEST_FILE_PATH}",
        files={"file": (TEST_FILE_PATH, TEST_FILE_CONTENT, TEST_FILE_CONTENT_TYPE)},
    )
    # Get file metadata
    response = client.head(f"/v1/files/{TEST_FILE_PATH}")
    assert response.status_code == status.HTTP_200_OK
    headers = response.headers
    assert headers["Content-Type"] == TEST_FILE_CONTENT_TYPE
    assert headers["Content-Length"] == str(len(TEST_FILE_CONTENT))
    assert "Last-Modified" in headers


def test_get_file(client: TestClient):
    # Upload a file
    client.put(
        f"/v1/files/{TEST_FILE_PATH}",
        files={"file": (TEST_FILE_PATH, TEST_FILE_CONTENT, TEST_FILE_CONTENT_TYPE)},
    )
    # Get file
    response = client.get(f"/v1/files/{TEST_FILE_PATH}")
    assert response.status_code == status.HTTP_200_OK
    assert response.content == TEST_FILE_CONTENT


def test_delete_file(client: TestClient):
    # Upload a file
    client.put(
        f"/v1/files/{TEST_FILE_PATH}",
        files={"file": (TEST_FILE_PATH, TEST_FILE_CONTENT, TEST_FILE_CONTENT_TYPE)},
    )

    # Delete file
    response = client.delete(f"/v1/files/{TEST_FILE_PATH}")
    assert response.status_code == status.HTTP_204_NO_CONTENT

    # the file should not be found if it was deleted
    response = client.get(f"/v1/files/{TEST_FILE_PATH}")
    assert response.status_code == status.HTTP_404_NOT_FOUND