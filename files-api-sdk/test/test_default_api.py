# coding: utf-8

"""
    FastAPI

    No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

    The version of the OpenAPI document: 0.1.0
    Generated by OpenAPI Generator (https://openapi-generator.tech)

    Do not edit the class manually.
"""  # noqa: E501


import unittest

from openapi_client.api.default_api import DefaultApi  # noqa: E501


class TestDefaultApi(unittest.TestCase):
    """DefaultApi unit test stubs"""

    def setUp(self) -> None:
        self.api = DefaultApi()

    def tearDown(self) -> None:
        pass

    def test_delete_file_v1_files_file_path_delete(self) -> None:
        """Test case for delete_file_v1_files_file_path_delete

        Delete File  # noqa: E501
        """

    def test_get_file_metadata_v1_files_file_path_head(self) -> None:
        """Test case for get_file_metadata_v1_files_file_path_head

        Get File Metadata  # noqa: E501
        """

    def test_get_file_v1_files_file_path_get(self) -> None:
        """Test case for get_file_v1_files_file_path_get

        Get File  # noqa: E501
        """

    def test_list_files_v1_files_get(self) -> None:
        """Test case for list_files_v1_files_get

        List Files  # noqa: E501
        """

    def test_upload_file_v1_file_file_path_put(self) -> None:
        """Test case for upload_file_v1_file_file_path_put

        Upload File  # noqa: E501
        """


if __name__ == "__main__":
    unittest.main()
