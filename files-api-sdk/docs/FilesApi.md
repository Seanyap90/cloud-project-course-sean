# files_api_sdk.FilesApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**files_delete_file**](FilesApi.md#files_delete_file) | **DELETE** /v1/files/{file_path} | Delete File
[**files_get_file**](FilesApi.md#files_get_file) | **GET** /v1/files/{file_path} | Get File
[**files_get_file_metadata**](FilesApi.md#files_get_file_metadata) | **HEAD** /v1/files/{file_path} | Get File Metadata
[**files_list_files**](FilesApi.md#files_list_files) | **GET** /v1/files | List Files
[**files_upload_file**](FilesApi.md#files_upload_file) | **PUT** /v1/files/{file_path} | Upload File


# **files_delete_file**
> object files_delete_file(file_path)

Delete File

Delete a file.  NOTE: DELETE requests MUST NOT return a body in the response.

### Example

```python
import time
import os
import files_api_sdk
from files_api_sdk.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = files_api_sdk.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with files_api_sdk.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = files_api_sdk.FilesApi(api_client)
    file_path = 'file_path_example' # str |

    try:
        # Delete File
        api_response = api_instance.files_delete_file(file_path)
        print("The response of FilesApi->files_delete_file:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling FilesApi->files_delete_file: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **file_path** | **str**|  |

### Return type

**object**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |
**404** | File not found for the given &#x60;file_path&#x60;. |  -  |
**204** | File deleted successfully. |  -  |
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **files_get_file**
> object files_get_file(file_path)

Get File

Retrieve a file.

### Example

```python
import time
import os
import files_api_sdk
from files_api_sdk.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = files_api_sdk.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with files_api_sdk.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = files_api_sdk.FilesApi(api_client)
    file_path = 'file_path_example' # str |

    try:
        # Get File
        api_response = api_instance.files_get_file(file_path)
        print("The response of FilesApi->files_get_file:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling FilesApi->files_get_file: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **file_path** | **str**|  |

### Return type

**object**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/octet-stream

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | The file content. |  -  |
**404** | File not found for the given &#x60;file_path&#x60;. |  -  |
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **files_get_file_metadata**
> object files_get_file_metadata(file_path)

Get File Metadata

Retrieve file metadata.  Note: by convention, HEAD requests MUST NOT return a body in the response.

### Example

```python
import time
import os
import files_api_sdk
from files_api_sdk.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = files_api_sdk.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with files_api_sdk.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = files_api_sdk.FilesApi(api_client)
    file_path = 'file_path_example' # str |

    try:
        # Get File Metadata
        api_response = api_instance.files_get_file_metadata(file_path)
        print("The response of FilesApi->files_get_file_metadata:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling FilesApi->files_get_file_metadata: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **file_path** | **str**|  |

### Return type

**object**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  * Content-Type - The [MIME type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types) of the file. <br>  * Content-Length - The size of the file in bytes. <br>  * Last-Modified - The last modified date of the file. <br>  |
**404** | File not found for the given &#x60;file_path&#x60;. |  -  |
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **files_list_files**
> GetFilesResponse files_list_files(page_size=page_size, directory=directory, page_token=page_token)

List Files

List files with pagination.

### Example

```python
import time
import os
import files_api_sdk
from files_api_sdk.models.get_files_response import GetFilesResponse
from files_api_sdk.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = files_api_sdk.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with files_api_sdk.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = files_api_sdk.FilesApi(api_client)
    page_size = 10 # int |  (optional) (default to 10)
    directory = '' # str |  (optional) (default to '')
    page_token = 'page_token_example' # str |  (optional)

    try:
        # List Files
        api_response = api_instance.files_list_files(page_size=page_size, directory=directory, page_token=page_token)
        print("The response of FilesApi->files_list_files:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling FilesApi->files_list_files: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **page_size** | **int**|  | [optional] [default to 10]
 **directory** | **str**|  | [optional] [default to &#39;&#39;]
 **page_token** | **str**|  | [optional]

### Return type

[**GetFilesResponse**](GetFilesResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **files_upload_file**
> PutFileResponse files_upload_file(file_path, file_content)

Upload File

Upload a file.

### Example

```python
import time
import os
import files_api_sdk
from files_api_sdk.models.put_file_response import PutFileResponse
from files_api_sdk.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = files_api_sdk.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with files_api_sdk.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = files_api_sdk.FilesApi(api_client)
    file_path = 'file_path_example' # str |
    file_content = None # bytearray |

    try:
        # Upload File
        api_response = api_instance.files_upload_file(file_path, file_content)
        print("The response of FilesApi->files_upload_file:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling FilesApi->files_upload_file: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **file_path** | **str**|  |
 **file_content** | **bytearray**|  |

### Return type

[**PutFileResponse**](PutFileResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: multipart/form-data
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |
**201** | Created |  -  |
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)
