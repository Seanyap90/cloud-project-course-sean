# files_api_sdk.DefaultApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**delete_file_v1_files_file_path_delete**](DefaultApi.md#delete_file_v1_files_file_path_delete) | **DELETE** /v1/files/{file_path} | Delete File
[**get_file_metadata_v1_files_file_path_head**](DefaultApi.md#get_file_metadata_v1_files_file_path_head) | **HEAD** /v1/files/{file_path} | Get File Metadata
[**get_file_v1_files_file_path_get**](DefaultApi.md#get_file_v1_files_file_path_get) | **GET** /v1/files/{file_path} | Get File
[**list_files_v1_files_get**](DefaultApi.md#list_files_v1_files_get) | **GET** /v1/files | List Files
[**upload_file_v1_files_file_path_put**](DefaultApi.md#upload_file_v1_files_file_path_put) | **PUT** /v1/files/{file_path} | Upload File


# **delete_file_v1_files_file_path_delete**
> object delete_file_v1_files_file_path_delete(file_path)

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
    api_instance = files_api_sdk.DefaultApi(api_client)
    file_path = 'file_path_example' # str |

    try:
        # Delete File
        api_response = api_instance.delete_file_v1_files_file_path_delete(file_path)
        print("The response of DefaultApi->delete_file_v1_files_file_path_delete:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DefaultApi->delete_file_v1_files_file_path_delete: %s\n" % e)
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
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_file_metadata_v1_files_file_path_head**
> object get_file_metadata_v1_files_file_path_head(file_path)

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
    api_instance = files_api_sdk.DefaultApi(api_client)
    file_path = 'file_path_example' # str |

    try:
        # Get File Metadata
        api_response = api_instance.get_file_metadata_v1_files_file_path_head(file_path)
        print("The response of DefaultApi->get_file_metadata_v1_files_file_path_head:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DefaultApi->get_file_metadata_v1_files_file_path_head: %s\n" % e)
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
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_file_v1_files_file_path_get**
> object get_file_v1_files_file_path_get(file_path)

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
    api_instance = files_api_sdk.DefaultApi(api_client)
    file_path = 'file_path_example' # str |

    try:
        # Get File
        api_response = api_instance.get_file_v1_files_file_path_get(file_path)
        print("The response of DefaultApi->get_file_v1_files_file_path_get:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DefaultApi->get_file_v1_files_file_path_get: %s\n" % e)
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
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **list_files_v1_files_get**
> GetFilesResponse list_files_v1_files_get(page_size=page_size, directory=directory, page_token=page_token)

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
    api_instance = files_api_sdk.DefaultApi(api_client)
    page_size = 10 # int |  (optional) (default to 10)
    directory = '' # str |  (optional) (default to '')
    page_token = 'page_token_example' # str |  (optional)

    try:
        # List Files
        api_response = api_instance.list_files_v1_files_get(page_size=page_size, directory=directory, page_token=page_token)
        print("The response of DefaultApi->list_files_v1_files_get:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DefaultApi->list_files_v1_files_get: %s\n" % e)
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

# **upload_file_v1_files_file_path_put**
> PutFileResponse upload_file_v1_files_file_path_put(file_path, file)

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
    api_instance = files_api_sdk.DefaultApi(api_client)
    file_path = 'file_path_example' # str |
    file = None # bytearray |

    try:
        # Upload File
        api_response = api_instance.upload_file_v1_files_file_path_put(file_path, file)
        print("The response of DefaultApi->upload_file_v1_files_file_path_put:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DefaultApi->upload_file_v1_files_file_path_put: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **file_path** | **str**|  |
 **file** | **bytearray**|  |

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
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)
