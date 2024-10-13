import time
import files_api_sdk
from files_api_sdk.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = files_api_sdk.Configuration(
    host = "http://localhost:8000"
)



# Enter a context with an instance of the API client
with files_api_sdk.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = files_api_sdk.FilesApi(api_client)
    file_path = 'file_path_example' # str | 

    try:
        # Delete File
        api_response = api_instance.delete_file_v1_files_file_path_delete(file_path)
        print("The response of FilesApi->delete_file_v1_files_file_path_delete:\n")
        pprint(api_response)
    except ApiException as e:
        print("Exception when calling FilesApi->delete_file_v1_files_file_path_delete: %s\n" % e)
