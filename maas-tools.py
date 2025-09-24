"""
FastMCP Server with Portal and Patch API Integration and Unified Authentication
"""

from fastmcp import FastMCP
import requests
import json
import xml.etree.ElementTree as ET
from enum import Enum
from typing import List, Union, Annotated
from pydantic import Field

# API Base URLs Configuration
SERVICES_BASE_URL = "https://iq5services.far360.com"
PORTAL_BASE_URL = "https://iq5portal.far360.com"

# Unified Configuration
CUSTOMER_ID = "45002247"
PORTAL_POLICY_ID = "1274702"
IOS_POLICY_ID = "1274698"
PORTAL_COOKIE = "JSESSIONID=7CC4E097745D2063F94D6CB9B89B90DE; _FBP=Fiberlink"

# Unified Authentication Configuration
AUTH_CONFIG = {
    "billing_id": CUSTOMER_ID,
    "password": "admin@123",
    "username": "45002247_himanshu.gupta1",
    "app_id": "maas360",
    "app_version": "1.0",
    "platform_id": "3",
    "app_access_key": "1AF854C1-8239-453c-96E8-62F89B704F4B"
}

# Create server
mcp = FastMCP("Combined Server")

# Classes
class BinaryFilter(str, Enum):
    YES = "1"
    NO = "0"

class PlatformId(str, Enum):
    ALL = "1"
    IOS = "3"
    ANDROID = "5"

class DistributionType(int, Enum):
    DEVICE = 0
    DEVICE_GROUP = 1
    ALL_DEVICES = 2



def send_slack_notification(message: str) -> str:
    """
    Sends a notification message to a Slack channel using a webhook URL.

    Args:
        message (str): The message to send to Slack.

    Returns:
        str: Result of the Slack API call.
    """
    slack_url = "https://hooks.slack.com/services/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"  # Replace with actual Slack webhook
    headers = {
        "Content-type": "application/json"
    }
    payload = {
        "text": message
    }

    try:
        response = requests.post(slack_url, headers=headers, json=payload)
        response.raise_for_status()
        return f"Slack notification sent successfully. Status Code: {response.status_code}"
    except requests.exceptions.HTTPError as e:
        return f"Slack HTTP error: {str(e)} - Response: {response.text}"
    except requests.exceptions.RequestException as e:
        return f"Slack request failed: {str(e)}"
    except Exception as e:
        return f"Unexpected error while sending Slack notification: {str(e)}"


# Authentication functions
def get_auth_token() -> str:
    """
    Authenticate with the MaaS360 API and get a fresh auth token.
    
    Returns:
        Authentication token string
    
    Raises:
        Exception: If authentication fails
    """
    url = f"{SERVICES_BASE_URL}/auth-apis/auth/1.0/authenticate/{AUTH_CONFIG['billing_id']}"
    
    headers = {
        'Host': 'iq5services.far360.com',
        'Connection': 'keep-alive',
        'Accept-Charset': 'UTF-8',
        'Content-Type': 'application/xml'
    }
    
    xml_payload = f"""<authRequest>
  <maaS360AdminAuth>
    <billingID>{AUTH_CONFIG['billing_id']}</billingID>
    <password>{AUTH_CONFIG['password']}</password>
    <userName>{AUTH_CONFIG['username']}</userName>
    <appID>{AUTH_CONFIG['app_id']}</appID>
    <appVersion>{AUTH_CONFIG['app_version']}</appVersion>
    <platformID>{AUTH_CONFIG['platform_id']}</platformID>
    <appAccessKey>{AUTH_CONFIG['app_access_key']}</appAccessKey>
  </maaS360AdminAuth>
</authRequest>"""
    
    try:
        response = requests.post(url, headers=headers, data=xml_payload)
        response.raise_for_status()
        
        # Parse XML response
        root = ET.fromstring(response.text)
        auth_token = root.find('authToken')
        error_code = root.find('errorCode')
        
        if error_code is not None and error_code.text != '0':
            raise Exception(f"Authentication failed with error code: {error_code.text}")
        
        if auth_token is None:
            raise Exception("No auth token found in response")
        
        return auth_token.text
    
    except requests.exceptions.RequestException as e:
        raise Exception(f"Authentication request failed: {str(e)}")
    except ET.ParseError as e:
        raise Exception(f"Failed to parse authentication response: {str(e)}")

def get_auth_headers() -> dict:
    """Get headers with fresh authentication token."""
    token = get_auth_token()
    return {'Authorization': f'MaaS token="{token}"'}

def get_bearer_auth_headers() -> dict:
    """Get headers with fresh Bearer authentication token."""
    token = get_auth_token()
    return {'Authorization': f'Bearer MaaS token="{token}"'}

def get_maas_app_auth_headers() -> dict:
    """Get headers with maas app authtoken."""
    token = "0d2a988f-82ff-49a6-acb0-407c3528fa13-IhRkgCK"
    return {'Authorization': f'MaaS token="{token}"'}

# Generic publish method
def _publish_policy(policy_id: str) -> str:
    """
    Internal helper function to publish a policy after policy changes.
    
    Args:
        policy_id: The policy ID to publish
    
    Returns:
        A message indicating the success or failure of the policy publication
    """
    publish_url = f"{PORTAL_BASE_URL}/policy-self-service-apis/api/customer/{CUSTOMER_ID}/3.0/policy/{policy_id}/publish"
    
    publish_headers = {
        'X-FBL-UI-LOC': 'en',
        'Accept-Charset': 'UTF',
        'Cookie': PORTAL_COOKIE,
        'Content-Type': 'application/json'
    }
    
    publish_payload = {
        "comments": "",
        "needsPublish": True
    }
    
    try:
        publish_response = requests.post(publish_url, headers=publish_headers, json=publish_payload)
        
        publish_debug_info = {
            "status_code": publish_response.status_code,
            "headers": dict(publish_response.headers),
            "content_length": len(publish_response.content),
            "request_url": publish_response.url,
            "raw_content": publish_response.text[:200] + "..." if len(publish_response.text) > 200 else publish_response.text
        }
        
        publish_response.raise_for_status()
        
        if not publish_response.text.strip():
            return f"Policy published successfully (empty response). Debug info: {json.dumps(publish_debug_info, indent=2)}"
        
        try:
            publish_json_data = publish_response.json()
            return f"Policy published successfully. Response: {json.dumps(publish_json_data, indent=2)}"
        except json.JSONDecodeError:
            return f"Policy published successfully. Non-JSON response: {publish_response.text}"
            
    except requests.exceptions.HTTPError as e:
        return f"Policy publish failed - HTTP Error {publish_response.status_code}: {str(e)}\nResponse: {publish_response.text}"
    except requests.exceptions.RequestException as e:
        return f"Policy publish request failed: {str(e)}"
    except Exception as e:
        return f"Policy publish unexpected error: {str(e)}"


# Tool definitions

@mcp.tool
def echo_tool(text: str) -> str:
    """Echo the input text"""
    return text

@mcp.tool
def get_patch_summaries() -> str:
    """
    Retrieve a list of patch summaries for a customer account by authenticating with the MaaS360 authentication API
    and then calling the patch summary API. The patch summaries contain details about software patches,
    including their severity, category, and the number of devices missing each patch.

    Returns:
        Patch summaries with following information in a tabular format:
            - id: Unique identifier for the patch (integer).
            - name: Name of the patch (e.g., "MS14-043: Security Update for Windows 1").
            - category: Category of the patch (e.g., "Security").
            - severity: Severity level of the patch (e.g., "Critical").
            - kbArticle: Knowledge base article ID (e.g., "Q2978742").
            - patchUrl: URL for the patch (null if unavailable).
            - product: Affected product (e.g., "Windows 1").
            - vendor: Vendor of the product (e.g., "Microsoft Corporation").
            - bulletin: Bulletin ID (e.g., "MS14-043").
            - missingCount: Number of devices missing the patch (integer).
        Or Error or debug info.

    Raises:
        Exception: If the authentication or patch summary API call fails.
    """
    try:
        # Get fresh auth token
        headers = get_maas_app_auth_headers()
        
        url = f"{SERVICES_BASE_URL}/patch-mgmt/apis/2.0/internal/customer/{CUSTOMER_ID}/patch-summary"
        response = requests.get(url, headers=headers, timeout=30)
        # Debug information
        debug_info = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
        }
        response.raise_for_status()  # Raises an HTTPError for bad responses
        # Check if response has content
        if not response.text.strip():
            return f"API returned empty response. Debug info: {json.dumps(debug_info, indent=2)}"
        # Check if patchRecords is present in response
        response_json = response.json()
        if 'patchRecords' not in response_json:
            raise Exception(f"Patch summary API response missing 'patchRecords' key. Debug info: {json.dumps(debug_info, indent=2)}")

        return json.dumps(response_json['patchRecords'], indent=2)
        
    except Exception as e:
        if "Authentication" in str(e):
            return f"Authentication failed: {str(e)}"
        elif hasattr(e, 'response'):
            return f"HTTP Error {e.response.status_code}: {str(e)}\nResponse: {e.response.text}"
        else:
            return f"Request failed: {str(e)}"


@mcp.tool
def get_patch_device_counts(is_missing_patch: str | BinaryFilter | None = BinaryFilter.YES, is_active: str | BinaryFilter | None = BinaryFilter.YES) -> str:
    """
    Retrieve device counts for patches associated with a customer account by calling the patch device count API. 
    The counts are filtered by patch status on device and device active status.
    This tool should be used only when no patchId context is available.

    Args:
        is_missing_patch: Filter by patch status on device (1 for missing, 0 for installed). Defaults to "1" (missing).
        is_active: Filter by device active status (1 for active, 0 for inactive). Defaults to "1" (active).

    Returns:
        A string in the format of dictionary containing:
            - patchDeviceCountList: A list of dictionaries, each with:
                - patchId: The ID of the patch (integer).
                - deviceCount: Number of devices matching the criteria for the patch (integer).
            - resultSize: The total number of patch records in the list (integer).
            - errorCode: 0 for success, non-zero for errors (integer).

    Raises:
        Exception: If the authentication or patch device count API call fails.
    """
    try:
        # Get fresh auth token
        headers = get_maas_app_auth_headers()
        
        url = f"{SERVICES_BASE_URL}/device-apis/patches/1.0/customer/{CUSTOMER_ID}/patch/device/count"
        count_params = {
            'isMissingPatch': (is_missing_patch if isinstance(is_missing_patch, str) else is_missing_patch.value) if is_missing_patch else None,
            'isActive': (is_active if isinstance(is_active, str) else is_active.value) if is_active else None
        }
        count_params = {k: v for k, v in count_params.items() if v is not None}
        response = requests.get(url, headers=headers, params=count_params, timeout=30)
        # Debug information
        debug_info = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
        }
        response.raise_for_status()  # Raises an HTTPError for bad responses
        # Check if response has content
        if not response.text.strip():
            return f"API returned empty response. Debug info: {json.dumps(debug_info, indent=2)}"
        # Check if patchRecords is present in response
        response_json = response.json()
        if 'patchDeviceCountList' not in response_json or 'resultSize' not in response_json or 'errorCode' not in response_json:
            raise Exception("Patch device count API response missing required keys: 'patchDeviceCountList', 'resultSize', or 'errorCode'")

        if response_json['errorCode'] != 0:
            raise Exception(f"Patch device count API failed with error code {response_json['errorCode']}")

        result = {
            'patchDeviceCountList': response_json['patchDeviceCountList'],
            'resultSize': response_json['resultSize'],
            'errorCode': response_json['errorCode']
        }
        return json.dumps(result, indent=2)
        
    except Exception as e:
        if "Authentication" in str(e):
            return f"Authentication failed: {str(e)}"
        elif hasattr(e, 'response'):
            return f"HTTP Error {e.response.status_code}: {str(e)}\nResponse: {e.response.text}"
        else:
            return f"Request failed: {str(e)}"


# @mcp.tool
# def get_device_information(device_id: str) -> str:
#     """
#     Retrieve device information for a customer account by calling the device management API. 

#     Args:
#         device_id: The ID of the device to query (e.g., "17022218").

#     Returns:
#         The string of a dictionary containing:
#             - devices: A list of device dictionaries with key details (deviceId, deviceName, platformName, etc.).
#             - resultSize: The number of devices in the list (integer).
#             - errorCode: 0 for success, non-zero for errors (integer).

#     Raises:
#         ValueError: If device_id is invalid.
#         Exception: If the authentication or device API call fails.
#     """
#     try:
#         if not device_id:
#             raise ValueError("device_id must not be empty")

#         headers = get_maas_app_auth_headers()

#         url = (
#             f"{SERVICES_BASE_URL}/device-mgmt-apis/api/customer/{CUSTOMER_ID}/1.0/devices/?billingId={CUSTOMER_ID}&categories=coreDevice&identifiers={device_id}&identifierType=id"
#         )

#         response = requests.get(url, headers=headers, timeout=30)
#         debug_info = {
#             "status_code": response.status_code,
#             "headers": dict(response.headers),
#             "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
#         }
#         response.raise_for_status()

#         if not response.text.strip():
#             return f"API returned empty response. Debug info: {json.dumps(debug_info, indent=2)}"

#         response_json = response.json()

#         if "data" not in response_json or not response_json["data"]:
#             raise Exception(f"No devices found. Debug info: {json.dumps(debug_info, indent=2)}")

#         devices = []
#         for item in response_json["data"]:
#             attrs = item["attributes"]["categories"].get("coreDevice", {})
#             devices.append({
#                 "deviceId": attrs.get("deviceId"),
#                 "deviceName": attrs.get("deviceName"),
#                 "platformName": attrs.get("platformName"),
#                 "emailAddress": attrs.get("emailAddress"),
#                 "managedStatus": attrs.get("managedStatus"),
#                 "agentType": attrs.get("agentType"),
#                 "active": attrs.get("active")
#             })

#         result = {
#             "devices": devices,
#             "resultSize": len(devices),
#             "errorCode": 0
#         }
#         return json.dumps(result, indent=2)

#     except Exception as e:
#         if "Authentication" in str(e):
#             return f"Authentication failed: {str(e)}"
#         elif hasattr(e, 'response'):
#             return f"HTTP Error {e.response.status_code}: {str(e)}\nResponse: {e.response.text}"
#         else:
#             return f"Request failed: {str(e)}"


@mcp.tool
def get_patch_devices(patch_id: str, platform_id: PlatformId = PlatformId.ALL, is_missing_patch: str | BinaryFilter | None = None, is_active: str | BinaryFilter | None = None) -> str:
    """
    Retrieve a list of device IDs for a customer account that match specific patch criteria by calling the device patch API. 
    The devices are filtered by platform, patch status, and active status.

    Args:
        patch_id: The ID of the patch to query (e.g., "18658665").
        platform_id: The platform to filter devices (1 for all, 3 for iOS, 5 for Android). Defaults to "1" (all).
        is_missing_patch: Filter by patch status (1 for missing, 0 for installed). Optional, defaults to None (no filter).
        is_active: Filter by device active status (1 for active, 0 for inactive). Optional, defaults to None (no filter).

    Returns:
        The string of a dictionary containing:
            - devices: A list of device IDs (integers) matching the criteria.
            - resultSize: The number of devices in the list (integer).
            - errorCode: 0 for success, non-zero for errors (integer).

    Raises:
        ValueError: If patch_id is invalid.
        Exception: If the authentication or device patch API call fails.
    """
    try:
        # Get fresh auth token
        headers = get_maas_app_auth_headers()
        
        url = f"{SERVICES_BASE_URL}/device-apis/patches/1.0/customer/{CUSTOMER_ID}/devices/patch/{patch_id}"
        response = requests.get(url, headers=headers, timeout=30)
        # Debug information
        debug_info = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
        }
        response.raise_for_status()  # Raises an HTTPError for bad responses
        # Check if response has content
        if not response.text.strip():
            return f"API returned empty response. Debug info: {json.dumps(debug_info, indent=2)}"
        # Check if devices is present in response
        response_json = response.json()
        if 'devices' not in response_json:
            raise Exception(f"Patch summary API response missing 'devices' key. Debug info: {json.dumps(debug_info, indent=2)}")
        
        size = 50
        patch_records_50_batch = [response_json['devices'][i:i + size] for i in range(0, len(response_json['devices']), size)]

        devices_result = []
        for batch_50 in patch_records_50_batch:
            device_ids = ",".join(map(str, batch_50))

            headers = get_maas_app_auth_headers()

            url = (
                f"{SERVICES_BASE_URL}/device-mgmt-apis/api/customer/{CUSTOMER_ID}/1.0/devices/?billingId={CUSTOMER_ID}&categories=coreDevice&identifiers={device_ids}&identifierType=id"
            )

            response = requests.get(url, headers=headers, timeout=30)
            debug_info = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
            }
            response.raise_for_status()

            if not response.text.strip():
                return f"API returned empty response. Debug info: {json.dumps(debug_info, indent=2)}"

            response_json = response.json()

            if "data" not in response_json or not response_json["data"]:
                raise Exception(f"No devices found. Debug info: {json.dumps(debug_info, indent=2)}")

            devices = []
            for item in response_json["data"]:
                attrs = item["attributes"]["categories"].get("coreDevice", {})
                devices.append({
                    "deviceId": attrs.get("deviceId"),
                    "deviceName": attrs.get("deviceIdentifier"),
                    "platformName": attrs.get("platformName"),
                })

            result = {
                "devices": devices,
                "resultSize": len(devices),
                "errorCode": 0
            }
            devices_result.append(result)

        return json.dumps(devices_result, indent=2)
        
    except Exception as e:
        if "Authentication" in str(e):
            return f"Authentication failed: {str(e)}"
        elif hasattr(e, 'response'):
            return f"HTTP Error {e.response.status_code}: {str(e)}\nResponse: {e.response.text}"
        else:
            return f"Request failed: {str(e)}"


@mcp.tool
def get_patch_info_for_deviceId(device_id: str, is_missing_patch: str | None = None, is_security_patch: str | None = None) -> str:
    """
    Retrieve patch information for a given device from the MaaS360 Device Patch API.

    Args:
        device_id: The unique identifier of the device (e.g., "n3bk").
        is_missing_patch: "1" for missing patches, "0" for installed, or None (no filter).
        is_security_patch: "1" to include security patches, "0" to exclude, or None (no filter).

    Returns:
        An XML string from the API, e.g.:
            <patchInformations>
                <count>...</count>
                <maas360DeviceID>...</maas360DeviceID>
                ...
            </patchInformations>

    Raises:
        ValueError: If device_id is invalid.
        Exception: If the API call fails.
    """
    try:
        if not device_id:
            raise ValueError("device_id cannot be empty")

        # Get fresh auth token
        headers = get_auth_headers()
        headers["Content-Type"] = "application/json"

        # Build query params
        params = {"deviceId": device_id}
        if is_missing_patch is not None:
            params["missingPatches"] = is_missing_patch
        if is_security_patch is not None:
            params["securityPatches"] = is_security_patch

        url = f"{SERVICES_BASE_URL}/device-apis/devices/1.0/getPatchInformation/{CUSTOMER_ID}"
        response = requests.get(url, headers=headers, params=params, timeout=30)

        debug_info = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
        }

        response.raise_for_status()

        if not response.text.strip():
            return f"API returned empty response. Debug info: {json.dumps(debug_info, indent=2)}"

        # The API returns XML, so just return it directly
        return response.text

    except Exception as e:
        if "Authentication" in str(e):
            return f"Authentication failed: {str(e)}"
        elif hasattr(e, "response"):
            return f"HTTP Error {e.response.status_code}: {str(e)}\nResponse: {e.response.text}"
        else:
            return f"Request failed: {str(e)}"


@mcp.tool(
    name="distribute_patches",
    description="Distribute one or more patches to a customer account",
    
)
def distribute_patches(
    patch_ids: Annotated[Union[List[int], str], Field(description="List of patch IDs. Should always pass a Json Array of integers")], 
    distributionStartDate: str, 
    targetId: int) -> str:
    """
    Distribute one or more patches to a customer account using the patch management API. 
    Returns the distribution IDs assigned to the request if successful.

    Args:
        patch_ids (List[int]): A list of patch IDs to be distributed to the customer account.
            Example: [12345, 67890]
        distributionStartDate (str): The scheduled date when patch distribution begins. The date is in the format of MM/dd/yyyy.
        targetId (int): The group identifier of the device group user wants to distribute the patch to.

    Returns:
        str: A JSON-formatted string containing the distributionIds assigned by the API.
        If the API response is empty or missing required keys, an error message or debug 
        information will be returned instead.

    Raises:
        Exception: If the API response does not include the required keys ('status', 'reason', 
        'distributionIds') or if the distribution fails with an error status.
        AuthenticationError: If authentication fails while generating the request.
        HTTPError: If the request fails with a non-2xx response.

    Example Prompts:
        - "Distribute patch 12345 to my account" -> patch_ids=[12345]
        - "Push patches 12345 and 67890 to the servers" -> patch_ids=[12345, 67890]
    """
    if isinstance(patch_ids, str):
        # split on commas, strip spaces, convert to int
        patch_ids = [int(x.strip()) for x in patch_ids.replace("[", "").replace("]", "").split(",") if x.strip()]

    try:
        # Get fresh auth token
        headers = get_maas_app_auth_headers()
        
        url = f"{SERVICES_BASE_URL}/patch-mgmt/apis/2.0/internal/customer/{CUSTOMER_ID}/distribute"
        payload = {
            "distributePatch": {
                "patchIds": patch_ids,
                "distributionType": 1,
                "targetId": targetId,
                "expiryInDays": 90,
                "distributionStartDate": distributionStartDate
            },
            "randomization": {
                "type": "duration",
                "unit": "hours",
                "value": 1,
                "start": -1
            },
            "restartSettings": {
                "restartRequired": True,
                "snoozeEnabled": "true",
                "snoozeOption": 300
            },
            "createUser": f"{AUTH_CONFIG['username']}",
            "updateUser": f"{AUTH_CONFIG['username']}"
        }

        response = requests.post(url, headers=headers, json=payload, timeout=30)
        # Debug information
        debug_info = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
        }
        response.raise_for_status()  # Raises an HTTPError for bad responses
        # Check if response has content
        if not response.text.strip():
            return f"API returned empty response. Debug info: {json.dumps(debug_info, indent=2)}"
        # Check if patchRecords is present in response
        response_json = response.json()
        if 'status' not in response_json or 'reason' not in response_json or 'distributionIds' not in response_json:
            raise Exception("Patch distribution API response missing required keys: 'status', 'reason', or 'distributionIds'")

        if response_json['status'] != "SUCCESS":
            raise Exception(f"Patch distribution failed with status {response_json['status']} and reason {response_json.get('reason', 'N/A')}")

        send_slack_notification(f"👋 Hi, I'm your MaaS Agent! ✅ Your patch is successfully scheduled for distribution on 💻 device group {targetId} . 🗓️ Scheduled Date: {distributionStartDate} ")
        result = response_json['distributionIds']
        return json.dumps(result, indent=2)
        
    except Exception as e:
        if "Authentication" in str(e):
            return f"Authentication failed: {str(e)}"
        elif hasattr(e, 'response'):
            return f"HTTP Error {e.response.status_code}: {str(e)}\nResponse: {e.response.text}"
        else:
            return f"Request failed: {str(e)}"


@mcp.tool
def fetch_distribution_status(distribution_id: str ) -> str:
    """
    Fetch the status of a patch distribution for a customer account using the distribution status API. 
    Returns the patchDistributionStatusList or a message if empty.

    Args:
        distribution_id: The distribution ID from the distribute_patches tool (e.g., 53687).

    Returns:
        A list containing the patchDistributionStatusList from the API response. If the list is empty,
        returns ["No update on the status yet"].

    Raises:
        ValueError: If distribution_id are invalid.

    Example Prompts:
        - "Get the status of distribution 53687" ->
            distribution_id=53687
    """
    try:
        # Get fresh auth token
        headers = get_maas_app_auth_headers()
        
        url = f"{SERVICES_BASE_URL}/patch-mgmt/apis/2.0/internal/customer/{CUSTOMER_ID}/distribution/{distribution_id}/status"

        response = requests.get(url, headers=headers, timeout=30)
        # Debug information
        debug_info = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
        }
        response.raise_for_status()  # Raises an HTTPError for bad responses
        # Check if response has content
        if not response.text.strip():
            return f"API returned empty response. Debug info: {json.dumps(debug_info, indent=2)}"
        # Check if patchRecords is present in response
        response_json = response.json()
        if 'patchDistributionStatusList' not in response_json:
            raise Exception("Distribution status API response missing required key: 'patchDistributionStatusList'")
        if 'errorCode' not in response_json or response_json['errorCode'] != 0:
            raise Exception(f"Distribution status API failed with error code {response_json.get('errorCode', 'N/A')}")

        result = response_json['patchDistributionStatusList']
        return json.dumps(result, indent=2)
        
    except Exception as e:
        if "Authentication" in str(e):
            return f"Authentication failed: {str(e)}"
        elif hasattr(e, 'response'):
            return f"HTTP Error {e.response.status_code}: {str(e)}\nResponse: {e.response.text}"
        else:
            return f"Request failed: {str(e)}"


@mcp.tool
def get_customer_groups() -> str:
    """
    Get All customer groups which includes device groups and user groups from the MaaS360 API
    
    Returns:
        JSON response from the API as a string
    """
    try:
        # Get fresh auth token
        headers = get_auth_headers()
        
        url = f"{SERVICES_BASE_URL}/group-apis/group/1.0/groups/customer/{CUSTOMER_ID}"

        response = requests.get(url, headers=headers)

        # Debug information
        debug_info = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
        }

        response.raise_for_status()  # Raises an HTTPError for bad responses

        # Check if response has content
        if not response.text.strip():
            return f"API returned empty response. Debug info: {json.dumps(debug_info, indent=2)}"

        # Try to parse as JSON
        try:
            json_data = response.json()
            return json.dumps(json_data, indent=2)
        except json.JSONDecodeError:
            # If not JSON, return raw text response
            return f"Non-JSON response received:\n{response.text}\n\nDebug info: {json.dumps(debug_info, indent=2)}"

    except Exception as e:
        if "Authentication" in str(e):
            return f"Authentication failed: {str(e)}"
        elif hasattr(e, 'response'):
            return f"HTTP Error {e.response.status_code}: {str(e)}\nResponse: {e.response.text}"
        else:
            return f"Request failed: {str(e)}"


@mcp.tool
def enable_eps_advance_protection_policy() -> str:
    """
    Enable the Endpoint Security Policy (EPS) advanced protection under policy section.
    
    This function enables advanced protection in the EPS policy configuration, then
    performs admin credential authentication, and finally publishes the policy.
        
    Returns:
        A message indicating the success or failure of the EPS advanced protection enablement, authentication, and publishing
    """
    url = f"{PORTAL_BASE_URL}/policy-self-service-apis/api/customer/{CUSTOMER_ID}/3.0/policy/{PORTAL_POLICY_ID}/values"

    headers = {
        'X-FBL-UI-LOC': 'en',
        'Accept-Charset': 'UTF',
        'Cookie': PORTAL_COOKIE,
        'Content-Type': 'application/json'
    }

    # Prepare request payload
    payload = {
        "event": "SAVE",
        "comments": "Enabling EPS advanced protection via API",
        "save": {
            "validate": False,
            "values": {
                "mtd.mblthrtdefense.adv.protection": True
            }
        }
    }

    try:
        response = requests.put(url, headers=headers, json=payload)

        # Debug information
        debug_info = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "request_url": response.url,
            "request_payload": payload,
            "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
        }

        response.raise_for_status()  # Raises an HTTPError for bad responses

        # If policy update was successful (200 status), proceed with admin credential authentication
        if response.status_code == 200:
            auth_result = _authenticate_admin_credential()
            
            # If authentication was successful (indicated by not containing "failed"), proceed with publishing
            if "failed" not in auth_result.lower():
                publish_result = _publish_policy(PORTAL_POLICY_ID)
                
                # Check if response has content
                if not response.text.strip():
                    return f"EPS policy enabled successfully. Admin authentication: {auth_result}. Policy publish: {publish_result}. Debug info: {json.dumps(debug_info, indent=2)}"

                # Try to parse as JSON
                try:
                    json_data = response.json()
                    send_slack_notification("👋 Hi, I’m your MaaS Agent! 🚀 Just wanted to let you know that the EPS Policy has been published successfully. ✅ Everything is up and running!")
                    return f"EPS policy enabled successfully. Admin authentication: {auth_result}. Policy publish: {publish_result}. Response: {json.dumps(json_data, indent=2)}"
                except json.JSONDecodeError:
                    # If not JSON, return raw text response
                    return f"EPS policy enabled. Admin authentication: {auth_result}. Policy publish: {publish_result}. Non-JSON response received:\n{response.text}\n\nDebug info: {json.dumps(debug_info, indent=2)}"
            else:
                return f"EPS policy enabled successfully, but admin authentication failed: {auth_result}. Policy not published."
        else:
            return f"EPS policy update completed with status {response.status_code}. Debug info: {json.dumps(debug_info, indent=2)}"

    except requests.exceptions.HTTPError as e:
        return f"HTTP Error {response.status_code}: {str(e)}\nResponse: {response.text}\nDebug info: {json.dumps(debug_info, indent=2)}"
    except requests.exceptions.RequestException as e:
        return f"Request failed: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"

@mcp.tool
def assign_policy_to_group(group_id: str) -> str:
    """
    Assign the Endpoint Security Policy to a device group.
    
    This function assigns the Endpoint Security Policy to a device group.
    
    Args:
        group_id: The identifier of the group to assign the policy to
        
    Returns:
        A message indicating the success or failure of the policy change
    """
    try:
        # Get fresh auth token
        auth_headers = get_auth_headers()
        
        url = f"{SERVICES_BASE_URL}/group-apis/group/1.0/changeGroupPolicy/customer/{CUSTOMER_ID}"

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            **auth_headers
        }

        # Prepare request payload
        payload = {
            "changePolicyRequest": {
                "groupId": group_id,
                "policyRequest": {
                    "policyType": "MTD",
                    "policyName": ["Endpoint Security Policy"]
                }
            }
        }

        response = requests.post(url, headers=headers, json=payload)

        # Debug information
        debug_info = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "request_url": response.url,
            "request_payload": payload,
            "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
        }

        response.raise_for_status()  # Raises an HTTPError for bad responses

        # Check if response has content
        if not response.text.strip():
            return f"Policy change completed successfully. Debug info: {json.dumps(debug_info, indent=2)}"

        # Try to parse as JSON
        try:
            json_data = response.json()
            return f"Policy change successful. Response: {json.dumps(json_data, indent=2)}"
        except json.JSONDecodeError:
            # If not JSON, return raw text response
            return f"Policy change completed. Non-JSON response received:\n{response.text}\n\nDebug info: {json.dumps(debug_info, indent=2)}"

    except Exception as e:
        if "Authentication" in str(e):
            return f"Authentication failed: {str(e)}"
        elif hasattr(e, 'response'):
            return f"HTTP Error {e.response.status_code}: {str(e)}\nResponse: {e.response.text}\nDebug info: {json.dumps(debug_info, indent=2)}"
        else:
            return f"Request failed: {str(e)}"

@mcp.tool
def get_devices_in_group(device_group_id: str) -> str:
    """
    Get devices present in a specific group from the MaaS360 API
    
    Args:
        device_group_id: The device group ID to fetch devices for
    
    Returns:
        JSON response from the API as a string
    """
    try:
        # Get fresh auth token
        headers = get_auth_headers()
        
        url = f"{SERVICES_BASE_URL}/device-apis/devices/1.0/searchByDeviceGroup/{CUSTOMER_ID}"

        params = {
            'deviceGroupId': device_group_id,
            'pageSize': 25
        }

        response = requests.get(url, headers=headers, params=params)

        # Debug information
        debug_info = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "request_url": response.url,
            "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
        }

        response.raise_for_status()  # Raises an HTTPError for bad responses

        # Check if response has content
        if not response.text.strip():
            return f"API returned empty response. Debug info: {json.dumps(debug_info, indent=2)}"

        # Try to parse as JSON
        try:
            json_data = response.json()
            return json.dumps(json_data, indent=2)
        except json.JSONDecodeError:
            # If not JSON, return raw text response
            return f"Non-JSON response received:\n{response.text}\n\nDebug info: {json.dumps(debug_info, indent=2)}"

    except Exception as e:
        if "Authentication" in str(e):
            return f"Authentication failed: {str(e)}"
        elif hasattr(e, 'response'):
            return f"HTTP Error {e.response.status_code}: {str(e)}\nResponse: {e.response.text}"
        else:
            return f"Request failed: {str(e)}"

@mcp.tool
def create_device_group(group_name: str) -> str:
    """
    Create a device group with standard configuration.
    
    Args:
        group_name: Name of the device group
    
    Returns:
        JSON response from the API as a string
    """
    try:
        # Get fresh auth token
        auth_headers = get_auth_headers()
        
        url = f"{SERVICES_BASE_URL}/group-apis/group/2.0/deviceGroups/customer/{CUSTOMER_ID}"
        headers = {
            'Content-Type': 'application/json',
            **auth_headers
        }
        # Prepare request payload with hardcoded values
        payload = {
            "groupName": group_name,
            "groupDescription": "Device Group",    # Hardcoded
            "deviceStatus": "Active Devices",      # Hardcoded
            "lastReported": "All Records",         # Hardcoded
            "criteriaOperator": "Any Condition (OR)",
            "deviceTypes": [
                "Smartphones",
                "Tablets"
            ],
            "conditions": [
                {
                    "category": "Users",
                    "attribute": "Username",
                    "criteria": "Begins With",
                    "value1": "sto"
                }
            ]
        }
        response = requests.post(url, headers=headers, json=payload)
        # Debug information
        debug_info = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "request_url": response.url,
            "request_payload": payload,
            "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
        }
        response.raise_for_status()  # Raises an HTTPError for bad responses
        # Check if response has content
        if not response.text.strip():
            return f"API returned empty response. Debug info: {json.dumps(debug_info, indent=2)}"
        # Try to parse as JSON
        try:
            json_data = response.json()
            return json.dumps(json_data, indent=2)
        except json.JSONDecodeError:
            # If not JSON, return raw text response
            return f"Non-JSON response received:\n{response.text}\n\nDebug info: {json.dumps(debug_info, indent=2)}"
    except Exception as e:
        if "Authentication" in str(e):
            return f"Authentication failed: {str(e)}"
        elif hasattr(e, 'response'):
            return f"HTTP Error {e.response.status_code}: {str(e)}\nResponse: {e.response.text}\nDebug info: {json.dumps(debug_info, indent=2)}"
        else:
            return f"Request failed: {str(e)}"

@mcp.tool
def create_device_group_for_IT_admins(group_name: str) -> str:
    """
    Create an device group for devices with Bussiness Unit attribute as "IT".
    
    Args:
        group_name: Name of the device group
    
    Returns:
        JSON response from the API as a string
    """
    try:
        # Get fresh auth token
        auth_headers = get_auth_headers()
        
        url = f"{SERVICES_BASE_URL}/group-apis/group/2.0/deviceGroups/customer/{CUSTOMER_ID}"
        headers = {
            'Content-Type': 'application/json',
            **auth_headers
        }
        # Prepare request payload with hardcoded values
        payload = {
            "groupName": group_name,
            "groupDescription": "Device Group",
            "deviceStatus": "All Devices",              
            "lastReported": "Today",                    
            "criteriaOperator": "All Conditions (AND)", 
            "conditions": [
                {
                    "category": "Custom Attributes",   
                    "attribute": "BU",                  
                    "criteria": "Equal To",            
                    "value1": "IT"                      
                }
            ]
        }

        response = requests.post(url, headers=headers, json=payload)
        # Debug information
        debug_info = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "request_url": response.url,
            "request_payload": payload,
            "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
        }
        response.raise_for_status()  # Raises an HTTPError for bad responses
        # Check if response has content
        if not response.text.strip():
            return f"API returned empty response. Debug info: {json.dumps(debug_info, indent=2)}"
        # Try to parse as JSON
        try:
            json_data = response.json()
            return json.dumps(json_data, indent=2)
        except json.JSONDecodeError:
            # If not JSON, return raw text response
            return f"Non-JSON response received:\n{response.text}\n\nDebug info: {json.dumps(debug_info, indent=2)}"
    except Exception as e:
        if "Authentication" in str(e):
            return f"Authentication failed: {str(e)}"
        elif hasattr(e, 'response'):
            return f"HTTP Error {e.response.status_code}: {str(e)}\nResponse: {e.response.text}\nDebug info: {json.dumps(debug_info, indent=2)}"
        else:
            return f"Request failed: {str(e)}"


@mcp.tool
def create_device_group_for_others(group_name: str) -> str:
    """
    Create an device group for devices with Bussiness Unit attribute as "OTHERS".
    
    Args:
        group_name: Name of the device group
    
    Returns:
        JSON response from the API as a string
    """
    try:
        # Get fresh auth token
        auth_headers = get_auth_headers()
        
        url = f"{SERVICES_BASE_URL}/group-apis/group/2.0/deviceGroups/customer/{CUSTOMER_ID}"
        headers = {
            'Content-Type': 'application/json',
            **auth_headers
        }
        # Prepare request payload with hardcoded values
        payload = {
            "groupName": group_name,
            "groupDescription": "Device Group",
            "deviceStatus": "All Devices",
            "lastReported": "Today",
            "criteriaOperator": "All Conditions (AND)",
            "conditions": [
                {
                    "category": "Custom Attributes",
                    "attribute": "BU",
                    "criteria": "Equal To",
                    "value1": "OTHERS"
                }
            ]
        }

        response = requests.post(url, headers=headers, json=payload)
        # Debug information
        debug_info = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "request_url": response.url,
            "request_payload": payload,
            "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
        }
        response.raise_for_status()  # Raises an HTTPError for bad responses
        # Check if response has content
        if not response.text.strip():
            return f"API returned empty response. Debug info: {json.dumps(debug_info, indent=2)}"
        # Try to parse as JSON
        try:
            json_data = response.json()
            return json.dumps(json_data, indent=2)
        except json.JSONDecodeError:
            # If not JSON, return raw text response
            return f"Non-JSON response received:\n{response.text}\n\nDebug info: {json.dumps(debug_info, indent=2)}"
    except Exception as e:
        if "Authentication" in str(e):
            return f"Authentication failed: {str(e)}"
        elif hasattr(e, 'response'):
            return f"HTTP Error {e.response.status_code}: {str(e)}\nResponse: {e.response.text}\nDebug info: {json.dumps(debug_info, indent=2)}"
        else:
            return f"Request failed: {str(e)}"


@mcp.tool
def enable_ios_passcode_policy() -> str:
    """
    Enable iOS passcode policy requirements including requiring passcode, requiring passcode on device,
    and setting minimum passcode length to 6 characters. After successful policy update, authenticates
    the admin credentials and publishes the policy.
    
    This function enables iOS passcode security settings in the policy configuration, then
    performs admin credential authentication, and finally publishes the policy.
        
    Returns:
        A message indicating the success or failure of the iOS passcode policy enablement, authentication, and publishing
    """
    url = f"{PORTAL_BASE_URL}/policy-self-service-apis/api/customer/{CUSTOMER_ID}/3.0/policy/{IOS_POLICY_ID}/values"

    headers = {
        'X-FBL-UI-LOC': 'en',
        'Accept-Charset': 'UTF',
        'Cookie': PORTAL_COOKIE,
        'Content-Type': 'application/json'
    }

    # Prepare request payload
    payload = {
        "event": "SAVE",
        "comments": None,
        "save": {
            "validate": False,
            "values": {
                "iOS.requirePasscode": True,
                "iOS.requirePasscodeOnDevice": True,
                "iOS.minimumPasscodeLength": "N_6"
            }
        }
    }

    try:
        response = requests.put(url, headers=headers, json=payload)

        # Debug information
        debug_info = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "request_url": response.url,
            "request_payload": payload,
            "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
        }

        response.raise_for_status()  # Raises an HTTPError for bad responses

        # If policy update was successful (200 status), proceed with admin credential authentication
        if response.status_code == 200:
            auth_result = _authenticate_admin_credential()
            
            # If authentication was successful (indicated by not containing "failed"), proceed with publishing
            if "failed" not in auth_result.lower():
                publish_result = _publish_policy(IOS_POLICY_ID)
                
                # Check if response has content
                if not response.text.strip():
                    return f"iOS passcode policy enabled successfully. Admin authentication: {auth_result}. Policy publish: {publish_result}. Debug info: {json.dumps(debug_info, indent=2)}"

                # Try to parse as JSON
                try:
                    json_data = response.json()
                    send_slack_notification("👋 Hi, I’m your MaaS Agent! ✅ Your iOS Passcode Policy has been enabled successfully. 🔐 You're all set! ")
                    return f"iOS passcode policy enabled successfully. Admin authentication: {auth_result}. Policy publish: {publish_result}. Response: {json.dumps(json_data, indent=2)}"
                except json.JSONDecodeError:
                    # If not JSON, return raw text response
                    return f"iOS passcode policy enabled. Admin authentication: {auth_result}. Policy publish: {publish_result}. Non-JSON response received:\n{response.text}\n\nDebug info: {json.dumps(debug_info, indent=2)}"
            else:
                return f"iOS passcode policy enabled successfully, but admin authentication failed: {auth_result}. Policy not published."
        else:
            return f"iOS passcode policy update completed with status {response.status_code}. Debug info: {json.dumps(debug_info, indent=2)}"

    except requests.exceptions.HTTPError as e:
        return f"HTTP Error {response.status_code}: {str(e)}\nResponse: {response.text}\nDebug info: {json.dumps(debug_info, indent=2)}"
    except requests.exceptions.RequestException as e:
        return f"Request failed: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"


@mcp.tool
def get_devices_with_bad_battery_health(page_number: int = 1, page_size: int = 10) -> str:
    """
    Retrieve devices with bad battery health from the MaaS360 Battery Health Dashboard.
    
    This tool fetches devices that have battery health issues such as Cold, Dead,
    non-genuine, Overheat, Overvoltage, or service-recommended status.
    
    Args:
        page_number: The page number to retrieve (default: 1)
        page_size: The number of results per page (default: 10)
    
    Returns:
        JSON response containing devices with bad battery health
    """
    try:
        url = f"{PORTAL_BASE_URL}/reports-apis/api/customer/{CUSTOMER_ID}/1.0/reports/dashboardData/BATTERY_HEALTH_DASHBOARD/report/BATTERY_HEALTH_REPORT"
        
        # Query parameters for bad battery health
        params = {
            "pn": page_number,
            "ps": page_size,
            "srchStr": "",
            "bh": ["Cold", "Dead", "non-genuine", "Overheat", "Overvoltage", "service-recommended"]
        }
        
        headers = {
            'X-FBL-UI-LOC': 'en',
            'Accept-Charset': 'UTF',
            'Cookie': PORTAL_COOKIE,
            'Content-Type': 'application/json'
        }
        
        response = requests.get(url, headers=headers, params=params)
        
        # Debug information
        debug_info = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "request_url": response.url,
            "raw_content": response.text[:500] + "..." if len(response.text) > 500 else response.text
        }
        
        response.raise_for_status()  # Raises an HTTPError for bad responses
        
        # Check if response has content
        if not response.text.strip():
            return f"API returned empty response. Debug info: {json.dumps(debug_info, indent=2)}"
        
        # Try to parse as JSON
        try:
            json_data = response.json()
            return json.dumps(json_data, indent=2)
        except json.JSONDecodeError:
            # If not JSON, return raw text response
            return f"Non-JSON response received:\n{response.text}\n\nDebug info: {json.dumps(debug_info, indent=2)}"
            
    except requests.exceptions.HTTPError as e:
        return f"HTTP Error {response.status_code}: {str(e)}\nResponse: {response.text}"
    except requests.exceptions.RequestException as e:
        return f"Request failed: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"


# Updated _authenticate_admin_credential function
def _authenticate_admin_credential() -> str:
    """
    Internal helper function to authenticate admin credentials after policy changes.
    
    Returns:
        A message indicating the success or failure of the admin credential authentication
    """
    auth_url = f"{PORTAL_BASE_URL}/portal-manager-apis/api/customer/{CUSTOMER_ID}/3.0/adminCredential/authenticate"
    
    auth_headers = {
        'X-FBL-UI-LOC': 'en',
        'Accept-Charset': 'UTF',
        'Cookie': PORTAL_COOKIE,
        'Content-Type': 'application/json'
    }
    
    auth_payload = {
        "selected": "ALWAYS",
        "password": AUTH_CONFIG['password']
    }
    
    try:
        auth_response = requests.post(auth_url, headers=auth_headers, json=auth_payload)
        
        auth_debug_info = {
            "status_code": auth_response.status_code,
            "headers": dict(auth_response.headers),
            "content_length": len(auth_response.content),
            "request_url": auth_response.url,
            "raw_content": auth_response.text[:200] + "..." if len(auth_response.text) > 200 else auth_response.text
        }
        
        auth_response.raise_for_status()
        
        if not auth_response.text.strip():
            return f"Authentication successful (empty response). Debug info: {json.dumps(auth_debug_info, indent=2)}"
        
        try:
            auth_json_data = auth_response.json()
            return f"Authentication successful. Response: {json.dumps(auth_json_data, indent=2)}"
        except json.JSONDecodeError:
            return f"Authentication completed. Non-JSON response: {auth_response.text}"
            
    except requests.exceptions.HTTPError as e:
        return f"Authentication failed - HTTP Error {auth_response.status_code}: {str(e)}\nResponse: {auth_response.text}"
    except requests.exceptions.RequestException as e:
        return f"Authentication request failed: {str(e)}"
    except Exception as e:
        return f"Authentication unexpected error: {str(e)}"


@mcp.resource("echo://static")
def echo_resource() -> str:
    return "Echo!"

@mcp.resource("echo://{text}")
def echo_template(text: str) -> str:
    """Echo the input text"""
    return f"Echo: {text}"

@mcp.prompt("echo")
def echo_prompt(text: str) -> str:
    return text