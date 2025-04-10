import os
import dotenv
import requests
import json

# Load environment variables
dotenv.load_dotenv()
AF_API_KEY = os.getenv("AF_API_KEY")
AF_BASE_URL = os.getenv("AF_BASE_URL")

# Headers for AttackForge API authentication
HEADERS_AF = {
    "X-SSAPI-KEY": AF_API_KEY,
    "Content-Type": "application/json",
}

HEADERS_AF_PLAIN = {"X-SSAPI-KEY": AF_API_KEY, "Accept": "application/json"}


# URL Builders
def build_url(endpoint, query=None, skip_count=None):
    url = f"{AF_BASE_URL}/{endpoint}"
    # Check if the endpoint already contains query parameters
    has_params = "?" in endpoint

    # Add query if present
    if query:
        url += "&" if has_params else "?"
        url += f"q={query}"

    # Add skip_count if present
    if skip_count is not None:
        url += "&" if (has_params or query) else "?"
        url += f"skip={skip_count}"

    return url


# verify AttackForge access
def verify_af_access():
    endpoint = "users"
    url = build_url(endpoint)
    try:
        fetch_af(url)
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False


# Helper Functions for GET, POST, PUT requests
def fetch_af(url):
    response = requests.get(url, headers=HEADERS_AF)
    return response.json()


def post_data(url, payload):
    response = requests.post(url, headers=HEADERS_AF, json=payload)
    return response.json()


def put_data(url, payload):
    response = requests.put(url, headers=HEADERS_AF, json=payload)
    return response.json()


# upload evidence to the AF vuln
def upload_evidence(vuln_id, file_path, file_name, file_type):
    url = build_url(f"vulnerability/{vuln_id}/evidence")
    files = {"file": (file_name, open(file_path, "rb"), file_type)}
    data = {"description": file_name}
    response = requests.post(url, headers=HEADERS_AF_PLAIN, files=files, data=data)
    return response.json()


# API Functions
def send_email_af(payload):
    url = build_url("email")
    response = post_data(url, payload)
    response_json = json.dumps(response)
    return response_json


def get_asset_id(endpoint, query):
    url = build_url(endpoint, query=query)
    response = fetch_af(url)
    return response["assets"][0]["id"]


def get_asset_id_ip(endpoint, query):
    return get_asset_id(endpoint, query)


def export_project_data(project_id):
    endpoint = f"project/{project_id}/report/raw?excludeBinaries=true"
    url = build_url(endpoint)
    response = fetch_af(url)
    response_json = json.dumps(response)
    return response_json


def get_asset_id_list(endpoint, query):
    url = build_url(endpoint, query=query)
    response = fetch_af(url)
    asset_id_dict = {}
    for asset in response.get("assets", []):
        try:
            asset_name = asset["name"]
            asset_id = asset["id"]
            external_id = asset["external_id"]
            if isinstance(asset.get("projects"), list):
                asset_in_projects = asset["projects"]
            else:
                asset_in_projects = None
            asset_id_dict[asset_name] = [asset_id, external_id, asset_in_projects]
        except (KeyError, TypeError) as e:
            print(f"Error processing asset {asset.get('name', 'unknown')}: {e}")
    return asset_id_dict


def verify_entity(url, entity_type):
    response = fetch_af(url)
    count = response["count"]
    if count == 0 or count > 1:
        return "error"
    if entity_type == "asset":
        return response["assets"][0]["id"]
    if entity_type == "writeup":
        return response["vulnerabilities"][0]["id"], response["vulnerabilities"][0]["reference_id"]
    if entity_type == "vuln":
        return response["vulnerabilities"][0]["vulnerability_id"]
    return "error"


# check for asset_id from external_id.
# Will return asset_id if found, otherwise returns error
def verify_asset(entity_id):
    """Use to check if an asset already exists in AttackForge."""
    query = f'{{ external_id: {{ $eq: "{entity_id}" }} }}'
    url = build_url("library/assets", query)
    return verify_entity(url, "asset")


# check if a writeup exists for a plugin_id (ex: tenable plugin) in a specific writeup library. custom_tags are used to filter by plugin_id. Change it if you need to filter by a different tag.
# will return id and reference_id if found, otherwise returns error
def verify_writeup(plugin_id, writeup_library_id):
    """Use to check if a writeup already exists in AttackForge."""
    query = f'{{custom_tags: {{ $elemMatch: {{ name: {{ $eq: "pluginID" }}, value: {{ $eq: "{plugin_id}" }} }} }}}}&belongs_to_library={writeup_library_id}'
    url = build_url("library", query)
    return verify_entity(url, "writeup")


# check if a vulnerability exists for a plugin_id (ex: tenable plugin) in a specific project. custom_tags are used to filter by plugin_id. Change it if you need to filter by a different tag.
# will return the vulnerability id if found, otherwise returns error
def verify_vuln(plugin_id, project_id):
    """Use to check if a vulnerability already exists in AttackForge."""
    query = f'{{custom_tags: {{ $elemMatch: {{ name: {{ $eq: "pluginID" }}, value: {{ $eq: "{plugin_id}" }} }} }}}}'
    url = build_url("project/" + project_id + "/vulnerabilities", query)
    return verify_entity(url, "vuln")


# get project vulns stats
def get_project_vulns_stats(project_id):
    url = build_url(f"project/{project_id}")
    response_temp = fetch_af(url)
    response = response_temp["project"]
    data = {
        "total_vulnerabilities": response["project_total_vulnerabilities"],
        "open_vulnerabilities": response["project_open_vulnerabilities"],
        "closed_vulnerabilities": response["project_closed_vulnerabilities"],
        "critical_vulnerabilities": response["project_critical_vulnerabilities"],
        "critical_open_vulnerabilities": response["project_critical_open_vulnerabilities"],
        "critical_closed_vulnerabilities": response["project_critical_closed_vulnerabilities"],
        "high_vulnerabilities": response["project_high_vulnerabilities"],
        "high_open_vulnerabilities": response["project_high_open_vulnerabilities"],
        "high_closed_vulnerabilities": response["project_high_closed_vulnerabilities"],
        "medium_vulnerabilities": response["project_medium_vulnerabilities"],
        "medium_open_vulnerabilities": response["project_medium_open_vulnerabilities"],
        "medium_closed_vulnerabilities": response["project_medium_closed_vulnerabilities"],
        "low_vulnerabilities": response["project_low_vulnerabilities"],
        "low_open_vulnerabilities": response["project_low_open_vulnerabilities"],
        "low_closed_vulnerabilities": response["project_low_closed_vulnerabilities"],
        "info_vulnerabilities": response["project_info_vulnerabilities"],
        "info_open_vulnerabilities": response["project_info_open_vulnerabilities"],
        "info_closed_vulnerabilities": response["project_info_closed_vulnerabilities"],
    }
    return data
