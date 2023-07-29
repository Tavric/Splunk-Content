import requests

# IP or hostname
host = "127.0.0.1"
# Usually 8089
mgmt_port = "8089"
# Get the value of the splunkd_* cookie after authenticating to Splunk web
auth_cookie = ""

"""
Use this search to populate the search_groups field. Modify to filter to the searches you want to enable

| rest splunk_server=local /servicesNS/-/-/configs/conf-savedsearches 
| where match(title, "ESCU") AND match('action.escu.analytic_story', "Windows") AND match(search, "(?i)datamodel=Endpoint\.Processes") AND match(search, "dest") AND !match(description, "^WARNING") 
| search action.risk=1 
| table title eai:acl.app disabled action.escu.analytic_story description search 
| stats values(title) as searches by eai:acl.app 
| rename eai:acl.app as app 
| tojson output_field=search_groups
| stats values(search_group) as search_groups
| eval search_groups="[".mvjoin(search_groups, ",")."]"
"""

search_groups = 

headers = {'Authorization': f'Splunk {auth_cookie}'}

for search_group in search_groups:
    for search in search_group['searches']:

        url = f"https://{host}:{mgmt_port}/servicesNS/nobody/{search_group['app']}/saved/searches/{search}/enable"

        response = requests.request("POST", url, headers=headers, verify=False)

        if response.status_code == 200:
            print(f"Successfully enabled {search}.")
        else:
            print(f"Failed to enable {search}. Response code: {response.status_code}")
