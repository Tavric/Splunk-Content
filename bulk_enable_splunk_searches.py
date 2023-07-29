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

search_groups = [{"app":"DA-ESS-ContentUpdate","searches":["ESCU - Detect PsExec With accepteula Flag - Rule","ESCU - Domain Account Discovery With Net App - Rule","ESCU - Domain Account Discovery with Wmic - Rule","ESCU - Domain Controller Discovery with Nltest - Rule","ESCU - Elevated Group Discovery With Net - Rule","ESCU - Elevated Group Discovery With Wmic - Rule","ESCU - Get ADUserResultantPasswordPolicy with Powershell - Rule","ESCU - Get DomainPolicy with Powershell - Rule","ESCU - Get DomainUser with PowerShell - Rule","ESCU - Get-DomainTrust with PowerShell - Rule","ESCU - Get-ForestTrust with PowerShell - Rule","ESCU - GetDomainComputer with PowerShell - Rule","ESCU - GetDomainGroup with PowerShell - Rule","ESCU - GetWmiObject DS User with PowerShell - Rule","ESCU - GetWmiObject Ds Computer with PowerShell - Rule","ESCU - GetWmiObject Ds Group with PowerShell - Rule","ESCU - Impacket Lateral Movement Commandline Parameters - Rule","ESCU - Impacket Lateral Movement WMIExec Commandline Parameters - Rule","ESCU - Impacket Lateral Movement smbexec CommandLine Parameters - Rule","ESCU - Mimikatz PassTheTicket CommandLine Parameters - Rule","ESCU - Mmc LOLBAS Execution Process Spawn - Rule","ESCU - Possible Lateral Movement PowerShell Spawn - Rule","ESCU - Remote Process Instantiation via DCOM and PowerShell - Rule","ESCU - Remote Process Instantiation via WMI - Rule","ESCU - Remote Process Instantiation via WMI and PowerShell - Rule","ESCU - Remote Process Instantiation via WinRM and PowerShell - Rule","ESCU - Remote Process Instantiation via WinRM and Winrs - Rule","ESCU - Remote System Discovery with Wmic - Rule","ESCU - Rubeus Command Line Parameters - Rule","ESCU - Scheduled Task Creation on Remote Endpoint using At - Rule","ESCU - Scheduled Task Initiation on Remote Endpoint - Rule","ESCU - Schtasks scheduling job on remote system - Rule","ESCU - ServicePrincipalNames Discovery with SetSPN - Rule","ESCU - Services LOLBAS Execution Process Spawn - Rule","ESCU - Svchost LOLBAS Execution Process Spawn - Rule","ESCU - Unknown Process Using The Kerberos Protocol - Rule","ESCU - Windows Default Group Policy Object Modified with GPME - Rule","ESCU - Windows Findstr GPP Discovery - Rule","ESCU - Windows Lateral Tool Transfer RemCom - Rule","ESCU - Windows Remote Create Service - Rule","ESCU - Windows Service Create with Tscon - Rule","ESCU - Windows Service Creation on Remote Endpoint - Rule","ESCU - Windows Service Initiation on Remote Endpoint - Rule","ESCU - Wmiprsve LOLBAS Execution Process Spawn - Rule","ESCU - Wsmprovhost LOLBAS Execution Process Spawn - Rule"]}]

headers = {'Authorization': f'Splunk {auth_cookie}'}

for search_group in search_groups:
    for search in search_group['searches']:

        url = f"https://{host}:{mgmt_port}/servicesNS/nobody/{search_group['app']}/saved/searches/{search}/enable"

        response = requests.request("POST", url, headers=headers, verify=False)

        if response.status_code == 200:
            print(f"Successfully enabled {search}.")
        else:
            print(f"Failed to enable {search}. Response code: {response.status_code}")