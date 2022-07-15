# IMPORTANT: update "API_config.ini" file before running the script. The following fields are currently empty and need to be updated:
```
URL --> introduce your API URL (e.g. "https://api2.eu.prismacloud.io")
ACCESS_KEY_ID --> introduce your Prisma Cloud ACCESS KEY ID
SECRET_KEY --> introduce your Prisma Cloud SECRET KEY
```
## Prerequisites:
- The script is tested on Python 3.10
- Install requests package
    
## Functioning description:

The script contains couple of functions that helps automat account groups creation and manipulation. The main use case is to create account groups based on the naming convention of Cloud Accounts.


## Applicable use cases:

The purpose of the script is to have dynamic adding of accounts to account groups. This is to make sure that all onboarded accounts are mapped to proper account groups automatically without manual intervention. The script can be run on a regular basis (e.g. daily) to constantly update the accounts.

The current code covers the exactly following scenario in its last lines:
- create_account_groups_based_cloudAccounts : If a new Cloud Account is added, the script will check if it is matching the naming convention of your organization. If yes it will create an account group based on the name of the cloud account and removes that cloud Account from the Default Account Group  
- assign_account_groups_based_cloudAccounts : Will check all the Cloud Account matching the naming convention and make sure they are associated to the correct Account Group
- The script is valid for all CloudType
- That lines can be changed to cover different scenarios or use cases.
## Variables examples:

- azureOrgAccountsMatching shows all the Azure Cloud Accounts that matches the naming convention
- azureOrgAccountsNotMatching shows all the Azure Cloud Accounts that matches the naming convention
- nameConvention should contain the regex that define the organizaton naming convention

