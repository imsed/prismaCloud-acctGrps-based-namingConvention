from __future__ import print_function
import json
import requests
import configparser
import os
import re

requests.packages.urllib3.disable_warnings()  # Added to avoid warnings in output if proxy


def return_error(message):
    print("\nERROR: " + message)
    exit(1)


def get_parser_from_sections_file(file_name):
    file_parser = configparser.ConfigParser()
    try:  # Checks if the file has the proper format
        file_parser.read(file_name)
    except (ValueError, configparser.MissingSectionHeaderError, configparser.DuplicateOptionError,
            configparser.DuplicateOptionError):
        return_error("Unable to read file " + file_name)
    return file_parser


def read_value_from_sections_file(file_parser, section, option):
    value = {}
    value['Exists'] = False
    if file_parser.has_option(section, option):  # Checks if section and option exist in file
        value['Value'] = file_parser.get(section, option)
        if not value['Value'] == '':  # Checks if NOT blank (so properly updated)
            value['Exists'] = True
    return value


def read_value_from_sections_file_and_exit_if_not_found(file_name, file_parser, section, option):
    value = read_value_from_sections_file(file_parser, section, option)
    if not value['Exists']:
        return_error("Section \"" + section + "\" and option \"" + option + "\" not found in file " + file_name)
    return value['Value']


def load_api_config(iniFilePath):
    if not os.path.exists(iniFilePath):
        return_error("Config file " + iniFilePath + " does not exist")
    iniFileParser = get_parser_from_sections_file(iniFilePath)
    api_config = {}
    api_config['BaseURL'] = read_value_from_sections_file_and_exit_if_not_found(iniFilePath, iniFileParser, 'URL',
                                                                                'URL')
    api_config['AccessKey'] = read_value_from_sections_file_and_exit_if_not_found(iniFilePath, iniFileParser,
                                                                                  'AUTHENTICATION', 'ACCESS_KEY_ID')
    api_config['SecretKey'] = read_value_from_sections_file_and_exit_if_not_found(iniFilePath, iniFileParser,
                                                                                  'AUTHENTICATION', 'SECRET_KEY')
    return api_config


def handle_api_response(apiResponse):
    status = apiResponse.status_code
    if (status != 200):
        return_error("API call failed with HTTP response " + str(status))


def run_api_call_with_payload(action, url, headers_value, payload):
    apiResponse = requests.request(action, url, headers=headers_value, data=json.dumps(payload),
                                   verify=False)  # verify=False to avoid CA certificate error if proxy between script and console
    handle_api_response(apiResponse)
    return apiResponse


def run_api_call_without_payload(action, url, headers_value):
    apiResponse = requests.request(action, url, headers=headers_value,
                                   verify=False)  # verify=False to avoid CA certificate error if proxy between script and console
    handle_api_response(apiResponse)
    return apiResponse


def login(api_config):
    action = "POST"
    url = api_config['BaseURL'] + "/login"
    headers = {
        'Content-Type': 'application/json'
    }
    payload = {
        'username': api_config['AccessKey'],
        'password': api_config['SecretKey'],
    }
    apiResponse = run_api_call_with_payload(action, url, headers, payload)
    authentication_response = apiResponse.json()
    token = authentication_response['token']
    return token


### APIs to interact  with  Account Groups ###

def get_account_groups(api_config):
    action = "GET"
    url = api_config['BaseURL'] + "/cloud/group"
    headers = {
        'x-redlock-auth': api_config['Token']
    }
    apiResponse = run_api_call_without_payload(action, url, headers)
    accountGroups = json.loads(apiResponse.text)
    return accountGroups


def update_account_group(api_config, accountGroupName, accountGroupId, accountIds, description):
    action = "PUT"
    url = api_config['BaseURL'] + "/cloud/group/" + accountGroupId
    headers = {
        'Content-type': 'application/json',
        'Accept': 'application/json',
        'x-redlock-auth': api_config['Token']
    }
    payload = {
        'accountIds': accountIds,
        'name': accountGroupName,
        'description': description
    }
    run_api_call_with_payload(action, url, headers, payload)


def create_account_group(api_config, accountGroupName, accountIds, description):
    action = "POST"
    url = api_config['BaseURL'] + "/cloud/group/"
    headers = {
        'Content-type': 'application/json',
        'Accept': 'application/json',
        'x-redlock-auth': api_config['Token']
    }
    payload = {
        'accountIds': accountIds,
        'name': accountGroupName,
        'description': description
    }
    run_api_call_with_payload(action, url, headers, payload)


def delete_account_group(api_config, accountGroupId):
    action = "DELETE"
    url = api_config['BaseURL'] + "/cloud/group/" + accountGroupId
    headers = {
        'Content-type': 'application/json',
        'Accept': 'application/json',
        'x-redlock-auth': api_config['Token']
    }
    run_api_call_with_payload(action, url, headers)


### APIs to interact  with Cloud Accounts and Organization Accounts ###


def get_cloud_accounts(api_config):
    action = "GET"
    url = api_config['BaseURL'] + "/cloud/"
    headers = {
        'x-redlock-auth': api_config['Token']
    }
    apiResponse = run_api_call_without_payload(action, url, headers)
    accounts = json.loads(apiResponse.text)
    return accounts


def get_org_cloud_account_from_cloud_account(api_config, cloudAccountId, cloudType):
    action = "GET"
    url = api_config['BaseURL'] + "/cloud/" + cloudType + "/" + cloudAccountId + "/project"
    headers = {
        'x-redlock-auth': api_config['Token']
    }
    apiResponse = run_api_call_without_payload(action, url, headers)
    accounts = json.loads(apiResponse.text)
    return accounts


### Processing Functions  Cloud Accounts###
def get_all_org_cloud_account_per_cloud_type(api_config, cloudAccountList, cloudType):
    orgAccounts = []
    for cloudAccount in cloudAccountList:
        if cloudAccount["accountType"] in ('tenant', 'organization'):
            accounts = get_org_cloud_account_from_cloud_account(api_config, cloudAccount["accountId"], cloudType)
            for account in accounts:
                orgAccounts.append(account)
        else:
            orgAccounts.append(cloudAccount)
    return orgAccounts


def get_all_org_cloud_account_based_name_convention(orgAccountList, nameConvention):
    orgAccountsMatching = []
    orgAccountsNotMatching = []
    for account in orgAccountList:
        if re.match(nameConvention, account["name"]):
            orgAccountsMatching.append(account)
        else:
            orgAccountsNotMatching.append(account)
    return orgAccountsMatching, orgAccountsNotMatching


def get_cloud_accounts_by_cloud_type(cloudAccountList, cloudType):
    cloudAccountsMatching = []
    for cloudAccount in cloudAccountList:
        if (cloudAccount['cloudType'].lower() == cloudType.lower()):
            cloudAccountsMatching.append(cloudAccount)
    return cloudAccountsMatching


def get_cloud_accounts_not_having_acount_group(cloudAccountList, accountGroupsList):
    cloudAccountsMatching = []
    for cloudAccount in cloudAccountList:
        accountGroupName = "custom_" + cloudAccount["name"].split()[0]
        accountGroupExist = if_accountGroupName_exist_in_accountGroupList(accountGroupName, accountGroupsList)
        if not accountGroupExist:
            cloudAccountsMatching.append(cloudAccount)
    return cloudAccountsMatching


### Processing Functions  Account Groups###


def get_name_of_all_accountGroup(accountGroupsList):
    accountGroupNames = []
    for accountGroup in accountGroupsList:
        accountGroupNames.append(accountGroup['name'])
    return accountGroupNames


def get_account_groups_of_cloudAccount(cloudAccount, accountGroupsList):
    accountGroupsMatching = []
    for accountGroup in accountGroupsList:
        if accountGroup['id'] in cloudAccount['groupIds']:
            accountGroupsMatching.append(accountGroup)
    return accountGroupsMatching


def if_accountGroupName_exist_in_accountGroupList(accountGroupName, accountGroupsList):
    accountGroupExists = False
    for accountGroup in accountGroupsList:
        if (accountGroup['name'].lower() == accountGroupName.lower()):
            accountGroupExists = True
            break
    return accountGroupExists


def get_accountGroupData_from_accountGroupList_by_name_equals(accountGroupName, accountGroupsList):
    accountGroupExists = False
    for accountGroup in accountGroupsList:
        if (accountGroup['name'].lower() == accountGroupName.lower()):
            accountGroupExists = True
            break
    if not accountGroupExists:
        return_error("Account Group \"" + accountGroupName + "\" does not exist")
    return accountGroup


def get_accountIds_from_accountGroup_by_name_contains(nameToSearch, accountGroupData):
    accountsMatching = []
    for account in accountGroupData['accounts']:
        if (nameToSearch.lower() in account['name'].lower()):
            accountsMatching.append(account)
    print("Number of Cloud Accounts matching \"" + nameToSearch + "\" in Account Group \"" + accountGroupData[
        'name'] + "\": " + str(len(accountsMatching)))
    if (len(accountsMatching) > 0):
        for account in accountsMatching:
            print("\t" + account['name'])
    return accountsMatching


def delete_item_from_list_if_exists(item, list):
    if item in list:
        list.remove(item)
    return list


def add_item_in_list_if_not_exists(item, list):
    if item not in list:
        list.append(item)
    return list


def delete_account_from_account_group(api_config, account, accountGroup):
    accountIds = delete_item_from_list_if_exists(account['accountId'], accountGroup['accountIds'])
    print("Deleting account \"" + account['name'] + "\" from Account Group \"" + accountGroup['name'] + "\"")
    update_account_group(api_config, accountGroup['name'], accountGroup['id'], accountIds, accountGroup['description'])


def add_account_in_account_group(api_config, account, accountGroup):
    accountIds = add_item_in_list_if_not_exists(account['id'], accountGroup['accountIds'])
    print("Adding account \"" + account['name'] + "\" to Account Group \"" + accountGroup['name'] + "\"")
    update_account_group(api_config, accountGroup['name'], accountGroup['id'], accountIds, accountGroup['description'])

def create_account_groups_based_cloudAccounts(api_config, cloudAccountList, accountGroupsList):
    AccountGroupNameList = []
    defaultAccountGroup = get_accountGroupData_from_accountGroupList_by_name_equals("Default Account Group",
                                                                                    accountGroupsList)
    for cloudAccount in cloudAccountList:
        NewAccountGroupName = "custom_" + cloudAccount["name"].split()[0]
        if NewAccountGroupName not in AccountGroupNameList:
            AccountGroupNameList.append(NewAccountGroupName)
            create_account_group(api_config, NewAccountGroupName, [cloudAccount["accountId"]],
                                 "Account Group created for Service type " + cloudAccount["name"].split()[0])
            delete_account_from_account_group(api_config, cloudAccount, defaultAccountGroup)
            print("Account Group " + NewAccountGroupName + " is created and assigned to the cloud Account " +
                  cloudAccount['name'])

        else:
            accountGroup = get_accountGroupData_from_accountGroupList_by_name_equals(NewAccountGroupName,
                                                                                     accountGroupsList)
            accountId = cloudAccount['accountId']
            accountIds = accountGroup['accountIds']
            if accountId not in accountIds:
                accountIds.append(accountId)
                update_account_group(api_config, NewAccountGroupName, accountGroup['id'], accountIds,
                                     "Account Group created for Service type " + cloudAccount["name"].split()[0])
                delete_account_from_account_group(api_config, cloudAccount, defaultAccountGroup)
                print("The Account Group " + NewAccountGroupName + " is assigned to the cloud Account " + cloudAccount[
                    'name'])


def assign_account_groups_based_cloudAccounts(api_config, cloudAccountList, accountGroupsList):
    AccountGroupNameList = []
    defaultAccountGroup = get_accountGroupData_from_accountGroupList_by_name_equals("Default Account Group",
                                                                                    accountGroupsList)
    for cloudAccount in cloudAccountList:
        accountGroupName = "custom_" + cloudAccount["name"].split()[0]
        accountGroup = get_accountGroupData_from_accountGroupList_by_name_equals(accountGroupName, accountGroupsList)
        accountId = cloudAccount['accountId']
        accountIds = accountGroup['accountIds']
        if accountId not in accountIds:
            accountIds.append(accountId)
            print("The Account Group " + accountGroupName + " is assigned to the cloud Account " + cloudAccount['name'])
            update_account_group(api_config, accountGroupName, accountGroup['id'], accountIds,
                                 "Account Group created for Service type " + cloudAccount["name"].split()[0])
            delete_account_from_account_group(api_config, cloudAccount, defaultAccountGroup)


def main():
    # ----------- Load API configuration from .ini file -----------

    api_config = load_api_config("API_config.ini")

    # ----------- First API call for authentication -----------

    token = login(api_config)
    api_config['Token'] = token

    # ----------- Naming Convention -----------

    nameConvention = "([a-zA-Z0-9]*)[_ ]Subscription*"

    # ----------- Get Account Groups and Cloud Accounts -----------

    accountGroupsList = get_account_groups(api_config)
    cloudAccountList = get_cloud_accounts(api_config)

    # ----------- Get org Accounts based on Cloud Accounts and cloud type-----------

    azureCloudAccountList = get_cloud_accounts_by_cloud_type(cloudAccountList, 'azure')
    azureAllOrgAccountList = get_all_org_cloud_account_per_cloud_type(api_config, azureCloudAccountList, 'azure')

    # ----------- Filter all cloud accounts in a cloud Type based on the name convention-----------

    (azureOrgAccountsMatching, azureOrgAccountsNotMatching) = get_all_org_cloud_account_based_name_convention(
        azureAllOrgAccountList, nameConvention)

    # ----------- List of cloud accounts that doesn't have a matching Account Group-----------
    newAzureAccountList = get_cloud_accounts_not_having_acount_group(azureOrgAccountsMatching, accountGroupsList)

    # ----------- Create missing account groups and assign them to the source Cloud Account filtered by cloud Type-----------

    create_account_groups_based_cloudAccounts(api_config, newAzureAccountList, accountGroupsList)

    # ----------- do a recursive lookup in all cloud accounts of a cloudType matching the name convention and assign them to the corresponding Account Group-----------
    accountGroupsList = get_account_groups(api_config)
    assign_account_groups_based_cloudAccounts(api_config, azureOrgAccountsMatching, accountGroupsList)


if __name__ == "__main__":
    main()