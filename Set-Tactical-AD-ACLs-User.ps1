################################################################################################
# New Script Name : Set-Tactical-AD-ACLs-User.ps1
# 
# 
# ORIGINAL AUTHOR: Chris Bragg, Microsoft Corporation
# VERSION: v0.2
# DATE: 04.29.2022
#
# THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
# FITNESS FOR A PARTICULAR PURPOSE.
#
# This sample is not supported under any Microsoft standard support program or service. 
# The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
# implied warranties including, without limitation, any implied warranties of merchantability
# or of fitness for a particular purpose. The entire risk arising out of the use or performance
# of the sample and documentation remains with you. In no event shall Microsoft, its authors,
# or anyone else involved in the creation, production, or delivery of the script be liable for 
# any damages whatsoever (including, without limitation, damages for loss of business profits, 
# business interruption, loss of business information, or other pecuniary loss) arising out of 
# the use of or inability to use the sample or documentation, even if Microsoft has been advised 
# of the possibility of such damages.
#
#-------------------------------------------------------------------------------------------------
# SCRIPT PURPOSE:
#
# The purpose of this script is to quickly implement the necessary permissions on specific OUs within
# Active Directory to allow administrators the ability to administer user objects
# that are NOT Tier 0.
# 
# SCRIPT FUNCTIONS:
# - ACLs specific OUs with a specific group
#
# USAGE:
# Set-Tactical-T1-User-Admin-ACL.ps1 -OrganizationalUnit "OU=Contoso Users,OU=Company,DC=Contoso,DC=Com" -DelegationGroupName "Contoso Tier 1 AD User Admins" -All
# Set-Tactical-T1-User-Admin-ACL.ps1 -OrganizationalUnit "OU=Contoso Users,OU=Company,DC=Contoso,DC=Com" -DelegationGroupName "Contoso Tier 1 AD User Admins" -MoveObjects -Unlock -GeneralInfo -PublicInfo
# 
# [-OrganizationalUnit]
#     This parameter is REQUIRED and must have the distinguished name of the OU where the ACLs will be set. (EX: "OU=Contoso Users,OU=Company,DC=Contoso,DC=Com")
# 
# [-DelegationGroupName]
#     This parameter is REQUIRED and must have the name of the group that will have the delegated permissions
#
# [-All]
#     This OPTIONAL switch performs all ACLs from the other switches on the designated OU
#
# [-MoveObjects]
#     This OPTIONAL switch allow a user to move objects to or from the designated OU. If you want to move objects to OUs that are not nested as child OUs, then this needs to be run on all parent OUs to move resources to or from
#
# [-ResetPasswords]
#     This OPTIONAL switch allows the ability to reset and change passwords of user objects
#
# [-Unlock]
#     This OPTIONAL switch allows the user account to be unlocked when it is locked out
#
# [-userAccountControl]
#     This OPTIONAL switch allows the ability to manage all settings that calculate the userAccountControl attribute (Attributes can be found here: https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-account-restrictions)
#
# [-Profile]
#     This OPTIONAL switch allows the ability to update attributes on the profile tab of a user
#
# [-PublicInfo]
#     This OPTIONAL switch allows all public attributes to be updated (Attributes can be found here: https://docs.microsoft.com/en-us/windows/win32/adschema/r-public-information)
# 
# [-GeneralInfo]
#     This OPTIONAL switch allows all public attributes to be updated (Attributes can be found here: https://docs.microsoft.com/en-us/windows/win32/adschema/r-general-information)
#
# [-PersonalInfo]
#     This OPTIONAL switch allows all personal attributes to be updated (Attributes can be found here: https://docs.microsoft.com/en-us/windows/win32/adschema/r-personal-information)
#
# [-WebPage]
#     This OPTIONAL switch allows the ability to update the web page attribute on a user object
#
#
# RESOURCES:
# https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-force-change-password
# https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-change-password
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol
# https://docs.microsoft.com/en-us/windows/win32/adschema/r-domain-password
# https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-account-restrictions
# https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-logon
# https://docs.microsoft.com/en-us/windows/win32/adschema/r-public-information
# https://docs.microsoft.com/en-us/windows/win32/adschema/r-general-information
# https://docs.microsoft.com/en-us/windows/win32/adschema/r-personal-information
# https://docs.microsoft.com/en-us/windows/win32/adschema/r-web-information
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-distinguishedname
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-cn
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-name
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-lockouttime
# https://docs.microsoft.com/en-us/windows/win32/adschema/c-computer
# 
#-------------------------------------------------------------------------------------------------

param(
[Parameter(Mandatory=$true)]
[string[]] $OrganizationalUnit,

[Parameter(Mandatory=$true)]
[string[]] $DelegationGroupName,

[switch]$All = [bool]$false,
[switch]$MoveObjects = [bool]$false,
[switch]$ResetPasswords = [bool]$false,
[switch]$Unlock = [bool]$false,
[switch]$userAccountControl = [bool]$false,
[switch]$Profile = [bool]$false,
[switch]$PublicInfo = [bool]$false,
[switch]$GeneralInfo = [bool]$false,
[switch]$PersonalInfo = [bool]$false,
[switch]$WebPage = [bool]$false

)

####################################################################
# Functions  
####################################################################

#-------------------------------------------------------------------------------------------------
# Begin Common Functions
#-------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------
# Descendant User Object functions
#-------------------------------------------------------------------------------------------------

function Set-ADAclDeleteAttributesUser(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Delete" - Top Left
    #ACL Applies To: Descendant User objects
    #NOTES: Required to move user objects between OUs
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "Delete"
    $confDelegatedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2" # User Object Type GUID
    $confExtendedRight = "00000000-0000-0000-0000-000000000000" # Extended Right Delete GUID
 
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}
function Set-ADAclResetPasswordsUser(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Reset Password" - Top Right
    #ACL Applies To: Descendant User objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-force-change-password
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "ExtendedRight"
    $confDelegatedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2" # User Object Type GUID
    $confExtendedRight = "00299570-246d-11d0-a768-00aa006e0529" # Extended Right PasswordReset GUID
 
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}
function Set-ADAclChangePasswordsUser(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Change Password" - Top Right
    #ACL Applies To: Descendant User objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-change-password
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "ExtendedRight"
    $confDelegatedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2" # User Object Type GUID
    $confExtendedRight = "ab721a53-1e2f-11d0-9819-00aa0040529b" # Extended Right PasswordReset GUID
 
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}
function Set-ADAclEnableDisableUser(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write userAccountControl" - Bottom Right
    #ACL Applies To: Descendant User objects
    # https://docs.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2" # User Object Type GUID
    $confExtendedRight = "bf967a68-0de6-11d0-a285-00aa003049e2" # Extended Right Enable Disable GUID
 
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}
function Set-ADAclUnlockUser(){
    #ACL Set in: ADSIEDIT.MSC
    #ACL Checkbox name: "Write domain password lockout policies" - Top Left
    #ACL Applies To: Descendant Domain objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/r-domain-password
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "19195a5a-6da0-11d0-afd3-00c04fd930c9" # Domain Object Type GUID
    $confExtendedRight = "c7407360-20bf-11d0-a768-00aa006e0529" # Extended Right PasswordReset GUID
 
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}
function Set-ADAclAccountRestrictionsUser(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write account restrictions" - Middle Left
    #ACL Applies To: Descendant User objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-account-restrictions
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2" # User Object Type GUID
    $confExtendedRight = "4C164200-20C0-11D0-A768-00AA006E0529" # Extended Right PasswordReset GUID
 
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}
function Set-ADAclUserLogonInfoUser(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write logon information" - Top Left
    #ACL Applies To: Descendant User objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-logon
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2" # User Object Type GUID
    $confExtendedRight = "5f202010-79a5-11d0-9020-00c04fc2d4cf" # Extended Right Logon Information GUID
 
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}
function Set-ADAclPublicInfoUser(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write public information" - Top Left
    #ACL Applies To: Descendant User objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/r-public-information
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2" # User Object Type GUID
    $confExtendedRight = "e48d0154-bcf8-11d1-8702-00c04fb96050" # Extended Right Public Information GUID
    
 
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}
function Set-ADAclGeneralInfoUser(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write General information" - Top Left
    #ACL Applies To: Descendant User objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/r-general-information
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2" # User Object Type GUID
    $confExtendedRight = "59ba2f42-79a2-11d0-9020-00c04fc2d3cf" # Extended Right General Information GUID
 
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}
function Set-ADAclPersonalInfoUser(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write Personal information" - Top Left
    #ACL Applies To: Descendant User objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/r-personal-information
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2" # User Object Type GUID
    $confExtendedRight = "77b5b886-944a-11d1-aebd-0000f80367c1" # Extended Right Personal Information GUID
 
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}
function Set-ADAclWebInfoUser(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write Web information" - Top Left
    #ACL Applies To: Descendant User objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/r-web-information
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2" # User Object Type GUID
    $confExtendedRight = "e45795b3-9455-11d1-aebd-0000f80367c1" # Extended Right Web Information GUID
 
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}
function Set-ADAclUserDistinguishedNameUser(){
    #ACL Set in: ADSIEDIT.MSC
    #ACL Checkbox name: "Write Distinguished Name" - Middle Left
    #ACL Applies To: Descendant User objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/a-distinguishedname
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2" # User Object Type GUID
    $confExtendedRight = "bf9679e4-0de6-11d0-a285-00aa003049e2" # Extended Right distinguishedName (Obj-Dist-Name) GUID
     
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}
function Set-ADAclCommonNameUser(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write Name" - Middle Right
    #ACL Applies To: Descendant User objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/a-cn
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2" # User Object Type GUID
    $confExtendedRight = "bf96793f-0de6-11d0-a285-00aa003049e2" # Extended Right Common-Name GUID
     
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}
function Set-ADAclRDNUser(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write name" - Middle Right
    #ACL Applies To: Descendant User objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/a-name
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2" # User Object Type GUID
    $confExtendedRight = "bf967a0e-0de6-11d0-a285-00aa003049e2" # Extended Right RDN (Relative Distinguished Name) GUID
     
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}
function Set-ADAclLockOutTimeUser(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write lockouttime" - Middle Left
    #ACL Applies To: Descendant User objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/a-lockouttime
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2" # User Object Type GUID
    $confExtendedRight = "28630ebf-41d5-11d1-a9c1-0000f80367c1" # Extended Right lockout time GUID
     
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}

#-------------------------------------------------------------------------------------------------
# All objects and descendent object functions
#-------------------------------------------------------------------------------------------------

function Set-ADAclCreateUsersAll(){
    #ACL Set in: ADSIEDIT.MSC
    #ACL Checkbox name: "Create Users" - Top Left
    #ACL Applies To: This object and all descendent objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/c-computer
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "CreateChild"
    $confDelegatedObjectType = "00000000-0000-0000-0000-000000000000" # All Object Type GUID
    $confExtendedRight = "bf967aba-0de6-11d0-a285-00aa003049e2" # Extended Right Create User GUID
                          
     
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}
function Set-ADAclDeleteUsersAll(){
    #ACL Set in: ADSIEDIT.MSC
    #ACL Checkbox name: "Delete Users" - Top Left
    #ACL Applies To: This object and all descendent objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/c-computer
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "DeleteChild"
    $confDelegatedObjectType = "00000000-0000-0000-0000-000000000000" # All Object Type GUID
    $confExtendedRight = "bf967aba-0de6-11d0-a285-00aa003049e2" # Extended Right Delete User GUID

     
    # Collect and prepare Objects
    $delegationGroup = Get-ADGroup -Identity $DelegationGroupName
    $delegationGroupSID = [System.Security.Principal.SecurityIdentifier] $delegationGroup.SID
    $delegationGroupACL = Get-Acl -Path "AD:\$OrganizationalUnit"
 
    # Build Access Control Entry (ACE)
    $aceIdentity = [System.Security.Principal.IdentityReference] $delegationGroupSID
    $aceADRight = [System.DirectoryServices.ActiveDirectoryRights]::$confADRight
    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceIdentity, $aceADRight, $aceType, $confExtendedRight, $aceInheritanceType,$confDelegatedObjectType)
 
    # Apply ACL
    $delegationGroupACL.AddAccessRule($ace)
    Set-Acl -Path "AD:\$OrganizationalUnit" -AclObject $delegationGroupACL
}

#-------------------------------------------------------------------------------------------------
# End Common Functions
#-------------------------------------------------------------------------------------------------
If ($All -eq $false -and $MoveObjects -eq $false -and $ResetPasswords -eq $false -and $Unlock -eq $false -and $userAccountControl -eq $false -and $Profile -eq $false -and $PublicInfo -eq $false -and $GeneralInfo -eq $false -and $PersonalInfo -eq $false -and $WebPage -eq $false)
{
Write-host "Please specify at least one of the following switches.
-All
-MoveObjects
-ResetPasswords
-Unlock
-userAccountControl
-Profile
-PublicInfo
-GeneralInfo
-PersonalInfo
-WebPage
" -ForegroundColor Red
Break All
}

If ($MoveObjects -eq $true -or $All -eq $true)
    {
    Write-host "Setting Create User ACL" -ForegroundColor Yellow
    Set-ADAclCreateUsersAll -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting Delete User ACL" -ForegroundColor Yellow
    Set-ADAclDeleteUsersAll -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting DistinguishedName User ACL" -ForegroundColor Yellow
    Set-ADAclUserDistinguishedNameUser -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting CN User ACL" -ForegroundColor Yellow
    Set-ADAclCommonNameUser -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting RDN User ACL" -ForegroundColor Yellow
    Set-ADAclRDNUser -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting Delete Attributes User ACL" -ForegroundColor Yellow
    Set-ADAclDeleteAttributesUser -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($ResetPasswords -eq $true -or $All -eq $true)
    {
    Write-host "Setting Reset Password User ACL" -ForegroundColor Yellow
    Set-ADAclResetPasswordsUser -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting Change Password User ACL" -ForegroundColor Yellow
    Set-ADAclChangePasswordsUser -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($Unlock -eq $true -or $All -eq $true)
    {
    Write-host "Setting Unlock User ACL" -ForegroundColor Yellow
    Set-ADAclUnlockUser -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting Write lockout time Attribute User ACL" -ForegroundColor Yellow
    Set-ADAclLockOutTimeUser -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($userAccountControl -eq $true -or $All -eq $true)
    {
    Write-host "Setting UserAccountControl User ACL" -ForegroundColor Yellow
    Set-ADAclAccountRestrictionsUser -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($Profile -eq $true -or $All -eq $true)
    {
    Write-host "Setting Logon Info User ACL" -ForegroundColor Yellow
    Set-ADAclUserLogonInfoUser -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($PublicInfo -eq $true -or $All -eq $true)
    {
    Write-host "Setting Public Information User ACL" -ForegroundColor Yellow
    Set-ADAclPublicInfoUser -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($GeneralInfo -eq $true -or $All -eq $true)
    {
    Write-host "Setting General Information User ACL" -ForegroundColor Yellow
    Set-ADAclGeneralInfoUser -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($PersonalInfo -eq $true -or $All -eq $true)
    {
    Write-host "Setting Personal Information User ACL" -ForegroundColor Yellow
    Set-ADAclPersonalInfoUser -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($WebPage -eq $true -or $All -eq $true)
    {
    Write-host "Setting Web Page User ACL" -ForegroundColor Yellow
    Set-ADAclWebInfoUser -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

#-------------------------------------------------------------------------------------------------
# END of File
#-------------------------------------------------------------------------------------------------
