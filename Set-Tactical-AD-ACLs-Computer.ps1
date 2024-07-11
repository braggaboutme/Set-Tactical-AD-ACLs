################################################################################################
# New Script Name : Set-Tactical-AD-ACLs-Computer.ps1
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
# Active Directory to allow administrators the ability to administer computer objects
# that are NOT Tier 0.
# 
# SCRIPT FUNCTIONS:
# - ACLs specific OUs with a specific group
#
# USAGE:
# Set-Tactical-T1-Computer-Admin-ACL.ps1 -OrganizationalUnit "OU=Contoso Users,OU=Company,DC=Contoso,DC=Com" -DelegationGroupName "Contoso Tier 1 AD User Admins" -All
# Set-Tactical-T1-Computer-Admin-ACL.ps1 -OrganizationalUnit "OU=Contoso Users,OU=Company,DC=Contoso,DC=Com" -DelegationGroupName "Contoso Tier 1 AD User Admins" -JoinToDomain -MoveObjects -Description
# 
# [-OrganizationalUnit]
#     This parameter is REQUIRED and must have the distinguished name of the OU where the ACLs will be set. (EX: "OU=Contoso Computers,OU=Company,DC=Contoso,DC=Com" OR "CN=Computers,DC=Contoso,DC=Com")
# 
# [-DelegationGroupName]
#     This parameter is REQUIRED and must have the name of the group that will have the delegated permissions
#
# [-All]
#     This OPTIONAL switch performs all ACLs from the other switches on the designated OU
#
## [-MoveObjects]
#     This OPTIONAL switch allow a user to move objects to or from the designated OU. If you want to move objects to OUs that are not nested as child OUs, then this needs to be run on all parent OUs to move resources to or from
#
# [-JoinDomain]
#     This OPTIONAL switch allows users to join computers to the domain from the OU where this switch is run on
#
# [-Description]
#     This OPTIONAL switch allows modification of the description attribute
#
# [-ResetPasswords]
#     This OPTIONAL switch allows the ability to reset the password of the computer object
#
# [-EnableDisable]
#     This OPTIONAL switch allows the ability to enable or disable the computer object
#
#
# RESOURCES:
# https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-force-change-password
# https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-change-password
# https://docs.microsoft.com/en-us/windows/win32/adschema/r-dns-host-name-attributes
# https://docs.microsoft.com/en-us/windows/win32/adschema/r-validated-spn
# https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-account-restrictions
# https://docs.microsoft.com/en-us/windows/win32/adschema/r-dns-host-name-attributes
# https://docs.microsoft.com/en-us/windows/win32/adschema/r-ms-ts-gatewayaccess
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-description
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-distinguishedname
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-cn
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-name
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
[switch]$JoinToDomain = [bool]$false,
[switch]$Description = [bool]$false,
[switch]$ResetPasswords = [bool]$false,
[switch]$EnableDisable = [bool]$false

)

#-------------------------------------------------------------------------------------------------
# Begin Common Functions
#-------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------
# Computer functions
#-------------------------------------------------------------------------------------------------

function Set-ADAclResetPasswordComputer(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Reset Password" - Top Right
    #ACL Applies To: Descendant Computer objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-force-change-password
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "ExtendedRight"
    $confDelegatedObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2" # Computer Object Type GUID
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
function Set-ADAclChangePasswordComputer(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Change Password" - Top Right
    #ACL Applies To: Descendant Computer objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-change-password
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "ExtendedRight"
    $confDelegatedObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2" # Computer Object Type GUID
    $confExtendedRight = "ab721a53-1e2f-11d0-9819-00aa0040529b" # Extended Right Change Password GUID
 
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
function Set-ADAclValidateWriteDnsHostNameComputer(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Validated write to DNS host name" - Top Right
    #ACL Applies To: Descendant Computer objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/r-dns-host-name-attributes
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "Self"
    $confDelegatedObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2" # Computer Object Type GUID
    $confExtendedRight = "72e39547-7b18-11d1-adef-00c04fd8d5cd" # Extended Right Validated write to DNS host anem GUID
 
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
function Set-ADAclValidateWriteSPNComputer(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Validated write to service principal name" - Top right
    #ACL Applies To: Descendant Computer objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/r-validated-spn
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "Self"
    $confDelegatedObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2" # Computer Object Type GUID
    $confExtendedRight = "f3a64788-5306-11d1-a9c5-0000f80367c1" # Extended Right Validate write to service principal name GUID
 
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
function Set-ADAclAccountRestrictionsComputer(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write account restrictions" - Middle Left
    #ACL Applies To: Descendant Computer objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-account-restrictions
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2" # Computer Object Type GUID
    $confExtendedRight = "4C164200-20C0-11D0-A768-00AA006E0529" # Extended Right AccountRestrictions GUID
 
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
function Set-ADAclDNSInfoComputer(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Change Password" - Top Right
    #ACL Applies To: Descendant Computer objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/r-dns-host-name-attributes
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "ExtendedRight"
    $confDelegatedObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2" # Computer Object Type GUID
    $confExtendedRight = "72e39547-7b18-11d1-adef-00c04fd8d5cd" # Extended Right DNS Host Name Attributes GUID
 
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
function Set-ADAclMsTsGatewayInfoComputer(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write MS-TS-GatewayAccess" - Top Left
    #ACL Applies To: Descendant Computer objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/r-ms-ts-gatewayaccess
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2" # Computer Object Type GUID
    $confExtendedRight = "ffa6f046-ca4b-4feb-b40d-04dfee722543" # Extended Right MS-TS-GatewayAccess GUID
 
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
function Set-ADAclDescriptionComputer(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write Description" - Middle Left
    #ACL Applies To: Descendant Computer objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/a-description
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2" # Computer Object Type GUID
    $confExtendedRight = "bf967950-0de6-11d0-a285-00aa003049e2" # Extended Right Description GUID
 
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
function Set-ADAclComputerDistinguishedNameComputer(){
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
    $confDelegatedObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2" # Computer Object Type GUID
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
function Set-ADAclCommonNameComputer(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write Name" - Middle Right
    #ACL Applies To: Descendant Computer objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/a-cn
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2" # Computer Object Type GUID
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
function Set-ADAclRDNComputer(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write name" - Middle Right
    #ACL Applies To: Descendant Computer objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/a-name
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2" # Computer Object Type GUID
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

#-------------------------------------------------------------------------------------------------
# All objects and descendent objects
#-------------------------------------------------------------------------------------------------

function Set-ADAclCreateComputersAll(){
    #ACL Set in: ADSIEDIT.MSC
    #ACL Checkbox name: "Create Computers" - Top Left
    #ACL Applies To: This object and all descendent objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/c-computer
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "CreateChild"
    $confDelegatedObjectType = "00000000-0000-0000-0000-000000000000" # All Object Type GUID
    $confExtendedRight = "bf967a86-0de6-11d0-a285-00aa003049e2" # Extended Right Create Computer GUID
     
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
function Set-ADAclDeleteComputersAll(){
    #ACL Set in: ADSIEDIT.MSC
    #ACL Checkbox name: "Delete Computers" - Top Left
    #ACL Applies To: This object and all descendent objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/c-computer
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "DeleteChild"
    $confDelegatedObjectType = "00000000-0000-0000-0000-000000000000" # All Object Type GUID
    $confExtendedRight = "bf967a86-0de6-11d0-a285-00aa003049e2" # Extended Right Create Computer GUID
     
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
# End Common Functions
#-------------------------------------------------------------------------------------------------
If ($All -eq $false -and $MoveObjects -eq $false -and $JoinToDomain -eq $false -and $Description -eq $false -and $ResetPasswords -eq $false -and $EnableDisable -eq $false)
{
Write-host "Please specify at least one of the following switches.
-All
-MoveObjects
-JoinToDomain
-Description
-ResetPasswords
-EnableDisable
" -ForegroundColor Red
Break All
}
<#
If ($OrganizationalUnit -notlike "*CN=Computers,DC=*" -and $JoinToDomain -eq $true)
    {
    Write-host "Are you sure you would like to delegate these permissions to this OU instead of the default Computers container?" -ForegroundColor Yellow
    $Response1 = Read-host "(Y or N)"
        If ($Response1 = "N")
            {Break All}
    }

If ($OrganizationalUnit -notlike "*CN=Computers,DC=*" -and $All -eq $true)
    {
    Write-host "Are you sure you would like to delegate these permissions to this OU instead of the default Computers container?" -ForegroundColor Yellow
    $Response2 = Read-host "(Y or N)"
        If ($Response2 = "N")
            {Break All}
    }
#>
If ($MoveObjects -eq $true -or $All -eq $true)
    {
    Write-host "Setting DistinguishedName Computer ACL" -ForegroundColor Yellow
    Set-ADAclComputerDistinguishedNameComputer -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting CN Computer ACL" -ForegroundColor Yellow
    Set-ADAclCommonNameComputer -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting RDN Computer ACL" -ForegroundColor Yellow
    Set-ADAclRDNComputer -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting Create Computer ACL" -ForegroundColor Yellow
    Set-ADAclCreateComputersAll -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting Delete Computer ACL" -ForegroundColor Yellow
    Set-ADAclDeleteComputersAll -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($JoinToDomain -eq $true -or $All -eq $true)
    {
    Write-host "Setting Reset Password Computer ACL" -ForegroundColor Yellow
    Set-ADAclResetPasswordComputer -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting MS-TS-GatewayInfo Computer ACL" -ForegroundColor Yellow    
    Set-ADAclMsTsGatewayInfoComputer -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting Validate Write DNS Host Name Computer ACL" -ForegroundColor Yellow
    Set-ADAclValidateWriteDnsHostNameComputer -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting Validate Write SPN Computer ACL" -ForegroundColor Yellow
    Set-ADAclValidateWriteSPNComputer -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting Account Restrictions Computer ACL" -ForegroundColor Yellow
    Set-ADAclAccountRestrictionsComputer -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($Description -eq $true -or $All -eq $true)
    {
    Write-host "Setting Description Computer ACL" -ForegroundColor Yellow
    Set-ADAclDescriptionComputer -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($ResetPasswords -eq $true -or $All -eq $true)
    {
    Write-host "Setting Reset Password Computer ACL" -ForegroundColor Yellow
    Set-ADAclResetPasswordComputer -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting Change Password Computer ACL" -ForegroundColor Yellow
    Set-ADAclChangePasswordComputer -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($EnableDisable -eq $true -or $All -eq $true)
    {
    Write-host "Setting Account Restrictions Computer ACL" -ForegroundColor Yellow
    Set-ADAclAccountRestrictionsComputer -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

#>
#-------------------------------------------------------------------------------------------------
# END of File
#-------------------------------------------------------------------------------------------------
