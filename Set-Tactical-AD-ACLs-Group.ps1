################################################################################################
# New Script Name : Set-Tactical-AD-ACLs-Group.ps1
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
# Active Directory to allow administrators the ability to administer group objects
# that are NOT Tier 0.
# 
# SCRIPT FUNCTIONS:
# - ACLs specific OUs with a specific group
#
# USAGE:
# Set-Tactical-T1-Group-Admin-ACL.ps1 -OrganizationalUnit "OU=Contoso Groups,OU=Company,DC=Contoso,DC=Com" -DelegationGroupName "Contoso Tier 1 AD Group Admins" -All
# Set-Tactical-T1-Group-Admin-ACL.ps1 -OrganizationalUnit "OU=Contoso Groups,OU=Company,DC=Contoso,DC=Com" -DelegationGroupName "Contoso Tier 1 AD Group Admins" -ManagedBy -MoveObjects -Description
# 
# [-OrganizationalUnit]
#     This parameter is REQUIRED and must have the distinguished name of the OU where the ACLs will be set. (EX: "OU=Contoso Groups,OU=Company,DC=Contoso,DC=Com")
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
# [-Description]
#     This OPTIONAL switch allows modification of the Description attribute
#
# [-Mail]
#     This OPTIONAL switch allows modification of the mail attribute
#
# [-ManagedBy]
#     This OPTIONAL switch allows the ability to change the managedBy attribute and select the checkbox "Manager can update membership list"
#
# [-Notes]
#     This OPTIONAL switch allows modification of the Notes attribute
#
# [-Membership]
#     This OPTIONAL switch grants the ability to add or remove objects from the Members tab
#
#
# RESOURCES:
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-member
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-description
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-mail
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-managedby
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-comment
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-cn
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-name
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-distinguishedname
# https://docs.microsoft.com/en-us/windows/win32/adschema/c-group
#
#-------------------------------------------------------------------------------------------------

param(
[Parameter(Mandatory=$true)]
[string[]] $OrganizationalUnit,

[Parameter(Mandatory=$true)]
[string[]] $DelegationGroupName,

[switch]$All = [bool]$false,
[switch]$MoveObjects = [bool]$false,
[switch]$Description = [bool]$false,
[switch]$Mail = [bool]$false,
[switch]$ManagedBy = [bool]$false,
[switch]$Notes = [bool]$false,
[switch]$Membership = [bool]$false

)

####################################################################
# Functions  
####################################################################
#-------------------------------------------------------------------------------------------------
# Begin Common Functions
#-------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------
# Group ACLs
#-------------------------------------------------------------------------------------------------

function Set-ADAclUpdateMembershipGroup(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write Members" - Middle Left
    #ACL Applies To: Descendant Group objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/a-member
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967a9c-0de6-11d0-a285-00aa003049e2" # Group Object Type GUID
    $confExtendedRight = "bf9679c0-0de6-11d0-a285-00aa003049e2" # Extended Right Membership GUID
     
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
function Set-ADAclDescriptionGroup(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write Description" - Top Left
    #ACL Applies To: Descendant Group objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/a-description
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967a9c-0de6-11d0-a285-00aa003049e2" # Group Object Type GUID
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
function Set-ADAclMailGroup(){
    #ACL Set in: ADSIEDIT.MSC
    #ACL Checkbox name: "Write Mail" - Middle Left
    #ACL Applies To: Descendant Group objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/a-mail
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967a9c-0de6-11d0-a285-00aa003049e2" # Group Object Type GUID
    $confExtendedRight = "bf967961-0de6-11d0-a285-00aa003049e2" # Extended Right Description GUID
     
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
function Set-ADAclManagedByGroup(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Update ManagedBy" - Middle Left
    #ACL Applies To: Descendant Group objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/a-managedby
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967a9c-0de6-11d0-a285-00aa003049e2" # Group Object Type GUID
    $confExtendedRight = "0296c120-40da-11d1-a9c0-0000f80367c1" # Extended Right ManagedBy GUID
     
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
function Set-ADAclModifyPermissionsGroup(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Update ManagedBy" - Top Left
    #ACL Applies To: Descendant Group objects
    #NOTE: This is required to be able to check the box that says "Manager can update membership list"
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteDacl"
    $confDelegatedObjectType = "bf967a9c-0de6-11d0-a285-00aa003049e2" # Group Object Type GUID
    $confExtendedRight = "00000000-0000-0000-0000-000000000000" # Extended Right ManagedBy GUID
     
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
function Set-ADAclNotesGroup(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Update Notes" - Middle Right
    #ACL Applies To: Descendant Group objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/a-comment
    
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967a9c-0de6-11d0-a285-00aa003049e2" # Group Object Type GUID
    $confExtendedRight = "bf96793e-0de6-11d0-a285-00aa003049e2" # Extended Right Notes GUID
     
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
function Set-ADAclCommonNameGroup(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write Name" - Middle Right
    #ACL Applies To: Descendant Group objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/a-cn
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967a9c-0de6-11d0-a285-00aa003049e2" # Group Object Type GUID
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
function Set-ADAclRDNGroup(){
    #ACL Set in: DSA.MSC
    #ACL Checkbox name: "Write name" - Middle Right
    #ACL Applies To: Descendant Group objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/a-name
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967a9c-0de6-11d0-a285-00aa003049e2" # Group Object Type GUID
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
function Set-ADAclGroupDistinguishedNameGroup(){
    #ACL Set in: ADSIEDIT.MSC
    #ACL Checkbox name: "Write Distinguished Name" - Middle Left
    #ACL Applies To: Descendant Group objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/a-distinguishedname
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "WriteProperty"
    $confDelegatedObjectType = "bf967a9c-0de6-11d0-a285-00aa003049e2" # Group Object Type GUID
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

#-------------------------------------------------------------------------------------------------
# All objects and descendent objects
#-------------------------------------------------------------------------------------------------

function Set-ADAclCreateGroupsAll(){
    #ACL Set in: ADSIEDIT.MSC
    #ACL Checkbox name: "Create Groups" - Top Left
    #ACL Applies To: This object and all descendent objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/c-group
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "CreateChild"
    $confDelegatedObjectType = "00000000-0000-0000-0000-000000000000" # All Object Type GUID
    $confExtendedRight = "bf967a9c-0de6-11d0-a285-00aa003049e2" # Extended Right Create Group GUID
                          
     
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
function Set-ADAclDeleteGroupsAll(){
    #ACL Set in: ADSIEDIT.MSC
    #ACL Checkbox name: "Delete Groups" - Top Left
    #ACL Applies To: This object and all descendent objects
    #https://docs.microsoft.com/en-us/windows/win32/adschema/c-group
    param(
    [string]$OrganizationalUnit,
    [string]$DelegationGroupName
    )
    # Configuration Parameters
    $confADRight = "DeleteChild"
    $confDelegatedObjectType = "00000000-0000-0000-0000-000000000000" # All Object Type GUID
    $confExtendedRight = "bf967a9c-0de6-11d0-a285-00aa003049e2" # Extended Right Delete Group GUID
     
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
If ($All -eq $false -and $MoveObjects -eq $false -and $Description -eq $false -and $Mail -eq $false -and $ManagedBy -eq $false -and $Notes -eq $false -and $Membership -eq $false)
{
Write-host "Please specify at least one of the following switches.
-All
-MoveObjects
-Description
-Mail
-ManagedBy
-Notes
-Membership
" -ForegroundColor Red
Break All
}

If ($MoveObjects -eq $true -or $All -eq $true)
    {
    Write-host "Setting DN ACL" -ForegroundColor Yellow
    Set-ADAclGroupDistinguishedNameGroup -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting CN Group ACL" -ForegroundColor Yellow
    Set-ADAclCommonNameGroup -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting RDN Group ACL" -ForegroundColor Yellow
    Set-ADAclRDNGroup -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting Create Group All ACL" -ForegroundColor Yellow
    Set-ADAclCreateGroupsAll -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting Delete Group All ACL" -ForegroundColor Yellow
    Set-ADAclDeleteGroupsAll -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($Description -eq $true -or $All -eq $true)
    {
    Write-host "Setting Write Description Group ACL" -ForegroundColor Yellow
    Set-ADAclDescriptionGroup -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($Mail -eq $true -or $All -eq $true)
    {
    Write-host "Setting Write Mail Group ACL" -ForegroundColor Yellow
    Set-ADAclMailGroup -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($ManagedBy -eq $true -or $All -eq $true)
    {
    Write-host "Setting Write ManagedBy Group ACL" -ForegroundColor Yellow
    Set-ADAclManagedByGroup -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    Write-host "Setting Write Modify Permissions Group ACL" -ForegroundColor Yellow
    Set-ADAclModifyPermissionsGroup -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($Notes -eq $true -or $All -eq $true)
    {
    Write-host "Setting Write Notes Group ACL" -ForegroundColor Yellow
    Set-ADAclNotesGroup -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }

If ($Membership -eq $true -or $All -eq $true)
    {
    Write-host "Setting Update Membership Group ACL" -ForegroundColor Yellow
    Set-ADAclUpdateMembershipGroup -OrganizationalUnit $OrganizationalUnit -DelegationGroupName $DelegationGroupName
    }


#-------------------------------------------------------------------------------------------------
# END of File
#-------------------------------------------------------------------------------------------------
