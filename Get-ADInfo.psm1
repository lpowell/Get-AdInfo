<#
 .Synopsis
  Cmdlet for gathering AD User information.

 .Description
  Get-UserInfo lists important information about Active Directory Users. Includes membership information. 

 .Parameter Name
  Name of an AD User.

 .Example 
   # List information about a group
   Get-UserInfo -Name Administrator

 .Example
   # List information about all groups
   Get-UserInfo -Name *

 .Link
   
#>
function Get-UserInfo{
  param($Name)
    if($Name -eq "*"){
        $User = Get-ADUser -Filter * -properties *
    }elseif($Name){
        $User = Get-ADUser $Name -properties *
    }else{
        $User = Get-ADUser -Filter * -properties *
    }
    foreach($x in $User){
        $MemberOf = (Get-ADUser $x -Properties *).MemberOf | %{ ($_ -split "," -like "CN=*" -split "=")[1]}
        $UserInfo = New-Object PSObject -Property $([ordered]@{
            SAM       = $x.SamAccountName
            SID       = $x.SID
            CN        = $x.CN
            DN        = $x.DistinguishedName
            Created   = $x.Created
            Changed   = $x.WhenChanged
            Home      = $x.HomeDirectory
            LastLogon = $x.LastLogonDate
            LastFailedLogon = $x.LastBadPasswordAttempt
            LogonCount = $x.LogonCount
            LockedOut = $x.LockedOut
            PassLastSet = $x.PasswordLastSet
            PassExpired = $x.PasswordExpired
            PasswordNeverExpires = $x.PasswordNeverExpires
            MemberOf    = $MemberOf
          })
        $UserInfo
    }
}

<#
 .Synopsis
  Cmdlet for gathering AD Organizational Unit information.

 .Description
  Get-OUInfo lists important information about Active Directory Organizational Units. Includes linked Users, Groups, Computers, and Group Policy Objects. 

 .Parameter Name
  Name of an Organizational Unit.

 .Example 
   # List information about an orgnaizational unit
   Get-OUInfo -Name Test-OU

 .Example
   # List information about all organizational units
   Get-OUInfo -Name *

 .Example
   # List all users in an orgainzational unit
   Get-OUInfo -Name Test-OU | Select -ExpandProperty Users

 .Link
   
#>
function Get-OUInfo{
    param($Name)
    $ErrorActionPreference = "SilentlyContinue"
    if($Name -eq "*"){
        $OU = Get-ADOrganizationalUnit -filter * -properties *
        }elseif($Name){
            $OU = Get-ADOrganizationalUnit -filter 'Name -like $Name' -properties *
        }else{
            $OU = Get-ADOrganizationalUnit -filter * -properties *
        }
    foreach($x in $OU){
        $Users = Get-ADUser -filter * -SearchBase $x.DistinguishedName
        $Computers = Get-ADComputer -filter * -SearchBase $x.DistinguishedName
        $Groups = Get-ADGroup -filter * -SearchBase $x.DistinguishedName
        $OUInfo = New-Object PSObject -Property $([ordered]@{
            Name        = $x.Name
            CN          = $x.CanonicalName
            DN          = $x.DistinguishedName
            ManagedBy   = $x.ManagedBy
            Created     = $x.Created
            Changed     = $x.WhenChanged
            Description = $x.Description
            GPO         = $x.LinkedGroupPolicyObjects
            Users       = $Users
            Groups      = $Groups
            Computers   = $Computers
            })
        $OUInfo
    }
}

<#
 .Synopsis
  Cmdlet for gathering AD Group information.

 .Description
  Get-GroupInfo lists important information about Active Directory Groups. Includes membership information. 

 .Parameter Name
  Name of an AD Group.

 .Example 
   # List information about a group
   Get-GroupInfo -Name Administrators

 .Example
   # List information about all groups
   Get-GroupInfo -Name *

 .Link
   
#>
function Get-GroupInfo{
    param($Name)
    if($Name -eq "*"){
        $Group = Get-AdGroup -Filter * -Properties *
    }elseif($Name){
        $Group = Get-ADGroup "$Name" -Properties *
    }else{
        $Group = Get-AdGroup -Filter * -Properties *
    }
    foreach($x in $Group){
        $GroupMembers = Get-ADGroupMember $x.Name | % SamAccountName
        $MemberOf = (Get-AdGroup $x.Name -properties *).MemberOf 
        $GroupInfo = New-Object PSObject -Property $([ordered]@{
          Group     = $x.CN
          SID       = $x.SID
          DN        = $x.DistinguishedName
          Created   = $x.Created
          Changed   = $x.WhenChanged
          Description = $x.Description
          MemberOf  = $MemberOf
          GroupMembers = $GroupMembers
        })
        $GroupInfo
    }
}

<#
 .Synopsis
  Cmdlet for gathering AD Computer information.

 .Description
  Get-ADComputerInfo lists important information about Active Directory Computers. Includes membership and address information. 

 .Parameter Name
  Name of an AD Computer.

 .Example 
   # List information about a computer
   Get-ADComputerInfo -Name WIN-3JT8OEGQT3D

 .Example
   # List information about all computers
   Get-ADComputerInfo -Name *

 .Link
   
#>
function Get-ADComputerInfo{
    param($Name)
    $ErrorActionPreference = 'SilentlyContinue'
    if($Name -eq "*"){
        $Computer = Get-ADComputer -filter * -properties *
        }elseif($Name){
            $Computer = Get-ADComputer -Identity $Name -properties *
        }else{
            $Computer = Get-ADComputer -filter * -properties *
        }
    foreach($x in $Computer){
        Try{
                # $Zone = Get-ADComputer -Identity $x.Name -Property CanonicalName |select -ExpandProperty CanonicalName | %{($_ -split "/")[0]}
                # $ComputerIP = (Get-DnsServerResourceRecord -ZoneName $Zone -Name $x.Name -RRType A).RecordData.IPv4Address.IPAddressToSTring
                $ComputerIP = Resolve-DnsName $x.Name -ErrorAction Stop -ErrorVariable e
            }catch{
                $ComputerIP = $null
                # $ComputerIP = @{IP4Address=((($e -split "Stop" -like "*DNS*" -split "at")[0]).Trim(": "));IP6Address=((($e -split "Stop" -like "*DNS*" -split "at")[0]).Trim(": "))}
            }
        $PrimaryGroup = (($x).PrimaryGroup -split "," -like "CN=*" -split "=")[1]
        $MemberOf = (($x).MemberOf -split "," -like "CN=*" -split "=")[1]
        $ManagedBy = (($x).ManagedBy -split "," -like "CN=*" -split "=")[1] 

        $ADComputerInfo = New-Object PSObject -Property $([ordered]@{
          Name          = $x.Name
          OperatingSystem = $x.OperatingSystem
          SID           = $x.SID
          DN            = $x.DistinguishedName
          Created       = $x.Created
          Changed       = $x.WhenChanged
          Enabled       = $x.Enabled
          DNSHostName   = $x.DNSHostName
          IPv4Address   = $ComputerIP.IP4Address
          IPv6Address   = $ComputerIP.IP6Address
          LastLogon     = $x.LastLogonDate
          LastFailedLogon = $x.LastBadPasswordAttempt
          LockedOut = $x.LockedOut
          PassLastSet = $x.PasswordLastSet
          PassExpired = $x.PasswordExpired
          PasswordNeverExpires = $x.PasswordNeverExpires
          PrimaryGroup  = $PrimaryGroup
          MemberOf      = $MemberOf
          ManagedBy     = $ManagedBy
        })
        $ADComputerInfo
    }
}