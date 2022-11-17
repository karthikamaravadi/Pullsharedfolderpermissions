$ParentDirectories = Get-WmiObject -Class win32_share | Select Path -ExpandProperty Path
$ParentDirectories

foreach ($Folder in $ParentDirectories) {
    if($Folder -ne $nullOrEmpty){
        $secure=get-acl $Folder
        foreach ($item in $secure.Access) {
            if ( ($item.IdentityReference -match "NT AUTHORITY\\SYSTEM"   ) -or
                 ($item.IdentityReference -match "NT AUTHORITY\\Authenticated Users"  ) -or
                 ($item.IdentityReference -match "NT AUTHORITY\\NETWORK"  ) -or
                 ($item.IdentityReference -match "BUILTIN\\Administrators") -or
                 ($item.IdentityReference -match "BUILTIN\\Users"   ) )  {
                 if ($item.FileSystemRights.tostring() -match "Read|ReadandExecute|Write|Special Permissions|FullControl|Modify|Change") {
                   
                   $IdentityReferencename=($item.IdentityReference)
                   $AccessControlType= ($item.AccessControlType)
                   $FileSystemRights= ($item.FileSystemRights)
                   $IsInherited= ($item.IsInherited)
                   $InheritanceFlags= ($item.InheritanceFlags)
                   $PropagationFlags= ($item.PropagationFlags)

                   $path
                   $Folder
                   $AccessControlType
                   $FileSystemRights 
                   $IsInherited
                   $InheritanceFlags
                   $PropagationFlags
                   
                   $report = New-Object psobject
                   $report | Add-Member -MemberType NoteProperty -name Path             -value $path
                   $report | Add-Member -MemberType NoteProperty -name FolderName     -value $Folder.ToString()
                   $report | Add-Member -MemberType NoteProperty -name IdentityReferencename     -value $IdentityReferencename 
                   $report | Add-Member -MemberType NoteProperty -name AccessControlType     -value $AccessControlType 
                   $report | Add-Member -MemberType NoteProperty -name FileSystemRights     -value $FileSystemRights 
                   $report | Add-Member -MemberType NoteProperty -name InheritanceFlags     -value $InheritanceFlags  
                   $report | Add-Member -MemberType NoteProperty -name PropagationFlags     -value $PropagationFlags
                   $report | export-csv "NetworkShareAccess.csv" -Append -NoClobber
                   
                }
            } else {         
                
                 
            }

        }
    }
    }

    foreach ($Folder in $ParentDirectories) {
    if($Folder -ne $nullOrEmpty){
        $secure=get-acl $Folder
        foreach ($item in $secure.Access) {
            if ( ($item.IdentityReference -match "NT AUTHORITY\\Authenticated Users"  ) -or
                 ($item.IdentityReference -match "BUILTIN\\Users"   ) )  {
                 if ($item.FileSystemRights.tostring() -match "Write|Special Permissions|FullControl|Modify|Change") {
                   
                   $IdentityReferencename=($item.IdentityReference)
                   $AccessControlType= ($item.AccessControlType)
                   $FileSystemRights= ($item.FileSystemRights)
                   $IsInherited= ($item.IsInherited)
                   $InheritanceFlags= ($item.InheritanceFlags)
                   $PropagationFlags= ($item.PropagationFlags)

                   $path
                   $Folder
                   $AccessControlType
                   $FileSystemRights 
                   $IsInherited
                   $InheritanceFlags
                   $PropagationFlags
                   
                   $report = New-Object psobject
                   $report | Add-Member -MemberType NoteProperty -name Path             -value $path
                   $report | Add-Member -MemberType NoteProperty -name FolderName     -value $Folder.ToString()
                   $report | Add-Member -MemberType NoteProperty -name IdentityReferencename     -value $IdentityReferencename 
                   $report | Add-Member -MemberType NoteProperty -name AccessControlType     -value $AccessControlType 
                   $report | Add-Member -MemberType NoteProperty -name FileSystemRights     -value $FileSystemRights 
                   $report | Add-Member -MemberType NoteProperty -name InheritanceFlags     -value $InheritanceFlags  
                   $report | Add-Member -MemberType NoteProperty -name PropagationFlags     -value $PropagationFlags
                   $report | export-csv "NetworkShareAccessAlert.csv" -Append -NoClobber
                   
                }
            } else {         
                
                 
            }

        }
    }
    }