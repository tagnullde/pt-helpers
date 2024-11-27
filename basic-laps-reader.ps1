# Define the domain and computer name
$ComputerName = "LAPSSERVER"
$Domain = "yourdomain.com"  # Replace with your domain name

# Build the LDAP path
$LDAPPath = "LDAP://$Domain"

# Create a DirectorySearcher object
$Searcher = New-Object System.DirectoryServices.DirectorySearcher
$Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($LDAPPath)
$Searcher.Filter = "(&(objectClass=computer)(name=$ComputerName))"

# Add the LAPS attribute to the properties to load
$Searcher.PropertiesToLoad.Add("ms-Mcs-AdmPwd") | Out-Null

# Perform the search
try {
    Write-Host "Searching for computer: $ComputerName in domain: $Domain"
    $Result = $Searcher.FindOne()

    if ($Result) {
        Write-Host "Computer object found in Active Directory."
        if ($Result.Properties["ms-Mcs-AdmPwd"] -and $Result.Properties["ms-Mcs-AdmPwd"].Count -gt 0) {
            $LAPSPassword = $Result.Properties["ms-Mcs-AdmPwd"][0]
            Write-Output "LAPS password for ${ComputerName}: ${LAPSPassword}"
        } else {
            Write-Warning "No LAPS password found for ${ComputerName}. Ensure LAPS is properly configured for this machine and that you have permissions to read the ms-Mcs-AdmPwd attribute."
        }
    } else {
        Write-Warning "Computer object not found in Active Directory. Verify the computer name and domain."
    }
}
catch {
    Write-Error "An error occurred while retrieving the LAPS password."
    Write-Error "Error Details: $($_.Exception.Message)"
    Write-Debug "Full Error: $($_.Exception)"
}
