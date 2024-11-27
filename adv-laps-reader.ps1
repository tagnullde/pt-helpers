# Define the domain and optional computer name
$ComputerName = "LAPSSERVER"   # Set to $null to query all computers
$Domain = "yourdomain.com"      # Replace with your domain name
$LogFilePath = "\\smbshare\laps\laps_passwords.txt"  # Replace with your SMB share path

# Ensure the log file directory exists
if (!(Test-Path -Path (Split-Path $LogFilePath))) {
    Write-Error "Log file directory does not exist: $(Split-Path $LogFilePath)"
    exit
}

# Build the LDAP path
$LDAPPath = "LDAP://$Domain"

# Create a DirectorySearcher object
$Searcher = New-Object System.DirectoryServices.DirectorySearcher
$Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($LDAPPath)

# Set the search filter
if ([string]::IsNullOrEmpty($ComputerName)) {
    # Query all computers with a LAPS password
    $Searcher.Filter = "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))"
} else {
    # Query a specific computer
    $Searcher.Filter = "(&(objectClass=computer)(name=$ComputerName))"
}

# Add the LAPS attribute to the properties to load
$Searcher.PropertiesToLoad.Add("ms-Mcs-AdmPwd") | Out-Null
$Searcher.PropertiesToLoad.Add("name") | Out-Null

# Perform the search
try {
    Write-Host "Searching for LAPS passwords in domain: $Domain"
    $Results = $Searcher.FindAll()

    if ($Results.Count -gt 0) {
        foreach ($Result in $Results) {
            $ComputerName = $Result.Properties["name"][0]
            if ($Result.Properties["ms-Mcs-AdmPwd"] -and $Result.Properties["ms-Mcs-AdmPwd"].Count -gt 0) {
                $LAPSPassword = $Result.Properties["ms-Mcs-AdmPwd"][0]

                # Console output
                Write-Host "==========================================" -ForegroundColor Yellow
                Write-Host "LAPS password for $ComputerName:" -ForegroundColor Green
                Write-Host "$LAPSPassword" -ForegroundColor Cyan
                Write-Host "==========================================" -ForegroundColor Yellow

                # Log output
                $LogEntry = "$ComputerName:$LAPSPassword"
                Add-Content -Path $LogFilePath -Value $LogEntry
            } else {
                Write-Warning "No LAPS password found for $ComputerName. Ensure LAPS is properly configured and you have permissions."
            }
        }
        Write-Host "LAPS passwords have been logged to $LogFilePath"
    } else {
        Write-Warning "No computers found with LAPS passwords. Verify your search parameters."
    }
}
catch {
    Write-Error "An error occurred while retrieving LAPS passwords."
    Write-Error "Error Details: $($_.Exception.Message)"
}
