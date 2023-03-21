[CmdletBinding()]
param (
    [Parameter(Mandatory=$true,HelpMessage="Please provide the name of the xml file to process.")]
    [string]$filepath
)

# Read the xml file
[xml]$xml = Get-Content -Path $filepath

# Loop through each user node
foreach ($user in $xml.users.user) {
    # Create the OU if it does not exist
    $ou = $user.ou
    if (-not (Get-ADOrganizationalUnit -Filter {Name -eq $ou})) {
        New-ADOrganizationalUnit -Name $ou -Path "DC=mydomain,DC=com"
        Write-Host "Created OU $ou"
    }

    # Create the user account
    $account = $user.account
    $password = ConvertTo-SecureString $user.password -AsPlainText -Force
    $props = @{
        Name = $account
        DisplayName = $user.displayName
        GivenName = $user.givenName
        Surname = $user.sn
        EmailAddress = $user.mail
        AccountPassword = $password
        Enabled = $true
        ChangePasswordAtLogon = $true
        Path = "OU=$ou,DC=mydomain,DC=com"
    }
    try {
        New-ADUser @props
        Write-Host "Created user $account"
    }
    catch {
        Write-Host "Failed to create user $account : $_" -ForegroundColor Red
    }

    # Add the user to the global security groups
    foreach ($group in $user.memberOf) {
        if (-not (Get-ADGroup -Filter {Name -eq $group})) {
            New-ADGroup -Name $group -GroupScope Global -Path "DC=mydomain,DC=com"
            Write-Host "Created group $group"
        }
        Add-ADGroupMember -Identity $group -Members $account
        Write-Host "Added $account to group $group"
    }
}
