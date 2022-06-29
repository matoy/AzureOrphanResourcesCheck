using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request."

#####
#
# TT 20211215 AzureOrphanResourcesCheck
# This script is executed by an Azure Function App
# It checks if there are some orphan resources in a specific subscription
#
# It can be triggered by any monitoring system to get the results and status
#
# "subscriptionid" GET parameter allows to specify the subscription to check
#
# "exclusion" GET parameter can be passed with comma separated resource names
# that should be excluded from the check
#
# used AAD credentials read access to the specified subscription
#
#
#####

$exclusion = [string] $Request.Query.exclusion
if (-not $exclusion) {
    $exclusion = ""
}

$exclusiontypes = [string] $Request.Query.exclusiontypes
if (-not $exclusiontypes) {
    $exclusiontypes = ""
}

$subscriptionid = [string] $Request.Query.Subscriptionid
if (-not $subscriptionid) {
    $subscriptionid = "00000000-0000-0000-0000-000000000000"
}

# init variables
$signature = $env:Signature
[System.Collections.ArrayList] $exclusionsTab = $exclusion.split(",")
foreach ($current in ($env:AzureOrphanResourcesCheckGlobalExceptions).split(",")) {
	$exclusionsTab.Add($current)
}
$alert = 0
$body_critical = ""
$orphanResults = @()

$exclusiontypesTab = $exclusiontypes.split(",")

# connect with SPN account creds
$tenantId = $env:TenantId
$applicationId = $env:AzureOrphanResourcesCheckApplicationID
$password = $env:AzureOrphanResourcesCheckSecret
$securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $applicationId, $securePassword
Connect-AzAccount -Credential $credential -Tenant $tenantId -ServicePrincipal

# get token
$azContext = Get-AzContext
$azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
$token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)

# create http headers
$headers = @{}
$headers.Add("Authorization", "bearer " + "$($Token.Accesstoken)")
$headers.Add("contenttype", "application/json")

Try {
	# disks
	if ($exclusiontypesTab -notcontains "disks") {
		$uri = "https://management.azure.com/subscriptions/$subscriptionid/providers/Microsoft.Compute/disks?api-version=2021-04-01"
		$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
		$disks = $results.value | where {$_.properties.diskState -eq "Unattached" -and $exclusionsTab -notcontains $_.Name}
		while ($results.nextLink) {
			$uri = $results.nextLink
			$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
			$disks += $results.value | where {$_.properties.diskState -eq "Unattached" -and $exclusionsTab -notcontains $_.Name}
		}
		foreach ($disk in $disks) {
			$currentItem = [pscustomobject]@{
				ResourceGroup = $disk.id.Split("/")[4]
				AppOwnerTag = $disk.tags.appOwner
				ResourceType  = "ManagedDisk"
				ResourceName  = $disk.Name
			}
			$orphanResults += $currentItem
		}
	}

	# nics
	if ($exclusiontypesTab -notcontains "nics") {
		$uri = "https://management.azure.com/subscriptions/$subscriptionid/providers/Microsoft.Network/networkInterfaces?api-version=2021-05-01"
		$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
		$nics = $results.value | where {$_.properties.VirtualMachine.Count -eq 0 -and (-not $_.properties.privateEndpoint) -and $exclusionsTab -notcontains $_.Name}
		while ($results.nextLink) {
			$uri = $results.nextLink
			$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
			$nics += $results.value | where {$_.properties.VirtualMachine.Count -eq 0 -and (-not $_.properties.privateEndpoint) -and $exclusionsTab -notcontains $_.Name}
		}
		foreach ($nic in $nics) {
			$currentItem = [pscustomobject]@{
				ResourceGroup = $nic.id.Split("/")[4]
				AppOwnerTag = $nic.tags.appOwner
				ResourceType  = "NicInterface"
				ResourceName  = $nic.Name
			}
			$orphanResults += $currentItem
		}
	}

	# nsgs
	if ($exclusiontypesTab -notcontains "nsgs") {
		$uri = "https://management.azure.com/subscriptions/$subscriptionid/providers/Microsoft.Network/networkSecurityGroups?api-version=2021-05-01"
		$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
		$nsgs = $results.value | where {$_.properties.subnets.Count -eq 0 -and $_.properties.subnets.NetworkInterface.Count -eq 0 -and $_.properties.networkInterfaces.Count -eq 0 -and $exclusionsTab -notcontains $_.Name}
		while ($results.nextLink) {
			$uri = $results.nextLink
			$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
			$nsgs += $results.value | where {$_.properties.subnets.Count -eq 0 -and $_.properties.subnets.NetworkInterface.Count -eq 0 -and $_.properties.networkInterfaces.Count -eq 0 -and $exclusionsTab -notcontains $_.Name}
		}
		foreach ($nsg in $nsgs) {
			$currentItem = [pscustomobject]@{
				ResourceGroup = $nsg.id.Split("/")[4]
				AppOwnerTag = $nsg.tags.appOwner
				ResourceType  = "NetworkSecurityGroup"
				ResourceName  = $nsg.Name
			}
			$orphanResults += $currentItem
		}
	}

	# pub ips
	if ($exclusiontypesTab -notcontains "pubips") {
		$uri = "https://management.azure.com/subscriptions/$subscriptionid/providers/Microsoft.Network/publicIPAddresses?api-version=2021-05-01"
		$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
		$ips = $results.value | where {$_.properties.ipconfiguration.Count -eq 0 -and $exclusionsTab -notcontains $_.Name}
		while ($results.nextLink) {
			$uri = $results.nextLink
			$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
			$ips += $results.value | where {$_.properties.ipconfiguration.Count -eq 0 -and $exclusionsTab -notcontains $_.Name}
		}
		foreach ($ip in $ips) {
			$currentItem = [pscustomobject]@{
				ResourceGroup = $ip.id.Split("/")[4]
				AppOwnerTag = $ip.tags.appOwner
				ResourceType  = "PublicIp"
				ResourceName  = $ip.Name
			}
			$orphanResults += $currentItem
		}
	}

	# routes
	if ($exclusiontypesTab -notcontains "routes") {
		$uri = "https://management.azure.com/subscriptions/$subscriptionid/providers/Microsoft.Network/routeTables?api-version=2021-05-01"
		$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
		$routes = $results.value | where {$_.properties.routes.Count -eq 0 -and $exclusionsTab -notcontains $_.Name}
		while ($results.nextLink) {
			$uri = $results.nextLink
			$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
			$routes += $results.value | where {$_.properties.routes.Count -eq 0 -and $exclusionsTab -notcontains $_.Name}
		}
		foreach ($route in $routes) {
			$currentItem = [pscustomobject]@{
				ResourceGroup = $route.id.Split("/")[4]
				AppOwnerTag = $route.tags.appOwner
				ResourceType  = "RouteTable"
				ResourceName  = $route.Name
			}
			$orphanResults += $currentItem
		}
	}

	# snapshots
	if ($exclusiontypesTab -notcontains "snapshots") {
		$uri = "https://management.azure.com/subscriptions/$subscriptionid/providers/Microsoft.Compute/snapshots?api-version=2021-04-01"
		$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
		$snapshots = $results.value | where {$exclusionsTab -notcontains $_.Name}
		while ($results.nextLink) {
			$uri = $results.nextLink
			$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
			$snapshots += $results.value | where {$exclusionsTab -notcontains $_.Name}
		}
		foreach ($snapshot in $snapshots) {
			$currentItem = [pscustomobject]@{
				ResourceGroup = $snapshot.id.Split("/")[4]
				AppOwnerTag = $snapshot.tags.appOwner
				ResourceType  = "Snapshot"
				ResourceName  = $snapshot.Name
			}
			$orphanResults += $currentItem
		}
	}

	# VM Hybrid Use Benefit & finopsstartstop tag
	# ref: https://www.isjw.uk/post/azure/check-azure-hybrid-benefits-with-powershell/
	$uri = "https://management.azure.com/subscriptions/$subscriptionid/providers/Microsoft.Compute/virtualMachines?api-version=2021-07-01"
	$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
	$vms = $results.value | where {$_.properties.osProfile.windowsConfiguration -and (-not $_.properties.licenseType) -and $exclusionsTab -notcontains $_.Name}
	$vmsNoFinopsTag = $results.value | where {!$_.tags.finopsstartstop -and $exclusionsTab -notcontains $_.Name}
	while ($results.nextLink) {
		$uri = $results.nextLink
		$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
		$vms += $results.value | where {$_.properties.osProfile.windowsConfiguration -and (-not $_.properties.licenseType) -and $exclusionsTab -notcontains $_.Name}
		$vmsNoFinopsTag += $results.value | where {!$_.tags.finopsstartstop -and $exclusionsTab -notcontains $_.Name}
	}
	if ($exclusiontypesTab -notcontains "vmhub") {
		foreach ($vm in $vms) {
			$currentItem = [pscustomobject]@{
				ResourceGroup = $vm.id.Split("/")[4]
				AppOwnerTag = $vm.tags.appOwner
				ResourceType  = "VmHybridBenefits"
				ResourceName  = $vm.Name
			}
			$orphanResults += $currentItem
		}
	}
	if ($exclusiontypesTab -notcontains "finopstag") {
		foreach ($vm in $vmsNoFinopsTag) {
			$currentItem = [pscustomobject]@{
				ResourceGroup = $vm.id.Split("/")[4]
				AppOwnerTag = $vm.tags.appOwner
				ResourceType  = "No finopsstartstop tag"
				ResourceName  = $vm.Name
			}
			$orphanResults += $currentItem
		}
	}
	
	# SQL VM Hybrid Use Benefit
	if ($exclusiontypesTab -notcontains "sqlvmhub") {
		$uri = "https://management.azure.com/subscriptions/$subscriptionid/providers/Microsoft.SqlVirtualMachine/sqlVirtualMachines?api-version=2017-03-01-preview"
		$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
		$sqlvms = $results.value | where {$_.properties.sqlServerLicenseType -ne "AHUB" -and $_.properties.sqlImageSku -ne "Express" -and $exclusionsTab -notcontains $_.Name}
		while ($results.nextLink) {
			$uri = $results.nextLink
			$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
			$sqlvms += $results.value | where {$_.properties.sqlServerLicenseType -ne "AHUB" -and $_.properties.sqlImageSku -ne "Express" -and $exclusionsTab -notcontains $_.Name}
		}
		foreach ($sqlvm in $sqlvms) {
			$currentItem = [pscustomobject]@{
				ResourceGroup = $sqlvm.id.Split("/")[4]
				AppOwnerTag = $sqlvm.tags.appOwner
				ResourceType  = "SqlVmHybridBenefits"
				ResourceName  = $sqlvm.Name
			}
			$orphanResults += $currentItem
		}
	}
	
	# SQL database / elastic pool Hybrid Use Benefit
	if ($exclusiontypesTab -notcontains "sqlhub") {
		$uri = "https://management.azure.com/subscriptions/$subscriptionid/providers/Microsoft.Sql/servers?api-version=2021-02-01-preview"
		$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
		$sqlservers = $results.value
		while ($results.nextLink) {
			$uri = $results.nextLink
			$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
			$sqlvms += $results.value
		}
		foreach ($sqlserver in $sqlservers) {
			$uri = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$($sqlserver.id.Split("/")[4])/providers/Microsoft.Sql/servers/$($sqlserver.name)/databases?api-version=2021-08-01-preview"
			$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
			$sqldatabases = $results.value | where {$_.properties.currentSku.name -ne "ElasticPool" -and $_.properties.licenseType -eq "LicenseIncluded" -and $exclusionsTab -notcontains $_.Name}
			while ($results.nextLink) {
				$uri = $results.nextLink
				$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
				$sqldatabases += $results.value | where {$_.properties.currentSku.name -ne "ElasticPool" -and $_.properties.licenseType -eq "LicenseIncluded" -and $exclusionsTab -notcontains $_.Name}
			}
			$uri = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$($sqlserver.id.Split("/")[4])/providers/Microsoft.Sql/servers/$($sqlserver.name)/elasticPools?api-version=2021-02-01-preview"
			$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
			$sqlpools = $results.value | where {$_.properties.licenseType -eq "LicenseIncluded" -and $exclusionsTab -notcontains $_.Name}
			while ($results.nextLink) {
				$uri = $results.nextLink
				$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers | where {$_.properties.licenseType -eq "LicenseIncluded" -and $exclusionsTab -notcontains $_.Name}
				$sqlpools += $results.value
			}
		}
		foreach ($sqldatabase in $sqldatabases) {
			$currentItem = [pscustomobject]@{
				ResourceGroup = $sqldatabase.id.Split("/")[4]
				AppOwnerTag = $sqldatabase.tags.appOwner
				ResourceType  = "SqlDatabaseHybridBenefits"
				ResourceName  = $sqldatabase.Name
			}
			$orphanResults += $currentItem
		}
		foreach ($sqlpool in $sqlpools) {
			$currentItem = [pscustomobject]@{
				ResourceGroup = $sqlpool.id.Split("/")[4]
				AppOwnerTag = $sqlpool.tags.appOwner
				ResourceType  = "SqlElasticPoolHybridBenefits"
				ResourceName  = $sqlpool.Name
			}
			$orphanResults += $currentItem
		}
	}
}
Catch {
    if($_.ErrorDetails.Message) {
		$msg = ($_.ErrorDetails.Message | ConvertFrom-Json).error
		$body_critical += $msg.code + ": " + $msg.message + "`n"
		$alert++
    }
}

$alert += $orphanResults.count
$body_critical += ($orphanResults | out-string)

# add ending status and signature
if ($alert) {
    $body = "Status CRITICAL - Found $alert orphan ressource(s)!`n$body_critical$signature"
}
else {
    $body = "Status OK - No orphan resource`n`n$signature"
}
Write-Host $body

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = $body
})
