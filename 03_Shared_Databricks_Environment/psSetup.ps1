function RefreshTokens() {
    #Copy external blob content
    $global:powerbitoken = ((az account get-access-token --resource https://analysis.windows.net/powerbi/api) | ConvertFrom-Json).accessToken
    $global:graphToken = ((az account get-access-token --resource https://graph.microsoft.com) | ConvertFrom-Json).accessToken
    $global:managementToken = ((az account get-access-token --resource https://management.azure.com) | ConvertFrom-Json).accessToken
    $global:fabric = ((az account get-access-token --resource https://api.fabric.microsoft.com) | ConvertFrom-Json).accessToken
}

function Check-HttpRedirect($uri) {
    $httpReq = [system.net.HttpWebRequest]::Create($uri)
    $httpReq.Accept = "text/html, application/xhtml+xml, */*"
    $httpReq.method = "GET"   
    $httpReq.AllowAutoRedirect = $false;

    #use them all...
    #[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Ssl3 -bor [System.Net.SecurityProtocolType]::Tls;

    $global:httpCode = -1;

    $response = "";            

    try {
        $res = $httpReq.GetResponse();

        $statusCode = $res.StatusCode.ToString();
        $global:httpCode = [int]$res.StatusCode;
        $cookieC = $res.Cookies;
        $resHeaders = $res.Headers;  
        $global:rescontentLength = $res.ContentLength;
        $global:location = $null;
                            
        try {
            $global:location = $res.Headers["Location"].ToString();
            return $global:location;
        }
        catch {
        }

        return $null;

    }
    catch {
        $res2 = $_.Exception.InnerException.Response;
        $global:httpCode = $_.Exception.InnerException.HResult;
        $global:httperror = $_.exception.message;

        try {
            $global:location = $res2.Headers["Location"].ToString();
            return $global:location;
        }
        catch {
        }
    } 

    return $null;
}

Set-ExecutionPolicy Unrestricted

# Install the Az module
Install-Module -Name Az -Force -AllowClobber
Import-Module -Name Az

#The below code snippet will help to login with Username and password to avoid interactive login.
$userCred = read-host "Enter your username";
$passwordCred = read-host "Enter your password";

# Install-Module Az 
az login -u $userCred -p $passwordCred

$subs = Get-AzSubscription | Select-Object -ExpandProperty Name
 if ($subs.GetType().IsArray -and $subs.length -gt 1) {
     $subOptions = [System.Collections.ArrayList]::new()
  for ($subIdx = 0; $subIdx -lt $subs.length; $subIdx++) {
      $opt = New-Object System.Management.Automation.Host.ChoiceDescription "$($subs[$subIdx])", "Selects the $($subs[$subIdx]) subscription."   
       $subOptions.Add($opt)
   }     $selectedSubIdx = $host.ui.PromptForChoice('Enter the desired Azure Subscription for this lab', 'Copy and paste the name of the subscription to make your choice.', $subOptions.ToArray(), 0)
    $selectedSubName = $subs[$selectedSubIdx]
     Write-Host "Selecting the subscription : $selectedSubName "
    $title = 'Subscription selection'
     $question = 'Are you sure you want to select this subscription for this lab?'
}

$subscriptionId = (az account show --query 'id' -o tsv)

$AzCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($userCred, (ConvertTo-SecureString -AsPlainText -Force -String $passwordCred))
Connect-AzAccount -Credential $AzCredential -Subscription $subscriptionId 

$starttime = get-date

#download azcopy command
if ([System.Environment]::OSVersion.Platform -eq "Unix") {
    $azCopyLink = Check-HttpRedirect "https://aka.ms/downloadazcopy-v10-linux"

    if (!$azCopyLink) {
        $azCopyLink = "https://azcopyvnext.azureedge.net/release20200709/azcopy_linux_amd64_10.5.0.tar.gz"
    }

    Invoke-WebRequest $azCopyLink -OutFile "azCopy.tar.gz"
    tar -xf "azCopy.tar.gz"
    $azCopyCommand = (Get-ChildItem -Path ".\" -Recurse azcopy).Directory.FullName

    if ($azCopyCommand.count -gt 1) {
        $azCopyCommand = $azCopyCommand[0];
    }

    cd $azCopyCommand
    chmod +x azcopy
    cd ..
    $azCopyCommand += "\azcopy"
} else {
    $azCopyLink = Check-HttpRedirect "https://aka.ms/downloadazcopy-v10-windows"

    if (!$azCopyLink) {
        $azCopyLink = "https://azcopyvnext.azureedge.net/release20200501/azcopy_windows_amd64_10.4.3.zip"
    }

    Invoke-WebRequest $azCopyLink -OutFile "azCopy.zip"
    Expand-Archive "azCopy.zip" -DestinationPath ".\" -Force
    $azCopyCommand = (Get-ChildItem -Path ".\" -Recurse azcopy.exe).Directory.FullName

    if ($azCopyCommand.count -gt 1) {
        $azCopyCommand = $azCopyCommand[0];
    }

    $azCopyCommand += "\azcopy"
}

Start-Transcript -Path ./log.txt
$subscriptionId = (Get-AzContext).Subscription.Id
$signedinusername = az ad signed-in-user show | ConvertFrom-Json
$signedinusername = $signedinusername.userPrincipalName

# Check if the user has Owner role on the subscription
Add-Content log.txt "Check if the user has Owner role on the subscription..."
Write-Host "Check if the user has Owner role on the subscription..."

$roleAssignments = az role assignment list --assignee $signedinusername --subscription $subscriptionId | ConvertFrom-Json
$hasOwnerRole = $roleAssignments | Where-Object { $_.roleDefinitionName -eq "Owner" }

if ($null -ne $hasOwnerRole) {
    Write-Host "User has Owner permission on the subscription. Proceeding..." -ForegroundColor Green
} else {
    Write-Host "User does not have Owner permission on the subscription. Deployment will fail. Would you still like to continue? (Yes/No)" -ForegroundColor Red

    $response = Read-Host
    if ($response -eq "Y" -or $response -eq "Yes") {
        Write-Host "Proceeding with deployment..."
    } else {
        Write-Host "Aborting deployment."
        exit
    }
}

## Checking Requirements
Add-Content log.txt "----------------Checking pre-requisites------------------"
Write-host "----------------Checking pre-requisites------------------"
Write-Host "Registering resource providers..."
# List of resource providers to check and register if not registered
$resourceProviders = @(
    "Microsoft.Databricks",
    "Microsoft.SQL",
    "Microsoft.Storage",
    "Microsoft.Compute"
)

# Loop through each resource provider
foreach ($provider in $resourceProviders) {
    # Get the registration state of the resource provider
    $providerState = (Get-AzResourceProvider -ProviderNamespace $provider).RegistrationState

    # Check if the resource provider is not registered
    if ($providerState -ne "Registered") {
        Write-Host "Registering resource provider: $provider" -ForegroundColor Yellow
        # Register the resource provider
        Register-AzResourceProvider -ProviderNamespace $provider
    } else {
        Write-Host "Resource provider $provider is already registered" -ForegroundColor Green
    }
}

[string]$suffix = -join ((48..57) + (97..122) | Get-Random -Count 7 | % { [char]$_ })
$rgName = "rg-fabric-adb-$suffix"
$Region = read-host "Enter the region for deployment"
$tenantId = (Get-AzContext).Tenant.Id
$databricks_workspace_name = "adb-fabric-$suffix"
$databricks_managed_resource_group_name = "rg-managed-adb-$suffix"
$userAssignedIdentities_ami_databricks_build = "ami-databricks-$suffix"
$dataLakeAccountName = "stfabricadb$suffix"
$databricksconnector = "access-adb-connector-$suffix"
$keyVaultName = "kv-adb-$suffix"
$containerName = "containerdatabricksmetastore"

Write-Host "Deploying Resources on Microsoft Azure Started ..."
Write-Host "Creating $rgName resource group in $Region ..."
New-AzResourceGroup -Name $rgName -Location $Region | Out-Null
Write-Host "Resource group $rgName creation COMPLETE"

Write-Host "Creating resources in $rgName..."
New-AzResourceGroupDeployment -ResourceGroupName $rgName `
-TemplateFile "mainTemplate.json" `
-Mode Complete `
-location $Region `
-databricks_workspace_name $databricks_workspace_name `
-databricks_managed_resource_group_name $databricks_managed_resource_group_name `
-userAssignedIdentities_ami_databricks_build $userAssignedIdentities_ami_databricks_build `
-storage_account_name $dataLakeAccountName `
-vaults_kv_databricks_prod_name $keyVaultName `
-Force

$templatedeployment = Get-AzResourceGroupDeployment -Name "mainTemplate" -ResourceGroupName $rgName
$deploymentStatus = $templatedeployment.ProvisioningState
Write-Host "Deployment in $rgName : $deploymentStatus"

if ($deploymentStatus -eq "Succeeded") {
    Write-Host "Template deployment succeeded. Have you provided yourself as account administrator on Databricks? (Yes/No)"

    $response = Read-Host
    if ($response -eq "Y" -or $response -eq "Yes") {
        Write-Host "Proceeding with further resource creation..."
    } else {
        Write-Host "Further resource creation in Databricks will fail, proceeding with further deployment..."
    }
} else {
    Write-Host "Template deployment failed or is not complete. Aborting further actions,please redeploy the template. "
    exit
}

##creating databricks connector
Write-Host "Creating Access Connector for Azure Databricks in $rgName"

New-AzDatabricksAccessConnector -Name $databricksconnector `
   -ResourceGroupName $rgName `
   -Location $Region `
   -SubscriptionId $subscriptionId `
   -IdentityType UserAssigned `
   -UserAssignedIdentity @{"/subscriptions/$subscriptionId/resourceGroups/$rgName/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$userAssignedIdentities_ami_databricks_build" = @{} }

$datbricksconnectorstatus = Get-AzDatabricksAccessConnector -Name $databricksconnector -ResourceGroupName $rgName
$datbricksconnectorstatus = $datbricksconnectorstatus.ProvisioningState
Write-Host "Creation of Access Connector for Azure Databricks : $datbricksconnectorstatus"

## storage az copy
Write-Host "Copying files to Storage Container"

$storage_account_key = (Get-AzStorageAccountKey -ResourceGroupName $rgName -AccountName $dataLakeAccountName)[0].Value
$dataLakeContext = New-AzStorageContext -StorageAccountName $dataLakeAccountName -StorageAccountKey $storage_account_key

$destinationSasKey = New-AzStorageContainerSASToken -Container "data" -Context $dataLakeContext -Permission rwdl
if (-not $destinationSasKey.StartsWith('?')) { $destinationSasKey = "?$destinationSasKey"}
$destinationUri = "https://$($dataLakeAccountName).blob.core.windows.net/data$($destinationSasKey)"
$azCopy_Data_container = & $azCopyCommand copy "https://stmsftbuild2024.blob.core.windows.net/data/" $destinationUri --recursive

if ($LASTEXITCODE -eq 0) {
    Write-Output "azcopy completed successfully."
} else {
    Write-Output "azcopy failed with exit code $LASTEXITCODE. Output: $azCopy_Data_container"
}

##Role assingment for managed identity##
Write-Host "Assigning required roles to managed identity..."
$userassignedidentityid = (Get-AzUserAssignedIdentity -Name "ami-databricks-$suffix" -ResourceGroupName $rgName).clientid
$assignment1 = az role assignment create --role "Key Vault Reader" --assignee $userassignedidentityid --scope /subscriptions/$subscriptionId/resourcegroups/$rgName/providers/Microsoft.KeyVault/vaults/$keyVaultName
$assignment2 = az role assignment create --role "Storage Blob Data Contributor" --assignee $userassignedidentityid --scope /subscriptions/$subscriptionId/resourcegroups/$rgName/providers/Microsoft.Storage/storageAccounts/$dataLakeAccountName
$assignment3 = az role assignment create --role "Contributor" --assignee $userassignedidentityid --scope /subscriptions/$subscriptionId/resourcegroups/$rgName
# $asssignment4 = az keyvault set-policy --name $keyVaultName --upn $signedinusername --secret-permissions set list get

$roleassigments = If ($assignment1,$assignment2,$assignment3,$asssignment4 -ne $null) {"Role assignment COMPLETE..."} Else {"Role assignment Failed"}
write-host $roleassigments

$storage_account_key = (Get-AzStorageAccountKey -ResourceGroupName $rgName -AccountName $dataLakeAccountName)[0].Value
$dataLakeContext = New-AzStorageContext -StorageAccountName $dataLakeAccountName -StorageAccountKey $storage_account_key

$filesystemName = "containerdatabricksmetastore"
$dirname = "metastore_root/"
$directory = New-AzDataLakeGen2Item -Context $dataLakeContext -FileSystem $filesystemName -Path $dirname -Directory

$dir = if ($directory -ne $null) {"created container named containerdatabricksmetastore"} Else {"failed to create container containerdatabricksmetastore"}
write-host $dir 

## Create Directory in ADLS Gen2
#az storage fs directory create -n metastore_root -f "containerdatabricksmetastore" --connection-string myconnectionstring
Write-Host "-----Deploying Resources on Microsoft Azure COMPLETE-----"

Write-Host "---------AZURE DATABRICKS---------"
Write-Host "---Deploying Resources on Azure Databricks..."

$dbswsId = $(az resource show `
            --resource-type Microsoft.Databricks/workspaces `
            -g "$rgName" `
            -n "$databricks_workspace_name" `
            --query id -o tsv)

$dbsId = $(az resource show `
            --resource-type Microsoft.Databricks/workspaces `
            -g "$rgName" `
            -n "$databricks_workspace_name" `
            --query properties.workspaceId -o tsv)

$workspaceUrl = $(az resource show `
            --resource-type Microsoft.Databricks/workspaces `
            -g "$rgName" `
            -n "$databricks_workspace_name" `
            --query properties.workspaceUrl -o tsv)

# Get a token for the global Databricks application.
    # The resource ID is fixed and never changes.
    $token_response = $(az account get-access-token --resource 2ff814a6-3304-4ab8-85cb-cd0e6f879c1d --output json) | ConvertFrom-Json
    $token = $token_response.accessToken

# Get a token for the Azure management API
    $token_response = $(az account get-access-token --resource https://management.core.windows.net/ --output json) | ConvertFrom-Json
    $azToken = $token_response.accessToken

$uri = "https://$($workspaceUrl)/api/2.0/token/create"
    $baseUrl = 'https://' + $workspaceUrl
    # You can also generate a PAT token. Note the quota limit of 600 tokens.
    $body = '{"lifetime_seconds": 1000000, "comment": "catalog" }';
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $token")
    $headers.Add("X-Databricks-Azure-SP-Management-Token", "$azToken")
    $headers.Add("X-Databricks-Azure-Workspace-Resource-Id", "$dbswsId")
    $pat_token = Invoke-RestMethod -Uri $uri -Method Post -Body $body -Header $headers 
    $pat_token = $pat_token.token_value

$pattokenvalidation = if($pat_token -ne $null){"Pat token created"}Else{"Failed to create pat token"}
write-host $pattokenvalidation


# creating personal compute

$requestHeaders = @{
        Authorization  = "Bearer" + " " + $pat_token
        "Content-Type" = "application/json"
    }

# to create a new cluster
Write-Host "Creating CLUSTERS in Azure Databricks..."

    $body = '{
    "cluster_name": "PersonalCluster",
    "spark_version": "13.3.x-scala2.12",
    "spark_conf": {
        "spark.master": "local[*, 4]",
        "spark.databricks.cluster.profile": "singleNode"
    },
    "azure_attributes": {
        "first_on_demand": 1,
        "availability": "ON_DEMAND_AZURE",
        "spot_bid_max_price": -1
    },
    "node_type_id": "Standard_DS3_v2",
    "driver_node_type_id": "Standard_DS3_v2",
    "custom_tags": {
        "ResourceClass": "SingleNode"
    },
    "autotermination_minutes": 45,
    "enable_elastic_disk": true,
    "data_security_mode": "SINGLE_USER",
    "runtime_engine": "STANDARD",
    "num_workers": 0
}'

$endPoint = $baseURL + "/api/2.0/clusters/create"
$clusterId_1 = Invoke-RestMethod $endPoint `
    -Method Post `
    -Headers $requestHeaders `
    -Body $body

$clusterstatus = if($clusterId_1.cluster_id -ne $Null) {"Provisioning Cluster..."} else {"cluster creation failed."}
write-host $clusterstatus
$clusterId_1 = $clusterId_1.cluster_id

## creating Metastore
Write-Host "----Creating Metastore----"

$requestHeaders = @{
        Authorization  = "Bearer" + " " + $pat_token
        "Content-Type" = "application/json"
    }

$body = '{
  "name": "metastore-'+$Region+'",
  "storage_root": "abfss://'+ $containerName + '@' + $dataLakeAccountName + '.dfs.core.windows.net/metastore_root",
  "region": "' + $Region +'"
}'

$endPoint = $baseURL + "/api/2.1/unity-catalog/metastores"
    $metastore= Invoke-RestMethod $endPoint `
        -Method Post `
        -Headers $requestHeaders `
        -Body $body

Start-Sleep -Seconds 5
$metastorestatus = if($metastore.metastore_id -ne $Null) {"Metastore has been created successfully."} else {"Metastore creation failed."}
Write-host $metastorestatus
$metastoreid = $metastore.metastore_id

## Assigning metastore to workspace 
Write-Host "Assigning Metastore to your Azure Databricks workspace..."

$body = '{
  "metastore_id": "' + $metastoreid + '"
}'

$endPoint = $baseURL + "/api/2.1/unity-catalog/workspaces/$dbsId/metastore"
    $metastorews= Invoke-RestMethod $endPoint `
        -Method PUT `
        -Headers $requestHeaders `
        -Body $body

## fecthing workspace assignment
$endPoint = $baseURL + "/api/2.1/unity-catalog/current-metastore-assignment"
    $metastorewsassignment= Invoke-RestMethod $endPoint `
        -Method GET `
        -Headers $requestHeaders
        
$metastorewsassignmentstatus = if($metastorewsassignment.metastore_id -ne $Null){"Metastore has been assigned to your Azure Databricks workspace."} else {" Failed to assign Metastore Azure Databricks workspace."}
write-host $metastorewsassignmentstatus

##Creating Storage Credentials 
Write-Host "Creating Storage Credentials..."

$body = '{
  "name": "storagecred",
  "comment": "none",
  "read_only": false,
  "azure_managed_identity": {
    "access_connector_id": "/subscriptions/' + $subscriptionId + '/resourceGroups/' + $rgName + '/providers/Microsoft.Databricks/accessConnectors/' + $databricksconnector + '",
    "managed_identity_id": "/subscriptions/' + $subscriptionId + '/resourcegroups/' + $rgName + '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/' + $userAssignedIdentities_ami_databricks_build + '"
  },
  "skip_validation": false
}'

$endPoint = $baseURL + "/api/2.1/unity-catalog/storage-credentials"
    $storagecred= Invoke-RestMethod $endPoint `
        -Method Post `
        -Headers $requestHeaders `
        -Body $body

Start-Sleep -Seconds 5
$storagecredstatus = if($storagecred.id -ne $Null){"Storage credentials has been created successfully."} else {"Failed to create Storage Credentials."}
write-host $storagecredstatus

##Creating External location 
Write-Host "Creating External Location..."

$body = 
'{
  "name": "externalbuild",
  "url": "abfss://'+ $containerName + '@' + $dataLakeAccountName + '.dfs.core.windows.net/metastore_root",
  "credential_name": "storagecred",
  "read_only": false,
  "comment": "string",
  "skip_validation": true
}'

$endPoint = $baseURL + "/api/2.1/unity-catalog/external-locations"
    $extlocation= Invoke-RestMethod $endPoint `
        -Method Post `
        -Headers $requestHeaders `
        -Body $body

Start-Sleep -Seconds 5
$extlocationstatus = if($extlocation.id -ne $Null){"External location has been created successfully."} else {"Failed to create External location."}
write-host $extlocationstatus

## creating Unity Catalog
Write-Host "Creating Unity Catalog..."

$body = 
'{
  "name": "litware_unity_catalog",
  "comment": "none",
  "properties": {},
  "storage_root": "abfss://'+ $containerName + '@' + $dataLakeAccountName + '.dfs.core.windows.net/metastore_root/catalog"
}'

$endPoint = $baseURL + "/api/2.1/unity-catalog/catalogs"
    $catalog = Invoke-RestMethod $endPoint `
        -Method Post `
        -Headers $requestHeaders `
        -Body $body

Start-Sleep -Seconds 5
$catalogstatus = if($catalog.id -ne $Null){"Unity Catalog has been created successfully."} else {"Failed to create Unity Catalog."}
write-host $catalogstatus

##Creating Schema
Write-Host "Creating Schema..."

$body = 
'{
  "name": "rag",
  "catalog_name": "litware_unity_catalog",
  "comment": "schema",
  "properties": {
  },
  "storage_root": "abfss://'+ $containerName + '@' + $dataLakeAccountName + '.dfs.core.windows.net/metastore_root/ragschema"
}'

$endPoint = $baseURL + "/api/2.1/unity-catalog/schemas"
    $schema= Invoke-RestMethod $endPoint `
        -Method Post `
        -Headers $requestHeaders `
        -Body $body

Start-Sleep -Seconds 5
$schemastatus = if($schema.schema_id -ne $Null){"Schema has been created successfully."} else {"Failed to create Schema."}
write-host $schemastatus
$schema = $schema.schema_id

# create Volume
Write-Host "Creating Volume..."

$maxRetries = 1
$retryIntervalSeconds = 2

for ($i = 0; $i -lt $maxRetries; $i++) {
    
$body = '{
  "catalog_name": "litware_unity_catalog",
  "schema_name": "rag",
  "name": "documents_store",
  "volume_type": "MANAGED"
}'

$endPoint = $baseURL + "/api/2.1/unity-catalog/volumes"
    $volume= Invoke-RestMethod $endPoint `
        -Method Post `
        -Headers $requestHeaders `
        -Body $body
    
    if ($volume.volume_id -ne $Null) {
        Write-Host "Volume has been created successfully."
        break  # Exit the loop if Volume is created.
    } else {
        Write-Host "creating Volume is in progress. Retrying in $retryIntervalSeconds seconds..."
        Start-Sleep -Seconds $retryIntervalSeconds
    }
}

if ($i -eq $maxRetries) {
    Write-Host "Max retries reached. Failed to create Volume."
}

## raw_data Data Directory
$endPoint = $baseURL + "/api/2.0/fs/directories/Volumes/litware_unity_catalog/rag/documents_store/raw_data"
    $volume= Invoke-RestMethod $endPoint `
        -Method PUT `
        -Headers $requestHeaders 

Write-Host "Directories creation in Volume. COMPLETE.."

# create diretory in Shared folder
Write-Host "Creating directory in Shared folder..."

##Analytics with ADB

$body = '{
  "path": "/Workspace/Shared/Analytics with ADB"
}'

$endPoint = $baseURL + "/api/2.0/workspace/mkdirs"
    $volume= Invoke-RestMethod $endPoint `
        -Method Post `
        -Headers $requestHeaders `
        -Body $body

Write-Host "Directory created successfully in shared folder."
Start-Sleep -Seconds 5

$destinationSasKey = New-AzStorageContainerSASToken -Container "data" -Context $dataLakeContext -Permission rwdl
if (-not $destinationSasKey.StartsWith('?')) { $destinationSasKey = "?$destinationSasKey"}

(Get-Content -path "artifacts/databricks/1. Notebook to analyze customer churn.ipynb" -Raw) | Foreach-Object { $_ `
            -replace '#STORAGEACCOUNT#', $dataLakeAccountName `
            -replace '#SASTOKEN#', $destinationSasKey `
} | Set-Content -Path "artifacts/databricks/1. Notebook to analyze customer churn.ipynb"

#uploading Notebooks
Write-Host "Uploading Notebooks in shared folder..."

$files = Get-ChildItem -path "artifacts/databricks" -File -Recurse  #all files uploaded in one folder change config paths in python jobs
    Set-Location ./artifacts/databricks
   foreach ($file in $files) {
    if ($file.Name -eq "00-init.ipynb" -or $file.Name -eq "1. Notebook to analyze customer churn.ipynb") {
        $fileContent = Get-Content -Raw $file.FullName
        $fileContentBytes = [System.Text.Encoding]::UTF8.GetBytes($fileContent)
        $fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)
        
        # Extract the name without extension
        $nameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
            $body = '{"content": "' + $fileContentEncoded + '",  "path": "/Workspace/Shared/Analytics with ADB/' + $nameWithoutExtension + '",  "language": "PYTHON","overwrite": true,  "format": "JUPYTER"}'
            #get job list
            $endPoint = $baseURL + "/api/2.0/workspace/import"
            $result = Invoke-RestMethod $endPoint `
                -ContentType 'application/json' `
                -Method Post `
                -Headers $requestHeaders `
                -Body $body
         }
   }

Set-Location ../../

if ($LASTEXITCODE -eq 0) {
    Write-Output "Notebooks upload completed successfully."
} else {
    Write-Output "Notebooks upload failed with exit code $LASTEXITCODE."
}

## fecthing Volume id 
$endPoint = $baseURL + "/api/2.1/unity-catalog/volumes/litware_unity_catalog.rag.documents_store"
    $volume= Invoke-RestMethod $endPoint `
        -Method GET `
        -Headers $requestHeaders 

$volumestatus = if($volume -ne $null){"Volume have been created successfully"}Else{"Failed to create volume"}
$volumeid = $volume.volume_id
write-host $volumestatus

# Uploading CSV to Volume
Write-Host "Uploading CSVs to volume... "

$destinationSasKey = New-AzStorageContainerSASToken -Container "containerdatabricksmetastore" -Context $dataLakeContext -Permission rwdl
if (-not $destinationSasKey.StartsWith('?')) { $destinationSasKey = "?$destinationSasKey"}
$destinationUri = "https://$($dataLakeAccountName).blob.core.windows.net/containerdatabricksmetastore/metastore_root/ragschema/__unitystorage/schemas/$($schema)/volumes/$($volumeid)/raw_data$($destinationSasKey)"
$volupload2 = & $azCopyCommand copy "https://stignite24.blob.core.windows.net/volume/*" $destinationUri --recursive

$volupload2 = if ($LASTEXITCODE -eq 0) {
    "CSVs upload to volume COMPLETE...."
} else {
     "Upload failed with exit code $LASTEXITCODE. Output: $volupload2"
}
write-host $volupload2

#Creating Jobs to run Notebooks
Write-Host "Creating Jobs to run Notebooks..."

$body = '{
  "name": "first notebook run",
  "email_notifications": {
    "no_alert_for_skipped_runs": false
  },
  "webhook_notifications": {},
  "timeout_seconds": 0,
  "max_concurrent_runs": 1,
  "tasks": [
    {
      "task_key": "first_notebook_run",
      "run_if": "ALL_SUCCESS",
      "notebook_task": {
        "notebook_path": "/Shared/Analytics with ADB/1. Notebook to analyze customer churn.ipynb",
        "source": "WORKSPACE"
      },
      "existing_cluster_id": "'+$clusterId_1+'",
      "timeout_seconds": 0,
      "email_notifications": {}
    }
  ]
}'

  $endPoint = $baseURL + "/api/2.1/jobs/create"
    $job1= Invoke-RestMethod $endPoint `
        -Method Post `
        -Headers $requestHeaders `
        -Body $body

$job1status = if($Null -ne $job1.job_id){"Created a job for the Notebook."} else {"Failed to create a job for the Notebook."}
write-host $job1status
$job1id = $job1.job_id

#Running jobs
#Running job1
Write-Host "Running job1"

$maxRetries = 3
$retryIntervalSeconds = 300
$clusterState = $null
$run1 = $null

# Loop to retrieve cluster state and check if it's "RUNNING"
for ($i = 0; $i -lt $maxRetries; $i++) {
    $body = '{"cluster_id": "' + $clusterId_1 + '"}'
    $endPoint = $baseURL + "/api/2.0/clusters/get"
    $clusterResponse = Invoke-RestMethod $endPoint `
        -Method Post `
        -Headers $requestHeaders `
        -Body $body
    
    $clusterState = $clusterResponse.state
    
    if ($clusterState -eq "RUNNING") {
        Write-Host "Cluster is running. Proceeding with job execution."
        $jobBody = '{"job_id": "' + $job1id + '"}'
        $jobEndPoint = $baseURL + "/api/2.1/jobs/run-now"
        $run1 = Invoke-RestMethod $jobEndPoint `
            -Method Post `
            -Headers $requestHeaders `
            -Body $jobBody
        break  # Exit the loop if cluster is running
    } else {
        Write-Host "Cluster is provisioning. Retrying in $retryIntervalSeconds seconds..."
        Start-Sleep -Seconds $retryIntervalSeconds
    }
}

if ($i -eq $maxRetries) {
    Write-Host "Max retries reached. Cluster is still not running."
}  else {
        Write-Host "Error: Failed to start the job, please run the Notebook manually."
}

Write-Host "Deploying Resources on Azure Databricks Completed... "

$endtime=get-date
$executiontime=$endtime-$starttime
Write-Host "Execution Time - "$executiontime.TotalMinutes

Write-Host "List of resources deployed in $rgName resource group"
$deployed_resources = Get-AzResource -resourcegroup $rgName
$deployed_resources = $deployed_resources | Select-Object Name, Type | Format-Table -AutoSize
Write-Output $deployed_resources

$operationStatus = @("mainTemplate : $deploymentStatus","DatabricksConnector : $datbricksconnectorstatus",$roleassigments,$dir,$pattokenvalidation,$clusterstatus,$metastorestatus,$metastorewsassignmentstatus,$storagecredstatus,$extlocationstatus,$catalogstatus,$schemastatus,$job1status)
$executionStatus = if ($operationStatus -contains $Null) {"Execution completed with errors."} else {"-----------------EXECUTION COMPLETED---------------"}
Write-Host "Operation Status:"
$operationStatus
Write-Host $executionStatus
Stop-Transcript
