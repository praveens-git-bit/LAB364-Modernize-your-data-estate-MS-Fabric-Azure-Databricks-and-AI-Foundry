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

az login
$subscriptionId = (az account show --query id --output tsv)
Connect-AzAccount -UseDeviceAuthentication -Subscription $subscriptionId 

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

[string]$suffix = -join ((48..57) + (97..122) | Get-Random -Count 7 | % { [char]$_ })
$rgName = "rg-build25-$suffix"
$Region = read-host "Enter the region for resource group deployment "
$tenantId = (Get-AzContext).Tenant.Id
$subscriptionId = (Get-AzContext).Subscription.Id
$databricks_workspace_name = "adb-build-$suffix"
$databricks_managed_resource_group_name = "rg-managed-adb-$suffix"
$dataLakeAccountName = "stbuild$suffix"
$keyVaultName = "kv-build-$suffix"
$namespaces_adx_thermostat_occupancy_name = "evh-thermostat-$suffix"
$sites_adx_thermostat_realtime_name = "app-realtime-simulator-$suffix"
$serverfarm_adx_thermostat_realtime_name = "asp-realtime-simulator-$suffix"
$mssql_server_name = "mssql$suffix"
$mssql_database_name = "SalesDb"
$mssql_administrator_login = "labsqladmin"
$sql_administrator_login_password = "Smoothie@2024"
$aiHubName = "hub-$suffix"
$containerRegistryName = "Contreg-$suffix"
$aiServicesName = "AIhub-$suffix"
$storage_account_AIstudio = "staistudio$suffix"
$search_service = "srch-$suffix"
$workspaces_prj_name = "prj-build-$suffix"
$openAIResource = "openAIResource$suffix"
$contentsafety = "contsafety$suffix"
$openAIResource2 = "openAIResource2$suffix"
$cosmosdb_account = "cosmosdb$suffix"
$location_1 = read-host "Enter the location for OpenAI with gpt-4 "
$location_2 = read-host "Enter the location for OpenAI with gpt-4o and text-embedding-ada-002 "
$func_shopping_copilot = "funcapp$suffix"
$serverfarm_asp_func_app_name = "asp$suffix"
$funstorageAccountName = "stfunc$suffix"
$shoppingWebappname = "app-shopping-copilot-$suffix"
$shoppingWebhostingPlan = "asp-shopping-copilot-$suffix"

Write-Host "Deploying Resources on Microsoft Azure Started ..."
Write-Host "Creating $rgName resource group in $Region ..."
New-AzResourceGroup -Name $rgName -Location $Region | Out-Null
Write-Host "Resource group $rgName creation COMPLETE"

Write-Host "Creating resources in $rgName..."
New-AzResourceGroupDeployment -ResourceGroupName $rgName `
-TemplateFile "mainTemplate.json" `
-Mode Complete `
-aiHubName $aiHubName `
-containerRegistryName $containerRegistryName `
-aiServicesName $aiServicesName `
-azure_open_ai $openAIResource `
-location $Region `
-databricks_workspace_name $databricks_workspace_name `
-accounts_openai_content_safety_name $contentsafety `
-databricks_managed_resource_group_name $databricks_managed_resource_group_name `
-storage_account_name $dataLakeAccountName `
-vaults_kv_databricks_prod_name $keyVaultName `
-sites_adx_thermostat_realtime_name $sites_adx_thermostat_realtime_name `
-serverfarm_adx_thermostat_realtime_name $serverfarm_adx_thermostat_realtime_name `
-namespaces_adx_thermostat_occupancy_name $namespaces_adx_thermostat_occupancy_name `
-mssql_server_name $mssql_server_name `
-mssql_database_name $mssql_database_name `
-mssql_administrator_login $mssql_administrator_login `
-sql_administrator_login_password $sql_administrator_login_password `
-storage_account_AIstudio $storage_account_AIstudio `
-search_service $search_service `
-workspaces_prj_name $workspaces_prj_name `
-azure_open_ai_2 $openAIResource2 `
-cosmosdb_account $cosmosdb_account `
-openAI_location_1 $location_1 `
-openAI_location_2 $location_2 `
-func_shopping_copilot $func_shopping_copilot `
-serverfarm_asp_func_app_name $serverfarm_asp_func_app_name `
-funstorageAccountName $funstorageAccountName `
-shoppingWebappname $shoppingWebappname `
-shoppingWebhostingPlan $shoppingWebhostingPlan `
-Force

$templatedeployment = Get-AzResourceGroupDeployment -Name "mainTemplate" -ResourceGroupName $rgName
$deploymentStatus = $templatedeployment.ProvisioningState
Write-Host "Deployment in $rgName : $deploymentStatus"

## storage az copy
Write-Host "Copying files to Storage Container"

$storage_account_key = (Get-AzStorageAccountKey -ResourceGroupName $rgName -AccountName $dataLakeAccountName)[0].Value
$dataLakeContext = New-AzStorageContext -StorageAccountName $dataLakeAccountName -StorageAccountKey $storage_account_key
 
$destinationSasKey = New-AzStorageContainerSASToken -Container "data" -Context $dataLakeContext -Permission rwdl
if (-not $destinationSasKey.StartsWith('?')) { $destinationSasKey = "?$destinationSasKey"}
$destinationUri = "https://$($dataLakeAccountName).blob.core.windows.net/data$($destinationSasKey)"
$azCopy_Data_container = & $azCopyCommand copy "https://stignite24.blob.core.windows.net/data/" $destinationUri --recursive

$destinationSasKey = New-AzStorageContainerSASToken -Container "litwaredata" -Context $dataLakeContext -Permission rwdl
if (-not $destinationSasKey.StartsWith('?')) { $destinationSasKey = "?$destinationSasKey"}
$destinationUri = "https://$($dataLakeAccountName).blob.core.windows.net/litwaredata$($destinationSasKey)"
$azCopy_Data_container = & $azCopyCommand copy "https://stignite24.blob.core.windows.net/pbi-copilot-raw-csv/" $destinationUri --recursive

#Copy shopping copilot container for indexers.
$destinationSasKey = New-AzStorageContainerSASToken -Container "cog-search-product-images" -Context $dataLakeContext -Permission rwdl
if (-not $destinationSasKey.StartsWith('?')) { $destinationSasKey = "?$destinationSasKey"}
$destinationUri2 = "https://$($dataLakeAccountName).blob.core.windows.net/cog-search-product-images$($destinationSasKey)"
$azCopy_Data_container2 = & $azCopyCommand copy "https://stignite24.blob.core.windows.net/cog-search-product-images/" $destinationUri2 --recursive

$storage_account_key1 = (Get-AzStorageAccountKey -ResourceGroupName $rgName -AccountName $storage_account_AIstudio)[0].Value
$dataLakeContext1 = New-AzStorageContext -StorageAccountName $storage_account_AIstudio -StorageAccountKey $storage_account_key1

$destinationSasKey1 = New-AzStorageContainerSASToken -Container "input" -Context $dataLakeContext1 -Permission rwdl
if (-not $destinationSasKey1.StartsWith('?')) { $destinationSasKey1 = "?$destinationSasKey1"}
$destinationUri = "https://$($storage_account_AIstudio).blob.core.windows.net/input$($destinationSasKey1)"
$azCopy_Data_container = & $azCopyCommand copy "https://stignite24.blob.core.windows.net/input/" $destinationUri --recursive

(Get-Content -path artifacts/cosmos/products.json -Raw) | Foreach-Object { $_ `
    -replace '#STORAGE_ACCOUNT#', $dataLakeAccountName `
} | Set-Content -Path artifacts/cosmos/products.json

$destinationSasKey = New-AzStorageContainerSASToken -Container "products" -Context $dataLakeContext -Permission rwdl
if (-not $destinationSasKey.StartsWith('?')) { $destinationSasKey = "?$destinationSasKey"}
$destinationUri = "https://$($dataLakeAccountName).blob.core.windows.net/products$($destinationSasKey)"
$azCopy_Data_container = & $azCopyCommand copy "artifacts/cosmos/products.json" $destinationUri --recursive

if ($LASTEXITCODE -eq 0) {
    Write-Output "azcopy completed successfully."
} else {
    Write-Output "azcopy failed with exit code $LASTEXITCODE. Output: $azCopy_Data_container"
}

## Fecthing Keys and Endpoints
Write-Host "Fecthing Keys and Endpoints"
$openAIModel1 = az cognitiveservices account deployment create -g $rgName -n $openAIResource --deployment-name "gpt-4" --model-name "gpt-4" --model-version "0613" --model-format OpenAI --sku-capacity 30 --sku-name "Standard" 
$openAIModel2 = az cognitiveservices account deployment create -g $rgName -n $openAIResource2 --deployment-name "gpt-4o" --model-name "gpt-4o" --model-version "2024-05-13" --model-format OpenAI --sku-capacity 30 --sku-name "Standard"
$openAIModel3 = az cognitiveservices account deployment create -g $rgName -n $openAIResource2 --deployment-name "text-embedding-ada-002" --model-name "text-embedding-ada-002" --model-version "2" --model-format OpenAI --sku-capacity 30 --sku-name "Standard"

#retirieving primary key
$openAIPrimaryKey = az cognitiveservices account keys list -n $openAIResource -g $rgName | jq -r .key1

#retrieving openai endpoint
$openAIEndpoint2 = az cognitiveservices account show -n $openAIResource2 -g $rgName | jq -r .properties.endpoint

#retirieving primary key
$openAIPrimaryKey2 = az cognitiveservices account keys list -n $openAIResource2 -g $rgName | jq -r .key1

#retirieving cosmos DB key
$cosmos_account_key = az cosmosdb keys list -n $cosmosdb_account -g $rgName | ConvertFrom-Json
$cosmos_account_key = $cosmos_account_key.primarymasterkey

$cosmosendpoint = "https://$cosmosdb_account.documents.azure.com:443/"

$cosmosconnectionstring = "AccountEndpoint=$cosmosendpoint;AccountKey=$cosmos_account_key;"

## retirieving content safety key
$contentsafetykey = az cognitiveservices account keys list -n $contentsafety -g $rgName | jq -r .key1

Write-Host "---------Fecthing Keys and Endpoints COMPLETE--------"

## mssql
Write-Host "---------Loading files to MS SQL DB--------"
Add-Content log.txt "-----Loading files to MS SQL DB-----"
$SQLScriptsPath="./artifacts/sqlscripts"
$sqlQuery = Get-Content -Raw -Path "$($SQLScriptsPath)/salesSqlDbScript.sql"
$sqlEndpoint="$($mssql_server_name).database.windows.net"
$result=Invoke-SqlCmd -Query $sqlQuery -ServerInstance $sqlEndpoint -Database $mssql_database_name -Username $mssql_administrator_login -Password $sql_administrator_login_password
Write-Host "---------Loading files to MS SQL DB COMPLETE--------"
Add-Content log.txt "-----Loading files to MS SQL DB COMPLETE-----"

Write-Host  "---------Deploying the simulator web app-----------"
RefreshTokens

$zips = @("app-adx-thermostat-realtime", "webapp-shopping-copilot")
foreach($zip in $zips)
{
    expand-archive -path "./artifacts/binaries/$($zip).zip" -destinationpath "./$($zip)" -force
}

# ADX Thermostat Realtime
$thermostat_endpoint = az eventhubs eventhub authorization-rule keys list --resource-group $rgName --namespace-name $namespaces_adx_thermostat_occupancy_name --eventhub-name thermostat --name thermostat | ConvertFrom-Json
$thermostat_endpoint = $thermostat_endpoint.primaryConnectionString

(Get-Content -path adx-config-appsetting.json -Raw) | Foreach-Object { $_ `
    -replace '#NAMESPACES_ADX_THERMOSTAT_OCCUPANCY_THERMOSTAT_ENDPOINT#', $thermostat_endpoint`
   -replace '#THERMOSTATTELEMETRY_URL#', $thermostat_telemetry_Realtime_URL`
} | Set-Content -Path adx-config-appsetting-with-replacement.json

$config = az webapp config appsettings set -g $rgName -n $sites_adx_thermostat_realtime_name --settings @adx-config-appsetting-with-replacement.json

Write-Information "Deploying Realtime Simulator App"

$TOKEN_2 = az account get-access-token --query accessToken | tr -d '"'

$deployment = curl -X POST -H "Authorization: Bearer $TOKEN_2" -T "./artifacts/binaries/app-adx-thermostat-realtime.zip" "https://$sites_adx_thermostat_realtime_name.scm.azurewebsites.net/api/publish?type=zip"

Write-Host "-----Deploying Resources on Microsoft Azure COMPLETE-----"

Write-Host "---------AZURE DATABRICKS---------"
Write-Host "---Deploying Resources on Azure Databricks..."

$dbswsId = $(az resource show `
            --resource-type Microsoft.Databricks/workspaces `
            -g "$rgName" `
            -n "$databricks_workspace_name" `
            --query id -o tsv)

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

# headers
$requestHeaders = @{
        Authorization  = "Bearer" + " " + $pat_token
        "Content-Type" = "application/json"
    }

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

(Get-Content -path "artifacts/databricks/01 DLT Notebook.ipynb" -Raw) | Foreach-Object { $_ `
            -replace '#STORAGEACCOUNT#', $dataLakeAccountName `
            -replace '#storage_account_key#', $storage_account_key `
} | Set-Content -Path "artifacts/databricks/01 DLT Notebook.ipynb"

#uploading Notebooks
Write-Host "Uploading Notebooks in shared folder..."

$files = Get-ChildItem -path "artifacts/databricks" -File -Recurse  #all files uploaded in one folder change config paths in python jobs
    Set-Location ./artifacts/databricks
   foreach ($file in $files) {
    if ($file.Name -eq "01 DLT Notebook.ipynb") {
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

# Updating details prompt flow files..
expand-archive -path "./artifacts/aistudio/enterprise-chatbot-prompt-flow.zip" -destinationpath "enterprise-chatbot-prompt-flow" -force

(Get-Content -path "./enterprise-chatbot-prompt-flow/flow.dag.yaml" -Raw) | Foreach-Object { $_ `
    -replace '#SubscriptionID#', $subscriptionId `
    -replace '#ResourcegroupName#', $rgName `
    -replace '#WorkspaceName#', $aiHubName `
    -replace '#ConnectionNameOpenAI#', $openAIResource `
    -replace '#AzureAISearch#', $search_service `
    -replace '#content_safety#', $contentsafety `
} | Set-Content -Path "./enterprise-chatbot-prompt-flow/flow.dag.yaml"

Compress-Archive -Path "enterprise-chatbot-prompt-flow/*" -DestinationPath "artifacts/aistudio/enterprise-chatbot-prompt-flow.zip" -f

# Updating details prompt flow files..
expand-archive -path "./artifacts/aistudio/shopping-assistant-prompt-flow.zip" -destinationpath "shopping-assistant-prompt-flow" -force

(Get-Content -path "./shopping-assistant-prompt-flow/flow.dag.yaml" -Raw) | Foreach-Object { $_ `
    -replace '#SubscriptionID#', $subscriptionId `
    -replace '#ResourcegroupName#', $rgName `
    -replace '#WorkspaceName#', $aiHubName `
    -replace '#OpenAI_resource_name#', $openAIResource `
    -replace '#OpenAI_key#', $openAIPrimaryKey `
    -replace '#AzureAISearch#', $search_service `
    -replace '#content_safety#', $contentsafety `
} | Set-Content -Path "./shopping-assistant-prompt-flow/flow.dag.yaml"

Compress-Archive -Path "shopping-assistant-prompt-flow/*" -DestinationPath "artifacts/aistudio/shopping-assistant-prompt-flow.zip" -f

Write-Host  "-----------------Uploading Cosmos Data Started--------------"
#uploading Cosmos data
Add-Content log.txt "-----------------uploading Cosmos data--------------"

az cosmosdb sql container create --account-name $cosmosdb_account --database-name "database" --name "products" --partition-key-path "/id" --resource-group $rgName --throughput "400"

RefreshTokens
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-Module -Name PowerShellGet -Force
    Install-Module -Name CosmosDB -Force
    $cosmosDbAccountName = $cosmos_appcosmos_name
    $cosmosDatabaseName = "database"
    $cosmos = Get-ChildItem "./artifacts/cosmos" | Select BaseName 

    foreach ($name in $cosmos) {
        $collection = $name.BaseName 
        $cosmosDbContext = New-CosmosDbContext -Account $cosmosdb_account -Database $cosmosDatabaseName -ResourceGroup $rgName
        $path = "./artifacts/cosmos/" + $name.BaseName + ".json"
        $document = Get-Content -Raw -Path $path
        $document = ConvertFrom-Json $document

        foreach ($json in $document) {
            $key = $json.id
            $body = ConvertTo-Json $json
            $res = New-CosmosDbDocument -Context $cosmosDbContext -CollectionId "products" -DocumentBody $body -PartitionKey $key -ErrorAction SilentlyContinue
        }
    } 

#Search service 
Write-Host "-----------------Search service ---------------"
Add-Content log.txt "-----------------Search service ---------------"
RefreshTokens
Install-Module -Name Az.Search -f
# Get search primary admin key
$adminKeyPair = Get-AzSearchAdminKeyPair -ResourceGroupName $rgName -ServiceName $search_service
$primaryAdminKey = $adminKeyPair.Primary

# Fetch connection string
$storageKey = (Get-AzStorageAccountKey -Name $storage_account_AIstudio -ResourceGroupName $rgName)[0].Value
$storageConnectionString = "DefaultEndpointsProtocol=https;AccountName=$($storage_account_AIstudio);AccountKey=$($storageKey);EndpointSuffix=core.windows.net"

# Create Datasource endpoint
Write-Host "Creating Data source in Azure search service..."
Get-ChildItem "artifacts/search" -Filter search_datasource.json |
        ForEach-Object {
            $datasourceDefinition = (Get-Content $_.FullName -Raw).replace("#STORAGE_CONNECTION#", $storageConnectionString).Replace("#STORAGE_ACCOUNT#", $storage_account_AIstudio)
            $headers = @{
                'api-key' = $primaryAdminKey
                'Content-Type' = 'application/json'
                'Accept' = 'application/json' }

             $url = "https://$search_service.search.windows.net/datasources?api-version=2023-11-01"
             Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $dataSourceDefinition | ConvertTo-Json
        }
Start-Sleep -s 10

# Create Index
Write-Host "Creating Index in Azure search service..."
Get-ChildItem "artifacts/search" -Filter index.json |
        ForEach-Object {
            $indexDefinition = (Get-Content $_.FullName -Raw).Replace("#SEARCHSERVICE#", $search_service)
            $headers = @{
                'api-key' = $primaryAdminKey
                'Content-Type' = 'application/json'
                'Accept' = 'application/json' }

            $url = "https://$search_service.search.windows.net/indexes?api-version=2023-11-01"
            Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $indexDefinition | ConvertTo-Json
        }
Start-Sleep -s 10

# Create Indexer
Write-Host "Creating Indexer in Azure search service..."
Get-ChildItem "artifacts/search" -Filter indexer.json |
        ForEach-Object {
            $indexerDefinition = (Get-Content $_.FullName -Raw).Replace("#STORAGE_ACCOUNT#", $storage_account_AIstudio)
            $headers = @{
                'api-key' = $primaryAdminKey
                'Content-Type' = 'application/json'
                'Accept' = 'application/json' }

            $url = "https://$search_service.search.windows.net/indexers?api-version=2023-11-01"
            Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $indexerDefinition | ConvertTo-Json
        }
Start-Sleep -s 10

# Create Datasource endpoint
Write-Host "Creating Data source in Azure search service..."
Get-ChildItem "artifacts/search" -Filter cosmos_source.json |
        ForEach-Object {
            $datasourceDefinition = (Get-Content $_.FullName -Raw).replace("#COSMOSDBSTRING#", $cosmosconnectionstring)
            $headers = @{
                'api-key' = $primaryAdminKey
                'Content-Type' = 'application/json'
                'Accept' = 'application/json' }

             $url = "https://$search_service.search.windows.net/datasources?api-version=2023-11-01"
             Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $dataSourceDefinition | ConvertTo-Json
        }
Start-Sleep -s 10

# Create Index
Write-Host "Creating Index in Azure search service..."
Get-ChildItem "artifacts/search" -Filter cosmos_index.json |
        ForEach-Object {
            $indexDefinition = (Get-Content $_.FullName -Raw)
            $headers = @{
                'api-key' = $primaryAdminKey
                'Content-Type' = 'application/json'
                'Accept' = 'application/json' }

            $url = "https://$search_service.search.windows.net/indexes?api-version=2023-11-01"
            Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $indexDefinition | ConvertTo-Json
        }
Start-Sleep -s 10

# Create Indexer
Write-Host "Creating Indexer in Azure search service..."
Get-ChildItem "artifacts/search" -Filter cosmos_indexer.json |
        ForEach-Object {
            $indexerDefinition = (Get-Content $_.FullName -Raw)
            $headers = @{
                'api-key' = $primaryAdminKey
                'Content-Type' = 'application/json'
                'Accept' = 'application/json' }

            $url = "https://$search_service.search.windows.net/indexers?api-version=2023-11-01"
            Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $indexerDefinition | ConvertTo-Json
        }
Start-Sleep -s 10

#Function app
$configPI = az functionapp config appsettings set --name $func_shopping_copilot --resource-group $rgName --settings AZURE_OPENAI_SERVICE_GPT4O=$openAIResource2
$configPI = az functionapp config appsettings set --name $func_shopping_copilot --resource-group $rgName --settings AZURE_OPENAI_MODEL_GPT4O="gpt-4o"
$configPI = az functionapp config appsettings set --name $func_shopping_copilot --resource-group $rgName --settings AZURE_OPENAI_SERVICE_KEY_GPT4O=$openAIPrimaryKey2
$configPI = az functionapp config appsettings set --name $func_shopping_copilot --resource-group $rgName --settings AZURE_OPENAI_API_BASE_GPT4O=$openAIEndpoint2
$configPI = az functionapp config appsettings set --name $func_shopping_copilot --resource-group $rgName --settings AZURE_OPENAI_VERSION_GPT4O="2024-08-01-preview"
$configPI = az functionapp config appsettings set --name $func_shopping_copilot --resource-group $rgName --settings AZURE_OPENAI_EMBEDDING="text-embedding-ada-002"
$configPI = az functionapp config appsettings set --name $func_shopping_copilot --resource-group $rgName --settings AZURE_CONTENT_SAFETY_KEY=$contentsafetykey 
$configPI = az functionapp config appsettings set --name $func_shopping_copilot --resource-group $rgName --settings AZURE_CONTENT_SAFETY_ENDPOINT="https://$contentsafety.cognitiveservices.azure.com"
$configPI = az functionapp config appsettings set --name $func_shopping_copilot --resource-group $rgName --settings AZURE_CONTENT_SAFETY_API_VERSION="2023-10-15-preview"
$configPI = az functionapp config appsettings set --name $func_shopping_copilot --resource-group $rgName --settings AZURE_AI_SEARCH_ENDPOINT="https://$search_service.search.windows.net"
$configPI = az functionapp config appsettings set --name $func_shopping_copilot --resource-group $rgName --settings AZURE_AI_INDEX_NAME="cosmosdb-index"
$configPI = az functionapp config appsettings set --name $func_shopping_copilot --resource-group $rgName --settings AZURE_AI_SEARCH_API_KEY=$primaryAdminKey
$configPI = az functionapp config appsettings set --name $func_shopping_copilot --resource-group $rgName --settings AZURE_COSMOSDB_HOST="https://$cosmosdb_account.documents.azure.com:443/"
$configPI = az functionapp config appsettings set --name $func_shopping_copilot --resource-group $rgName --settings AZURE_COSMOSDB_MASTER_KEY=$cosmos_account_key
$configPI = az functionapp config appsettings set --name $func_shopping_copilot --resource-group $rgName --settings AZURE_COSMOSDB_DATABASE_ID="database"
$configPI = az functionapp config appsettings set --name $func_shopping_copilot --resource-group $rgName --settings AZURE_COSMOSDB_CONTAINER_ID="products"

Write-Host "Uploading function app build, it may take upto 5 min..."
$TOKEN_3 = az account get-access-token --query accessToken | tr -d '"'  
$deployment = curl -X POST -H "Authorization: Bearer $TOKEN_3" -T "./artifacts/binaries/func-shopping-copilot.zip" "https://$func_shopping_copilot.scm.azurewebsites.net/api/zipdeploy"

if ([string]::IsNullOrEmpty($deployment)) {
    Write-Output "Deployment response empty. Retrying..."
    $deployment = curl -X POST -H "Authorization: Bearer $TOKEN_3" -T "./artifacts/binaries/func-shopping-copilot.zip" "https://$func_shopping_copilot.scm.azurewebsites.net/api/zipdeploy"
}

Write-Host "-----------------Function app build deployment compeleted ---------------"
Add-Content log.txt "-----------------Function app build deployment compeleted  ---------------"

#Shopping copilot webapp
Write-Host "Uploading shopping copilot webapp build, ..."
(Get-Content -path webapp-shopping-copilot/wwwroot/config.js -Raw) | Foreach-Object { $_ `
    -replace '#func_shopping_copilot#', $func_shopping_copilot `
} | Set-Content -Path webapp-shopping-copilot/wwwroot/config.js

compress-archive -path "./webapp-shopping-copilot/*" "./webapp-shopping-copilot.zip"

$TOKEN_4 = az account get-access-token --query accessToken | tr -d '"'

$deployment = curl -X POST -H "Authorization: Bearer $TOKEN_4" -T "./webapp-shopping-copilot.zip" "https://$shoppingWebappname.scm.azurewebsites.net/api/publish?type=zip"

Write-Host "-----------------Shopping Copilot webapp build deployment compeleted ---------------"

$endtime=get-date
$executiontime=$endtime-$starttime
Write-Host "Execution Time - "$executiontime.TotalMinutes

Write-Host "List of resources deployed in $rgName resource group"
$deployed_resources = Get-AzResource -resourcegroup $rgName
$deployed_resources = $deployed_resources | Select-Object Name, Type | Format-Table -AutoSize
Write-Output $deployed_resources

$executionStatus = {"-----------------EXECUTION COMPLETED---------------"}
Write-Host "Operation Status:"
Write-Host $executionStatus
Stop-Transcript
