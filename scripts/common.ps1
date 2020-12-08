<#
COPYRIGHT SOLLIANCE / CHRIS GIVENS
#>

function AddShortcut($user, $path, $name, $exec, $args)
{
    write-host "Creating shortcut to $path"

    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$path\$name.lnk");
    $Shortcut.TargetPath = $exec;

    if ($ags)
    {
        $Shortcut.Arguments = $args;
    }

    $Shortcut.Save();

    return $shortcut;
}

function AddStartupItem($exePath)
{
    #$shortcut = AddDesktopShortcut "" "" "" "";

    $ComputerConfigDestination = "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\StartUp";

    #copy-item -path shortcut -Destination $ComputerConfigDestination;

    #%SystemDrive%\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
}

function CreateRebootTask($name, $scriptPath, $localPath, $user, $password)
{
  <#
  $content = Get-content "$localPath\setup-task.ps1";
  $content = $content.replace("{USERNAME}", $global:localusername)
  $content = $content.replace("{PASSWORD}", $global:password)
  $content = $content.replace("{SCRIPTPATH}", $scriptPath)
  $content = $content.replace("{TASKNAME}", $name)
  Set-Content "$localPath\setup-task.ps1" $content;

  $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList @($localusername,(ConvertTo-SecureString -String $password -AsPlainText -Force))
  start-process "powershell.exe" -ArgumentList "-file $localPath\setup-task.ps1" -RunAs $credentials
  #>

    $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument " -file `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $taskname = $name + " $user";

    write-host "Creating task [$taskname] with $user and $password";
    
    #doesn't work with static user due to OS level priv :(

    if ($user -eq "SYSTEM")
    {
        $params = @{
            Action  = $action
            Trigger = $trigger
            TaskName = $taskname
            User = "System"
            RunLevel = "Highest"
        }
    }
    else
    {
        $params = @{
            Action  = $action
            Trigger = $trigger
            TaskName = $taskname
            User = $user
            Password = $password
            RunLevel = "Highest"
        }
    }
    
    
    if(Get-ScheduledTask -TaskName $params.TaskName -EA SilentlyContinue) { 
        Set-ScheduledTask @params
        }
    else {
        Register-ScheduledTask @params
    }
}

function InstallMongoDriver()
{
    #TODO
}

function InstallVisualStudioCode()
{
    write-host "Installing Visual Studio Code";

    choco install vscode --ignoredetectedreboot
}

function LoadCosmosDbViaMongo($cosmosConnection)
{
    $databaseName = "contentdb";
    $partitionkey = "";
    $cosmosDbContext = New-CosmosDbContext -Account "fabmedical$deploymentid" -Database $databaseName -ResourceGroup $resourceGroupName
    New-CosmosDbDatabase -Context $cosmosDbContext -Id $databaseName
    $collectionName = "sessions";
    New-CosmosDbCollection -Context $cosmosDbContext -Id $collectionName -PartitionKey $partitionkey -OfferThroughput 400 -Database $databaseName
    $collectionName = "speaker";
    New-CosmosDbCollection -Context $cosmosDbContext -Id $collectionName -PartitionKey $partitionkey -OfferThroughput 400 -Database $databaseName

    $mongoDriverPath = "c:\Program Files (x86)\MongoDB\CSharpDriver 1.7"
    Add-Type -Path "$($mongoDriverPath)\MongoDB.Bson.dll"
    Add-Type -Path "$($mongoDriverPath)\MongoDB.Driver.dll"

    $db = [MongoDB.Driver.MongoDatabase]::Create('mongodb://localhost/contentdb');

    $strJson = Get-Content "c:\labfiles\microservices-workshop\artifacts\content-inti\json\sessions.json"
    $json = ConvertFrom-Json $strJson;    
    $coll = $db['sessions'];
    
    foreach($j in $json)
    {
        $coll.Insert( $j)
    }
    
    $strJson = Get-Content "c:\labfiles\microservices-workshop\artifacts\content-inti\json\speakers.json"
    $json = ConvertFrom-Json $strJson;    
    $coll = $db['speaker'];
    
    foreach($j in $json)
    {
        $coll.Insert($j)
    }
}

function LoadCosmosDb()
{
    $databaseName = "contentdb";
    $partitionkey = "";
    $cosmosDbContext = New-CosmosDbContext -Account "fabmedical$deploymentid" -Database $databaseName -ResourceGroup $resourceGroupName
    New-CosmosDbDatabase -Context $cosmosDbContext -Id $databaseName
    
    $strJson = Get-Content "c:\labfiles\microservices-workshop\artifacts\content-inti\json\sessions.json"
    $json = ConvertFrom-Json $strJson;
    $collectionName = "sessions";
    New-CosmosDbCollection -Context $cosmosDbContext -Id $collectionName -PartitionKey $partitionkey -OfferThroughput 400 -Database $databaseName
    
    foreach($j in $json)
    {
        New-CosmosDbDocument -Context $cosmosDbContext -CollectionId $collectionName -DocumentBody $j -PartitionKey "XYZ"
    }
    
    $strJson = Get-Content "c:\labfiles\microservices-workshop\artifacts\content-inti\json\speakers.json"
    $json = ConvertFrom-Json $strJson;
    $collectionName = "speaker";
    New-CosmosDbCollection -Context $cosmosDbContext -Id $collectionName -PartitionKey $partitionkey -OfferThroughput 400 -Database $databaseName
    
    foreach($j in $json)
    {
        New-CosmosDbDocument -Context $cosmosDbContext -CollectionId $collectionName -DocumentBody $j -PartitionKey "XYZ"
    }
}

function LoginGitWindows($password)
{
    $wshell.AppActivate('Sign in to your account')
    $wshell.sendkeys("{TAB}{ENTER}");
    $wshell.sendkeys($password);
    $wshell.sendkeys("{ENTER}");
}

$global:outputOnly = $true;

function SendKeys($wshell, $val)
{
    if (!$global:outputOnly)
    {
        $wshell.SendKeys($val);
    }
}

function ExecuteRemoteCommand($ip, $password, $cmd, $sleep, $isInitial)
{
    if ($isInitial -or $cmd.contains("`r"))
    {
        $argumentlist = "plink.exe -t -ssh -l adminfabmedical -pw `"$password`" $ip";
    }
    else
    {
        $argumentlist = "plink.exe -t -ssh -l adminfabmedical -pw `"$password`" $ip `"$cmd`"";
        add-content "c:\labfiles\setup.sh" $cmd;
    }

    if (!$global:outputOnly)
    {
        start-process "cmd.exe"
        start-sleep 5;
    }

    $wshell = New-Object -ComObject wscript.shell;
    $status = $wshell.AppActivate('cmd.exe');

    SendKeys $wshell $argumentlist;
    SendKeys $wshell "{ENTER}";
    
    if ($isinitial)
    {
        start-sleep 2;
        SendKeys $wshell "y"
        SendKeys $wshell "{ENTER}"
    }

    if ($argumentlist.contains("-t") -and $cmd.contains("sudo") -and !$isinitial)
    {
        SendKeys $wshell "{ENTER}"
        start-sleep 2;
        SendKeys $wshell $password;
        SendKeys $wshell "{ENTER}"
    }

    if ($cmd.contains("`r"))
    {
        $lines = $cmd.split("`r");

        foreach($line in $lines)
        {
            add-content "c:\labfiles\setup.sh" $line;

            [void]$wshell.AppActivate('cmd.exe');
            SendKeys $wshell $line
            SendKeys $wshell "{ENTER}"
            start-sleep 3;
        }

        SendKeys $wshell "exit"
        SendKeys $wshell "{ENTER}"
    }

    SendKeys $wshell "{ENTER}"

    if (!$global:outputOnly)
    {
        Start-Sleep $sleep;
    }

    #Stop-Process -Name "cmd" -Confirm:$true;
}

function GetConfig($html, $location)
{
    if ($html.contains("`$Config"))
    {
        $config = ParseValue $html "`$Config=" "]]";
        
        if($config.endswith(";//"))
        {
            $config = $config.substring(0, $config.length-3);
        }

        return ConvertFrom-Json $Config;
    }
}

function LoginDevOps($username, $password)
{
    $html = DoGet "https://dev.azure.com";

    $html = DoGet $global:location;

    $global:defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36";
    $headers.add("Sec-Fetch-Site","cross-site")
    $headers.add("Sec-Fetch-Mode","navigate")
    $headers.add("Sec-Fetch-Dest","document")
    $url = "https://login.microsoftonline.com/common/oauth2/authorize?client_id=499b84ac-1321-427f-aa17-267ca6975798&site_id=501454&response_mode=form_post&response_type=code+id_token&redirect_uri=https%3A%2F%2Fapp.vssps.visualstudio.com%2F_signedin&nonce=a0c857d6-c9e4-46e0-9681-0c5cd86c6207&state=realm%3Ddev.azure.com%26reply_to%3Dhttps%253A%252F%252Fdev.azure.com%252F%26ht%3D3%26nonce%3Da0c857d6-c9e4-46e0-9681-0c5cd86c6207%26githubsi%3Dtrue%26WebUserId%3D00E567095F7B68FC339768145E80699D&resource=https%3A%2F%2Fmanagement.core.windows.net%2F&cid=a0c857d6-c9e4-46e0-9681-0c5cd86c6207&wsucxt=1&githubsi=true&msaoauth2=true"
    $html = DoGet $url;

    $hpgid = ParseValue $html, "`"hpgid`":" ","

    $global:referer = $url;
    $html = DoGet "https://login.microsoftonline.com/common/oauth2/authorize?client_id=499b84ac-1321-427f-aa17-267ca6975798&site_id=501454&response_mode=form_post&response_type=code+id_token&redirect_uri=https%3A%2F%2Fapp.vssps.visualstudio.com%2F_signedin&nonce=a0c857d6-c9e4-46e0-9681-0c5cd86c6207&state=realm%3Ddev.azure.com%26reply_to%3Dhttps%253A%252F%252Fdev.azure.com%252F%26ht%3D3%26nonce%3Da0c857d6-c9e4-46e0-9681-0c5cd86c6207%26githubsi%3Dtrue%26WebUserId%3D00E567095F7B68FC339768145E80699D&resource=https%3A%2F%2Fmanagement.core.windows.net%2F&cid=a0c857d6-c9e4-46e0-9681-0c5cd86c6207&wsucxt=1&githubsi=true&msaoauth2=true&sso_reload=true"

    $config = GetConfig $html;

    $hpgid = ParseValue $html "`"sessionId`":`"" "`""
    $stsRequest = ParseValue $html "ctx%3d" "\u0026";
    $flowToken = ParseValue $html "sFT`":`"" "`"";
    $canary = ParseValue $html "`"canary`":`"" "`"";

    $orginalRequest = $stsRequest;

    $post = "{`"username`":`"$username`",`"isOtherIdpSupported`":true,`"checkPhones`":true,`"isRemoteNGCSupported`":true,`"isCookieBannerShown`":false,`"isFidoSupported`":true,`"originalRequest`":`"$orginalRequest`",`"country`":`"US`",`"forceotclogin`":false,`"isExternalFederationDisallowed`":false,`"isRemoteConnectSupported`":false,`"federationFlags`":0,`"isSignup`":false,`"flowToken`":`"$flowToken`",`"isAccessPassSupported`":true}";
    $html = DoPost "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US" $post;
    $json = ConvertFrom-Json $html;

    $flowToken = $json.FlowToken;
    $apiCanary = $json.apiCanary;

    $post = "i13=0&login=$([System.Web.HttpUtility]::UrlEncode($username))&loginfmt=$([System.Web.HttpUtility]::UrlEncode($username))&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd=$([System.Web.HttpUtility]::UrlEncode($password))&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=$([System.Web.HttpUtility]::UrlEncode($canary))&ctx=$([System.Web.HttpUtility]::UrlEncode($stsRequest))&hpgrequestid=$hpgid&flowToken=$([System.Web.HttpUtility]::UrlEncode($flowToken))&PPSX=&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&i2=1&i17=&i18=&i19=29262"
    $headers.add("Origin","https://login.microsoftonline.com")
    $headers.add("Sec-Fetch-Site","same-origin")
    $headers.add("Sec-Fetch-Mode","navigate")
    $headers.add("Sec-Fetch-User","?1")
    $headers.add("Sec-Fetch-Dest","document")
    $global:referer = "https://login.microsoftonline.com/common/oauth2/authorize?client_id=499b84ac-1321-427f-aa17-267ca6975798&site_id=501454&response_mode=form_post&response_type=code+id_token&redirect_uri=https%3A%2F%2Fapp.vssps.visualstudio.com%2F_signedin&nonce=a0c857d6-c9e4-46e0-9681-0c5cd86c6207&state=realm%3Ddev.azure.com%26reply_to%3Dhttps%253A%252F%252Fdev.azure.com%252F%26ht%3D3%26nonce%3Da0c857d6-c9e4-46e0-9681-0c5cd86c6207%26githubsi%3Dtrue%26WebUserId%3D00E567095F7B68FC339768145E80699D&resource=https%3A%2F%2Fmanagement.core.windows.net%2F&cid=a0c857d6-c9e4-46e0-9681-0c5cd86c6207&wsucxt=1&githubsi=true&msaoauth2=true&sso_reload=true";

    if (!$urlCookies["login.microsoftonline.com"].ContainsKey("AADSSO"))
    {
        $urlCookies["login.microsoftonline.com"].Add("AADSSO", "NA|NoExtension");
    }

    if (!$urlCookies["login.microsoftonline.com"].ContainsKey("SSOCOOKIEPULLED"))
    {
        $urlCookies["login.microsoftonline.com"].Add("SSOCOOKIEPULLED", "1");
    }
                
    $html = DoPost "https://login.microsoftonline.com/common/login" $post;

    $correlationId = ParseValue $html "`"correlationId`":`"" "`""
    $hpgid = ParseValue $html "`"hpgid`":" ","
    $hpgact = ParseValue $html "`"hpgact`":" ","
    $sessionId = ParseValue $html "`"sessionId`":`"" "`""
    $canary = ParseValue $html "`"canary`":`"" "`""
    $apiCanary = ParseValue $html "`"apiCanary`":`"" "`""
    $ctx = ParseValue $html "`"sCtx`":`"" "`""
    $flowToken = ParseValue $html "`"sFT`":`"" "`""

    $config = GetConfig $html;

    $ctx = $config.sCtx;
    $flowToken = $config.sFt;
    $canary = $config.canary;

    $post = "LoginOptions=1&type=28&ctx=$ctx&hpgrequestid=$hpgid&flowToken=$flowToken&canary=$canary&i2=&i17=&i18=&i19=4251";
    $html = DoPost "https://login.microsoftonline.com/kmsi" $post;

    $code = ParseValue $html "code`" value=`"" "`"";
    $idToken = ParseValue $html "id_token`" value=`"" "`"";
    $sessionState = ParseValue $html "session_state`" value=`"" "`"";
    $state = ParseValue $html "state`" value=`"" "`"";

    $state = $state.replace("&amp;","&")

    $post = "code=$([System.Web.HttpUtility]::UrlEncode($code))&id_token=$([System.Web.HttpUtility]::UrlEncode($idToken))&state=$([System.Web.HttpUtility]::UrlEncode($state))&session_state=$sessionState"
    $headers.add("Origin","https://login.microsoftonline.com")
    $headers.add("Sec-Fetch-Site","cross-site")
    $headers.add("Sec-Fetch-Mode","navigate")
    $headers.add("Sec-Fetch-Dest","document")

    $html = DoPost "https://app.vssps.visualstudio.com/_signedin" $post;

    if ($global:location -and $global:location.contains("aex.dev.azure.com"))
    {
        $alias = $username.split("@")[0];
        FirstLoginDevOps $alias $username;
    
        $post = "id_token=$idToken&FedAuth=$fedAuth&FedAuth1=$fedAuth1";
        $headers.add("Origin","https://app.vssps.visualstudio.com")
        $headers.add("Sec-Fetch-Site","cross-site")
        $headers.add("Sec-Fetch-Mode","navigate")
        $headers.add("Sec-Fetch-Dest","document")
        $global:referer = "https://app.vssps.visualstudio.com/_signedin";
        $Html = DoGet "https://vssps.dev.azure.com/_signedin?realm=dev.azure.com&protocol=&reply_to=https%3A%2F%2Fdev.azure.com%2F";
    }
    
    $idToken = ParseValue $html "id_token`" value=`"" "`"";
    $fedAuth = ParseValue $html "FedAuth`" value=`"" "`"";
    $fedAuth1 = ParseValue $html "FedAuth1`" value=`"" "`"";

    $post = "id_token=$idToken&FedAuth=$fedAuth&FedAuth1=$fedAuth1";
    $headers.add("Origin","https://app.vssps.visualstudio.com")
    $headers.add("Sec-Fetch-Site","cross-site")
    $headers.add("Sec-Fetch-Mode","navigate")
    $headers.add("Sec-Fetch-Dest","document")
    $global:referer = "https://app.vssps.visualstudio.com/_signedin";
    $Html = DoPost "https://vssps.dev.azure.com/_signedin?realm=dev.azure.com&protocol=&reply_to=https%3A%2F%2Fdev.azure.com%2F" $post;

    $html = DoGet "https://dev.azure.com";
    $azureCookies = $global:urlcookies["dev.azure.com"];

    foreach($key in $global:urlcookies["app.vssps.visualstudio.com"].keys)
    {
        if ($azureCookies.containskey($key))
        {
            $azureCookies[$key] = $global:urlcookies["app.vssps.visualstudio.com"][$key];
        }
        else
        {
            $azureCookies.add($key,$global:urlcookies["app.vssps.visualstudio.com"][$key]);
        }
    }

    foreach($key in $global:urlcookies["app.vssps.visualstudio.com"].keys)
    {

        if ($azureCookies.containskey($key))
        {
            $azureCookies[$key] = $global:urlcookies["aex.dev.azure.com"][$key];
        }
        else
        {
            $azureCookies.add($key,$global:urlcookies["aex.dev.azure.com"][$key]);
        }
    }
}

function FirstLoginDevOps($username, $email)
{
    $headers.add("Origin","https://aex.dev.azure.com")
    $headers.add("X-Requested-With", "XMLHttpRequest")
    $global:referer = "https://aex.dev.azure.com/profile/create?account=false&mkt=en-US&reply_to=https%3A%2F%2Fapp.vssps.visualstudio.com%2F_signedin%3Frealm%3Ddev.azure.com%26reply_to%3Dhttps%253A%252F%252Fdev.azure.com%252F";
    $url = "https://aex.dev.azure.com/_apis/WebPlatformAuth/SessionToken";
    $post = "{`"appId`":`"00000000-0000-0000-0000-000000000000`",`"force`":false,`"tokenType`":0,`"namedTokenId`":`"Aex.Profile`"}"
    $global:overrideContentType = "application/json";
    $html = DoPost $url $post;

    $json = ConvertFrom-Json $html;
    $token = $json.token;

    $headers.add("Origin","https://aex.dev.azure.com")
    $headers.add("X-Requested-With", "XMLHttpRequest")
    $global:referer = "https://aex.dev.azure.com/profile/create?account=false&mkt=en-US&reply_to=https%3A%2F%2Fapp.vssps.visualstudio.com%2F_signedin%3Frealm%3Ddev.azure.com%26reply_to%3Dhttps%253A%252F%252Fdev.azure.com%252F";
    $url = "https://aex.dev.azure.com/_apis/User/User";
    $post = "{`"country`":`"US`",`"data`":{`"CIData`":{`"createprofilesource`":`"web`"}},`"displayName`":`"$username`",`"mail`":`"$email`"}";
    $global:overrideContentType = "application/json";
    $headers.add("Authorization","Bearer $token");
    $html = DoPost $url $post;
}

function InstallPutty()
{
    write-host "Installing Putty";

    #check for executables...
	$item = get-item "C:\Program Files\Putty\putty.exe" -ea silentlycontinue;
	
	if (!$item)
	{
		$downloadNotePad = "https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-0.74-installer.msi";

        mkdir c:\temp -ea silentlycontinue 
		
		#download it...		
		Start-BitsTransfer -Source $DownloadNotePad -DisplayName Notepad -Destination "c:\temp\putty.msi"
        
        msiexec.exe /I c:\temp\Putty.msi /quiet
	}
}

function Refresh-Token {
  param(
  [parameter(Mandatory=$true)]
  [String]
  $TokenType
  )

  if(Test-Path C:\LabFiles\AzureCreds.ps1){
      if ($TokenType -eq "Synapse") {
          $result = Invoke-RestMethod  -Uri "https://login.microsoftonline.com/$($global:logindomain)/oauth2/v2.0/token" `
              -Method POST -Body $global:ropcBodySynapse -ContentType "application/x-www-form-urlencoded"
          $global:synapseToken = $result.access_token
      } elseif ($TokenType -eq "SynapseSQL") {
          $result = Invoke-RestMethod  -Uri "https://login.microsoftonline.com/$($global:logindomain)/oauth2/v2.0/token" `
              -Method POST -Body $global:ropcBodySynapseSQL -ContentType "application/x-www-form-urlencoded"
          $global:synapseSQLToken = $result.access_token
      } elseif ($TokenType -eq "Management") {
          $result = Invoke-RestMethod  -Uri "https://login.microsoftonline.com/$($global:logindomain)/oauth2/v2.0/token" `
              -Method POST -Body $global:ropcBodyManagement -ContentType "application/x-www-form-urlencoded"
          $global:managementToken = $result.access_token
      } elseif ($TokenType -eq "PowerBI") {
          $result = Invoke-RestMethod  -Uri "https://login.microsoftonline.com/$($global:logindomain)/oauth2/v2.0/token" `
              -Method POST -Body $global:ropcBodyPowerBI -ContentType "application/x-www-form-urlencoded"
          $global:powerbitoken = $result.access_token
      } elseif ($TokenType -eq "DevOps") {
        #$result = Invoke-RestMethod  -Uri "https://app.vssps.visualstudio.com/oauth2/token" -Method POST -Body $global:ropcBodyDevOps -ContentType "application/x-www-form-urlencoded"
        $result = Invoke-RestMethod  -Uri "https://login.microsoftonline.com/$($global:logindomain)/oauth2/v2.0/token" -Method POST -Body $global:ropcBodyDevOps -ContentType "application/x-www-form-urlencoded"
        $global:devopstoken = $result.access_token
    }
      else {
          throw "The token type $($TokenType) is not supported."
      }
  } else {
      switch($TokenType) {
          "Synapse" {
              $tokenValue = ((az account get-access-token --resource https://dev.azuresynapse.net) | ConvertFrom-Json).accessToken
              $global:synapseToken = $tokenValue; 
              break;
          }
          "SynapseSQL" {
              $tokenValue = ((az account get-access-token --resource https://sql.azuresynapse.net) | ConvertFrom-Json).accessToken
              $global:synapseSQLToken = $tokenValue; 
              break;
          }
          "Management" {
              $tokenValue = ((az account get-access-token --resource https://management.azure.com) | ConvertFrom-Json).accessToken
              $global:managementToken = $tokenValue; 
              break;
          }
          "PowerBI" {
              $tokenValue = ((az account get-access-token --resource https://analysis.windows.net/powerbi/api) | ConvertFrom-Json).accessToken
              $global:powerbitoken = $tokenValue; 
              break;
          }
          "DevOps" {
            $tokenValue = ((az account get-access-token --resource https://app.vssps.visualstudio.com) | ConvertFrom-Json).accessToken
            $global:devopstoken = $tokenValue; 
            break;
        }
          default {throw "The token type $($TokenType) is not supported.";}
      }
  }
}

function Ensure-ValidTokens {

  for ($i = 0; $i -lt $tokenTimes.Count; $i++) {
      Ensure-ValidToken $($tokenTimes.Keys)[$i]
  }
}

function Ensure-ValidToken {
  param(
      [parameter(Mandatory=$true)]
      [String]
      $TokenName
  )

  $refTime = Get-Date

  if (($refTime - $tokenTimes[$TokenName]).TotalMinutes -gt 30) {
      Write-Information "Refreshing $($TokenName) token."
      Refresh-Token $TokenName
      $tokenTimes[$TokenName] = $refTime
  }
  
  #Refresh-Token;
}

function CreateRepoToken($organziation, $projectName, $repoName)
{
    write-host "Creating Repo Token";

    $html = DoGet "https://dev.azure.com/$organziation/$projectName";

    $accountId = ParseValue $html "hostId`":`"" "`"";

    $uri = "https://dev.azure.com/$organziation/_details/security/tokens/Edit"
    $post = "{`"AccountMode`":`"SelectedAccounts`",`"AuthorizationId`":`"`",`"Description`":`"Git: https://dev.azure.com/$organization on the website.`",`"ScopeMode`":`"SelectedScopes`",`"SelectedAccounts`":`"$accountId`",`"SelectedExpiration`":`"365`",`"SelectedScopes`":`"vso.code_write`"}";

    $global:overrideContentType = "application/json";
    $html = DoPost $uri $post;
    $result = ConvertFrom-json $html;

    return $result.Token;
}

function CreateDevOpsRepos($organization, $projectName, $repoName)
{
    write-host "Creating repo [$repoName]";

    $uri = "https://dev.azure.com/$organization/$projectName/_apis/git/repositories?api-version=5.1"

    $item = Get-Content -Raw -Path "$($TemplatesPath)/repo.json"
    $item = $item.Replace("#NAME#", $repoName);
    $jsonItem = ConvertFrom-Json $item
    $item = ConvertTo-Json $jsonItem -Depth 100

    <#
    Ensure-ValidTokens;
    $azuredevopsLogin = "$($azureusername):$($azurepassword)";
    $AzureDevOpsAuthenicationHeader = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($azuredevopsLogin)")) }

    if ($global:pat)
    {
        $AzureDevOpsAuthenicationHeader = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($global:pat)")) }
    }
    else
    {
        $AzureDevOpsAuthenicationHeader = @{Authorization = 'Bearer ' + $global:devopsToken }
    }

    $result = Invoke-RestMethod  -Uri $uri -Method POST -Body $item -Headers $AzureDevOpsAuthenicationHeader -ContentType "application/json";
    #>

    $global:overrideContentType = "application/json";
    $html = DoPost $uri $item;
    $result = ConvertFrom-json $html;

    write-host "Creating repo result [$result]";

    return $result;
}

function GetDevOpsRepos($organization, $projectName)
{
    $uri = "https://dev.azure.com/$organization/$projectName/_apis/git/repositories?api-version=5.1"
    $global:overrideContentType = "application/json";
    $html = DoGet $uri;
    $result = ConvertFrom-json $html;

    return $result.value;
}

function CreateDevOpsProject($organization, $name)
{
    $uri = "https://dev.azure.com/$organization/_apis/projects?api-version=5.1";

    $item = Get-Content -Raw -Path "$($TemplatesPath)/project.json"
    $item = $item.Replace("#PROJECT_NAME#", $Name);
    $item = $item.Replace("#PROJECT_DESC#", $Name)
    $jsonItem = ConvertFrom-Json $item
    $item = ConvertTo-Json $jsonItem -Depth 100

    $global:overrideContentType = "application/json";
    $html = DoPost $uri $item;
    $result = ConvertFrom-json $html;
    return $result;
}

#https://borzenin.no/create-service-connection/
function CreateARMServiceConnection($organization, $name, $item, $spnId, $spnSecret, $tenantId, $subscriptionId, $subscriptionName, $projectName)
{
    $uri = " https://dev.azure.com/$organization/$projectName/_apis/serviceendpoint/endpoints?api-version=5.1-preview";
    $global:overrideContentType = "application/json";
    $html = DoPost $uri $item;
    $result = ConvertFrom-json $html;

    return $result;
}

function InstallNotepadPP()
{
    write-host "Installing Notepad++";
    
    #check for executables...
	$item = get-item "C:\Program Files (x86)\Notepad++\notepad++.exe" -ea silentlycontinue;
	
	if (!$item)
	{
        $downloadNotePad = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v7.9.1/npp.7.9.1.Installer.exe";
        
        #https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v7.9.1/npp.7.9.1.Installer.exe

        mkdir c:\temp -ea silentlycontinue   
		
		#download it...		
        #Start-BitsTransfer -Source $DownloadNotePad -DisplayName Notepad -Destination "c:\temp\npp.exe"
        
        Invoke-WebRequest $downloadNotePad -OutFile "c:\temp\npp.exe"
		
		#install it...
		$productPath = "c:\temp";				
		$productExec = "npp.exe"	
		$argList = "/S"
		start-process "$productPath\$productExec" -ArgumentList $argList -wait
	}
}

function InstallDocker()
{
    Install-Module -Name DockerMsftProvider -Repository PSGallery -Force;
    Install-Package -Name docker -ProviderName DockerMsftProvider -force;
}

function InstallDockerWin10()
{   
    Write-Host "Installing Docker." -ForegroundColor Yellow

    dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
    #WSL
 
    dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart

    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
    #wsl --set-default-version 2
}

function InstallUbuntu()
{
    write-host "Installing Ubuntu";

    winrm quickconfig -force

    write-host "Downloading Ubuntu (1604)";

    $Path = "c:/temp";
    Invoke-WebRequest -Uri https://aka.ms/wsl-ubuntu-1604 -OutFile "$path/Ubuntu1604.appx" -UseBasicParsing

    powershell.exe -c "`$user='$localusername'; `$pass='$password'; try { Invoke-Command -ScriptBlock { Add-AppxPackage `"$path\Ubuntu1604.appx`" } -ComputerName localhost -Credential (New-Object System.Management.Automation.PSCredential `$user,(ConvertTo-SecureString `$pass -AsPlainText -Force)) } catch { echo `$_.Exception.Message }" 

    write-host "Downloading Ubuntu (1804)";
    Invoke-WebRequest -Uri https://aka.ms/wsl-ubuntu-1804 -OutFile "$path/Ubuntu1804.appx" -UseBasicParsing

    powershell.exe -c "`$user='$localusername'; `$pass='$password'; try { Invoke-Command -ScriptBlock { Add-AppxPackage `"$path\Ubuntu1804.appx`" } -ComputerName localhost -Credential (New-Object System.Management.Automation.PSCredential `$user,(ConvertTo-SecureString `$pass -AsPlainText -Force)) } catch { echo `$_.Exception.Message }" 

    write-host "Downloading Ubuntu (2004)";
    Invoke-WebRequest -Uri https://aka.ms/wsl-ubuntu-2004 -OutFile "$path/Ubuntu2004.appx" -UseBasicParsing

    powershell.exe -c "`$user='$localusername'; `$pass='$password'; try { Invoke-Command -ScriptBlock { Add-AppxPackage `"$path\Ubuntu2004.appx`" } -ComputerName localhost -Credential (New-Object System.Management.Automation.PSCredential `$user,(ConvertTo-SecureString `$pass -AsPlainText -Force)) } catch { echo `$_.Exception.Message }" 
}

function InstallEdge()
{
    #get windows version...
    Get-AppXPackage -AllUsers -Name Microsoft.MicrosoftEdge | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -Verbose}
}

function InstallChrome()
{
    write-host "Installing Chrome";

    $Path = "c:\temp"; 
    $Installer = "chrome_installer.exe"; 
    Invoke-WebRequest "http://dl.google.com/chrome/install/375.126/chrome_installer.exe" -OutFile $Path\$Installer; 
    Start-Process -FilePath $Path\$Installer -Args "/silent /install" -Verb RunAs -Wait; 
    Remove-Item $Path\$Installer
}

function InstallFiddler()
{
  write-host "Installing Fiddler";

  InstallChocolaty;

  choco install fiddler --ignoredetectedreboot
}

function InstallPorter()
{
  iwr "https://cdn.porter.sh/latest/install-windows.ps1" -UseBasicParsing | iex
}

function InstallPostman()
{
  write-host "Installing Postman";

  InstallChocolaty;

  choco install postman --ignoredetectedreboot
}

function InstallSmtp4Dev()
{
  write-host "Installing Smtp4Dev";

  InstallChocolaty;

  choco install smtp4dev --ignoredetectedreboot
}

function InstallDotNet5()
{
  write-host "Installing DotNet5";

  $url = "https://download.visualstudio.microsoft.com/download/pr/21511476-7a5b-4bfe-b96e-3d9ebc1f01ab/f2cf00c22fcd52e96dfee7d18e47c343/dotnet-sdk-5.0.100-preview.7.20366.6-win-x64.exe";
  $output = "$env:TEMP\dotnet.exe";
  Invoke-WebRequest -Uri $url -OutFile $output; 

  $productPath = "$env:TEMP";
  $productExec = "dotnet.exe"	
  $argList = "/SILENT"
  start-process "$productPath\$productExec" -ArgumentList $argList -wait
}

function InstallDotNetCore($version)
{
  write-host "Installing Dot Core $version";

    try
    {
        Invoke-WebRequest 'https://dot.net/v1/dotnet-install.ps1' -OutFile 'dotnet-install.ps1';
        ./dotnet-install.ps1 -Channel $version;
    }
    catch
    {
        write-host $_.exception.message;
    }
}

function InstallDockerDesktop()
{
    write-host "Installing Docker Desktop";

    <#
    mkdir c:\temp -ea silentlycontinue
    #Docker%20Desktop%20Installer.exe install --quiet

    $downloadNotePad = "https://desktop.docker.com/win/stable/Docker%20Desktop%20Installer.exe";

    #download it...		
    Start-BitsTransfer -Source $DownloadNotePad -DisplayName Notepad -Destination "c:\temp\dockerdesktop.exe"
    
    #install it...
    $productPath = "c:\temp";				
    $productExec = "dockerdesktop.exe"	
    $argList = "install --quiet"

    $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList @($localusername,(ConvertTo-SecureString -String $password -AsPlainText -Force))

    start-process "$productPath\$productExec" -ArgumentList $argList -wait -Credential $credentials
    start-process "$productPath\$productExec" -ArgumentList $argList -wait
    #>

    choco install docker-desktop --pre --ignoredetectedreboot

    Add-LocalGroupMember -Group "docker-users" -Member $localusername;

    #enable kubernets mode
    <#
    $file = "C:\Users\adminfabmedical\AppData\Roaming\Docker\settings.json";
    $data = get-content $file -raw;
    $json = ConvertFrom-Json $data;
    $json.kubernetesEnabled = $true;
    set-content $file $json;
    #>
}

function InstallWSL2
{
    write-host "Installing WSL2";

    mkdir c:\temp -ea silentlycontinue
    cd c:\temp
    
    $downloadNotePad = "https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi";

    #download it...		
    Start-BitsTransfer -Source $DownloadNotePad -DisplayName Notepad -Destination "wsl_update_x64.msi"

    $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList @($localusername,(ConvertTo-SecureString -String $password -AsPlainText -Force))

    #Start-Process msiexec.exe -Wait -ArgumentList '/I C:\temp\wsl_update_x64.msi /quiet' -Credential $credentials
    Start-Process msiexec.exe -Wait -ArgumentList '/I C:\temp\wsl_update_x64.msi /quiet'

    <#
    wsl --set-default-version 2
    wsl --set-version Ubuntu 2
    wsl --list -v
    #>
}

function InstallVisualStudio($edition)
{
    Write-Host "Install Visual Studio [$edition]." -ForegroundColor Yellow

    # Install Chocolatey
    if (!(Get-Command choco.exe -ErrorAction SilentlyContinue)) 
    {
        Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
        
    if ($edition -eq "enterprise")
    {
      choco install visualstudio2019enterprise -y
    }

    if ($edition -eq "community")
    {
      choco install visualstudio2019community -y
    }
}

function InstallWSL()
{
    write-host "Installing WSL";

    $script = "dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart"

    #& $script

    powershell.exe -c "`$user='$localusername'; `$pass='$password'; try { Invoke-Command -ScriptBlock { & $script } -ComputerName localhost -Credential (New-Object System.Management.Automation.PSCredential `$user,(ConvertTo-SecureString `$pass -AsPlainText -Force)) } catch { echo `$_.Exception.Message }" 
    
    $script = "dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart"

    #& $script

    powershell.exe -c "`$user='$localusername'; `$pass='$password'; try { Invoke-Command -ScriptBlock { & $script } -ComputerName localhost -Credential (New-Object System.Management.Automation.PSCredential `$user,(ConvertTo-SecureString `$pass -AsPlainText -Force)) } catch { echo `$_.Exception.Message }" 

    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
}

function UpdateVisualStudio($edition, $year)
{
    $year = "2019";

    mkdir c:\temp -ea silentlycontinue
    cd c:\temp
    
    Write-Host "Update Visual Studio $year [$edition]."

    $Channel = 'Release';
    $channelUri = "https://aka.ms/vs/16/release";
    $responseFileName = "vs";
 
    $intermedateDir = "c:\temp";
    $bootstrapper = "$intermedateDir\vs_$edition.exe"
    #$responseFile = "$PSScriptRoot\$responseFileName.json"
    #$channelId = (Get-Content $responseFile | ConvertFrom-Json).channelId
    
    $bootstrapperUri = "$channelUri/vs_$($Edition.ToLowerInvariant()).exe"
    Write-Host "Downloading Visual Studio $year $Edition ($Channel) bootstrapper from $bootstrapperUri"

    #download a bootstrapper
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($bootstrapperUri,$bootstrapper)

    $bootstrapper = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vs_installer.exe";

    #update visual studio installer
    Start-Process $bootstrapper -Wait -ArgumentList 'update --quiet'

    #update visual studio
    Start-Process $bootstrapper -Wait -ArgumentList "update --quiet --norestart --installPath 'C:\Program Files (x86)\Microsoft Visual Studio\$year\$edition'"
}

#Disable-InternetExplorerESC
function DisableInternetExplorerESC
{
  $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
  $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
  Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force -ErrorAction SilentlyContinue -Verbose
  Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force -ErrorAction SilentlyContinue -Verbose
  Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green -Verbose
}

#Enable-InternetExplorer File Download
function EnableIEFileDownload
{
  $HKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
  $HKCU = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
  Set-ItemProperty -Path $HKLM -Name "1803" -Value 0 -ErrorAction SilentlyContinue -Verbose
  Set-ItemProperty -Path $HKCU -Name "1803" -Value 0 -ErrorAction SilentlyContinue -Verbose
  Set-ItemProperty -Path $HKLM -Name "1604" -Value 0 -ErrorAction SilentlyContinue -Verbose
  Set-ItemProperty -Path $HKCU -Name "1604" -Value 0 -ErrorAction SilentlyContinue -Verbose
}

function InstallGit()
{
    Write-Host "Installing Git" -ForegroundColor Yellow

    <#
    #download and install git...		
    $output = "c:\temp\git.exe";
    Invoke-WebRequest -Uri https://github.com/git-for-windows/git/releases/download/v2.27.0.windows.1/Git-2.27.0-64-bit.exe -OutFile $output; 

    $productPath = "c:\temp";
    $productExec = "git.exe"	
    $argList = "/SILENT"
    start-process "$productPath\$productExec" -ArgumentList $argList -wait
    #>

    choco install git.install --ignoredetectedreboot

    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
}

function InstallAzureCli()
{
  Write-Host "Install Azure CLI." -ForegroundColor Yellow

  #install azure cli
  Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; 
  Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; 
  rm .\AzureCLI.msi
}

function InstallChocolaty()
{
  $env:chocolateyUseWindowsCompression = 'true'
  Set-ExecutionPolicy Bypass -Scope Process -Force; 
  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; 
  iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

  $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")

  choco feature enable -n allowGlobalConfirmation
}

#Create InstallAzPowerShellModule
function InstallAzPowerShellModule
{
    write-host "Installing Azure PowerShell";

    $pp = Get-PackageProvider -Name NuGet -Force
    
    Set-PSRepository PSGallery -InstallationPolicy Trusted

    $m = get-module -ListAvailable -name Az.Accounts

    if (!$m)
    {
        Install-Module Az -Repository PSGallery -Force -AllowClobber
    }
}

#Create-LabFilesDirectory
function CreateLabFilesDirectory
{
  New-Item -ItemType directory -Path C:\LabFiles -force
}

#Create Azure Credential File on Desktop
function CreateCredFile($azureUsername, $azurePassword, $azureTenantID, $azureSubscriptionID, $deploymentId)
{
  $WebClient = New-Object System.Net.WebClient
  $WebClient.DownloadFile("https://raw.githubusercontent.com/solliancenet/kubernetes-workshop/main/artifacts/environment-setup/automation/spektra/AzureCreds.txt","C:\LabFiles\AzureCreds.txt")
  $WebClient.DownloadFile("https://raw.githubusercontent.com/solliancenet/kubernetes-workshop/main/artifacts/environment-setup/automation/spektra/AzureCreds.ps1","C:\LabFiles\AzureCreds.ps1")

  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "ClientIdValue", ""} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzureUserNameValue", "$azureUsername"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzurePasswordValue", "$azurePassword"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzureSQLPasswordValue", "$azurePassword"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzureTenantIDValue", "$azureTenantID"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzureSubscriptionIDValue", "$azureSubscriptionID"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "DeploymentIDValue", "$deploymentId"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"               
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "ODLIDValue", "$odlId"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"  
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "ClientIdValue", ""} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzureUserNameValue", "$azureUsername"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzurePasswordValue", "$azurePassword"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzureSQLPasswordValue", "$azurePassword"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzureTenantIDValue", "$azureTenantID"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzureSubscriptionIDValue", "$azureSubscriptionID"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "DeploymentIDValue", "$deploymentId"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "ODLIDValue", "$odlId"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  Copy-Item "C:\LabFiles\AzureCreds.txt" -Destination "C:\Users\Public\Desktop"
}

function DownloadPSExec()
{
    $url = "https://download.sysinternals.com/files/PSTools.zip";

    $WebClient = New-Object System.Net.WebClient;
    $WebClient.DownloadFile($url,"C:\temp\PSTools.zip")

    #extract

}

function RunAsSystem($scriptPath, $arguments)
{
    psexec.exe -i -s powershell.exe -file $scriptpath -argumentlist $arguments;
}

function RerunInstall($scriptPath)
{
    #get the creds

    #call the script
    powershell.exe -FilePath $scriptpath;
}