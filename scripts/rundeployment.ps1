Param (
  [Parameter(Mandatory = $true)]
  [string]
  $templateFile,

  [Parameter(Mandatory = $true)]
  [string]
  $parametersFile,

  [Parameter(Mandatory = $true)]
  [string]
  $resourceGroupName
)

Start-Transcript -Path C:\WindowsAzure\Logs\CloudLabsCustomScriptExtension-subdeploy.txt -Append

New-AzResourceGroupDeployment -ResourceGroupName $resourceGroupName `
  -TemplateFile $templateFile `
  -TemplateParameterFile "$($parametersFile)"

Stop-Transcript