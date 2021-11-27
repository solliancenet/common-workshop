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

$item = Get-item $templateFile;

Start-Transcript -Path C:\WindowsAzure\Logs\CloudLabsCustomScriptExtension-$($item.Name).txt -Append

New-AzResourceGroupDeployment -ResourceGroupName $resourceGroupName `
  -Name $item.Name `
  -TemplateFile $templateFile `
  -TemplateParameterFile "$($parametersFile)"

Stop-Transcript