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


New-AzResourceGroupDeployment -ResourceGroupName $resourceGroupName `
  -TemplateFile $templateFile `
  -TemplateParameterFile "$($parametersFile)"
