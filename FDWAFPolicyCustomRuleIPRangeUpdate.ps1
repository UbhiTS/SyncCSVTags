# Source JSON file for Azure IP Address Ranges:
# Azure IP Ranges and Service Tags – Public Cloud - https://www.microsoft.com/en-us/download/details.aspx?id=56519
# Azure IP Ranges and Service Tags – US Government Cloud - https://www.microsoft.com/en-us/download/details.aspx?id=57063

# FDWAFPolicyCustomRuleIPRangeUpdate -jsonFilePath "C:\Temp\ServiceTags_Public_20240916.json" -subscriptionId "XXXX" -resourceGroupName "az-frontdoor-rg" -wafPolicyName "fdwafpolicy" -customRuleName "BlockIPsFromServiceTags" -customRulePriority 2000 -customRuleAction "Block" -serviceIdList @("StorageSyncService.AustraliaCentral2", "StorageSyncService.AustraliaSoutheast")

function FDWAFPolicyCustomRuleIPRangeUpdate {
    param (
        [string]$jsonFilePath,
        [string]$subscriptionId,
        [string]$resourceGroupName,
        [string]$wafPolicyName,
        [string]$customRuleName,
        [int]$customRulePriority,
        [string]$customRuleAction,
        [string[]]$serviceIdList
    )

    $jsonContent = Get-Content -Path $jsonFilePath -Raw | ConvertFrom-Json

    $ipRanges = @()
    foreach ($value in $jsonContent.values) {
        if ($serviceIdList -contains $value.id) {
            foreach ($property in $value.properties.addressPrefixes) {
                $ipRanges += $property
            }
        }
    }

    Connect-AzAccount -Subscription $subscriptionId

    $wafPolicy = Get-AzFrontDoorWafPolicy -ResourceGroupName $resourceGroupName -Name $wafPolicyName

    $existingRule = $wafPolicy.CustomRules | Where-Object { $_.Name -eq $customRuleName }

    if ($existingRule) {
        $existingIPRanges = $existingRule.MatchConditions | Where-Object { $_.MatchVariable -eq "RemoteAddr" } | Select-Object -ExpandProperty MatchValue

        $newIPRanges = $ipRanges | Where-Object { $existingIPRanges -notcontains $_ }
        $existingIPRanges += $newIPRanges

        $existingIPRanges = $existingIPRanges | Where-Object { $ipRanges -contains $_ }

        $existingRule.MatchConditions = @(
            New-AzFrontDoorWafMatchConditionObject -MatchVariable RemoteAddr -Operator IPMatch -MatchValue $existingIPRanges
        )
    } else {
        $customRule = New-AzFrontDoorWafCustomRuleObject -Name $customRuleName -Priority $customRulePriority -RuleType MatchRule -MatchCondition @(
            New-AzFrontDoorWafMatchConditionObject -MatchVariable RemoteAddr -Operator IPMatch -MatchValue $ipRanges
        ) -Action $customRuleAction

        $wafPolicy.CustomRules += $customRule
    }

    Update-AzFrontDoorWafPolicy -InputObject $wafPolicy

    Write-Output "Custom rule added or updated in WAF policy successfully."
}

FDWAFPolicyCustomRuleIPRangeUpdate -jsonFilePath "C:\Temp\ServiceTags_Public_20240916.json" -subscriptionId "XXXX" -resourceGroupName "az-frontdoor-rg" -wafPolicyName "fdwafpolicy" -customRuleName "BlockIPsFromServiceTags" -customRulePriority 2000 -customRuleAction "Block" -serviceIdList @("StorageSyncService.AustraliaCentral2", "StorageSyncService.AustraliaSoutheast")
