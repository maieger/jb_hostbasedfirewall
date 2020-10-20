<#
	.SYNOPSIS
	HOSTBASEDFIREWALL DSC Resource

	.DESCRIPTION
	This resource sets the Windows Firewall to the Ruleset provided in the $InRules and $OutRules Parameters
	
	.PARAMETER InRules
	A JSON string, which contains the Firewallrules for the allowed inbound connections

	.PARAMETER OutRules
	A JSON string, which contains the Firewallrules for the allowed outbound connections

	.PARAMETER Ensure
    An Enum (Present, Absent) which enables/disables the applying of the Resource
    
    .PARAMETER CreationTime
    a not configureable value, which returns the last Check time for the system
    
    .PARAMETER ResultRules
	a not configureable value, which returns the applied Firewall Rules for the system

	.NOTES
	Gerhard Maier, Version 1.0, 06.04.2020
	#>

enum Ensure {
    Present
    Absent
    }

[DscResource()]
class HostBasedFirewall {
    
    [DscProperty(Key)]
    [string]$InRules

    [DscProperty()]
    [string]$OutRules

    [DscProperty(Mandatory)]
    [Ensure] $Ensure

    [DscProperty(NotConfigurable)]
    [Nullable[datetime]] $CreationTime

    [DscProperty(NotConfigurable)]
    [string[]] $ResultRules

    
    [void] Set() {

        # Set if only inbound rules are provided
        if (($this.ensure -eq [Ensure]::Present) -and (!($this.OutRules)))  {   
            Write-Verbose -Message "Dealing with only Inbound Rules"
            # Set Firewall for allowing outbound connections in all Profiles
            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow             
            # Get Local and exspected Rules
            $this.InRules = $this.InRules -replace '\\', '\\'
            $thrules = $this.InRules | ConvertFrom-Json
            $exfwrules = $this.GetLocalFirewallRuleName()
            # Creating Rules which not exists
            foreach ($fwrule in $thrules) {   
                $fwrule = $fwrule -replace '\\', '\\'
                #$fwrule = ConvertFrom-StringData -StringData $fwrule
                $fwrule = $fwrule.split(";")
                $hrules = @{}
                foreach ($r in $fwrule) {
                    $r = $r -replace ("@{","")
                    $r = $r -replace ("}","")
                    $r = $r -replace ("\\\\","\")
                    $r = $r.split("=")
                    $hrules.Add($r[0].Trim(), $r[1].Trim())
                }
                [string]$out = $hrules.Name
                Write-Verbose $out
                if($exfwrules.Contains($hrules.Name)) {
                    Write-Verbose -Message "Rule already exists "
                }
                else {
                    New-NetFirewallRule @hrules
                    Write-Verbose -Message "Creating Rule "
                }
            }
            # Deleting Rules which are not in Ruleset
            $baserulename = $this.GetExpectedFirewallRuleName()
            foreach ($exrule in $exfwrules) {
                if ($baserulename.Contains($exrule)) {
                    Write-Verbose -Message "NOT deleting $exrule"
                }
                else {
                    Write-Verbose -Message "deleting $exrule"
                    Remove-NetFirewallRule -Name $exrule
                }
            }
        }
        elseif (($this.ensure -eq [Ensure]::Present) -and ($this.OutRules)){
            Write-Verbose -Message "Dealing with In- and Outbound Rules"
            # Set Firewall for allowing outbound connections in all Profiles
            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block             
            # Get Local and exspected Rules
            $this.InRules = $this.InRules -replace '\\', '\\'
            $this.OutRules = $this.OutRules -replace '\\', '\\'
            $thrules = $this.InRules | ConvertFrom-Json
            $thrules += $this.OutRules | ConvertFrom-Json
            $exfwrules = $this.GetLocalFirewallRuleName()
            # Creating Rules which not exists
            foreach ($fwrule in $thrules) {   
                $fwrule = $fwrule -replace '\\', '\\'
                $fwrule = $fwrule.split(";")
                $hrules = @{}
                foreach ($r in $fwrule) {
                    $r = $r -replace ("@{","")
                    $r = $r -replace ("}","")
                    $r = $r -replace ("\\\\","\")
                    $r = $r.split("=")
                    $hrules.Add($r[0].Trim(), $r[1].Trim())
                }
                if($exfwrules.Contains($hrules.Name)) {
                    Write-Verbose -Message "Rule already exists "
                }
                else {
                    New-NetFirewallRule @hrules
                    Write-Verbose -Message "Creating Rule "
                }
            }
            # Deleting Rules which are not in Ruleset
            $baserulename = $this.GetExpectedFirewallRuleName()
            foreach ($exrule in $exfwrules) {
                if ($baserulename.Contains($exrule)) {
                    Write-Verbose -Message "NOT deleting $exrule"
                }
                else {
                    Write-Verbose -Message "deleting $exrule"
                    Remove-NetFirewallRule -Name $exrule
                }
            }
        }
        elseif ($this.ensure -eq [Ensure]::Absent) {
            Write-Verbose -Message "If ABSENT dont do anything"
        }
    } # END [void] Set()
    
    [bool] Test() {
        $exfwrules = $this.GetLocalFirewallRuleName()
        $dscrules = $this.GetExpectedFirewallRuleName()
        if ($this.Ensure -eq [Ensure]::Present) {
            if (!(Compare-Object -ReferenceObject $exfwrules -DifferenceObject $dscrules)) {
                return $true
            }
            else {
                return $false
            }
        }
        else {
            return $false
        }
    } # END [bool] Test()
    
    [HostBasedFirewall] Get() {
        $exfwrules = $this.GetLocalFirewallRuleName()
        $dscrules = $this.GetExpectedFirewallRuleName()
        $present = Compare-Object -ReferenceObject $exfwrules -DifferenceObject $dscrules
        if (!$present) {
            $this.ResultRules = $exfwrules
            $this.CreationTime = Get-Date
            $this.Ensure = [Ensure]::Present
        }
        else {
            $this.ResultRules = $exfwrules
            $this.CreationTime = $null
            $this.Ensure = [Ensure]::Absent
        }
        return $this
    } # END [HostBasedFirewall] Get()

    [array] GetLocalFirewallRuleName() {
        <#
        .SYNOPSIS
        Returns all Firewall-Rules-Names as an Array
        .DESCRIPTION
        Returns all Firewall-Rules-Names as an Array
        .EXAMPLE
        Get-LocalFirewallRuleName
        .NOTES
        Gerhard Maier, Version 1.0, 27.03.2020
        #>
        Try {
            $fwrules = @()
            $fwrules = Get-NetFirewallRule | Select-Object Name
            return $fwrules.Name
        }
        Catch {
            return $_.Exception.Message
        }
        Finally {
        }
    } # End Function Get-LocalFirewallRuleName

    [array] GetExpectedFirewallRuleName() {
        <#
        .SYNOPSIS
        Returns all Firewall-Rules-Names as an Array
        .DESCRIPTION
        Returns all Firewall-Rules-Names as an Array
        .EXAMPLE
        Get-LocalFirewallRuleName
        .NOTES
        Gerhard Maier, Version 1.0, 27.03.2020
        #>
        Try {
            $fwrules = @()
            $this.InRules = $this.InRules -replace '\\', '\\'
            $thrules = $this.InRules | ConvertFrom-Json
            if ($this.OutRules) {
                $this.OutRules = $this.OutRules -replace '\\', '\\'
                $thrules += $this.OutRules | ConvertFrom-Json
            }
                      
            foreach ($fwrule in $thrules) {
                [string]$hlpstr = $fwrule
                $fw = $hlpstr.split(";")
                $hrules = @{}
                foreach ($r in $fw) {
                    $r = $r -replace ("@{","")
                    $r = $r -replace ("}","")
                    $r = $r -replace ("\\\\","\")
                    $r = $r.split("=")
                    $hrules.Add($r[0].Trim(), $r[1].Trim())
                }
                $fwrules += $hrules.Name
            }
            return $fwrules
        }
        Catch {
            return $_.Exception.Message
        }
        Finally {
        }
    } # End Function Get-LocalFirewallRuleName

} # This module defines a class for a DSC "FileResource" provider.