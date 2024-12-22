function Set-RiskRating {
    <#
        .SYNOPSIS
        This function takes an Issue object as input and assigns a numerical risk score depending on issue conditions.

        .DESCRIPTION
        Risk of Issue is based on:
        - Issue type: Templates issues are more risky than CA/Object issues by default.
        - Template status: Enabled templates are more risky than disabled templates.
        - Principals: Single users are less risky than groups, and custom groups are less risky than default groups.
        - Principal type: AD Admins aren't risky. gMSAs have little risk (assuming proper controls). Non-admins are most risky
        - Modifiers: Some issues are present a higher risk when certain conditions are met.

        .PARAMETER Issue
        A PSCustomObject that includes all pertinent information about an AD CS issue.

        .INPUTS
        PSCustomObject

        .OUTPUTS
        None. This function sets a new attribute on each Issue object and returns nothing to the pipeline.

        .EXAMPLE
        $Targets = Get-Target
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        $DangerousRights = @('GenericAll', 'WriteProperty', 'WriteOwner', 'WriteDacl')
        $SafeOwners = '-512$|-519$|-544$|-18$|-517$|-500$'
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-9$|-526$|-527$|S-1-5-10'
        $SafeObjectTypes = '0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2'
        $ESC4Issues = Find-ESC4 -ADCSObjects $ADCSObjects -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeUsers $SafeUsers -SafeObjectTypes $SafeObjectTypes -Mode 1
        foreach ($issue in $ESC4Issues) { if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                } }

        .LINK
    #>
    [CmdletBinding()]
    param (
        $Issue,
        $ADCSObjects,
        $SafeUsers,
        $UnsafeUsers
    )

    #requires -Version 5

    $RiskValue = 0
    $RiskName = ''
    $RiskScoring = @()

    # CA issues don't rely on a principal and have a base risk of Medium.
    if ($Issue.Technique -in @('DETECT', 'ESC6', 'ESC8', 'ESC11')) {
        $RiskValue += 3
        $RiskScoring += 'Base Score: 3'

        if ($Issue.CAEnrollmentEndpoint -like 'http:*') {
            $RiskValue += 2
            $RiskScoring += 'HTTP Enrollment: +2'
        }

        # TODO Check NtAuthCertificates for CA thumbnail. If found, +2, else -1
        # TODO Check if NTLMv1 is allowed.
    }

    # Template issues have their own scoring.
    if ($Issue.Technique -notin @('DETECT', 'ESC5', 'ESC6', 'ESC8', 'ESC11')) {
        $RiskScoring += 'Base Score: 0'

        # Templates are more dangerous when enabled.
        if ($Issue.Enabled) {
            $RiskValue += 1
            $RiskScoring += 'Enabled: +1'
        } else {
            $RiskValue -= 2
            $RiskScoring += 'Disabled: -3'
        }

        # The principal's objectClass impacts the Issue's risk
        $SID = $Issue.IdentityReferenceSID.ToString()
        $IdentityReferenceObjectClass = Get-ADObject -Filter { objectSid -eq $SID } | Select-Object objectClass

        # ESC1 and ESC4 templates are more dangerous than other templates because they can result in immediate compromise.
        if ($Issue.Technique -in @('ESC1', 'ESC4')) {
            $RiskValue += 1
            $RiskScoring += 'ESC1/4: +1'
        }

        if ($Issue.IdentityReferenceSID -match $UnsafeUsers) {
            # Authenticated Users, Domain Users, Domain Computers etc. are very risky
            $RiskValue += 2
            $RiskScoring += 'Very Large Group: +2'
        } elseif ($IdentityReferenceObjectClass -eq 'group') {
            # Groups are riskier than individual principals
            $RiskValue += 1
            $RiskScoring += 'Group: +1'
        }

        # Safe users and managed service accounts are inherently safer than other principals - except in ESC3 Condition 2!
        if ($Issue.Technique -eq 'ESC3' -and $Issue.Condition -eq 2) {
            if ($Issue.IdentityReferenceSID -match $SafeUsers) {
                # Safe Users are admins. Authenticating as an admin is bad.
                $RiskValue += 2
                $RiskScoring += 'Privileged Principal: +2'
            } elseif ($IdentityReferenceObjectClass -like '*ManagedServiceAccount') {
                # Managed Service Accounts are *probably* privileged in some way.
                $RiskValue += 1
                $RiskScoring += 'Managed Service Account: +1'
            }
        } elseif ($Issue.IdentityReferenceSID -notmatch $SafeUsers -and $IdentityReferenceObjectClass -notlike '*ManagedServiceAccount') {
            $RiskValue += 1
            $RiskScoring += 'Unprivileged Principal: +1'
        }

        # Modifiers that rely on the existence of other ESCs
        # ESC2 and ESC3C1 are more dangerous if ES3C2 templates exist or certain ESC15 templates are enabled
        if ($Issue.Technique -eq 'ESC2' -or ($Issue.Technique -eq 'ESC3' -and $Issue.Condition -eq 1)) {
            $ESC3C2 = Find-ESC3C2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers  -SkipRisk |
            Where-Object { $_.Enabled -eq $true }
            $ESC3C2Names = @(($ESC3C2 | Select-Object -Property Name -Unique).Name)
            if ($ESC3C2Names) {
                $CheckedESC3C2Templates = @{}
                foreach ($name in $ESC3C2Names) {
                    $OtherTemplateRisk = 0
                    $Principals = @()
                    foreach ($esc in $($ESC3C2 | Where-Object Name -eq $name) ) {
                        if ($CheckedESC3C2Templates.GetEnumerator().Name -contains $esc.Name) {
                            $Principals = $CheckedESC3C2Templates.$($esc.Name)
                        } else {
                            $CheckedESC3C2Templates = @{
                                $($esc.Name) = @()
                            }
                        }
                        $escSID = $esc.IdentityReferenceSID.ToString()
                        $escIdentityReferenceObjectClass = Get-ADObject -Filter { objectSid -eq $escSID } | Select-Object objectClass
                        if ($escSID -match $SafeUsers) {
                            # Safe Users are admins. Authenticating as an admin is bad.
                            $Principals += $esc.IdentityReference
                            $OtherTemplateRisk += 2
                        } elseif ($escSID -match $UnsafeUsers) {
                            # Unsafe Users are large groups that contain practically all principals and likely including admins.
                            # Authenticating as an admin is bad.
                            $Principals += $esc.IdentityReference
                            $OtherTemplateRisk += 2
                        } elseif ($escIdentityReferenceObjectClass -like '*ManagedServiceAccount') {
                            # Managed Service Accounts are *probably* privileged in some way.
                            $Principals += $esc.IdentityReference
                            $OtherTemplateRisk += 1
                        } elseif ($escIdentityReferenceObjectClass -eq 'group') {
                            # Groups are more dangerous than individual principles.
                            $Principals += $esc.IdentityReference
                            $OtherTemplateRisk += 1
                        }
                        $CheckedESC3C2Templates.$($esc.Name) = $Principals
                    }
                    $RiskScoring += "Principals ($($CheckedESC3C2Templates.$name -join ', ')) are able to enroll in an enabled ESC3 Condition 2 template ($name): +$OtherTemplateRisk"
                } # end foreach ($name)
                if ($OtherTemplateRisk -ge 2) {
                    $OtherTemplateRisk = 2
                }
            } # end if ($ESC3C2Names)

            # Default 'User' and 'Machine' templates are more dangerous
            $ESC15 = Find-ESC15 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers  -SkipRisk |
            Where-Object { $_.Enabled -eq $true }
            $ESC15Names = @('Machine', 'User')
            if ($ESC15Names) {
                $CheckedESC15Templates = @{}
                foreach ($name in $ESC15Names) {
                    $OtherTemplateRisk = 0
                    $Principals = @()
                    foreach ($esc in $($ESC15 | Where-Object Name -eq $name) ) {
                        if ($CheckedESC15Templates.GetEnumerator().Name -contains $esc.Name) {
                            $Principals = $CheckedESC15Templates.$($esc.Name)
                        } else {
                            $Principals = @()
                            $CheckedESC15Templates = @{
                                $($esc.Name) = @()
                            }
                        }
                        $escSID = $esc.IdentityReferenceSID.ToString()
                        $escIdentityReferenceObjectClass = Get-ADObject -Filter { objectSid -eq $escSID } | Select-Object objectClass
                        if ($escSID -match $SafeUsers) {
                            # Safe Users are admins. Authenticating as an admin is bad.
                            $Principals += $esc.IdentityReference
                            $OtherTemplateRisk += 2
                        } elseif ($escSID -match $UnsafeUsers) {
                            # Unsafe Users are large groups that contain practically all principals and likely including admins.
                            # Authenticating as an admin is bad.
                            $Principals += $esc.IdentityReference
                            $OtherTemplateRisk += 2
                        } elseif ($escIdentityReferenceObjectClass -like '*ManagedServiceAccount') {
                            # Managed Service Accounts are *probably* privileged in some way.
                            $Principals += $esc.IdentityReference
                            $OtherTemplateRisk += 1
                        } elseif ($escIdentityReferenceObjectClass -eq 'group') {
                            # Groups are more dangerous than individual principals.
                            $Principals += $esc.IdentityReference
                            $OtherTemplateRisk += 1
                        }
                        $CheckedESC15Templates.$($esc.Name) = $Principals
                    }
                    $RiskScoring += "Principals ($($CheckedESC15Templates.$name -join ', ')) are able to enroll in an enabled ESC15 template ($name)): +$OtherTemplateRisk"
                } # end foreach ($name)
                if ($OtherTemplateRisk -ge 2) {
                    $OtherTemplateRisk = 2
                }
            } # end if ($ESC15Names)
            $RiskValue += $OtherTemplateRisk
        }

        # ESC3 Condition 2 and ESC15 templates are only dangerous if ESC2 or ESC3 Condition 1 templates exist.
        if ($Issue.Technique -eq 'ESC15' -or ($Issue.Technique -eq 'ESC3' -and $Issue.Condition -eq 2) ) {
            $ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers  -SkipRisk |
            Where-Object { $_.Enabled -eq $true }
            $ESC2Names = @(($ESC2 | Select-Object -Property Name -Unique).Name)
            if ($ESC2Names) {
                $CheckedESC2Templates = @{}
                foreach ($name in $ESC2Names) {
                    $OtherTemplateRisk = 0
                    $Principals = @()
                    foreach ($esc in $($ESC2 | Where-Object Name -eq $name) ) {
                        if ($CheckedESC2Templates.GetEnumerator().Name -contains $esc.Name) {
                            $Principals = $CheckedESC2Templates.$($esc.Name)
                        } else {
                            $CheckedESC2Templates = @{
                                $($esc.Name) = @()
                            }
                        }
                        $escSID = $esc.IdentityReferenceSID.ToString()
                        $escIdentityReferenceObjectClass = Get-ADObject -Filter { objectSid -eq $escSID } | Select-Object objectClass
                        if ($escSID -match $UnsafeUsers) {
                            # Unsafe Users are large groups.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 2
                        } elseif ($escIdentityReferenceObjectClass -eq 'group') {
                            # Groups are more dangerous than individual principles.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 1
                        }
                        $CheckedESC2Templates.$($esc.Name) = $Principals
                    }
                    $RiskScoring += "Principals ($($CheckedESC2Templates.$name -join ', ')) are able to enroll in an enabled ESC2 template ($name): +$OtherTemplateRisk"
                } # end foreach ($name)
                if ($OtherTemplateRisk -ge 2) {
                    $OtherTemplateRisk = 2
                }
            } # end if ($ESC2Names)

            $ESC3C1 = Find-ESC3C1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers  -SkipRisk |
            Where-Object { $_.Enabled -eq $true }
            $ESC3C1Names = @(($ESC3C1 | Select-Object -Property Name -Unique).Name)
            if ($ESC3C1Names) {
                $CheckedESC3C1Templates = @{}
                foreach ($name in $ESC3C1Names) {
                    $OtherTemplateRisk = 0
                    $Principals = @()
                    foreach ($esc in $($ESC3C1 | Where-Object Name -eq $name) ) {
                        if ($CheckedESC3C1Templates.GetEnumerator().Name -contains $esc.Name) {
                            $Principals = $CheckedESC3C1Templates.$($esc.Name)
                        } else {
                            $CheckedESC3C1Templates = @{
                                $($esc.Name) = @()
                            }
                        }
                        $escSID = $esc.IdentityReferenceSID.ToString()
                        $escIdentityReferenceObjectClass = Get-ADObject -Filter { objectSid -eq $escSID } | Select-Object objectClass
                        if ($escSID -match $UnsafeUsers) {
                            # Unsafe Users are large groups.
                            $Principals += $esc.IdentityReference
                            $OtherTemplateRisk += 2
                        } elseif ($escIdentityReferenceObjectClass -eq 'group') {
                            # Groups are more dangerous than individual principles.
                            $Principals += $esc.IdentityReference
                            $OtherTemplateRisk += 1
                        }
                        $CheckedESC3C1Templates.$($esc.Name) = $Principals
                    }
                    $RiskScoring += "Principals ($($CheckedESC3C1Templates.$name -join ', ')) are able to enroll in an enabled ESC3C1 template ($name): +$OtherTemplateRisk"
                } # end foreach ($name...
                if ($OtherTemplateRisk -ge 2) {
                    $OtherTemplateRisk = 2
                }
            } # end if ($ESC3C1Names)
            $RiskValue += $OtherTemplateRisk
        }
    }

    # Convert Value to Name
    $RiskName = switch ($RiskValue) {
        { $_ -le 1 } { 'Informational' }
        2 { 'Low' }
        3 { 'Medium' }
        4 { 'High' }
        { $_ -ge 5 } { 'Critical' }
    }

    # Write Risk attributes
    $Issue | Add-Member -NotePropertyName RiskValue -NotePropertyValue $RiskValue -Force
    $Issue | Add-Member -NotePropertyName RiskName -NotePropertyValue $RiskName -Force
    $Issue | Add-Member -NotePropertyName RiskScoring -NotePropertyValue $RiskScoring -Force
}
