# encoding: utf-8

title 'Administrative Templates'

# 18.1 Control Panel

control 'cis-prevent-lock-screen-camera-on-18.1.1.1' do
    impact 0.7
    title '18.1.1.1 Ensure Prevent enabling lock screen camera is set to Enabled'
    desc 'Ensure Prevent enabling lock screen camera is set to Enabled' 

    tag cis: ['windows_2012r2:18.1.1.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('HKLM\Software\Policies\Microsoft\Windows\Personalization') do
    its('NoLockScreenCamera') { should eq 1 }
    end
end

control 'cis-prevent-enabling-lock-screen-slide-show-18.1.1.2' do
    impact 0.7
    title '18.1.1.2 Ensure Prevent enabling lock screen slide show is set to Enabled'
    desc 'Ensure Prevent enabling lock screen slide show is set to Enabled' 

    tag cis: ['windows_2012r2:18.1.1.2']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('HKLM\Software\Policies\Microsoft\Windows\Personalization') do
        its('NoLockScreenCamera') { should eq 1 }
    end
end

# 18.2 LAPS (Local Administrator Password Solutions)

control 'cis-laps-gpo-extension-18.2.1' do
    impact 0.7
    title '18.2.1 Ensure LAPS AdmPwd GPO Extension / CSE is installed'
    desc 'Ensure LAPS AdmPwd GPO Extension / CSE is installed' 

    tag cis: ['windows_2012r2:18.2.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    only_if { file('C:\Windows\PolicyDefinitions\AdmPwd.admx').file? }

    describe registry_key('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}') do
        its('DllName') { should eq 1 }
    end
end

control 'cis-password-expiration-time-18.2.2' do
    impact 0.7
    title '18.2.2 Ensure Do not allow password expiration time longer than
    required by policy is set to Enabled' 
    desc 'Ensure Do not allow password expiration time longer than
    required by policy is set to Enabled' 

    tag cis: ['windows_2012r2:18.2.2']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Services\AdmPwd') do
        its('PwdExpirationProtectionEnabled') { should eq 1 }
    end
end

control 'cis-password-expiration-time-18.2.3' do
    impact 0.7
    title '18.2.3 Ensure Enable Local Admin Password Management is set to Enabled' 
    desc 'Ensure Enable Local Admin Password Management is set to Enabled' 

    tag cis: ['windows_2012r2:18.2.3']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Services\AdmPwd') do
        its('PwdExpirationProtectionEnabled') { should eq 1 }
    end
end

control 'cis-password-settings-password-complexity-18.2.4' do
    impact 0.7
    title '18.2.4 Ensure Password Settings: Password Complexity is set to
    Enabled' 
    desc 'Ensure Password Settings: Password Complexity is set to
    Enabled' 

    tag cis: ['windows_2012r2:18.2.4']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Services\AdmPwd') do
        its('PasswordComplexity') { should eq 1 }
    end
end

control 'cis-password-settings-password-length-18.2.5' do
    impact 0.7
    title '18.2.5 Ensure Password Settings: Password Length is set to
    Enabled: 15 or more' 
    desc 'Ensure Password Settings: Password Length is set to
    Enabled: 15 or more' 

    tag cis: ['windows_2012r2:18.2.5']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Services\AdmPwd') do
        its('PasswordLength') { should eq 1 }
    end
end

control 'cis-password-settings-password-age-18.2.6' do
    impact 0.7
    title '18.2.6 Ensure Password Settings: Password Age (Days) is set to
    Enabled: 30 or fewer' 
    desc 'Ensure Password Settings: Password Age (Days) is set to
    Enabled: 30 or fewer' 

    tag cis: ['windows_2012r2:18.2.6']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Services\AdmPwd') do
        its('PasswordAgeDays') { should eq 1 }
    end
end

# 18.3 MSS (Legacy) - Mirosoft Solutions for Security

control 'cis-automatic-logon-18.3.1' do
    impact 0.7
    title '18.3.1 Ensure MSS: (AutoAdminLogon) Enable Automatic Logon
    (not recommended) is set to Disabled' 
    desc 'Ensure MSS: (AutoAdminLogon) Enable Automatic Logon
    (not recommended) is set to Disabled' 

    tag cis: ['windows_2012r2:18.3.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon') do
        its('AutoAdminLogon') { should eq 1 }
    end
end

control 'cis-ip-routing-protection-level-18.3.2' do
    impact 0.7
    title '18.2.6 Ensure MSS: (DisableIPSourceRouting IPv6) IP source routing
    protection level (protects against packet spoofing) is set to Enabled:
    Highest protection, source routing is completely disabled' 
    desc 'Ensure MSS: (DisableIPSourceRouting IPv6) IP source routing
    protection level (protects against packet spoofing) is set to Enabled:
    Highest protection, source routing is completely disabled' 

    tag cis: ['windows_2012r2:18.3.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters') do
        its('DisableIPSourceRouting') { should eq 1 }
    end
end

control 'cis-ensure-mss-disableipsourcerouting-ip-source-routing-protection-level-protects-against-packet-spoofing-is-set-to-enabled-18.3.3' do
    impact 0.7
    title '18.3.3 Ensure MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing) is set to Enabled' 
    desc 'Ensure MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing) is set to Enabled' 

    tag cis: ['windows_2012r2:18.3.3']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('MSS', 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters') do
        its('DisableIPSourceRouting') { should eq 1 }
  end
end

control 'cis-ensure-mss-enableicmpredirect-allow-icmp-redirects-to-override-ospf-generated-routes-is-set-to-disabled-18.3.4' do
    impact 0.7
    title '18.3.4 Ensure MSS EnableICMPRedirect Allow ICMP redirects to override OSPF generated routes is set to Disabled' 
    desc 'Ensure MSS EnableICMPRedirect Allow ICMP redirects to override OSPF generated routes is set to Disabled' 

    tag cis: ['windows_2012r2:18.3.4']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('MSS', 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters') do
        its('EnableICMPRedirect') { should eq 0 }
  end
end

control ' cis-ensure-mss-nonamereleaseondemand-allow-the-computer-to-ignore-netbios-name-release-requests-except-from-winsservers-18.3.6' do
    impact 0.7
    title '18.3.6 Ensure MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' 
    desc 'Ensure MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' 

    tag cis: ['windows_2012r2:18.3.6']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('MSS', 'HKLM\System\CurrentControlSet\Services\NetBT\Parameters') do
        its('nonamereleaseondemand') { should eq 1 }
  end
end

control 'cis-ensure-mss-safedllsearchmode-enable-safe-dll-search-mode-recommended-is-set-to-enabled-18.3.8' do
    impact 0.7
    title '18.3.8 Ensure MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended) is set to Enabled' 
    desc 'Ensure MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended) is set to Enabled' 

    tag cis: ['windows_2012r2:18.3.8']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('MSS', 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager') do
        its('SafeDllSearchMode') { should eq 1 }
  end
end

control 'cis-ensure-mss-screensavergraceperiod-the-time-in-seconds-before-the-screen-saver-grace-period-expires-18.3.9' do
    impact 0.7
    title '18.3.9 Ensure MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires is set to Enabled: 5 or fewer seconds' 
    desc 'Ensure MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires is set to Enabled: 5 or fewer seconds' 

    tag cis: ['windows_2012r2:18.3.9']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('MSS', 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon') do
        its('ScreenSaverGracePeriod') { should eq 1 }
  end
end

control ' cis-ensure-mss-WarningLevel-percentage-threshold-for-the-security-event-log-at-which-the-system-will-generate-a-warning-18.3.12' do
    impact 0.7
    title '18.3.12 Ensure MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning is Enabled' 
    desc 'Ensure MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning is Enabled' 

    tag cis: ['windows_2012r2:18.3.12']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('MSS', 'HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security') do
        its('WarningLevel') { should eq 1 }
  end
end

# 18.4.10 Network Connections

control 'cis-ensure-prohibit-installation-and-configuration-of-network-bridge-on-yourdns-domain-network-is-set-to-enabled-18.4.10.2' do
    impact 0.7
    title '18.4.10.2 Ensure Prohibit installation and configuration of Network Bridge on your DNS domain network is set to Enabled' 
    desc 'Ensure Prohibit installation and configuration of Network Bridge on your DNS domain network is set to Enabled' 

    tag cis: ['windows_2012r2:18.4.10.2']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Network Connections', 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections') do
        its('NC_AllowNetBridge_NLA') { should eq 1 }
  end
end

control 'cis-ensure-require-domain-users-to-elevate-when-setting-a-networks-location-is-set-to-enabled-18.4.10.3' do
    impact 0.7
    title '18.4.10.3 Ensure Require domain users to elevate when setting a networks locationis set to Enabled' 
    desc 'Ensure Require domain users to elevate when setting a networks locationis set to Enabled' 

    tag cis: ['windows_2012r2:18.4.10.3']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Network Connections', 'HKLM\Software\Policies\Microsoft\Windows\Network Connections') do
        its('NC_StdDomainUserSetLocation') { should eq 1 }
  end
end

# 18.4.13 Network Provider

control 'cis-ensure-hardened-unc-paths-is-set-to-enabled-with-require-mutual-authentication-18.4.13.1' do
    impact 0.7
    title '18.4.13.1 Ensure Hardened UNC Paths is set to Enabled with Require Mutual Authentication' 
    desc 'Ensure Hardened UNC Paths is set to Enabled with Require Mutual Authentication' 

    tag cis: ['windows_2012r2:18.4.13.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Network Provider', 'HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths') do
        its('*\NETLOGON') { should eq 1 }
  end
end

control 'cis-ensure-hardened-unc-paths-is-set-to-enabled-with-require-mutual-authentication-18.4.13.1' do
    impact 0.7
    title '18.4.13.1 Ensure Hardened UNC Paths is set to Enabled with Require Mutual Authentication' 
    desc 'Ensure Hardened UNC Paths is set to Enabled with Require Mutual Authentication' 

    tag cis: ['windows_2012r2:18.4.13.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Network Provider', 'HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths') do
        its('*\SYSVOL') { should eq 1 }
  end
end

# 18.4.20 Windows Connection Manager

control 'cis-Ensure-minimize-the-number-of-simultaneous-connections-to-the-internet-or-a-windows-domain-is-set-to-enabled-18.4.20.1' do
    impact 0.7
    title '18.4.20.1 Ensure Minimize the number of simultaneous connections to the Internet or a Windows Domain is set to Enabled' 
    desc 'Ensure Minimize the number of simultaneous connections to the Internet or a Windows Domain is set to Enabled' 

    tag cis: ['windows_2012r2:18.4.20.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Connection Manager', 'HKLM\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy') do
        its('fMinimizeConnections') { should eq 1 }
  end
end

# 18.6 SCM (Security Compliance Manager): Pass the Hash Mitigations

control 'cis-Ensure-apply-uac-restrictions-to-local-accounts-on-network-logons-is-set-to-enabled-18.6.1' do
    impact 0.7
    title '18.6.1 Ensure Apply UAC restrictions to local accounts on network logons is set to Enabled' 
    desc 'Ensure Apply UAC restrictions to local accounts on network logons is set to Enabled' 

    tag cis: ['windows_2012r2:18.6.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('SCM', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
        its('LocalAccountTokenFilterPolicy') { should eq 1 }
  end
end

control 'cis-ensure-wdigest-authentication-is-set-to-disabled-18.6.2' do
    impact 0.7
    title '18.6.2 Ensure WDigest Authentication is set to Disabled' 
    desc 'Ensure WDigest Authentication is set to Disabled' 

    tag cis: ['windows_2012r2:18.6.2']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('SCM', 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest') do
        its('UseLogonCredential') { should eq 0 }
  end
end


# 18.8 System

control 'cis-ensure-include-command-line-in-process-creation-events-is-set-to-disabled-18.8.2.1' do
    impact 0.7
    title '18.8.2.1 Ensure Include command line in process creation events is set to Disabled' 
    desc 'Ensure Include command line in process creation events is set to Disabled' 

    tag cis: ['windows_2012r2:18.8.2.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Audit Process Creation', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit') do
        its('ProcessCreationIncludeCmdLine_Enabled') { should eq 0 }
  end
end

control 'cis-ensure-boot-start-driver-initialization-policy-is-set-to-enabled-good-unknown-and-bad-but-critical-18.8.11.1' do
    impact 0.7
    title '18.8.11.1 Ensure Boot-Start Driver Initialization Policy is set to Enabled: Good unknown and bad but critica' 
    desc 'Ensure Boot-Start Driver Initialization Policy is set to Enabled: Good unknown and bad but critica' 

    tag cis: ['windows_2012r2:18.8.11.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Antimalware', 'HKLM\System\CurrentControlSet\Policies\EarlyLaunch') do
        its('DriverLoadPolicy') { should eq 1 }
  end
end

control 'cis-ensure-configure-registry-policy-processing-do-not-apply-during-periodic-background-processing-is-set-to-enabled-false-18.8.18.2' do
    impact 0.7
    title '18.8.18.2 Ensure Configure registry policy processing: Do not apply during periodic background processing is set to Enabled: FALSE' 
    desc 'Ensure Configure registry policy processing: Do not apply during periodic background processing is set to Enabled: FALSE' 

    tag cis: ['windows_2012r2:18.8.18.2']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Logging and tracing', 'HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
        its('NoBackgroundPolicy') { should eq 0 }
  end
end

control 'cis-ensure-configure-registry-policy-processing-process-even-if-the-group-policy-objects-have-not-changed-is-set-to-enabled-true-18.8.18.3' do
    impact 0.7
    title '18.8.18.3 Ensure Configure registry policy processing: Process even if the Group Policy objects have not changed is set to Enabled: TRUE' 
    desc 'Ensure Configure registry policy processing: Process even if the Group Policy objects have not changed is set to Enabled: TRUE' 

    tag cis: ['windows_2012r2:18.8.18.3']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Logging and tracing', 'HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
        its('NoGPOListChanges') { should eq 1 }
  end
end

control 'cis-ensure-turn-off-background-refresh-of-group-policy-is-set-to-Disabled-18.8.18.4' do
    impact 0.7
    title '18.8.18.4 Ensure Turn off background refresh of Group Policy is set to Disabled' 
    desc 'Ensure Turn off background refresh of Group Policy is set to Disabled' 

    tag cis: ['windows_2012r2:18.8.18.4']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Logging and tracing', 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
        its('DisableBkGndGroupPolicy') { should eq 0 }
  end
end

control 'cis-ensure-do-not-display-network-selection-ui-is-set-to-enabled-18.8.24.1' do
    impact 0.7
    title '18.8.24.1 Ensure Do not display network selection UI is set to Enabled' 
    desc 'Ensure Do not display network selection UI is set to Enabled' 

    tag cis: ['windows_2012r2:18.8.24.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Logon', 'HKLM\Software\Policies\Microsoft\Windows\System') do
        its('DontDisplayNetworkSelectionUI') { should eq 0 }
  end
end

control 'cis-ensure-do-not-enumerate-connected-users-on-domain-joined-computers-is-set-to-enabled-18.8.24.2' do
    impact 0.7
    title '18.8.24.2 Ensure Do not enumerate connected users on domain-joined computers is set to Enabled' 
    desc 'Ensure Do not enumerate connected users on domain-joined computers is set to Enabled' 

    tag cis: ['windows_2012r2:18.8.24.2']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Logon', 'HKLM\Software\Policies\Microsoft\Windows\System') do
        its('DontEnumerateConnectedUsers') { should eq 0 }
  end
end

control 'cis-ensure-enumerate-local-users-on-domain-joined-computers-is-set-to-disabled-18.8.24.' do
    impact 0.7
    title '18.8.24.3 Ensure Enumerate local users on domain-joined computers is set to Disabled' 
    desc 'Ensure Enumerate local users on domain-joined computers is set to Disabled' 

    tag cis: ['windows_2012r2:18.8.24.3']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Logon', 'HKLM\Software\Policies\Microsoft\Windows\System') do
        its('EnumerateLocalUsers') { should eq 0 }
  end
end

control 'cis-ensure-turn-off-app-notifications-on-the-lock-screen-is-set-to-enabled-18.8.24.4' do
    impact 0.7
    title '18.8.24.4 Ensure Turn off app notifications on the lock screen is set to Enabled' 
    desc 'Ensure Turn off app notifications on the lock screen is set to Enabled' 

    tag cis: ['windows_2012r2:18.8.24.4']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Logon', 'HKLM\Software\Policies\Microsoft\Windows\System') do
        its('DisableLockScreenAppNotifications') { should eq 1 }
  end
end

control 'cis-Ensure-turn-on-convenience-pin-sign-in-is-set-to-disabled-18.8.24.5' do
    impact 0.7
    title '18.8.24.5 Ensure Turn on convenience PIN sign-in is set to Disabled' 
    desc 'Ensure Turn on convenience PIN sign-in is set to Disabled' 

    tag cis: ['windows_2012r2:18.8.24.5']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Logon', 'HKLM\Software\Policies\Microsoft\Windows\System') do
        its('AllowDomainPINLogon') { should eq 0 }
  end
end

control 'cis-ensure-configure-offer-remote-assistance-is-set-to-disabled-18.8.30.1' do
    impact 0.7
    title '18.8.30.1 Ensure Configure Offer Remote Assistance is set to Disabled' 
    desc 'Ensure Configure Offer Remote Assistance is set to Disabled' 

    tag cis: ['windows_2012r2:18.8.30.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Remote Assistance', 'HKLM\Software\policies\Microsoft\Windows NT\Terminal Services') do
        its('fAllowUnsolicited') { should eq 0 }
  end
end

control 'cis-ensure-configure-solicited-remote-assistance-is-set-to-disabled-18.9.30.2' do
    impact 0.7
    title '18.8.30.2 Ensure Configure Solicited Remote Assistance is set to Disabled' 
    desc 'Ensure Configure Solicited Remote Assistance is set to Disabled' 

    tag cis: ['windows_2012r2:18.8.30.2']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Remote Assistance', 'HKLM\Software\policies\Microsoft\Windows NT\Terminal Services') do
        its('fAllowToGetHelp') { should eq 0 }
  end
end

control 'cis-ensure-enable-rpc-endpoint-mapper-client-authentication-is-set-to-enabled-18.8.31.1' do
    impact 0.7
    title '18.8.31.1 Ensure Enable RPC Endpoint Mapper Client Authentication is set to Enabled' 
    desc 'Ensure Enable RPC Endpoint Mapper Client Authentication is set to Enabled' 

    tag cis: ['windows_2012r2:18.8.31.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Remote Procedure Call', 'HKLM\Software\Policies\Microsoft\Windows NT\Rpc') do
        its('EnableAuthEpResolution') { should eq 1 }
  end
end

# 18.9 Windows Components

control 'cis-allow-microsoft-accounts-to-be-optional-is-set-to-enabled-18.9.6.1' do
    impact 0.7
    title '18.9.6.1 Ensure Allow Microsoft accounts to be optional is set to Enabled' 
    desc 'Ensure Allow Microsoft accounts to be optional is set to Enabled' 

    tag cis: ['windows_2012r2:18.9.6.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('EMET', 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
        its('MSAOptional') { should eq 1 }
  end
end

control 'cis-ensure-disallow-autoplay-for-non-volume-devices-is-set-to-enabled-18.9.8.1' do
    impact 0.7
    title '18.9.8.1 Ensure Disallow Autoplay for non-volume devices is set to Enabled' 
    desc 'Ensure Disallow Autoplay for non-volume devices is set to Enabled' 

    tag cis: ['windows_2012r2:18.9.8.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('AutoPlay Policies', 'HKLM\Software\Policies\Microsoft\Windows\Explorer') do
        its('NoAutoplayfornonVolume') { should eq 1 }
  end
end

control 'cis-ensure-set-the-default-behavior-for-autoRun-is-set-to-enabled-do-not-execute-any-autorun-commands-18.9.8.2' do
    impact 0.7
    title '18.9.8.2 Ensure Set the default behavior for AutoRun is set to Enabled: Do not execute any autorun commands' 
    desc 'Ensure Set the default behavior for AutoRun is set to Enabled: Do not execute any autorun commands' 

    tag cis: ['windows_2012r2:18.9.8.2']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('AutoPlay Policies', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
        its('NoAutorun') { should eq 1 }
  end
end

control 'cis-ensure-turn-off-autoplay-is-set-to-enabled-all-drives-18.9.8.3' do
    impact 0.7
    title '18.9.8.3 Ensure Turn off Autoplay is set to Enabled: All drives' 
    desc 'Ensure Turn off Autoplay is set to Enabled: All drives' 

    tag cis: ['windows_2012r2:18.9.8.3']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('AutoPlay Policies', 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
        its('NoDriveTypeAutoRun') { should eq 1 }
  end
end

control 'cis-ensure-do-not-display-the-password-reveal-button-is-set-to-enabled-18.9.13.1' do
    impact 0.7
    title '18.9.13.1 Ensure Do not display the password reveal button is set to Enabled' 
    desc 'Ensure Do not display the password reveal button is set to Enabled' 

    tag cis: ['windows_2012r2:18.9.13.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Credential User', 'HKLM\Software\Policies\Microsoft\Windows\CredUI') do
        its('DisablePasswordReveal') { should eq 1 }
  end
end

control 'cis-ensure-enumerate-administrator-accounts-on-elevation-is-set-to-disabled-18.9.13.2' do
    impact 0.7
    title '18.9.13.2 Ensure Enumerate administrator accounts on elevation is set to Disabled' 
    desc 'Ensure Enumerate administrator accounts on elevation is set to Disabled' 

    tag cis: ['windows_2012r2:18.9.13.2']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key('Credential User', 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI') do
        its('EnumerateAdministrators') { should eq 0 }
  end
end

control 'cis-ensure-emet-5.5-or-higher-is-installed-18.9.22.1' do
  impact 0.7
  title '18.9.22.1 Ensure EMET 5.5 or higher is installed'
  desc 'Ensure EMET 5.5 or higher is installed' 

  tag cis: ['windows_2012r2:18.9.22.1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
  only_if { file('C:\Windows\PolicyDefinitions\EMET.admx/adml').file? } 

  describe package("RabbitMQ Server 3.6.10 from control panel") do
    it { should be_installed }
  end
end

control 'cis-ensure-default-action-and-mitigation-settings-is-set-to-enabled-18.9.22.2' do
  impact 0.7
  title '18.9.22.2 Ensure Default Action and Mitigation Settings is set to Enabled (plus subsettings)'
  desc 'Ensure Default Action and Mitigation Settings is set to Enabled (plus subsettings)' 

  tag cis: ['windows_2012r2:18.9.22.2']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('EMET', 'HKLM\Software\Policies\Microsoft\EMET\SysSettings') do
    its('AntiDetours') { should eq 1 }
  end
end

control 'cis-ensure-default-action-and-mitigation-settings-is-set-to-enabled-18.9.22.2' do
  impact 0.7
  title '18.9.22.2 Ensure Default Action and Mitigation Settings is set to Enabled (plus subsettings)'
  desc 'Ensure Default Action and Mitigation Settings is set to Enabled (plus subsettings)' 

  tag cis: ['windows_2012r2:18.9.22.2']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe registry_key('EMET', 'HKLM\Software\Policies\Microsoft\EMET\SysSettings') do
    its('BannedFunctions') { should eq 1 }
  end
end

control 'cis-ensure-default-action-and-mitigation-settings-is-set-to-enabled-18.9.22.2' do
  impact 0.7
  title '18.9.22.2 Ensure Default Action and Mitigation Settings is set to Enabled (plus subsettings)'
  desc 'Ensure Default Action and Mitigation Settings is set to Enabled (plus subsettings)' 

  tag cis: ['windows_2012r2:18.9.22.2']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe registry_key('EMET', 'HKLM\Software\Policies\Microsoft\EMET\SysSettings') do
  its('DeepHooks') { should eq 1 }
  end
end

control 'cis-ensure-default-action-and-mitigation-settings-is-set-to-enabled-18.9.22.2' do
  impact 0.7
  title '18.9.22.2 Ensure Default Action and Mitigation Settings is set to Enabled (plus subsettings)'
  desc 'Ensure Default Action and Mitigation Settings is set to Enabled (plus subsettings)' 

  tag cis: ['windows_2012r2:18.9.22.2']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe registry_key('EMET', 'HKLM\Software\Policies\Microsoft\EMET\SysSettings') do
  its('ExploitAction') { should eq 1 }
  end
end

control 'cis-ensure-default-protections-for-internet-explorer-is-set-to-Enabled-18.9.22.3' do
  impact 0.7
  title '18.9.22.3 Ensure Default Protections for Internet Explorer is set to Enabled'
  desc 'Ensure Default Protections for Internet Explorer is set to Enabled' 

  tag cis: ['windows_2012r2:18.9.22.3']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('EMET', 'HKLM\Software\Policies\Microsoft\EMET\Defaults') do
    its('IE') { should eq 1 }
  end
end

control 'cis-ensure-default-protections-for-popular-software-is-set-to-Enabled-18.9.22.4' do
  impact 0.7
  title '18.9.22.4 Ensure Default Protections for Popular Software is set to Enabled'
  desc 'Ensure Default Protections for Popular Software is set to Enabled' 

  tag cis: ['windows_2012r2:18.9.22.4']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('EMET', 'HKLM\Software\Policies\Microsoft\EMET') do
    its('Defaults') { should eq 1 }
  end
end

control 'cis-ensure-default-protections-for-recommended-software-is-set-to-enabled-18.9.22.5' do
  impact 0.7
  title '18.9.22.5 Ensure Default Protections for Recommended Software is set to Enabled'
  desc 'Ensure Default Protections for Recommended Software is set to Enabled' 

  tag cis: ['windows_2012r2:18.9.22.5']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('EMET', 'HKLM\Software\Policies\Microsoft\EMET') do
    its('Defaults') { should eq 1 }
  end
end

control 'cis-Ensure-system-aslr-is-set-to-enabled-application-opt-in-18.9.22.6' do
  impact 0.7
  title '18.9.22.6 Ensure System ASLR is set to Enabled: Application Opt-In'
  desc 'Ensure System ASLR is set to Enabled: Application Opt-In' 

  tag cis: ['windows_2012r2:18.9.22.6']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('EMET', 'HKLM\Software\Policies\Microsoft\EMET\SysSettings') do
    its('ASLR') { should eq 1 }
  end
end

control 'cis-ensure-system-dep-is-set-to-enabled-application-opt-out-18.9.22.7' do
  impact 0.7
  title '18.9.22.7 Ensure System DEP is set to Enabled: Application Opt-Out'
  desc 'Ensure System DEP is set to Enabled: Application Opt-Out' 

  tag cis: ['windows_2012r2:18.9.22.7']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('EMET', 'HKLM\Software\Policies\Microsoft\EMET\SysSettings') do
    its('DEP') { should eq 1 }
  end
end

control 'cis-ensure-system-sehop-is-set-to-enabled-application-opt-out-18.9.22.8' do
  impact 0.7
  title '18.9.22.8 Ensure System SEHOP is set to Enabled: Application Opt-Out'
  desc 'Ensure System SEHOP is set to Enabled: Application Opt-Out' 

  tag cis: ['windows_2012r2:18.9.22.8']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('EMET', 'HKLM\Software\Policies\Microsoft\EMET\SysSettings') do
    its('SEHOP') { should eq 1 }
  end
end

control 'cis-ensure-application-control-event-log-behavior-when-the-log-file-reaches-its-maximum-size-is-set-to-disabled-18.9.24.1.1' do
  impact 0.7
  title '18.9.24.1.1 Ensure Application: Control Event Log behavior when the log file reaches its maximum size is set to Disabled'
  desc 'Ensure Application: Control Event Log behavior when the log file reaches its maximum size is set to Disabled' 

  tag cis: ['windows_2012r2:18.9.24.1.1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('Application', 'HKLM\Software\Policies\Microsoft\Windows\EventLog\Application') do
    its('Retention') { should eq 0 }
  end
end

control 'cis-ensure-application-specify-the-maximum-log-file-size-KB-is-set-to-enabled-32768-or-greater-18.9.24.1.2' do
  impact 0.7
  title '18.9.24.1.2 Ensure Application: Specify the maximum log file size (KB) is set to Enabled: 32,768 or greater'
  desc 'Ensure Application: Specify the maximum log file size (KB) is set to Enabled: 32,768 or greater' 

  tag cis: ['windows_2012r2:18.9.24.1.2']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('Application', 'HKLM\Software\Policies\Microsoft\Windows\EventLog\Application') do
    its('MaxSize') { should eq 32768 }
  end
end

control 'cis-ensure-security-control-event-log-behavior-when-the-log-file-reaches-its-maximum-size-is-set-to-disabled-18.9.24.2.1' do
  impact 0.7
  title '18.9.24.2.1 Ensure Security: Control Event Log behavior when the log file reaches its maximum size is set to Disabled'
  desc 'Ensure Security: Control Event Log behavior when the log file reaches its maximum size is set to Disabled' 

  tag cis: ['windows_2012r2:18.9.24.2.1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('System', 'HKLM\Software\Policies\Microsoft\Windows\EventLog\Security') do
    its('Retention') { should eq 0 }
  end
end

control 'cis-ensure-security-specify-the-maximum-log-file-size-KB-is-set-to-enabled-18.9.24.2.2' do
  impact 0.7
  title '18.9.24.2.2 Ensure Security: Specify the maximum log file size (KB) is set to Enabled: 196,608 or greater'
  desc 'Ensure Security: Specify the maximum log file size (KB) is set to Enabled: 196,608 or greater' 

  tag cis: ['windows_2012r2:18.9.24.2.2']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('System', 'HKLM\Software\Policies\Microsoft\Windows\EventLog\Security') do
    its('MaxSize') { should eq 196608 }
  end
end

control 'cis-ensure-setup-control-event-log-behavior-when-the-log-file-reaches-its-maximum-size-is-set-to-disabled-18.9.24.3.1' do
  impact 0.7
  title '18.9.24.3.1 Ensure Setup: Control Event Log behavior when the log file reaches its maximum size is set to Disabled'
  desc 'Ensure Setup: Control Event Log behavior when the log file reaches its maximum size is set to Disabled' 

  tag cis: ['windows_2012r2:18.9.24.3.1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('System', 'HKLM\Software\Policies\Microsoft\Windows\EventLog\Setup') do
    its('Retention') { should eq 0 }
  end
end

control 'cis-ensure-setup-specify-the-maximum-log-file-size-KB-is-set-to-enabled-18.9.24.3.2' do
  impact 0.7
  title '18.9.24.4.2 Set Ensure Setup: Specify the maximum log file size (KB) is set to Enabled: 32,768 or greater'
  desc 'Ensure Setup: Specify the maximum log file size (KB) is set to Enabled: 32,768 or greater' 

  tag cis: ['windows_2012r2:18.9.24.4.2']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('System', 'HKLM\Software\Policies\Microsoft\Windows\EventLog\Setup') do
    its('MaxSize') { should eq 32768 }
  end
end

control 'cis-ensure-system-control-event-log-behavior-when-the-log-file-reaches-its-maximum-size-is-set-to-disabled-18.9.24.4.1' do
  impact 0.7
  title '18.9.24.4.1 Ensure System: Control Event Log behavior when the log file reaches its maximum size is set to Disabled'
  desc 'Ensure System: Control Event Log behavior when the log file reaches its maximum size is set to Disabled' 

  tag cis: ['windows_2012r2:18.9.24.4.1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('System', 'HKLM\Software\Policies\Microsoft\Windows\EventLog\System') do
    its('Retention') { should eq 0 }
  end
end

control 'cis-ensure-system-specify-the-maximum-log-file-size-KB-is-set-to-enabled-18.9.24.4.2' do
  impact 0.7
  title '18.9.24.4.2 Ensure System Specify the maximum log file size (KB) is set to Enabled: 32,768 or greater'
  desc 'Ensure System Specify the maximum log file size (KB) is set to Enabled: 32,768 or greater' 

  tag cis: ['windows_2012r2:18.9.24.4.2']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('System', 'HKLM\Software\Policies\Microsoft\Windows\EventLog\System') do
    its('MaxSize') { should eq 32768 }
  end
end

control 'cis-ensure-configure-windows-smartScreen-is-set-to-enabled-require-approval-from-an-administrator-before-running-downloaded-unknown-software-18.9.28.2' do
  impact 0.7
  title '18.9.28.2 Ensure Configure Windows SmartScreen is set to Enabled: Require approval from an administrator before running downloaded unknown software'
  desc 'Ensure Configure Windows SmartScreen is set to Enabled: Require approval from an administrator before running downloaded unknown software' 

  tag cis: ['windows_2012r2:18.9.28.2']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('Previous Versions', 'HKLM\Software\Policies\Microsoft\Windows\System') do
    its('EnableSmartScreen') { should eq 1 }
  end
end

control 'cis-ensure-turn-off-data-execution-prevention-for-explorer-is-set-to-disabled-18.9.28.3' do
  impact 0.7
  title '18.9.28.3 Ensure Turn off Data Execution Prevention for Explorer is set to Disabled'
  desc 'Ensure Turn off Data Execution Prevention for Explorer is set to Disabled' 

  tag cis: ['windows_2012r2:18.9.28.3']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('Previous Versions', 'HKLM\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoDataExecutionPrevention') { should eq 0 }
  end
end

control 'cis-ensure-turn-off-heap-termination-on-corruption-is-set-to-disabled-18.9.28.4' do
  impact 0.7
  title '18.9.28.4 Ensure Turn off heap termination on corruption is set to Disabled'
  desc 'Ensure Turn off heap termination on corruption is set to Disabled' 

  tag cis: ['windows_2012r2:18.9.28.4']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('Previous Versions', 'HKLM\Software\Policies\Microsoft\Windows\Explorer') do
    its('NoHeapTerminationOnCorruption') { should eq 0 }
  end
end

control 'cis-ensure-turn-off-shell-protocol-protected-mode-is-set-to-disabled-18.9.28.5' do
  impact 0.7
  title '18.9.28.5 Ensure Turn off shell protocol protected mode is set to Disabled'
  desc 'Ensure Turn off shell protocol protected mode is set to Disabled' 

  tag cis: ['windows_2012r2:18.9.28.5']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('Previous Versions', 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    its('PreXPSP2ShellProtocolBehavior') { should eq 0 }
  end
end

control 'cis-ensure-do-not-allow-drive-redirection-is-set-to-enabled-18.9.48.2.2' do
  impact 0.7
  title '18.9.48.2.2 Ensure Do not allow drive redirection is set to Enabled'
  desc 'Ensure Do not allow drive redirection is set to Enabled' 

  tag cis: ['windows_2012r2:18.9.48.2.2']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('Redirection', 'HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('DisablePasswordSaving') { should eq 1 }
  end
end

control 'cis-ensure-do-not-allow-drive-redirection-is-set-to-enabled-18.9.48.3.3.2' do
  impact 0.7
  title '18.9.48.3.3.2 Ensure Do not allow drive redirection is set to Enabled'
  desc 'Ensure Do not allow drive redirection is set to Enabled' 

  tag cis: ['windows_2012r2:18.9.48.3.3.2']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('Redirection', 'HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fDisableCdm') { should eq 1 }
  end
end

control 'cis-ensure-always-prompt-for-password-upon-connection-is-set-to-enabled-18.9.48.3.9.1' do
  impact 0.7
  title '18.9.48.3.9.1 Ensure Always prompt for password upon connection is set to Enabled'
  desc 'Ensure Always prompt for password upon connection is set to Enabled' 

  tag cis: ['windows_2012r2:18.9.48.3.9.1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('Security', 'HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fPromptForPassword') { should eq 1 }
  end
end

control 'cis-ensure-require-secure-RPC-communication-is-set-to-enabled-18.9.48.3.9.2' do
  impact 0.7
  title '18.9.48.3.9.2 Ensure Require secure RPC communication is set to Enabled'
  desc 'Ensure Require secure RPC communication is set to Enabled' 

  tag cis: ['windows_2012r2:18.9.48.3.9.2']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
 
  describe registry_key('Security', 'HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fEncryptRPCTraffic') { should eq 1 }
  end
end

control 'cis-ensure-set-client-connection-encryption-level-is-set-to-enabled-high-level-18.9.48.3.9.3' do
  impact 0.7
  title '18.9.48.3.9.3 Ensure Set client connection encryption level is set to Enabled: High Level'
  desc 'Ensure Set client connection encryption level is set to Enabled: High Level' 
  
    tag cis: ['windows_2012r2:18.9.48.3.9.3']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe registry_key('Security', 'HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('MinEncryptionLevel') { should eq 1 }
  end
end

control 'cis-ensure-do-not-delete-temp-folders-upon-exit-is-set-to-disabled-18.9.48.3.11.1' do
  impact 0.7
  title '18.9.48.3.11.1 Ensure Do not delete temp folders upon exit is set to Disabled'
  desc 'Ensure Do not delete temp folders upon exit is set to Disabled' 
  
  describe registry_key('Temporary folders', 'HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('PerSessionTempDir') { should eq 0 }
  end
end

control 'cis-Ensure-do-not-use-temporary-folders-per-session-is-set-to-disabled-18.9.48.3.11.2' do
  impact 0.7
  title '18.9.48.3.11.2 Ensure Do not use temporary folders per session is set to Disabled'
  desc 'Ensure Do not use temporary folders per session is set to Disabled' 
  
  describe registry_key('Temporary folders', 'HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    its('PerSessionTempDir') { should eq 0 }
  end
end

control 'cis-ensure-prevent-downloading-of-enclosures-is-set-to-enabled-18.9.49.1' do
  impact 0.7
  title '18.9.49.1 Ensure Prevent downloading of enclosures is set to Enabled'
  desc 'Ensure Prevent downloading of enclosures is set to Enabled' 
  
  describe registry_key('RSS Feeds', 'HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds') do
    its('DisableEnclosureDownload') { should eq 1 }
  end
end

control 'cis-ensure-allow-indexing-of-encrypted-files-is-set-to-disabled-18.9.50.2' do
  impact 0.7
  title '18.9.50.2 Ensure Allow indexing of encrypted files is set to Disabled'
  desc 'Ensure Allow indexing of encrypted files is set to Disabled' 
  
  describe registry_key('Windows Search', 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search') do
    its('AllowIndexingEncryptedStoresOrItems') { should eq 0 }
  end
end

control 'cis-ensure-prevent-the-usage-of-SkyDrive-for-file-storage-is-set-to-enabled-18.9.54.1' do
  impact 0.7
  title '18.9.54.1 Ensure Prevent the usage of SkyDrive for file storage is set to Enabled'
  desc 'Ensure Prevent the usage of SkyDrive for file storage is set to Enabled' 
  
  describe registry_key('Skydrive', 'HKLM\Software\Policies\Microsoft\Windows\Skydrive') do
    its('DisableFileSync') { should eq 1 }
  end
end

control 'cis-ensure-turn-off-automatic-download-and-install-of-updates-is-set-to-disabled-18.9.58.1' do
  impact 0.7
  title '18.9.58.1 Ensure Turn off Automatic Download and Install of updates is set to Disabled'
  desc 'Ensure Turn off Automatic Download and Install of updates is set to Disabled' 
  
  describe registry_key('WindowsStore', 'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore') do
    its('AutoDownload') { should eq 0 }
  end
end

control 'cis-ensure-turn-off-the-offer-to-update-to-the-latest-version-of-Windows-is-set-to-enabled-18.9.58.2' do
  impact 0.7
  title '18.9.58.2 Ensure turn off the offer to update to the latest version of Windows is set to Enabled'
  desc 'Ensure turn off the offer to update to the latest version of Windows is set to Enabled' 
  
  describe registry_key('WindowsStore', 'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore') do
    its('DisableOSUpgrade') { should eq 1 }
  end
end

control 'cis-ensure-configure-default-consent-is-set-to-enabled-always-ask-before-sending-data-18.9.67.2.1' do
  impact 0.7
  title '18.9.67.2.1 Ensure Configure Default consent is set to Enabled: Always ask before sending data'
  desc 'Ensure Configure Default consent is set to Enabled: Always ask before sending data' 
  
  describe registry_key('Windows Error Reporting', 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent') do
    its('DefaultConsent') { should eq 1 }
  end
end

control 'cis-ensure-automatically-send-memory-dumps-for-os-generated-error-reports-is-set-to-disabled-18.9.67.3' do
  impact 0.7
  title '18.9.67.3 Ensure Automatically send memory dumps for OS-generated error reports is set to Disabled'
  desc 'Ensure Automatically send memory dumps for OS-generated error reports is set to Disabled' 
  
  describe registry_key('Windows Error Reporting', 'HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Error Reporting') do
    its('AutoApproveOSDumps') { should eq 0 }
  end
end

control 'cis-ensure-allow-user-control-over-installs-is-set-to-disabled-18.9.69.1' do
  impact 0.7
  title '18.9.69.1 Ensure Allow user control over installs is set to Disabled'
  desc 'Ensure Allow user control over installs is set to Disabled' 
  
  describe registry_key('PowerShell', 'HKLM\Software\Policies\Microsoft\Windows\Installer') do
    its('EnableUserControl') { should eq 0 }
  end
end

control 'cis-ensure-always-install-with-elevated-privileges-is-set-to-18.9.69.2' do
  impact 0.7
  title '18.9.69.2 Ensure Always install with elevated privileges is set to Disabled'
  desc 'Ensure Always install with elevated privileges is set to Disabled' 
  
  describe registry_key('PowerShell', 'HKLM\Software\Policies\Microsoft\Windows\Installer') do
    its('AlwaysInstallElevated') { should eq 0 }
  end
end

control 'cis-ensure-sign-in-last-interactive-user-automatically-after-a-system-initiated-restart-is-set-to-disabled-18.9.70.1' do
  impact 0.7
  title '18.9.70.1 Ensure Sign-in last interactive user automatically after a system-initiated restart is set to Disabled'
  desc 'Ensure Sign-in last interactive user automatically after a system-initiated restart is set to Disabled' 
  
  describe registry_key('WindowsLogon', 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('DisableAutomaticRestartSignOn') { should eq 0 }
  end
end

control 'cis-ensure-allow-basic-authentication-is-set-to-disabled-18.9.79.1' do
  impact 0.7
  title '18.9.81.1.1 Ensure Turn on PowerShell Script Block Logging is set to Disabled'
  desc 'Ensure Allow Basic authentication is set to Disabled' 
  
  describe registry_key('PowerShell', 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging') do
    its('EnableScriptBlockLogging') { should eq 0 }
  end
end

control 'cis-ensure-turn-on-powershell-transcription-is-set-to-disabled-18.9.79.2' do
  impact 0.7
  title '18.9.79.1 Ensure Turn on PowerShell Transcription is set to Disabled'
  desc 'Ensure Allow unencrypted traffic is set to Disabled' 
  
  describe registry_key('PowerShell', 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription') do
    its('EnableTranscripting') { should eq 0 }
  end
end

control 'cis-ensure-allow-basic-authentication-is-set-to-disabled-18.9.81.1.1' do
  impact 0.7
  title '18.9.81.1.1 Ensure Allow Basic authentication is set to Disabled'
  desc 'Ensure Allow Basic authentication is set to Disabled' 
  
  describe registry_key('WinRM', 'HKLM\Software\Policies\Microsoft\Windows\WinRM\Client') do
    its('AllowBasic') { should eq 0 }
  end
end

control 'cis-ensure-allow-unencrypted-traffic-is-set-to-disabled-18.9.81.1.2' do
  impact 0.7
  title '18.9.81.1.2 Ensure Allow unencrypted traffic is set to Disabled'
  desc 'Ensure Allow unencrypted traffic is set to Disabled' 
  
  describe registry_key('WinRM', 'HKLM\Software\Policies\Microsoft\Windows\WinRM\Client') do
    its('AllowUnencryptedTraffic') { should eq 0 }
  end
end

control 'cis-ensure-disallow-digest-authentication-is-set-to-enabled-18.9.81.1.3' do
  impact 0.7
  title '18.9.81.1.3 Ensure Disallow Digest authentication is set to Enabled'
  desc 'Ensure Disallow Digest authentication is set to Enabled' 
  
  describe registry_key('WinRM', 'HKLM\Software\Policies\Microsoft\Windows\WinRM\Client') do
    its('AllowDigest') { should eq 1 }
  end
end

control 'cis-ensure-allow-basic-authentication-is-set-to-disabled-18.9.81.2.1' do
  impact 0.7
  title '18.9.81.2.1 Ensure Allow Basic authentication is set to Disabled'
  desc 'Ensure Allow Basic authentication is set to Disabled' 
  
  describe registry_key('WinRM', 'HKLM\Software\Policies\Microsoft\Windows\WinRM\Service') do
    its('AllowBasic') { should eq 0 }
  end
end

control 'cis-ensure-allow-unencrypted-traffic-is-set-to-disabled-18.9.81.2.2' do
  impact 0.7
  title '18.9.81.2.2 Ensure Allow unencrypted traffic is set to Disabled'
  desc 'Ensure Allow unencrypted traffic is set to Disabled' 
  
  describe registry_key('WinRM', 'HKLM\Software\Policies\Microsoft\Windows\WinRM\Service') do
    its('AllowUnencryptedTraffic') { should eq 0 }
  end
end

control 'cis-ensure-disallow-winrm-from-storing-runas-credentials-18.9.81.2.3' do
  impact 0.7
  title '18.9.81.2.3 Ensure Disallow WinRM from storing RunAs credentials is set to Enabled'
  desc 'Ensure Disallow WinRM from storing RunAs credentials is set to Enabled' 
  
  describe registry_key('WinRM', 'HKLM\Software\Policies\Microsoft\Windows\WinRM\Service') do
    its('DisableRunAs') { should eq 1 }
  end
end

control 'cis-ensure-configure-automatic-updates-is-set-to-enabled-18.9.85.1' do
  impact 0.7
  title '18.9.85.1 Ensure Configure Automatic Updates is set to Enabled'
  desc 'Ensure Configure Automatic Updates is set to Enabled' 
  
  describe registry_key('WindowsUpdate', 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU') do
    its('NoAutoUpdate') { should eq 1 }
  end
end

control 'cis-ensure-configure-automatic-updates-Scheduled-install-every-day-18.9.85.2' do
  impact 0.7
  title '18.9.85.2 Ensure Configure Automatic Updates: Scheduled install Every day is set to 0 Every day'
  desc 'Ensure Configure Automatic Updates: Scheduled install Every day is set to 0 Every day' 
  
  describe registry_key('WindowsUpdate', 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU') do
    its('ScheduledInstallDay') { should eq 0 }
  end
end

control 'cis-ensure-no-auto-restart-with-logged-on-users-18.9.85.3' do
  impact 0.7
  title '18.9.85.3 Ensure No auto-restart with logged on users for scheduled automatic updates installations is set to Disabled'
  desc 'Ensure No auto-restart with logged on users for scheduled automatic updates installations is set to Disabled' 
  
  describe registry_key('WindowsUpdate', 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU') do
    its('NoAutoRebootWithLoggedOnUsers') { should eq 0 }
  end
end