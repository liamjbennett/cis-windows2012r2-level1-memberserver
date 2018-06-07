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

    only_if { file('C:\Windows\PolicyDefinitions\AdmPwd.admx').file? }

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

    only_if { file('C:\Windows\PolicyDefinitions\AdmPwd.admx').file? }

    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Services\AdmPwd') do
        its('PwdExpirationProtectionEnabled') { should eq 1 }
    end
end

control 'cis-password-settings-password-complexity-18.2.4' do
    impact 0.7
    title '18.2.4 Ensure Password Settings: Password Complexity is set to
    Enabled: Large letters + small letters + numbers + special characters' 
    desc 'Ensure Password Settings: Password Complexity is set to
    Enabled: Large letters + small letters + numbers + special characters' 

    tag cis: ['windows_2012r2:18.2.4']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    only_if { file('C:\Windows\PolicyDefinitions\AdmPwd.admx').file? }

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

    only_if { file('C:\Windows\PolicyDefinitions\AdmPwd.admx').file? }

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

    only_if { file('C:\Windows\PolicyDefinitions\AdmPwd.admx').file? }

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

    only_if { file('C:\Windows\PolicyDefinitions\MSS-legacy.admx').file? }

    describe registry_key('HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon') do
        its('AutoAdminLogon') { should eq 1 }
    end
end

control 'cis-ipv6-routing-protection-level-18.3.2' do
    impact 0.7
    title '18.3.2 Ensure MSS: (DisableIPSourceRouting IPv6) IP source routing
    protection level (protects against packet spoofing) is set to Enabled:
    Highest protection, source routing is completely disabled' 
    desc 'Ensure MSS: (DisableIPSourceRouting IPv6) IP source routing
    protection level (protects against packet spoofing) is set to Enabled:
    Highest protection, source routing is completely disabled' 

    tag cis: ['windows_2012r2:18.3.2']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    only_if { file('C:\Windows\PolicyDefinitions\MSS-legacy.admx').file? }

    describe registry_key('HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters') do
        its('DisableIPSourceRouting') { should eq 1 }
    end
end

# 18.9 Windows Components

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
