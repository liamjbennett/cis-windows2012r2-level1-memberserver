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



