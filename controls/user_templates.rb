# encoding: utf-8

title 'Administrative Templates (User)'

# 19.1.3 Personalisation

control 'cis-enable-screen-saver-19.1.3.1' do
    impact 0.7
    title '19.1.3.1 Ensure Enable screen saver is set to Enabled'
    desc 'Ensure Enable screen saver is set to Enabled' 

    tag cis: ['windows_2012r2:19.1.3.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key({hive: 'HKEY_USERS'}).children(
        /S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\Control Panel\\Desktop\z/).each { |key|
    describe registry_key(key) do
        its('ScreenSaveActive') { should eq '1' }
    end
    }
    describe registry_key('HKU\S-1-5-19\Control Panel\Desktop') do  
        its('ScreenSaveActive') { should eq '1' }
    end
    describe registry_key('HKU\S-1-5-20\Control Panel\Desktop') do  
        its('ScreenSaveActive') { should eq '1' }
    end
end

control 'cis-force-specific-screensaver-19.1.3.2' do
    impact 0.7
    title '19.1.3.2 Ensure Force specific screen saver: screen saver executable name is set to Enabled: scrnsave.scr'
    desc 'Ensure Enable screen saver is set to Enabled' 

    tag cis: ['windows_2012r2:19.1.3.2']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key({hive: 'HKEY_USERS'}).children(
        /S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\Control Panel\\Desktop\z/).each { |key|
    describe registry_key(key) do
        it { should have_property_value('SCRNSAVE.EXE', :string, 'scrnsave.scr') }
    end
    }
    describe registry_key('HKU\S-1-5-19\Control Panel\Desktop') do  
        it { should have_property_value('SCRNSAVE.EXE', :string, 'scrnsave.scr') }
    end
    describe registry_key('HKU\S-1-5-20\Control Panel\Desktop') do  
        it { should have_property_value('SCRNSAVE.EXE', :string, 'scrnsave.scr') }
    end
end

control 'cis-password-protect-screen-saver-19.1.3.3' do
    impact 0.7
    title '19.1.3.3 Ensure Password protect the screen saver is set to Enabled'
    desc 'Ensure Password protect the screen saver is set to Enabled' 

    tag cis: ['windows_2012r2:19.1.3.3']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key({hive: 'HKEY_USERS'}).children(
        /S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\Control Panel\\Desktop\z/).each { |key|
    describe registry_key(key) do
        its('ScreenSaverIsSecure') { should eq '1' }
    end
    }
    describe registry_key('HKU\S-1-5-19\Control Panel\Desktop') do  
        its('ScreenSaverIsSecure') { should eq '1' }
    end
    describe registry_key('HKU\S-1-5-20\Control Panel\Desktop') do  
        its('ScreenSaverIsSecure') { should eq '1' }
    end
end

control 'cis-screen-saver-timeout-19.1.3.4' do
    impact 0.7
    title '19.1.3.4 Ensure Screen saver timeout is set to Enabled: 900
    seconds or fewer, but not 0'
    desc 'Ensure Screen saver timeout is set to Enabled: 900
    seconds or fewer, but not 0' 

    tag cis: ['windows_2012r2:19.1.3.4']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key({hive: 'HKEY_USERS'}).children(
        /S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\Control Panel\\Desktop\z/).each { |key|
    describe registry_key(key) do
        its('ScreenSaveTimeOut') { should be > 0 }
        its('ScreenSaveTimeOut') { should be <= 900 }
    end
    }
    describe registry_key('HKU\S-1-5-19\Control Panel\Desktop') do  
        its('ScreenSaveTimeOut') { should be > 0 }
        its('ScreenSaveTimeOut') { should be <= 900 }
    end
    describe registry_key('HKU\S-1-5-20\Control Panel\Desktop') do  
        its('ScreenSaveTimeOut') { should be > 0 }
        its('ScreenSaveTimeOut') { should be <= 900 }
    end
end

# 19.5 Start Menu and Taskbar

control 'cis-turn-off-toast-notifications-19.5.1.1' do
    impact 0.7
    title '19.5.1.1 Ensure Turn off toast notifications on the lock screen is set to Enabled: scrnsave.scr'
    desc 'Ensure Turn off toast notifications on the lock screen is set to Enabled' 

    tag cis: ['windows_2012r2:19.5.1.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key({hive: 'HKEY_USERS'}).children(
        /S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\z/).each { |key|
    describe registry_key(key) do
        its('NoToastApplicationNotificationOnLockScreen') { should eq 1 }
    end
    }
    describe registry_key('HKU\S-1-5-19\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications') do  
        its('NoToastApplicationNotificationOnLockScreen') { should eq 1 }
    end
    describe registry_key('HKU\S-1-5-20\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications') do  
        its('NoToastApplicationNotificationOnLockScreen') { should eq 1 }
    end
end

# 19.6 Internet Communication Management

control 'cis-turn-off-help-experience-improvement-program-19.6.5.1.1' do
    impact 0.7
    title '19.6.5.1.1 Ensure Turn off Help Experience Improvement Program is set to Enabled: scrnsave.scr'
    desc 'Ensure Turn off Help Experience Improvement Program is set to Enabled' 

    tag cis: ['windows_2012r2:19.6.5.1.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key({hive: 'HKEY_USERS'}).children(
        /S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0\z/).each { |key|
    describe registry_key(key) do
        its('NoImplicitFeedback') { should eq 1 }
    end
    }
    describe registry_key('HKU\S-1-5-19\Software\Policies\Microsoft\Assistance\Client\1.0') do  
        its('NoImplicitFeedback') { should eq 1 }
    end
    describe registry_key('HKU\S-1-5-20\Software\Policies\Microsoft\Assistance\Client\1.0') do  
        its('NoImplicitFeedback') { should eq 1 }
    end
end

# 19.7.4 Attachment Manager

control 'cis-do-not-preserve-zone-information-19.7.4.1' do
    impact 0.7
    title '19.7.4.1 Ensure Do not preserve zone information in file attachments is set to Disabled'
    desc 'Ensure Do not preserve zone information in file attachments is set to Disabled' 

    tag cis: ['windows_2012r2:19.7.4.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key({hive: 'HKEY_USERS'}).children(
        /S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\z/).each { |key|
    describe registry_key(key) do
        its('SaveZoneInformation') { should eq 0 }
    end
    }
    describe registry_key('HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments') do  
        its('SaveZoneInformation') { should eq 0 }
    end
    describe registry_key('HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments') do  
        its('SaveZoneInformation') { should eq 0 }
    end
end

control 'cis-notify-antivirus-programs-19.7.4.2' do
    impact 0.7
    title '19.7.4.2 Ensure Notify antivirus programs when opening attachments is set to Enabled'
    desc 'Ensure Notify antivirus programs when opening attachments is set to Enabled' 

    tag cis: ['windows_2012r2:19.7.4.2']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key({hive: 'HKEY_USERS'}).children(
        /S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\z/).each { |key|
    describe registry_key(key) do
        its('ScanWithAntiVirus') { should eq 1 }
    end
    }
    describe registry_key('HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments') do  
        its('ScanWithAntiVirus') { should eq 1 }
    end
    describe registry_key('HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments') do  
        its('ScanWithAntiVirus') { should eq 1 }
    end
end

# 19.7.25 Network Sharing

control 'cis-prevent-profile-file-sharing-19.7.25.1' do
    impact 0.7
    title '19.7.25.1 Ensure Prevent users from sharing files within their profile is set to Enabled'
    desc 'Ensure Prevent users from sharing files within their profile is set to Enabled' 

    tag cis: ['windows_2012r2:19.7.25.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key({hive: 'HKEY_USERS'}).children(
        /S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\z/).each { |key|
    describe registry_key(key) do
        its('NoInplaceSharing') { should eq 1 }
    end
    }
    describe registry_key('HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer') do  
        its('NoInplaceSharing') { should eq 1 }
    end
    describe registry_key('HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer') do  
        its('NoInplaceSharing') { should eq 1 }
    end
end

# 19.7.37 Windows Installer

control 'cis-always-elevated-install-19.7.37.1' do
    impact 0.7
    title '19.7.37.1 Ensure Always install with elevated privileges is set to Disabled'
    desc 'Ensure Always install with elevated privileges is set to Disabled' 

    tag cis: ['windows_2012r2:19.7.37.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key({hive: 'HKEY_USERS'}).children(
        /S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\Software\\Policies\\Microsoft\\Windows\\Installer\z/).each { |key|
    describe registry_key(key) do
        its('AlwaysInstallElevated') { should eq 0 }
    end
    }
    describe registry_key('HKU\S-1-5-19\Software\Policies\Microsoft\Windows\Installer') do  
        its('AlwaysInstallElevated') { should eq 0 }
    end
    describe registry_key('HKU\S-1-5-20\Software\Policies\Microsoft\Windows\Installer') do  
        its('AlwaysInstallElevated') { should eq 0 }
    end
end

# 19.7.41.2 Playback

control 'cis-always-elevated-install-19.7.41.2.1' do
    impact 0.7
    title '19.7.41.2.1 Ensure Prevent Codec Download is set to Enabled'
    desc 'Ensure Prevent Codec Download is set to Enabled' 

    tag cis: ['windows_2012r2:19.7.41.2.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

    describe registry_key({hive: 'HKEY_USERS'}).children(
        /S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\Software\\Policies\\Microsoft\\WindowsMediaPlayer\z/).each { |key|
    describe registry_key(key) do
        its('PreventCodecDownload') { should eq 1 }
    end
    }
    describe registry_key('HKU\S-1-5-19\Software\Policies\Microsoft\WindowsMediaPlayer') do  
        its('PreventCodecDownload') { should eq 1 }
    end
    describe registry_key('HKU\S-1-5-20\Software\Policies\Microsoft\WindowsMediaPlayer') do  
        its('PreventCodecDownload') { should eq 1 }
    end
end
