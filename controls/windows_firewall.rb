# encoding: utf-8

title 'Windows Firewall With Advanced Security'

control 'cis-domain-firewall-on-9.1.1' do
  impact 0.7
  title '9.1.1 Ensure Windows Firewall: Domain: Firewall state is set to On'
  desc 'Ensure Windows Firewall: Domain: Firewall state is set to On' 
  
  describe registry_key('DomainProfile', 'HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile') do
    its('EnableFirewall') { should eq 1 }
  end
end

control 'cis-domain-firewall-inbound-9.1.2' do
  impact 0.7
  title '9.1.2 Ensure Windows Firewall: Domain: Inbound connections is set to Block'
  desc 'Ensure Windows Firewall: Domain: Inbound connections is set to Block'

  describe registry_key('DomainProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile') do
    its('DefaultInboundAction') { should eq 1 }
  end
end

control 'cis-domain-firewall-outbound-9.1.3' do
  impact 0.7
  title '9.1.3 Ensure Windows Firewall: Domain: Outbound connections is set to Allow'
  desc 'Ensure Windows Firewall: Domain: Outbound connections is set to Allow'

  describe registry_key('DomainProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile') do
    its('DefaultOutboundAction') { should eq 0 }
  end
end

control 'cis-domain-firewall-notification-9.1.4' do
  impact 0.7
  title '9.1.4 Ensure Windows Firewall: Domain: Outbound connections is set to Allow'
  desc 'Ensure Windows Firewall: Domain: Outbound connections is set to Allow'

  describe registry_key('DomainProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile') do
    its('DisableNotifications') { should eq 1 }
  end
end

control 'cis-domain-firewall-local-firewall-rules-9.1.5' do
  impact 0.7
  title '9.1.5 Ensure Windows Firewall: Domain: Settings: Apply local
  firewall rules is set to Yes'
  desc 'Ensure Windows Firewall: Domain: Settings: Apply local
  firewall rules is set to Yes'

  describe registry_key('DomainProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile') do
    its('AllowLocalPolicyMerge') { should eq 1 }
  end
end

control 'cis-domain-firewall-local-security-rules-9.1.6' do
  impact 0.7
  title '9.1.6 Ensure Windows Firewall: Domain: Settings: Apply local
  connection security rules is set to Yes'
  desc 'Ensure Windows Firewall: Domain: Settings: Apply local
  connection security rules is set to Yes'

  describe registry_key('DomainProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile') do
    its('AllowLocalIPsecPolicyMerge') { should eq 1 }
  end
end

control 'cis-domain-firewall-logging-name-9.1.7' do
  impact 0.7
  title '9.1.7 Ensure Windows Firewall: Domain: Logging: Name is set to
  %SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'
  desc 'Ensure Windows Firewall: Domain: Logging: Name is set to
  %SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'

  describe registry_key('DomainProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging') do
    its('LogFilePath') { should eq '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log' }
  end
end

control 'cis-domain-firewall-logging-size-limit-9.1.8' do
  impact 0.7
  title '9.1.8 Ensure Windows Firewall: Domain: Logging: Size limit (KB) is
  set to 16,384 KB or greater'
  desc 'Ensure Windows Firewall: Domain: Logging: Size limit (KB) is
  set to 16,384 KB or greater'

  describe registry_key('DomainProfile', 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging') do
    its('LogFileSize') { should eq 16384 }
  end
end

control 'cis-domain-firewall-log-dropped-packets-9.1.9' do
  impact 0.7
  title '9.1.9 Ensure Windows Firewall: Domain: Logging: Log dropped
  packets is set to Yes'
  desc 'Ensure Windows Firewall: Domain: Logging: Log dropped
  packets is set to Yes'

  describe registry_key('DomainProfile', 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging') do
    its('LogDroppedPackets') { should eq 1 }
  end
end

control 'cis-domain-firewall-log-successful-connections-9.1.10' do
  impact 0.7
  title '9.1.10 Ensure Windows Firewall: Domain: Logging: Log successful
  connections is set to Yes'
  desc 'Ensure Windows Firewall: Domain: Logging: Log successful
  connections is set to Yes'

  describe registry_key('DomainProfile', 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging') do
    its('LogSuccessfulConnections') { should eq 1 }
  end
end

control 'cis-domain-firewall-on-9.2.1' do
  impact 0.7
  title '9.1.1 Ensure Windows Firewall: Private: Firewall state is set to On'
  desc 'Ensure Windows Firewall: Private: Firewall state is set to On' 
  
  describe registry_key('PrivateProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile') do
    its('EnableFirewall') { should eq 1 }
  end
end

control 'cis-private-firewall-inbound-9.2.2' do
  impact 0.7
  title '9.2.2 Ensure Windows Firewall: Private: Inbound connections is set to Block'
  desc 'Ensure Windows Firewall: Private: Inbound connections is set to Block'

  describe registry_key('PrivateProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile') do
    its('DefaultInboundAction') { should eq 1 }
  end
end

control 'cis-private-firewall-outbound-9.2.3' do
  impact 0.7
  title '9.2.3 Ensure Windows Firewall: Private: Outbound connections is set to Allow'
  desc 'Ensure Windows Firewall: Private: Outbound connections is set to Allow'

  describe registry_key('PrivateProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile') do
    its('DefaultOutboundAction') { should eq 0 }
  end
end

control 'cis-private-firewall-notification-9.2.4' do
  impact 0.7
  title '9.2.4 Ensure Windows Firewall: Private: Outbound connections is set to Allow'
  desc 'Ensure Windows Firewall: Private: Outbound connections is set to Allow'

  describe registry_key('PrivateProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile') do
    its('DisableNotifications') { should eq 1 }
  end
end

control 'cis-private-firewall-local-firewall-rules-9.2.5' do
  impact 0.7
  title '9.2.5 Ensure Windows Firewall: Private: Settings: Apply local
  firewall rules is set to Yes'
  desc 'Ensure Windows Firewall: Private: Settings: Apply local
  firewall rules is set to Yes'

  describe registry_key('PrivateProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile') do
    its('AllowLocalPolicyMerge') { should eq 1 }
  end
end

control 'cis-private-firewall-local-security-rules-9.2.6' do
  impact 0.7
  title '9.2.6 Ensure Windows Firewall: Private: Settings: Apply local
  connection security rules is set to Yes'
  desc 'Ensure Windows Firewall: Private: Settings: Apply local
  connection security rules is set to Yes'

  describe registry_key('PrivateProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile') do
    its('AllowLocalIPsecPolicyMerge') { should eq 1 }
  end
end

control 'cis-private-firewall-logging-name-9.2.7' do
  impact 0.7
  title '9.2.7 Ensure Windows Firewall: Private: Logging: Name is set to
  %SYSTEMROOT%\System32\logfiles\firewall\privatefw.log'
  desc 'Ensure Windows Firewall: Private: Logging: Name is set to
  %SYSTEMROOT%\System32\logfiles\firewall\privatefw.log'

  describe registry_key('PrivateProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging') do
    its('LogFilePath') { should eq '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log' }
  end
end

control 'cis-private-firewall-logging-size-limit-9.2.8' do
  impact 0.7
  title '9.2.8 Ensure Windows Firewall: Private: Logging: Size limit (KB) is
  set to 16,384 KB or greater'
  desc 'Ensure Windows Firewall: Private: Logging: Size limit (KB) is
  set to 16,384 KB or greater'

  describe registry_key('PrivateProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging') do
    its('LogFileSize') { should eq 16384 }
  end
end

control 'cis-private-firewall-log-dropped-packets-9.2.9' do
  impact 0.7
  title '9.2.9 Ensure Windows Firewall: Private: Logging: Log dropped
  packets is set to Yes'
  desc 'Ensure Windows Firewall: Private: Logging: Log dropped
  packets is set to Yes'

  describe registry_key('PrivateProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging') do
    its('LogDroppedPackets') { should eq 1 }
  end
end

control 'cis-private-firewall-log-successful-connections-9.2.10' do
  impact 0.7
  title '9.2.10 Ensure Windows Firewall: Private: Logging: Log successful
  connections is set to Yes'
  desc 'Ensure Windows Firewall: Private: Logging: Log successful
  connections is set to Yes'

  describe registry_key('PrivateProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging') do
    its('LogSuccessfulConnections') { should eq 1 }
  end
end

control 'cis-domain-firewall-on-9.3.1' do
  impact 0.7
  title '9.3.1 Ensure Windows Firewall: Public: Firewall state is set to On'
  desc 'Ensure Windows Firewall: Public: Firewall state is set to On' 
  
  describe registry_key('PublicProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile') do
    its('EnableFirewall') { should eq 1 }
  end
end

control 'cis-public-firewall-inbound-9.3.2' do
  impact 0.7
  title '9.3.2 Ensure Windows Firewall: Public: Inbound connections is set to Block'
  desc 'Ensure Windows Firewall: Public: Inbound connections is set to Block'

  describe registry_key('PublicProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile') do
    its('DefaultInboundAction') { should eq 1 }
  end
end

control 'cis-public-firewall-outbound-9.3.3' do
  impact 0.7
  title '9.3.3 Ensure Windows Firewall: Public: Outbound connections is set to Allow'
  desc 'Ensure Windows Firewall: Public: Outbound connections is set to Allow'

  describe registry_key('PublicProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile') do
    its('DefaultOutboundAction') { should eq 0 }
  end
end

control 'cis-public-firewall-notification-9.3.4' do
  impact 0.7
  title '9.3.4 Ensure Windows Firewall: Public: Outbound connections is set to Allow'
  desc 'Ensure Windows Firewall: Public: Outbound connections is set to Allow'

  describe registry_key('PublicProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile') do
    its('DisableNotifications') { should eq 1 }
  end
end

control 'cis-public-firewall-local-firewall-rules-9.3.5' do
  impact 0.7
  title '9.3.5 Ensure Windows Firewall: Public: Settings: Apply local
  firewall rules is set to Yes'
  desc 'Ensure Windows Firewall: Public: Settings: Apply local
  firewall rules is set to Yes'

  describe registry_key('PublicProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile') do
    its('AllowLocalPolicyMerge') { should eq 1 }
  end
end

control 'cis-public-firewall-local-security-rules-9.3.6' do
  impact 0.7
  title '9.3.6 Ensure Windows Firewall: Public: Settings: Apply local
  connection security rules is set to Yes'
  desc 'Ensure Windows Firewall: Public: Settings: Apply local
  connection security rules is set to Yes'

  describe registry_key('PublicProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile') do
    its('AllowLocalIPsecPolicyMerge') { should eq 1 }
  end
end

control 'cis-public-firewall-logging-name-9.3.7' do
  impact 0.7
  title '9.3.7 Ensure Windows Firewall: Public: Logging: Name is set to
  %SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'
  desc 'Ensure Windows Firewall: Public: Logging: Name is set to
  %SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'

  describe registry_key('PublicProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging') do
    its('LogFilePath') { should eq '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log' }
  end
end

control 'cis-public-firewall-logging-size-limit-9.3.8' do
  impact 0.7
  title '9.3.8 Ensure Windows Firewall: Public: Logging: Size limit (KB) is
  set to 16,384 KB or greater'
  desc 'Ensure Windows Firewall: Public: Logging: Size limit (KB) is
  set to 16,384 KB or greater'

  describe registry_key('PublicProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging') do
    its('LogFileSize') { should eq 16384 }
  end
end

control 'cis-public-firewall-log-dropped-packets-9.3.9' do
  impact 0.7
  title '9.3.9 Ensure Windows Firewall: Public: Logging: Log dropped
  packets is set to Yes'
  desc 'Ensure Windows Firewall: Public: Logging: Log dropped
  packets is set to Yes'

  describe registry_key('PublicProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging') do
    its('LogDroppedPackets') { should eq 1 }
  end
end

control 'cis-public-firewall-log-successful-connections-9.3.10' do
  impact 0.7
  title '9.3.10 Ensure Windows Firewall: Public: Logging: Log successful
  connections is set to Yes'
  desc 'Ensure Windows Firewall: Public: Logging: Log successful
  connections is set to Yes'

  describe registry_key('PublicProfile', 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging') do
    its('LogSuccessfulConnections') { should eq 1 }
  end
end
