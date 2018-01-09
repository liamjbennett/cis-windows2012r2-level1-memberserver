# encoding: utf-8

title 'User Rights Assignment'

control 'cis-access-cred-manager-2.2.1' do
  impact 0.7
  title '2.2.1 Set Access Credential Manager as a trusted caller to No One'
  desc 'Set Access Credential Manager as a trusted caller to No One'

  tag cis: ['windows_2012r2:2.2.1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { should eq ['S-1-0-0'] }
  end
end

control 'cis-network-access-2.2.2' do
  impact 0.7
  title '2.2.2 Set Access this computer from the network'
  desc 'Set Access this computer from the network'

  tag cis: ['windows_2012r2:2.2.2']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeNetworkLogonRight') { should eq ['S-1-0-0'] }
  end
end

control 'cis-act-as-os-2.2.3' do
  impact 0.7
  title '2.2.3 Set Act as part of the operating system to No One'
  desc 'Set Act as part of the operating system to No One'

  tag cis: ['windows_2012r2:2.2.3']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeTcbPrivilege') { should eq ['S-1-0-0'] }
  end
end

control 'cis-add-workstations-2.2.4' do
  impact 0.7
  title '2.2.4 Set Add workstations to domain to Administrators'
  desc 'Set Add workstations to domain to Administrators'

  tag cis: ['windows_2012r2:2.2.4']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeMachineAccountPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'cis-adjust-memory-quotas-2.2.5' do
  impact 0.7
  title '2.2.5 Set Adust memory quotas for a process to Administrators, LOCAL SERVICE, NETWORK SERVICE'
  desc 'Set Adust memory quotas for a process to Administrators, LOCAL SERVICE, NETWORK SERVICE'

  tag cis: ['windows_2012r2:2.2.5']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeIncreaseQuotaPrivilege') { should include 'S-1-5-19' }
    its('SeIncreaseQuotaPrivilege') { should include 'S-1-5-20' }
    its('SeIncreaseQuotaPrivilege') { should include 'S-1-5-32-544' }
  end
end

control 'cis-allow-login-locally-2.2.6' do
  impact 0.7
  title '2.2.6 Set Allow log on locally to Administrators'
  desc 'Set Allow log on locally to Administrators'

  tag cis: ['windows_2012r2:2.2.6']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeInteractiveLogonRight') { should include 'S-1-5-32-544' }
  end
end

control 'cis-allow-login-rds-2.2.7' do
  impact 0.7
  title '2.2.7 Set Allow log on through Remote Desktop Services'
  desc 'Set Allow log on through Remote Desktop Services'

  tag cis: ['windows_2012r2:2.2.7']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeRemoteInteractiveLogonRight') { should include 'S-1-5-32-544' }
    its('SeRemoteInteractiveLogonRights') { should include 'S-1-5-32-555' }
  end
end

control 'cis-ensure-backup-files-2.2.8' do
  impact 0.7
  title '2.2.8 Ensure Back up files and directories is set to Administrators'
  desc 'Ensure Back up files and directories is set to Administrators'

  tag cis: ['windows_2012r2:2.2.8']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeBackupPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'cis-ensure-change-system-time-2.2.9' do
  impact 0.7
  title '2.2.9 Ensure Change the system time is set'
  desc 'Ensure Change the system time is set'

  tag cis: ['windows_2012r2:2.2.9']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeSystemtimePrivilege') { should eq ['S-1-5-19','S-1-5-32-544'] }
  end
end

control 'cis-ensure-change-time-zone-2.2.10' do
  impact 0.7
  title '2.2.10 Ensure Change the time zone is set'
  desc 'Ensure Change the time zone is set'

  tag cis: ['windows_2012r2:2.2.10']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeTimeZonePrivilege') { should eq ['S-1-5-19','S-1-5-32-544'] }
  end
end

control 'cis-allow-create-pagefile-2.2.11' do
  impact 0.7
  title '2.2.11 Ensure Create a pagefile is set to Administrators'
  desc 'Ensure Create a pagefile is set to Administrators'

  tag cis: ['windows_2012r2:2.2.11']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeCreatePagefilePrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'cis-allow-create-token-object-2.2.12' do
  impact 0.7
  title '2.2.12 Ensure Create a token object is set to No one'
  desc 'Ensure Create a token object is set to No one'

  tag cis: ['windows_2012r2:2.2.12']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeCreateTokenPrivilege') { should eq ['S-1-0-0'] }
  end
end

control 'cis-allow-create-global-objects-2.2.13' do
  impact 0.7
  title '2.2.13 Ensure Create global objects is set'
  desc 'Ensure Create global objects is set'

  tag cis: ['windows_2012r2:2.2.13']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeCreateGlobalPrivilege') { should eq ['S-1-5-19','S-1-5-20','S-1-5-32-544','S-1-5-6'] }
  end
end

control 'cis-allow-create-shared-objects-2.2.14' do
  impact 0.7
  title '2.2.14 Ensure Create permentant shared objects is set to No one'
  desc 'Ensure Create permentant shared objects is set to No one'

  tag cis: ['windows_2012r2:2.2.14']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeCreatePermanentPrivilege') { should eq ['S-1-0-0'] }
  end
end

control 'cis-allow-create-symbolic-links-2.2.15' do
  impact 0.7
  title '2.2.14 Ensure Create Symblic links is net to Administrators'
  desc 'Ensure Create Symblic links is net to Administrators'

  tag cis: ['windows_2012r2:2.2.15']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeCreateSymbolicLinkPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'cis-allow-debug-programs-2.2.16' do
  impact 0.7
  title '2.2.16 Ensure Debug Programs is set to Administrators'
  desc 'Ensure Debug Programs is set to Administrators'

  tag cis: ['windows_2012r2:2.2.16']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeDebugPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'cis-deny-access-from-network-2.2.17' do
  impact 0.7
  title '2.2.17 Deny access from to this compute from the network'
  desc 'Deny access from to this compute from the network'

  tag cis: ['windows_2012r2:2.2.17']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeDenyNetworkLogonRight') { should eq ['S-1-5-32-546','S-1-2-0','S-1-5-32-544'] }
  end
end

control 'cis-deny-logon-as-batch-job-guests-2.2.18' do
  impact 0.7
  title '2.2.18 Deny Log on as Batch Job should include Guests'
  desc 'Deny Log on as Batch Job should include Guests'

  tag cis: ['windows_2012r2:2.2.18']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
  describe security_policy do
    its('SeDenyBatchLogonRight') { should include ['S-1-5-32-546'] }
  end
end

control 'cis-deny-logon-as-service-guests-2.2.19' do
  impact 0.7
  title '2.2.19 Deny Log on as Service should include Guests'
  desc 'Deny Log on as Service should include Guests'
  
  tag cis: ['windows_2012r2:2.2.19']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeDenyServiceLogonRight') { should include ['S-1-5-32-546'] }
  end
end

control 'cis-deny-logon-locally-guests-2.2.20' do
  impact 0.7
  title '2.2.20 Deny Log on Locally should include Guests'
  desc 'Deny Log on as Locally should include Guests'

  tag cis: ['windows_2012r2:2.2.20']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
  describe security_policy do
    its('SeDenyInteractiveLogonRight') { should include ['S-1-5-32-546'] }
  end
end

control 'cis-deny-logon-RDS-2.2.21' do
  impact 0.7
  title '2.2.21 Deny Log on through Remote Destkop Services'
  desc 'Deny Log on through Remote Destkop Services'

  tag cis: ['windows_2012r2:2.2.21']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeDenyRemoteInteractiveLogonRight') { should eq ['S-1-5-32-546','S-1-2-0'] }
  end
end

control 'cis-enable-accounts-trusted-for-delegation-2.2.22' do
  impact 0.7
  title '2.2.22 Enable computer and user accounts to be trusted for delegation'
  desc 'Enable computer and user accounts to be trusted for delegation'

  tag cis: ['windows_2012r2:2.2.22']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeEnableDelegationPrivilege') { should eq ['S-1-0-0'] }
  end
end

control 'cis-allow-force-shutdown-2.2.23' do
  impact 0.7
  title '2.2.23 Allow Force shutdown from a remote system is set to Administrators'
  desc 'Allow Force shutdown from a remote system is set to Administrators'

  tag cis: ['windows_2012r2:2.2.23']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeRemoteShutdownPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'cis-allow-generate-security-audits-2.2.24' do
  impact 0.7
  title '2.2.24 Ensure Generate security audits set to Local Service, Network Service'
  desc 'Ensure Generate security audits set to Local Service, Network Service'

  tag cis: ['windows_2012r2:2.2.24']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeAuditPrivilege') { should eq ['S-1-5-19','S-1-5-20'] }
  end
end

control 'cis-configure-impersonate-client-2.2.25' do
  impact 0.7
  title '2.2.25 Configure Impersonate a client after authentication'
  desc 'Configure Impersonate a client after authentication'

  tag cis: ['windows_2012r2:2.2.25']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeImpersonatePrivilege') { should eq ['S-1-5-19','S-1-5-20','S-1-5-32-544','S-1-5-6'] }
  end
end

control 'cis-increase-scheduling-priority-2.2.26' do
  impact 0.7
  title '2.2.26 Ensure Increase Scheduling priority is set to Administrators'
  desc 'Ensure Increase Scheduling priority is set to Administrators'
  
  tag cis: ['windows_2012r2:2.2.26']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeIncreaseBasePriorityPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'cis-load-unload-device-drivers-2.2.27' do
  impact 0.7
  title '2.2.27 Ensure Load and unload device drives is set to Administrators'
  desc 'Ensure Load and unload device drives is set to Administrators'
  
  tag cis: ['windows_2012r2:2.2.27']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeLoadDriverPrivilege') {should eq ['S-1-5-32-544'] }
  end
end 

control 'cis-lock-pages-in-memory-noone-2.2.28' do
  impact 0.7
  title '2.2.28 Ensure Lock pages in memory is set to No One'
  desc 'Ensure Lock pages in memory is set to No One'
  
  tag cis: ['windows_2012r2:2.2.28']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeLockMemoryPrivilege') { should eq ['S-1-0-0'] }
  end
end

control 'cis-logon-as-batch-job-2.2.29' do
  impact 0.7
  title '2.2.29 Ensure Logon as batch job is set to Administrators'
  desc 'Ensure Logon as batch job is set to Administrators'
  
  tag cis: ['windows_2012r2:2.2.29']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  # TODO: Domain policy only
end

control 'cis-manage-auditing-security-log-2.2.30' do
  impact 0.7
  title '2.2.30 Configure Manage auditing and security log'
  desc 'Configure Manage auditing and security log'
  
  tag cis: ['windows_2012r2:2.2.30']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeSecurityPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'cis-manage-object-label-noone-2.2.31' do
  impact 0.7
  title '2.2.31 Ensure Modify an object label is set to No One'
  desc 'Ensure Modify an object label is set to No One'

  tag cis: ['windows_2012r2:2.2.31']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
  describe security_policy do
    its('SeRelabelPrivilege') { should eq ['S-1-0-0'] }
  end
end

control 'cis-modify-fireware-environment-2.2.32' do
  impact 0.7
  title '2.2.32 Ensure Modify fireware evironment values is set to Administrators'
  desc 'Ensure Modify fireware evironment values is set to Administrators'

  tag cis: ['windows_2012r2:2.2.32']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeSystemEnvironmentPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'cis-perform-volume-maintaince-2.2.33' do
  impact 0.7
  title '2.2.33 Ensure Perform volume maintenance task is set to Administrators'
  desc 'Ensure Perform volume maintenance task is set to Administrators'
  
  tag cis: ['windows_2012r2:2.2.33']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeManageVolumePrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'cis-profile-single-process-2.2.34' do
  impact 0.7
  title '2.2.34 Ensure Profile single process is set to Administrators'
  desc 'Ensure Profile single process is set to Administrators'

  tag cis: ['windows_2012r2:2.2.34']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeProfileSingleProcessPrivilege') { should eq ['S-1-5-32-544'] }
  end  
end

control 'cis-profile-system-performance-2.2.35' do
  impact 0.7
  title '2.2.35 Ensure Profile system performance is set to Administrators and NT Service\WdiServiceHost'
  desc 'Ensure Profile system performance is set to Administrators and NT Service\WdiServiceHost'

  tag cis: ['windows_2012r2:2.2.35']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeSystemProfilePrivilege') { should eq ['S-1-5-32-544','S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420'] }
  end
end

control 'cis-replace-progress-level-token-2.2.36' do
  impact 0.7
  title '2.2.36 Ensure Replace a progress level token is set to Local Service and Network Service'
  desc 'Ensure Replace a progress level token is set to Local Service and Network Service'

  tag cis: ['windows_2012r2:2.2.36']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeAssignPrimaryTokenPrivilege') { should eq ['S-1-5-19','S-1-5-20'] }
  end 
end

control 'cis-restore-files-and-directories-2.2.37' do
  impact 0.7
  title '2.2.37 Ensure Restore files and directories set to Administrators'
  desc 'Ensure Restore files and directories set to Administrators'

  tag cis: ['windows_2012r2:2.2.37']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeRestorePrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'cis-shutdown-the-system-2.2.38' do
  impact 0.7
  title '2.2.38 Ensure the Shutdown the system is set to Administrators'
  desc 'Ensure the Shutdown the system is set to Administrators'

  tag cis: ['windows_2012r2:2.2.38']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeShutdownPrivilege') { should eq ['S-1-5-32-544'] }
  end  
end

# 2.2.39 - domain controller only

control 'cis-take-ownership-of-files-2.2.40' do
  impact 0.7
  title '2.2.40 Ensure Take ownership of files or other objects is set to Administrators'
  desc 'Ensure Take ownership of files or other objects is set to Administrators'

  tag cis: ['windows_2012r2:2.2.39']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('SeTakeOwnershipPrivilege') { should eq ['S-1-5-32-544'] }
  end
end