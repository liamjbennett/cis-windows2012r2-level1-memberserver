# encoding: utf-8

title 'Account Lockout Policy'

control 'cis-account-lockout-duration-1.2.1' do
  impact 0.7
  title '1.2.1 Set Account lockout duration to 15 or more minutes'
  desc 'Set Account lockout duration to 15 or more minutes'

  tag cis: ['windows_2012r2:1.2.1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('LockoutDuration') { should be >= 15 }
  end
end

control 'cis-account-lockout-threshold-1.2.2' do
  impact 0.7
  title '1.2.2 Set Account lockout threshold to 10 or fewer invalid logon attempts but not 0'
  desc 'Set Account lockout threshold to 10 or fewer invalid logon attempts but not 0'

  tag cis: ['windows_2012r2:1.2.2']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('LockoutBadCount') { should be <= 10 }
    its('LockoutBadCount') { should be > 0 }
  end
end

control 'cis-reset-account-lockout-1.2.3' do
  impact 0.7
  title '1.2.3 Set Reset account lockout counter after to 15 or more minutes'
  desc 'Set Reset account lockout counter after to 15 or more minutes'

  tag cis: ['windows_2012r2:1.2.3']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe security_policy do
    its('ResetLockoutCount') { should be >= 15 }
  end
end