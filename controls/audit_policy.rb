# encoding: utf-8

title 'Advanced Audit Policy'

control 'cis-audit-credential-validation-17.1.1' do
  impact 0.7
  title '17.1.1 Ensure Audit Credential Validation is set to Success and
  Failure'
  desc 'Ensure Audit Credential Validation is set to Success and
  Failure'
  
  tag cis: ['windows_2012r2:17.1.1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'

  describe audit_policy do
    its('Credential Validation') { should eq 'Success and Failure' }
  end
end

control 'cis-audit-application-group-management-17.2.1' do
    impact 0.7
    title '17.2.1 Ensure Audit Application Group Management is set to
    Success and Failure'
    desc 'Ensure Audit Application Group Management is set to
    Success and Failure'
    
    tag cis: ['windows_2012r2:17.2.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Application Group Management') { should eq 'Success and Failure' }
    end
  end

  control 'cis-audit-computer-account-management-17.2.2' do
    impact 0.7
    title '17.2.2 Ensure Audit Computer Account Management is set to
    Success and Failure'
    desc 'Ensure Audit Computer Account Management is set to
    Success and Failure'
    
    tag cis: ['windows_2012r2:17.2.2']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Computer Account Management') { should eq 'Success and Failure' }
    end
  end

  control 'cis-audit-other-account-management-events-17.2.4' do
    impact 0.7
    title '17.2.4 Ensure Audit Other Account Management Events is set to
    Success and Failure'
    desc 'Ensure Audit Other Account Management Events is set to
    Success and Failure'
    
    tag cis: ['windows_2012r2:17.2.4']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Other Account Management Events') { should eq 'Success and Failure' }
    end
  end

  control 'cis-audit-security-group-management-17.2.5' do
    impact 0.7
    title '17.2.5 Ensure Audit Security Group Management is set to
    Success and Failure'
    desc 'Ensure Audit Security Group Management is set to
    Success and Failure'
    
    tag cis: ['windows_2012r2:17.2.5']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Security Group Management') { should eq 'Success and Failure' }
    end
  end

  control 'cis-audit-user-account-management-17.2.6' do
    impact 0.7
    title '17.2.6 Ensure Audit User Account Management is set to
    Success and Failure'
    desc 'Ensure Audit User Account Management is set to
    Success and Failure'
    
    tag cis: ['windows_2012r2:17.2.6']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('User Account Management') { should eq 'Success and Failure' }
    end
  end

  control 'cis-audit-process-creation-17.3.1' do
    impact 0.7
    title '17.3.1 Ensure Audit Process Creation is set to
    Success'
    desc 'Ensure Audit Process Creation is set to
    Success'
    
    tag cis: ['windows_2012r2:17.3.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Process Creation') { should eq 'Success' }
    end
  end

  control 'cis-audit-account-lockout-17.5.1' do
    impact 0.7
    title '17.5.1 Ensure Audit Account Lockout is set to
    Success'
    desc 'Ensure Audit Account Lockout is set to
    Success'
    
    tag cis: ['windows_2012r2:17.5.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Account Lockout') { should eq 'Success' }
    end
  end

  control 'cis-audit-logoff-17.5.2' do
    impact 0.7
    title '17.5.2 Ensure Audit Logoff is set to
    Success'
    desc 'Ensure Audit Logoff is set to
    Success'
    
    tag cis: ['windows_2012r2:17.5.2']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Logoff') { should eq 'Success' }
    end
  end

  control 'cis-audit-logon-17.5.3' do
    impact 0.7
    title '17.5.3 Ensure Audit Logon is set to
    Success and Failure'
    desc 'Ensure Audit Logon is set to
    Success and Failure'
    
    tag cis: ['windows_2012r2:17.5.3']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Logon') { should eq 'Success and Failure' }
    end
  end

  control 'cis-audit-other-logon-logoff-17.5.4' do
    impact 0.7
    title '17.5.4 Ensure Audit Other Logon/Logoff Events is set to
    Success and Failure'
    desc 'Ensure Audit Other Logon/Logoff Events is set to
    Success and Failure'
    
    tag cis: ['windows_2012r2:17.5.4']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Other Logon/Logoff Events') { should eq 'Success and Failure' }
    end
  end

  control 'cis-audit-special-logon-17.5.5' do
    impact 0.7
    title '17.5.5 Ensure Audit Special Logon is set to
    Success'
    desc 'Ensure Audit Special Logon is set to
    Success'
    
    tag cis: ['windows_2012r2:17.5.5']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Special Logon') { should eq 'Success' }
    end
  end

  control 'cis-audit-removable-storage-17.6.1' do
    impact 0.7
    title '17.6.1 Ensure Audit Removable Storage is set to
    Success and Failure'
    desc 'Ensure Audit Removable Storage is set to
    Success and Failure'
    
    tag cis: ['windows_2012r2:17.6.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Removable Storage') { should eq 'Success and Failure' }
    end
  end

  control 'cis-audit-audit-policy-change-17.7.1' do
    impact 0.7
    title '17.7.1 Ensure Audit Policy Change is set to
    Success and Failure'
    desc 'Ensure Audit Policy Change is set to
    Success and Failure'
    
    tag cis: ['windows_2012r2:17.7.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Audit Policy Change') { should eq 'Success and Failure' }
    end
  end

  control 'cis-audit-audit-authentication-change-17.7.2' do
    impact 0.7
    title '17.7.2 Ensure Audit Authentication Policy Change is set to
    Success'
    desc 'Ensure Audit Authentication Policy Change is set to
    Success'
    
    tag cis: ['windows_2012r2:17.7.2']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Authentication Policy Change') { should eq 'Success' }
    end
  end

  control 'cis-audit-sensitive-privilege-use-17.8.1' do
    impact 0.7
    title '17.8.1 Ensure Audit Sensitive Privilege Use is set to
    Success and Failure'
    desc 'Ensure Audit Sensitive Privilege Use is set to
    Success and Failure'
    
    tag cis: ['windows_2012r2:17.8.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Sensitive Privilege Use') { should eq 'Success and Failure' }
    end
  end

  control 'cis-audit-ipsec-driver-17.9.1' do
    impact 0.7
    title '17.9.1 Ensure Audit IPsec Driver is set to
    Success and Failure'
    desc 'Ensure Audit IPsec Driver is set to
    Success and Failure'
    
    tag cis: ['windows_2012r2:17.9.1']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('IPsec Driver') { should eq 'Success and Failure' }
    end
  end

  control 'cis-audit-other-system-events-17.9.2' do
    impact 0.7
    title '17.9.2 Ensure Audit Other System Events is set to
    Success and Failure'
    desc 'Ensure Audit Other System Events is set to
    Success and Failure'
    
    tag cis: ['windows_2012r2:17.9.2']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Other System Events') { should eq 'Success and Failure' }
    end
  end

  control 'cis-audit-security-state-change-17.9.3' do
    impact 0.7
    title '17.9.3 Ensure Audit Security State Change is set to
    Success'
    desc 'Ensure Audit Security State Change is set to
    Success'
    
    tag cis: ['windows_2012r2:17.9.3']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Security State Change') { should eq 'Success' }
    end
  end

  control 'cis-audit-security-system-extension-17.9.4' do
    impact 0.7
    title '17.9.4 Ensure Audit Security System Extension is set to
    Success and Failure'
    desc 'Ensure Audit  Security System Extension is set to
    Success and Failure'
    
    tag cis: ['windows_2012r2:17.9.4']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('Security System Extension') { should eq 'Success and Failure' }
    end
  end

  control 'cis-audit-system-integrity-17.9.5' do
    impact 0.7
    title '17.9.5 Ensure Audit System Integrity is set to
    Success and Failure'
    desc 'Ensure Audit System Integrity is set to
    Success and Failure'
    
    tag cis: ['windows_2012r2:17.9.5']
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  
    describe audit_policy do
      its('System Integrity') { should eq 'Success and Failure' }
    end
  end