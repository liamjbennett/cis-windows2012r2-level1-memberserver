title 'Windows Firewall With Advanced Security'

control 'cis-domain-firewall-on-9.1.1' do
  impact 0.7
  title '9.1.1 Ensure Windows Firewall: Domain: Firewall state is set to On'
  desc 'Ensure Windows Firewall: Domain: Firewall state is set to On' 
  
  describe registry_key('DomainProfile', 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall') do
    its('EnableFirewall') { should eq 'On' }
  end
end