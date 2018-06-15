# Inspec profile for CIS Windows 2012 Level 1 Member Servers

## Standalone Usage

This Compliance Profile requires [InSpec](https://github.com/chef/inspec) for execution:

```
$ git clone https://github.com/liamjbennett/cis-windows2012r2-level1-memberserver
$ inspec exec cis-windows2012r2-level1-memberserver
```

You can also execute the profile directly from Github:

```
$ inspec exec https://github.com/liamjbennett/cis-windows2012r2-level1-memberserver

# run test on remote windows host on WinRM
$ inspec exec test.rb -t winrm://Administrator@windowshost --password 'your-password'
```

## Notes/corrections to CIS document

### 19.1.3

```
HKEY_USERS\<SID>\Software\Policies\Microsoft\Windows\Control
Panel\Desktop\ScreenSaveActive
```
is actually located at:
```
HKEY_USERS\<SID>\Control Panel\Desktop\

