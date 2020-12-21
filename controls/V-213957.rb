# encoding: UTF-8

control 'V-213957' do
  title "Access to xp_cmdshell must be disabled, unless specifically required
and approved."
  desc  "Information systems are capable of providing a wide variety of
functions and services. Some of the functions and services, provided by
default, may not be necessary to support essential organizational operations
(e.g., key missions, functions).

    It is detrimental for applications to provide, or install by default,
functionality exceeding requirements or mission objectives.

    Applications must adhere to the principles of least functionality by
providing only essential capabilities.

    SQL Server may spawn additional external processes to execute procedures
that are defined in the SQL Server but stored in external host files (external
procedures). The spawned process used to execute the external procedure may
operate within a different OS security context than SQL Server and provide
unauthorized access to the host system.

    The xp_cmdshell extended stored procedure allows execution of host
executables outside the controls of database access permissions. This access
may be exploited by malicious users who have compromised the integrity of the
SQL Server database process to control the host operating system to perpetrate
additional malicious activity.
  "
  desc  'rationale', ''
  desc  'check', "
    The xp_cmdshell extended stored procedure allows execution of host
executables outside the controls of database access permissions. This access
may be exploited by malicious users who have compromised the integrity of the
SQL Server database process to control the host operating system to perpetrate
additional malicious activity.

    To determine if xp_cmdshell is enabled, execute the following commands:

    EXEC SP_CONFIGURE 'show advanced options', '1';
    RECONFIGURE WITH OVERRIDE;
    EXEC SP_CONFIGURE 'xp_cmdshell';

    If the value of \"config_value\" is \"0\", this is not a finding.

    Review the system documentation to determine whether the use of
\"xp_cmdshell\" is required and approved. If it is not approved, this is a
finding.
  "
  desc  'fix', "
    Disable use of or remove any external application executable object
definitions that are not authorized.

    To disable the use of xp_cmdshell, from the query prompt: 

    EXEC sp_configure 'show advanced options', 1; 
    GO 
    RECONFIGURE; 
    GO 
    EXEC sp_configure 'xp_cmdshell', 0; 
    GO 
    RECONFIGURE; 
    GO??
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag gid: 'V-213957'
  tag rid: 'SV-213957r508026_rule'
  tag stig_id: 'SQL6-D0-007200'
  tag fix_id: 'F-15172r313655_fix'
  tag cci: ['SV-93883', 'V-79177', 'CCI-000381']
  tag nist: ['CM-7 a']
end

