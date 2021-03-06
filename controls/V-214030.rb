# encoding: UTF-8

control 'V-214030' do
  title "Execution of startup stored procedures must be restricted to necessary
cases only."
  desc  "In certain situations, to provide required functionality, a DBMS needs
to execute internal logic (stored procedures, functions, triggers, etc.) and/or
external code modules with elevated privileges. However, if the privileges
required for execution are at a higher level than the privileges assigned to
organizational users invoking the functionality applications/programs, those
users are indirectly provided with greater privileges than assigned by
organizations.

    When 'Scan for startup procs' is enabled, SQL Server scans for and runs all
automatically run stored procedures defined on the server.  The execution of
start-up stored procedures will be done under a high privileged context,
therefore it is a commonly used post-exploitation vector.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the system documentation to obtain a listing of documented stored
procedures used by SQL Server during start up. Execute the following query:

    Select [name] as StoredProc
    From sys.procedures
    Where OBJECTPROPERTY(OBJECT_ID, 'ExecIsStartup') = 1

    If any stored procedures are returned that are not documented, this is a
finding.
  "
  desc  'fix', "
    To disable start up stored procedure(s), run the following in Master for
each undocumented procedure:

    sp_procoption @procname = '<procedure name>', @OptionName = 'Startup',
@optionValue = 'Off'
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000342-DB-000302'
  tag gid: 'V-214030'
  tag rid: 'SV-214030r508026_rule'
  tag stig_id: 'SQL6-D0-016400'
  tag fix_id: 'F-15245r313874_fix'
  tag cci: ['V-79321', 'SV-94027', 'CCI-002233']
  tag nist: ['AC-6 (8)']
end

