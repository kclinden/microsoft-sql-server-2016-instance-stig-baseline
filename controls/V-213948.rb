# encoding: UTF-8

control 'V-213948' do
  title "SQL Server must protect its audit configuration from unauthorized
modification."
  desc  "Protecting audit data also includes identifying and protecting the
tools used to view and manipulate log data. Therefore, protecting audit tools
is necessary to prevent unauthorized operation on audit data.

    Applications providing tools to interface with audit data will leverage
user permissions and roles identifying the user accessing the tools and the
corresponding rights the user enjoys in order make access decisions regarding
the modification of audit tools.  SQL Server is an application that does
provide access to audit data.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.
  "
  desc  'rationale', ''
  desc  'check', "
    Check the server documentation for a list of approved users with access to
SQL Server Audits.

    To alter, or drop a server audit, principals require the ALTER ANY SERVER
AUDIT or the CONTROL SERVER permission.

    Review the SQL Server permissions granted to principals. Look for
permissions ALTER ANY SERVER AUDIT, ALTER ANY DATABASE AUDIT:

    SELECT login.name, perm.permission_name, perm.state_desc
    FROM sys.server_permissions perm
    JOIN sys.server_principals login
    ON perm.grantee_principal_id = login.principal_id
    WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT',
'ALTER ANY SERVER AUDIT')
    and login.name not like '##MS_%';

    If unauthorized accounts have these privileges, this is a finding.
  "
  desc  'fix', "
    Remove audit-related permissions from individuals and roles not authorized
to have them.

    USE master;
    DENY [ALTER ANY SERVER AUDIT] TO [User];
    GO
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000122-DB-000203'
  tag gid: 'V-213948'
  tag rid: 'SV-213948r508026_rule'
  tag stig_id: 'SQL6-D0-006300'
  tag fix_id: 'F-15163r313628_fix'
  tag cci: ['SV-93865', 'V-79159', 'CCI-001494']
  tag nist: ['AU-9']
end

