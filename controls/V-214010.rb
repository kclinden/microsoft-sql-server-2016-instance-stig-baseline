# encoding: UTF-8

control 'V-214010' do
  title "SQL Server must generate audit records when unsuccessful attempts to
delete security objects occur."
  desc  "The removal of security objects from the database/DBMS would seriously
degrade a system's information assurance posture. If such an action is
attempted, it must be logged.

    To aid in diagnosis, it is necessary to keep track of failed attempts in
addition to the successful ones.
  "
  desc  'rationale', ''
  desc  'check', "
    Determine if an audit is configured and started by executing the following
query.

    SELECT name AS 'Audit Name',
    status_desc AS 'Audit Status',
    audit_file_path AS 'Current Audit File'
    FROM sys.dm_server_audit_status

    If no records are returned, this is a finding.

    Execute the following query to verify the \"SCHEMA_OBJECT_CHANGE_GROUP\" is
included in the server audit specification.

    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id
= d.server_specification_id
    WHERE a.is_state_enabled = 1 AND d.audit_action_name =
'SCHEMA_OBJECT_CHANGE_GROUP'

    If the \"SCHEMA_OBJECT_CHANGE_GROUP\" is not returned in an active audit,
this is a finding.
  "
  desc  'fix', "
    Add the \"SCHEMA_OBJECT_CHANGE_GROUP\" to the server audit specification
    USE [master];
    GO

    ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH
(STATE = OFF);
    GO

    ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD
(SCHEMA_OBJECT_CHANGE_GROUP);
    GO

    ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH
(STATE = ON);
    GO

    See the supplemental script \"SQL 2016 Audit.sql\" for complete script.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000501-DB-000337'
  tag gid: 'V-214010'
  tag rid: 'SV-214010r508026_rule'
  tag stig_id: 'SQL6-D0-014400'
  tag fix_id: 'F-15225r313814_fix'
  tag cci: ['SV-93987', 'V-79281', 'CCI-000172']
  tag nist: ['AU-12 c']
end

