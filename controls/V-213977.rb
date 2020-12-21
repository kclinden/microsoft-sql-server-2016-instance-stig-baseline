# encoding: UTF-8

control 'V-213977' do
  title "Access to database files must be limited to relevant processes and to
authorized, administrative users."
  desc  "SQL Server must prevent unauthorized and unintended information
transfer via shared system resources. Permitting only SQL Server processes and
authorized, administrative users to have access to the files where the database
resides helps ensure that those files are not shared inappropriately and are
not open to backdoor access and manipulation."
  desc  'rationale', ''
  desc  'check', "
    Review the permissions granted to users by the operating system/file system
on the database files, database log files, and database backup files.

    To obtain the location of SQL Server data, transaction log, and backup
files, open and execute the supplemental file \"Get SQL Data and Backup
Directories.sql\".

    For each of the directories returned by the above script, verify whether
the correct permissions have been applied.

    1) Launch Windows Explorer.
    2) Navigate to the folder.
    3) Right-click the folder and click \"Properties\".
    4) Navigate to the \"Security\" tab.
    5) Review the listing of principals and permissions.

    Account Type\t\t\tDirectory Type\t\tPermission

-----------------------------------------------------------------------------------------------
    Database Administrators      \tALL                   \t\tFull Control
    SQL Server Service SID       \tData; Log; Backup;    \tFull Control
    SQL Server Agent Service SID \tBackup                \tFull Control
    SYSTEM                       \t\tALL                   \t\tFull Control
    CREATOR OWNER                \tALL                   \t\tFull Control

    For information on how to determine a \"Service SID\", go to:
    https://aka.ms/sql-service-sids

    Additional permission requirements, including full directory permissions
and operating system rights for SQL Server, are documented at:
    https://aka.ms/sqlservicepermissions

    If any additional permissions are granted but not documented as authorized,
this is a finding.
  "
  desc  'fix', "
    Remove any unauthorized permission grants from SQL Server data, log, and
backup directories.

    1) On the \"Security\" tab, highlight the user entry.
    2) Click \"Remove\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000243-DB-000374'
  tag gid: 'V-213977'
  tag rid: 'SV-213977r508026_rule'
  tag stig_id: 'SQL6-D0-010000'
  tag fix_id: 'F-15192r313715_fix'
  tag cci: ['SV-93921', 'V-79215', 'CCI-001090']
  tag nist: ['SC-4']
end

