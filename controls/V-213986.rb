# encoding: UTF-8

control 'V-213986' do
  title "SQL Server must record time stamps in audit records and application
data that can be mapped to Coordinated Universal Time (UTC, formerly GMT)."
  desc  "If time stamps are not consistently applied and there is no common
time reference, it is difficult to perform forensic analysis.

    Time stamps generated by SQL Server must include date and time. Time is
commonly expressed in Coordinated Universal Time (UTC), a modern continuation
of Greenwich Mean Time (GMT), or local time with an offset from UTC.
  "
  desc  'rationale', ''
  desc  'check', "
    SQL Server audits store the timestamp in UTC time.

    Determine if the computer is joined to a domain.

    SELECT DEFAULT_DOMAIN()[DomainName]

    If this is not NULL, this is not a finding.

    If the computer is not joined to a domain, determine what the time source
is. (Run the following command in an elevated PowerShell session.)

         w32tm /query /source

    If the results of the command return \"Local CMOS Clock\" and is not
documented with justification and AO authorization, this is a finding.

    If the OS does not synchronize with a time server, review the procedure for
maintaining accurate time on the system.

    If such a procedure does not exist, this is a finding.

    If the procedure exists, review evidence that the correct time is actually
maintained.

    If the evidence indicates otherwise, this is a finding.
  "
  desc  'fix', "
    Where possible, configure the operating system to automatic synchronize
with an official time server, using NTP.

    Where there is reason not to implement automatic synchronization with an
official time server, using NTP, document the reason, and the procedure for
maintaining the correct time, and obtain AO approval. Enforce the procedure.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000374-DB-000322'
  tag gid: 'V-213986'
  tag rid: 'SV-213986r508026_rule'
  tag stig_id: 'SQL6-D0-011200'
  tag fix_id: 'F-15201r313742_fix'
  tag cci: ['V-79233', 'SV-93939', 'CCI-001890']
  tag nist: ['AU-8 b']
end
