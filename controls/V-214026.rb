# encoding: UTF-8

control 'V-214026' do
  title 'SQL Server must configure Customer Feedback and Error Reporting.'
  desc  "By default, Microsoft SQL Server enables participation in the customer
experience improvement program (CEIP). This program collects information about
how its customers are using the product. Specifically, SQL Server collects
information about the installation experience, feature usage, and performance.
This information helps Microsoft improve the product to better meet customer
needs."
  desc  'rationale', ''
  desc  'check', "
    Launch \"Registry Editor\"

    Navigate to HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft SQL
Server\\[InstanceId]\\CPE
    Review the following values:  CustomerFeedback, EnableErrorReporting

    Navigate to HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft SQL
Server\\130
    Review the following values:  CustomerFeedback, EnableErrorReporting

    If this is a classified system, and any of the above values are not zero
(0), this is a finding.

    If this is an unclassified system, review the server documentation to
determine whether CEIP participation is authorized.

    If CEIP participation is not authorized, and any of the above values are
one (1), this is a finding.
  "
  desc  'fix', "
    To disable participation in the CEIP program, change the value of the
following registry keys to zero (0).

    To enable participation in the CEIP program, change the value of the
following registry keys to one (1).

    HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft SQL
Server\\[InstanceId]\\CPE\\CustomerFeedback
    HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft SQL
Server\\[InstanceId]\\CPE\\EnableErrorReporting
    HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft SQL
Server\\130\\CustomerFeedback
    HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft SQL
Server\\130\\EnableErrorReporting
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-214026'
  tag rid: 'SV-214026r508026_rule'
  tag stig_id: 'SQL6-D0-016000'
  tag fix_id: 'F-15241r313862_fix'
  tag cci: ['V-79313', 'SV-94019', 'CCI-000366']
  tag nist: ['CM-6 b']
end

