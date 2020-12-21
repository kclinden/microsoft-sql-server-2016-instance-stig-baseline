# encoding: UTF-8

control 'V-213955' do
  title "Unused database components, DBMS software, and database objects must
be removed."
  desc  "Information systems are capable of providing a wide variety of
functions and services. Some of the functions and services, provided by
default, may not be necessary to support essential organizational operations
(e.g., key missions, functions).

    It is detrimental for software products to provide, or install by default,
functionality exceeding requirements or mission objectives.

    DBMSs must adhere to the principles of least functionality by providing
only essential capabilities.
  "
  desc  'rationale', ''
  desc  'check', "
    From the server documentation, obtain a listing of required components.

    Generate a listing of components installed on the server.

    Click Start >> Type \"SQL Server 2016 Installation Center\" >> Launch the
program >> Click Tools >> Click \"Installed SQL Server features discovery
report\"

    Compare the feature listing against the required components listing.

    If any features are installed, but are not required, this is a finding.
  "
  desc  'fix', 'Remove all features that are not required.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag gid: 'V-213955'
  tag rid: 'SV-213955r508026_rule'
  tag stig_id: 'SQL6-D0-007000'
  tag fix_id: 'F-15170r313649_fix'
  tag cci: ['V-79173', 'SV-93879', 'CCI-000381']
  tag nist: ['CM-7 a']
end

