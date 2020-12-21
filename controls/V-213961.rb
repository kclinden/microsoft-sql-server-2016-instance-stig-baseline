# encoding: UTF-8

control 'V-213961' do
  title "SQL Server must be configured to prohibit or restrict the use of
organization-defined protocols as defined in the PPSM CAL and vulnerability
assessments."
  desc  "In order to prevent unauthorized connection of devices, unauthorized
transfer of information, or unauthorized tunneling (i.e., embedding of data
types within data types), organizations must disable or restrict unused or
unnecessary protocols on information systems.

    Applications are capable of providing a wide variety of functions and
services. Some of the functions and services provided by default may not be
necessary to support essential organizational operations. Additionally, it is
sometimes convenient to provide multiple services from a single component
(e.g., email and web services); however, doing so increases risk over limiting
the services provided by any one component.

    To support the requirements and principles of least functionality, the
application must support the organizational requirements providing only
essential capabilities and limiting the use of protocols to only those
required, authorized, and approved to conduct official business or to address
authorized quality of life issues.

    SQL Server using protocols deemed unsafe is open to attack through those
protocols. This can allow unauthorized access to the database and through the
database to other components of the information system.
  "
  desc  'rationale', ''
  desc  'check', "
    To determine the protocol(s) enabled for SQL Server, open SQL Server
Configuration Manager. In the left-hand pane, expand SQL Server Network
Configuration. Click on the entry for the SQL Server instance under review:
\"Protocols for \". The right-hand pane displays the protocols enabled for the
instance.

    If Named Pipes is enabled and not specifically required and authorized,
this is a finding.

    If any listed protocol is enabled but not authorized, this is a finding.
  "
  desc  'fix', "In SQL Server Configuration Manager >> SQL Server Network
Configuration >> Protocols, right-click on each listed protocol that is enabled
but not authorized and Select \"Disable\"."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag gid: 'V-213961'
  tag rid: 'SV-213961r508026_rule'
  tag stig_id: 'SQL6-D0-007600'
  tag fix_id: 'F-15176r313667_fix'
  tag cci: ['V-79185', 'SV-93891', 'CCI-000382']
  tag nist: ['CM-7 b']
end

