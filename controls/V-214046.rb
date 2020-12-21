# encoding: UTF-8

control 'V-214046' do
  title "Applications must obscure feedback of authentication information
during the authentication process to protect the information from possible
exploitation/use by unauthorized individuals."
  desc  "To prevent the compromise of authentication information, such as
passwords and PINs, during the authentication process, the feedback from the
information system must not provide any information that would allow an
unauthorized user to compromise the authentication mechanism.

    Obfuscation of user-provided information when typed into the system is a
method used in addressing this risk.

    For example, displaying asterisks when a user types in a password or PIN,
is an example of obscuring feedback of authentication information.

    Database applications may allow for entry of the account name and password
as a visible parameter of the application execution command. This practice must
be prohibited and disabled to prevent shoulder surfing.
  "
  desc  'rationale', ''
  desc  'check', "
    Determine whether any applications that access the database allow for entry
of the account name and password, or PIN.

    If any do, determine whether these applications obfuscate authentication
data; if they do not, this is a finding.
  "
  desc  'fix', "Configure or modify applications to prohibit display of
passwords in clear text."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000178-DB-000083'
  tag gid: 'V-214046'
  tag rid: 'SV-214046r508026_rule'
  tag stig_id: 'SQL6-D0-018200'
  tag fix_id: 'F-15261r313922_fix'
  tag cci: ['V-79357', 'SV-94063', 'CCI-000206']
  tag nist: ['IA-6']
end

