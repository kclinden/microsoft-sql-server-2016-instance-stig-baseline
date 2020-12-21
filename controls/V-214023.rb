# encoding: UTF-8

control 'V-214023' do
  title "SQL Server must implement NIST FIPS 140-2 validated cryptographic
modules to generate and validate cryptographic hashes."
  desc  "Use of weak or untested encryption algorithms undermines the purposes
of utilizing encryption to protect data. The application must implement
cryptographic modules adhering to the higher standards approved by the federal
government since this provides assurance they have been tested and validated.

    For detailed information, refer to NIST FIPS Publication 140-2, Security
Requirements For Cryptographic Modules. Note that the product's cryptographic
modules must be validated and certified by NIST as FIPS-compliant.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that Windows is configured to require the use of FIPS 140-2
algorithms.

    Click Start >> Type \"Local Security Policy\" >> Press Enter >> Expand
\"Local Policies\" >> Select \"Security Options\" >> Locate \"System
Cryptography:  Use FIPS compliant algorithms for encryption, hashing, and
signing.\"

    If  \"System Cryptography:  Use FIPS compliant algorithms for encryption,
hashing, and signing\" is not enabled, this is a finding.
  "
  desc  'fix', "
    Configure Windows to require the use of FIPS compliant algorithms.

    Click Start >> Type \"Local Security Policy\" >> Press Enter >> Expand
\"Local Policies\" >> Select \"Security Options\" >> Locate \"System
Cryptography:  Use FIPS compliant algorithms for encryption, hashing, and
signing.\" >> Change the Setting option to \"Enabled\" >> Restart Windows
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000514-DB-000382'
  tag gid: 'V-214023'
  tag rid: 'SV-214023r508026_rule'
  tag stig_id: 'SQL6-D0-015700'
  tag fix_id: 'F-15238r313853_fix'
  tag cci: ['SV-94013', 'V-79307', 'CCI-002450']
  tag nist: ['SC-13']
end

