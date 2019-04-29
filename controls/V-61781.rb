control 'V-61781' do
  title "The DBMS must prevent unauthorized and unintended information transfer
  via shared system resources."
  desc "The purpose of this control is to prevent information, including
  encrypted representations of information, produced by the actions of a prior
  user/role (or the actions of a process acting on behalf of a prior user/role)
  from being available to any current user/role (or current process) that obtains
  access to a shared system resource (e.g., registers, main memory, secondary
  storage) after the resource has been released back to the information system.
  Control of information in shared resources is also referred to as object reuse.

      Data used for the development and testing of applications often involves
  copying data from production.  It is important that specific procedures exist
  for this process, so copies of sensitive data are not misplaced or left in a
  temporary location without the proper controls.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000243-DB-000128'
  tag "gid": 'V-61781'
  tag "rid": 'SV-76271r1_rule'
  tag "stig_id": 'O121-C2-018900'
  tag "fix_id": 'F-67697r1_fix'
  tag "cci": ['CCI-001090']
  tag "nist": ['SC-4', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Verify there are proper procedures in place for the refreshing
  of development/test data from production.  Review any scripts or code that
  exists for the movement of production data to development/test, and verify
  copies of production data are not left in unprotected locations.

  If there is no documented procedure for data movement from production to
  development/test, this is a finding.

  If the code that exists for data movement does not remove any copies of
  production data from unprotected locations, this is a finding."
  tag "fix": "Create and document a process for moving data from production to
  development/test systems, and follow the process.

  Modify any code used for moving data from production to development/test
  systems to ensure copies of production data are not left in nonsecured
  locations.

  Moving data is only a part of the challenge of protecting the data.  When the
  data is moved, it should also be changed so sensitive information is not made
  available in development environments.

  With the Oracle Data Masking Pack for Oracle Enterprise Manager, organizations
  can comply with data privacy and protection mandates that restrict the use of
  actual customer data. With Oracle Data Masking Pack, sensitive information,
  such as credit card or social security numbers, can be replaced with realistic
  values, allowing production data to be safely used for development, testing, or
  sharing with out-source or off-shore partners for other nonproduction purposes.
   When used in conjunction with Oracle Enterprise Manager, it is easy to develop
  a secure process that is capable of obfuscating the data during the movement
  process.

  If the Oracle Data Masking Pack and Enterprise Manager are not available,
  develop site-specific procedures to manage and obfuscate sensitive data."
  describe 'A manual review is required to ensure the DBMS prevents unauthorized and unintended information transfer
    via shared system resources' do
    skip 'A manual review is required to ensure the DBMS prevents unauthorized and unintended information transfer
    via shared system resources'
  end
end
