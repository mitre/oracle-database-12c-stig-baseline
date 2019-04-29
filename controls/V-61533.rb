control 'V-61533' do
  title "Remote administration must be disabled for the Oracle connection
  manager."
  desc  "Remote administration provides a potential opportunity for malicious
  users to make unauthorized changes to the Connection Manager configuration or
  interrupt its service."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61533'
  tag "rid": 'SV-76023r1_rule'
  tag "stig_id": 'O121-BP-026500'
  tag "fix_id": 'F-67449r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
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
  tag "check": "View the cman.ora file in the ORACLE_HOME/network/admin
  directory.

  If the file does not exist, the database is not accessed via Oracle Connection
  Manager and this check is not a finding.

  If the entry and value for REMOTE_ADMIN is not listed or is not set to a value
  of NO (REMOTE_ADMIN = NO), this is a finding."
  tag "fix": "View the cman.ora file in the ORACLE_HOME/network/admin directory
  of the Connection Manager.

  Include the following line in the file:

  REMOTE_ADMIN = NO"
  oracle_home = command('echo $ORACLE_HOME').stdout.strip

  describe file "#{oracle_home}/network/admin/cman.ora" do
    its('content') { should include 'REMOTE_ADMIN = NO' }
    it { should exist }
  end
end
