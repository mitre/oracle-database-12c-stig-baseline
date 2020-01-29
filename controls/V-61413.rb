control 'V-61413' do
  title 'Oracle instance names must not contain Oracle version numbers.'
  desc  "Service names may be discovered by unauthenticated users. If the
  service name includes version numbers or other database product information, a
  malicious user may use that information to develop a targeted attack."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61413'
  tag "rid": 'SV-75903r1_rule'
  tag "stig_id": 'O121-BP-021300'
  tag "fix_id": 'F-67329r1_fix'
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
  tag "check": "From SQL*Plus:

  select instance_name from v$instance;
  select version from v$instance;

  If the instance name returned references the Oracle release number, this is a
  finding.

  Numbers used that include version numbers by coincidence are not a finding.

  The DBA should be able to relate the significance of the presence of a digit in
  the SID."
  tag "fix": "Follow the instructions in Oracle MetaLink Note 15390.1 (and
  related documents) to change the SID for the database without re-creating the
  database to a value that does not identify the Oracle version."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  version = sql.query('select version from v$instance;').column('version')
  db_instance_name = sql.query('select instance_name from v$instance;').column('instance_name')

  describe 'The oracle database instance name' do
    subject { db_instance_name }
    it { should_not include version.to_s }
  end

end
