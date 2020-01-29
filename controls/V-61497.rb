control 'V-61497' do
  title 'The ISSM must review changes to DBA role assignments.'
  desc  "Unauthorized assignment of DBA privileges can lead to a compromise of
  DBMS integrity. Providing oversight to the authorization and assignment of
  privileges provides the separation of duty to support sufficient oversight."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61497'
  tag "rid": 'SV-75987r1_rule'
  tag "stig_id": 'O121-BP-024600'
  tag "fix_id": 'F-67413r1_fix'
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
  tag "check": "Review policy and procedures documented or noted in the System
  Security Plan as well as evidence of implementation for monitoring changes to
  DBA role assignments and procedures for notifying the ISSM of the changes for
  review.

  If policy, procedures or implementation evidence do not exist, this is a
  finding."
  tag "fix": "Develop, document and implement procedures to monitor changes to
  DBA role assignments.

  Develop, document and implement procedures to notify the ISSM of changes to DBA
  role assignments.

  Include in the procedures methods that provide evidence of monitoring and
  notification."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  database_roles = sql.query('select * from dba_roles;').column('role')

  describe "A manual review is required to ensure the ISSM reviews changes to DBA role assignments. The database roles to review are: #{database_roles}" do
    skip "A manual review is required to ensure the ISSM reviews changes to DBA role assignments. The database roles to review are: #{database_roles}"
  end
end
