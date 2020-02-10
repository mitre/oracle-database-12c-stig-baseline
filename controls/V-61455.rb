control 'V-61455' do
  title "Application user privilege assignment must be reviewed monthly or more
  frequently to ensure compliance with least privilege and documented policy."
  desc "Users granted privileges not required to perform their assigned
  functions are able to make unauthorized modifications to the production data or
  database. Monthly or more frequent periodic review of privilege assignments
  assures that organizational and/or functional changes are reflected
  appropriately."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61455'
  tag "rid": 'SV-75945r1_rule'
  tag "stig_id": 'O121-BP-023400'
  tag "fix_id": 'F-67371r1_fix'
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
  tag "check": "Review policy, procedures and implementation evidence to
  determine if periodic reviews of user privileges by the ISSO are being
  performed.

  Evidence may consist of email or other correspondence that acknowledges receipt
  of periodic reports and notification of review between the DBA and ISSO or
  other auditors as assigned.

  If policy and procedures are incomplete or no evidence of implementation
  exists, this is a finding."
  tag "fix": "Develop, document and implement policy and procedures for
  periodic review of database user accounts and privilege assignments.

  Include methods to provide evidence of review in the procedures to verify
  reviews occur in accordance with the procedures."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  database_roles = sql.query('select * from dba_roles;').column('role')

  describe "A manual review is required to ensure application user privilege assignment are reviewed monthly or more frequently to ensure compliance with least privilege and documented policy. The database roles to review are: #{database_roles}" do
    skip "A manual review is required to ensure application user privilege assignment are reviewed monthly or more frequently to ensure compliance with least privilege and documented policy. The database roles to review are: #{database_roles}"
  end
end
