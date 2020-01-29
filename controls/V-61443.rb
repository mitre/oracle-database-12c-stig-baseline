control 'V-61443' do
  title "Application role permissions must not be assigned to the Oracle PUBLIC
  role."
  desc "Permissions granted to PUBLIC are granted to all users of the
  database. Custom roles must be used to assign application permissions to
  functional groups of application users. The installation of Oracle does not
  assign role permissions to PUBLIC."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61443'
  tag "rid": 'SV-75933r1_rule'
  tag "stig_id": 'O121-BP-022800'
  tag "fix_id": 'F-67359r1_fix'
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

  select granted_role from dba_role_privs where grantee = 'PUBLIC';

  If any roles are listed, this is a finding."
  tag "fix": "Revoke role grants from PUBLIC.

  Do not assign role privileges to PUBLIC.

  From SQL*Plus:

  revoke [role name] from PUBLIC;"

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  describe sql.query("select granted_role from dba_role_privs where grantee = 'PUBLIC';").row(0).column('granted_role') do
    its('value') { should be_empty }
  end
end
