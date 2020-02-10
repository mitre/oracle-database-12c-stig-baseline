control 'V-61435' do
  title 'System Privileges must not be granted to PUBLIC.'
  desc  "System privileges can be granted to users and roles and to the user
  group PUBLIC. All privileges granted to PUBLIC are accessible to every user in
  the database. Many of these privileges convey considerable authority over the
  database and should be granted only to those persons responsible for
  administering the database. In general, these privileges should be granted to
  roles and then the appropriate roles should be granted to users. System
  privileges must never be granted to PUBLIC as this could allow users to
  compromise the database."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61435'
  tag "rid": 'SV-75925r1_rule'
  tag "stig_id": 'O121-BP-022400'
  tag "fix_id": 'F-67351r1_fix'
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

  select privilege from dba_sys_privs where grantee = 'PUBLIC';

  If any records are returned, this is a finding."
  tag "fix": "Revoke any system privileges assigned to PUBLIC:

  From SQL*Plus:

  revoke [system privilege] from PUBLIC;

  Replace [system privilege] with the named system privilege.

  Note:  System privileges are not granted to PUBLIC by default and would
  indicate a custom action."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  describe sql.query("select privilege from dba_sys_privs where grantee = 'PUBLIC';").row(0).column('privilege') do
    its('value') { should be_empty }
  end
end
