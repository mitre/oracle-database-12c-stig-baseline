control 'V-61421' do
  title "The Oracle WITH GRANT OPTION privilege must not be granted to non-DBA
  or non-Application administrator user accounts."
  desc "An account permission to grant privileges within the database is an
  administrative function. Minimizing the number and privileges of administrative
  accounts reduces the chances of privileged account exploitation. Application
  user accounts must never require WITH GRANT OPTION privileges since, by
  definition, they require only privileges to execute procedures or view / edit
  data."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61421'
  tag "rid": 'SV-75911r2_rule'
  tag "stig_id": 'O121-BP-021700'
  tag "fix_id": 'F-67337r1_fix'
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
  tag "check": "Execute the query:

  select grantee||': '||owner||'.'||table_name
  from dba_tab_privs
  where grantable = 'YES'
  and grantee not in (select distinct owner from dba_objects)
  and grantee not in (select grantee from dba_role_privs where granted_role =
  'DBA')
  order by grantee;

  If any accounts are listed, this is a finding."
  tag "fix": "Revoke privileges granted the WITH GRANT OPTION from non-DBA and
  accounts that do not own application objects.

  Re-grant privileges without specifying WITH GRANT OPTION."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  describe sql.query("select grantee||': '||owner||'.'||table_name
  from dba_tab_privs
  where grantable = 'YES'
  and grantee not in (select distinct owner from dba_objects)
  and grantee not in (select grantee from dba_role_privs where granted_role =
  'DBA')
  order by grantee;").row(0).column("grantee||': '||owner||'.'||table_name") do
    its('value') { should be_empty }
  end
end
