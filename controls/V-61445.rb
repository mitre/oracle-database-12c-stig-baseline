ALLOWED_USERS_DBA_ROLE = input('allowed_users_dba_role')

control 'V-61445' do
  title "Oracle application administration roles must be disabled if not
  required and authorized."
  desc "Application administration roles, which are assigned system or
  elevated application object privileges, must be protected from default
  activation. Application administration roles are determined by system privilege
  assignment (create / alter / drop user) and application user role ADMIN OPTION
  privileges."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61445'
  tag "rid": 'SV-75935r2_rule'
  tag "stig_id": 'O121-BP-022900'
  tag "fix_id": 'F-67361r1_fix'
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
  tag "check": "Run the SQL query:

  select grantee, granted_role from dba_role_privs
  where default_role='YES'
  and granted_role in
  (select grantee from dba_sys_privs where upper(privilege) like '%USER%')
  and grantee not in
  (<list of non-applicable accounts>)
  and grantee not in (select distinct owner from dba_tables)
  and grantee not in
  (select distinct username from dba_users where upper(account_status) like
   '%LOCKED%');

  (With respect to the list of special accounts that are excluded from this
  requirement, it is expected that the DBA will maintain the list to suit local
  circumstances, adding special accounts as necessary and removing any that are
  not supposed to be in use in the Oracle deployment that is under review.)

  Review the list of accounts reported for this check and ensures that they are
  authorized application administration roles.

  If any are not authorized application administration roles, this is a finding."
  tag "fix": "For each role assignment returned, issue:

  From SQL*Plus:

  alter user [username] default role all except [role];

  If the user has more than one application administration role assigned, then
  remove assigned roles from default assignment and assign individually the
  appropriate default roles."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  users_with_dba_role = sql.query("select grantee from dba_role_privs
  where default_role='YES'
  and granted_role in
  (select grantee from dba_sys_privs where upper(privilege) like '%USER%')
  and grantee not in (select distinct owner from dba_tables)
  and grantee not in
  (select distinct username from dba_users where upper(account_status) like
   '%LOCKED%');").column('grantee').uniq
  if users_with_dba_role.empty?
    impact 0.0
    describe 'There are no oracle users with the dba role, therefore control N/A' do
      skip 'There are no oracle users with the dba role, therefore control N/A'
    end
  else
    users_with_dba_role.each do |user|
      describe "oracle users with admin option: #{user}" do
        subject { user }
        it { should be_in input('allowed_users_dba_role') }
      end
    end
  end
end
