control 'V-61467' do
  title "Application object owner accounts must be disabled when not performing
  installation or maintenance actions."
  desc "Object ownership provides all database object permissions to the owned
  object. Access to the application object owner accounts requires special
  protection to prevent unauthorized access and use of the object ownership
  privileges. In addition to the high privileges to application objects assigned
  to this account, it is also an account that, by definition, is not accessed
  interactively except for application installation and maintenance. This reduced
  access to the account means that unauthorized access to the account could go
  undetected. To help protect the account, it must be enabled only when access is
  required."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61467'
  tag "rid": 'SV-75957r4_rule'
  tag "stig_id": 'O121-BP-024000'
  tag "fix_id": 'F-67383r1_fix'
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

  select distinct o.owner from dba_objects o, dba_users u
   where o.owner not in
  (
   <list of non-applicable accounts>
  )
   and o.object_type <> 'SYNONYM'
   and o.owner = username
   and upper(account_status) not like '%LOCKED%';

  (With respect to the list of special accounts that are excluded from this
  requirement, it is expected that the DBA will maintain the list to suit local
  circumstances, adding special accounts as necessary and removing any that are
  not supposed to be in use in the Oracle deployment that is under review.)

  To obtain a list of users assigned DBA privileges, run the query:

    select grantee from dba_role_privs where granted_role = 'DBA';

  If any records are returned, then verify the account is an authorized
  application object owner account or a default account installed to support an
  Oracle product.

  Verify that any objects owned by custom DBA accounts are for the personal use
  of that DBA.

  If any objects are used to support applications or any functions other than DBA
  functions, this is a finding.

  Any unauthorized object owner accounts are not a finding under this check as
  they are noted as findings under check O121-C2-011000.

  Any other accounts listed are a finding."
  tag "fix": "Disable any application object owner accounts.

  From SQL*Plus:
    alter user [username] account lock;

  Enable application object owner accounts only for installation and maintenance.

  DBAs are special purpose accounts and do not require disabling although they
  may own objects.

  For application objects that require routine maintenance, e.g. index objects,
  to maintain performance, consider allowing a special purpose account to own the
  index or enable the application owner account for the duration of the routine
  maintenance function only."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  dba_users = sql.query("select grantee from dba_sys_privs
  where admin_option = 'YES' and grantee not in (select grantee from dba_role_privs where granted_role = 'DBA');").column('grantee').uniq
  if dba_users.empty?
    impact 0.0
    describe 'There are no oracle DBA users, control N/A' do
      skip 'There are no oracle DBA users, control N/A'
    end
  else
    dba_users.each do |user|
      describe "oracle DBA users: #{user}" do
        subject { user }
        it { should be_in input('allowed_dbadmin_users') }
      end
    end
  end

  unlocked_accounts = sql.query("select distinct o.owner from dba_objects o, dba_users u
  where
   o.object_type <> 'SYNONYM'
   and o.owner = username
   and upper(account_status) not like '%LOCKED%';").column('owner').uniq
  if unlocked_accounts.empty?
    impact 0.0
    describe 'There are no unlocked oracle accounts, control N/A' do
      skip 'There are no unlocked oracle accounts, control N/A'
    end
  else
    unlocked_accounts.each do |user|
      describe "oracle user: #{user}" do
        subject { user }
        it { should be_in input('allowed_unlocked_oracledb_accounts') }
      end
    end
  end
end
