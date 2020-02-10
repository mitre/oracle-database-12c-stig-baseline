control 'V-61439' do
  title 'Object permissions granted to PUBLIC must be restricted.'
  desc  "Permissions on objects may be granted to the user group PUBLIC.
  Because every database user is a member of the PUBLIC group, granting object
  permissions to PUBLIC gives all users in the database access to that object. In
  a secure environment, granting object permissions to PUBLIC must be restricted
  to those objects that all users are allowed to access. The policy does not
  require object permissions assigned to PUBLIC by the installation of Oracle
  Database server components be revoked."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61439'
  tag "rid": 'SV-75929r3_rule'
  tag "stig_id": 'O121-BP-022600'
  tag "fix_id": 'F-67355r2_fix'
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
  tag "check": "A default Oracle Database installation provides a set of
  predefined administrative accounts and non-administrative accounts. These are
  accounts that have special privileges required to administer areas of the
  database, such as the “CREATE ANY TABLE” or “ALTER SESSION” privilege, or
  “EXECUTE” privileges on packages owned by the SYS schema. The default
  tablespace for administrative accounts is either “SYSTEM” or “SYSAUX”.
  Non-administrative user accounts only have the minimum privileges needed to
  perform their jobs. Their default tablespace is “USERS”.

  To protect these accounts from unauthorized access, the installation process
  expires and locks most of these accounts, except where noted below. The
  database administrator is responsible for unlocking and resetting these
  accounts, as required.

  Non-Administrative Accounts - Expired and locked:
  APEX_PUBLIC_USER, DIP, FLOWS_040100*, FLOWS_FILES, MDDATA, ORACLE_OCM,
  SPATIAL_CSW_ADMIN_USR, SPATIAL_WFS_ADMIN_USR, XS$NULL

  Administrative Accounts - Expired and Locked:
  ANONYMOUS, CTXSTS, EXFSYS, LBACSYS, MDSYS, OLAPSYS, OEDDATA, OWBSYS,
  ORDPLUGINS, ORDSYS, OUTLN, SI_INFORMTN_SCHEMA, WK_TEST, WK_SYS, WKPROXY, WMSYS,
  XDB

  Administrative Accounts - Open:
  DBSNMP, MGMT_VIEW, SYS, SYSMAN, SYSTEM

  * Subject to change based on version installed

  Run the SQL query:

  select owner ||'.'|| table_name ||':'|| privilege from dba_tab_privs
  where grantee = 'PUBLIC';
  and owner not in
  (<list of non-applicable accounts>);

  (With respect to the list of special accounts that are excluded from this
  requirement, it is expected that the DBA will maintain the list to suit local
  circumstances, adding special accounts as necessary and removing any that are
  not supposed to be in use in the Oracle deployment that is under review.)

  If there are any records returned that are not Oracle product accounts, and are
  not documented and authorized, this is a finding.

  Note: This check may return false positives where other Oracle product accounts
  are not included in the exclusion list."
  tag "fix": "Revoke any privileges granted to PUBLIC for objects that are not
  owned by Oracle product accounts.

  From SQL*Plus:

  revoke [privilege name] from [user name] on [object name];

  Assign permissions to custom application user roles based on job functions:

  From SQL*Plus:

  grant [privilege name] to [user role] on [object name];"

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  users_with_public_access = sql.query("select DISTINCT owner from dba_tab_privs where grantee = 'PUBLIC';").column('owner').uniq

  if users_with_public_access.empty?
    impact 0.0
    describe 'There are no oracle users with access to PUBLIC, control N/A' do
      skip 'There are no oracle users with access to PUBLIC'
    end
  else
    users_with_public_access.each do |user|
      describe "oracle user: #{user} with access to PUBLIC" do
        subject { user }
        it { should be_in input('users_allowed_access_to_public')}
      end
    end
  end
end
