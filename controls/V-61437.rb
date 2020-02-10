control 'V-61437' do
  title "Oracle roles granted using the WITH ADMIN OPTION must not be granted
  to unauthorized accounts."
  desc "The WITH ADMIN OPTION allows the grantee to grant a role to another
  database account. Best security practice restricts the privilege of assigning
  privileges to authorized personnel. Authorized personnel include DBAs, object
  owners, and, where designed and included in the application's functions,
  application administrators. Restricting privilege-granting functions to
  authorized accounts can help decrease mismanagement of privileges and wrongful
  assignments to unauthorized accounts."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61437'
  tag "rid": 'SV-75927r3_rule'
  tag "stig_id": 'O121-BP-022500'
  tag "fix_id": 'F-67353r2_fix'
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
  database, such as the CREATE ANY TABLE or ALTER SESSION privilege, or EXECUTE
  privileges on packages owned by the SYS schema. The default tablespace for
  administrative accounts is either SYSTEM or SYSAUX. Non-administrative user
  accounts only have the minimum privileges needed to perform their jobs. Their
  default tablespace is USERS.

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

  Run the SQL statement:

    select grantee||': '||granted_role from dba_role_privs
    where admin_option = 'YES' and grantee not in
    (select distinct owner from dba_objects)
    and grantee not in
    (select grantee from dba_role_privs
     where granted_role = 'DBA')
    order by grantee;

  (With respect to the list of special accounts that are excluded from this
  requirement, it is expected that the DBA will maintain the list to suit local
  circumstances, adding special accounts as necessary and removing any that are
  not supposed to be in use in the Oracle deployment that is under review.)

  Review the System Security Plan to confirm any grantees listed are
  ISSO-authorized DBA accounts or application administration roles.

  If any grantees listed are not authorized and documented, this is a finding."
  tag "fix": "Revoke assignment of roles with the WITH ADMIN OPTION from
  unauthorized grantees and re-grant them without the option if required.

  SQL statements to remove the admin option from an unauthorized grantee:
    revoke <role name> from <grantee>;
    grant <role name> to <grantee>;

  Restrict use of the WITH ADMIN OPTION to authorized administrators.

  Document authorized role assignments with the WITH ADMIN OPTION in the System
  Security Plan."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  users_with_admin_option = sql.query("select grantee from dba_role_privs
    where admin_option = 'YES' and grantee not in
    (select distinct owner from dba_objects)
    and grantee not in
    (select grantee from dba_role_privs
     where granted_role = 'DBA')
    order by grantee;").column('grantee').uniq
  if users_with_admin_option.empty?
    impact 0.0
    describe 'There are no oracle users with the admin option, therefore control N/A' do
      skip 'There are no oracle users with the admin option, therefore control N/A'
    end
  else
    users_with_admin_option.each do |user|
      describe "oracle users with admin option: #{user}" do
        subject { user }
        it { should be_in input('allowed_dbadmin_users') }
      end
    end
  end
end
