control 'V-61575' do
  title "The DBMS must enforce approved authorizations for logical access to
  the system in accordance with applicable policy."
  desc "Strong access controls are critical to securing application data.
  Access control policies (e.g., identity-based policies, role-based policies,
  attribute-based policies) and access enforcement mechanisms (e.g., access
  control lists, access control matrices, cryptography) must be employed by
  applications, when applicable, to control access between users (or processes
  acting on behalf of users) and objects (e.g., devices, files, records,
  processes, programs, domains) in the information system.

      Consideration should be given to the implementation of an audited, explicit
  override of automated mechanisms in the event of emergencies or other serious
  events.

      If the DBMS does not follow applicable policy when approving access it may
  be in conflict with networks or other applications in the information system.
  This may result in users either gaining or being denied access inappropriately
  and may be in conflict with applicable policy.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000033-DB-000084'
  tag "gid": 'V-61575'
  tag "rid": 'SV-76065r1_rule'
  tag "stig_id": 'O121-C2-002700'
  tag "fix_id": 'F-67491r1_fix'
  tag "cci": ['CCI-000213']
  tag "nist": ['AC-3', 'Rev_4']
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
  tag "check": "Check DBMS settings to determine whether users are restricted
  from accessing objects and data they are not authorized to access. If
  appropriate access controls are not implemented to restrict access to
  authorized users and to restrict the access of those users to objects and data
  they are authorized to see, this is a finding.

  The easiest way to isolate access is by using the Oracle Database Vault.  To
  check to see if the Oracle Database Vault is installed, issue the following
  query:

  SQL> SELECT * FROM V$OPTION WHERE PARAMETER = 'Oracle Database Vault';

  If Oracle Database Vault is installed, review its settings for appropriateness
  and completeness of the access it permits and denies to each type of user.  If
  appropriate and complete, this is not a finding.

  If Oracle Database Vault is not installed, review the roles and profiles in the
  database and the assignment of users to these for appropriateness and
  completeness of the access permitted and denied each type of user. If
  appropriate and complete, this is not a finding.

  If the access permitted and denied each type of user is inappropriate or
  incomplete, this is a finding.

  Following are code examples for reviewing roles, profiles, etc.

  Find out what role the users have:
  select * from dba_role_privs where granted_role = '<role>'

  List all roles given to a user:
  select * from dba_role_privs where grantee = '<username>';

  List all roles for all users:
    column grantee format a32
    column granted_role format a32
    break on grantee
    select grantee, granted_role from dba_role_privs;

  Use the following query to list all privileges given to a user:
          select
            lpad(' ', 2*level) || granted_role \"User roles and privileges\"
          from
            (
            /* THE USERS */
              select
                null     grantee,
                username granted_role
              from
                dba_users
              where
                username like upper('<enter_username>')
            /* THE ROLES TO ROLES RELATIONS */
            union
              select
                grantee,
                granted_role
              from
                dba_role_privs
            /* THE ROLES TO PRIVILEGE RELATIONS */
            union
              select
                grantee,
                privilege
              from
                dba_sys_privs
            )
          start with grantee is null
          connect by grantee = prior granted_role;

  List which tables a certain role gives SELECT access to using the query:
  select * from role_tab_privs where role='<role>' and privilege = 'SELECT';

  List all tables a user can SELECT from using the query:
  select * from dba_tab_privs where GRANTEE ='<username>' and privilege =
  'SELECT';

  List all users who can SELECT on a particular table (either through being given
  a relevant role or through a direct grant - e.g., grant select on a table to
  Joe). The result of this query should also show through which role the user has
  this access or whether it was a direct grant.

          select
            Grantee,'Granted Through Role' as Grant_Type,
            role,
            table_name
          from role_tab_privs rtp, dba_role_privs drp
          where rtp.role = drp.granted_role
          and table_name = '<TABLENAME>'
          union
          select
             Grantee,
             'Direct Grant' as Grant_type,
             null as role,
             table_name
          from dba_tab_privs
          where table_name = '<TABLENAME>';"
  tag "fix": "If Oracle Database Vault is in use, use it to configure the
  correct access privileges for each type of user.

  If Oracle Database Vault is not in use, configure the correct access privileges
  for each type of user using Roles and Profiles.

  For more information on the configuration of Database Vault, refer to the
  following documents:
  Database Vault Administrator's  Guide:
  https://docs.oracle.com/database/121/DVADM/toc.htm"
  describe 'A manual review is required to ensure the DBMS enforces approved authorizations for logical access to
    the system in accordance with applicable policy' do
    skip 'A manual review is required to ensure the DBMS enforces approved authorizations for logical access to
    the system in accordance with applicable policy'
  end
end
