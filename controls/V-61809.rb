control 'V-61809' do
  title "The DBMS must implement separation of duties through assigned
    information access authorizations."
  desc  "Separation of duties is a prevalent Information Technology control
    that is implemented at different layers of the information system, including
    the operating system and in applications. It serves to eliminate or reduce the
    possibility that a single user may carry out a prohibited action. Separation of
    duties requires that the person accountable for approving an action is not the
    same person who is tasked with implementing or carrying out that action.

        Additionally, the person or entity accountable for monitoring the activity
    must be separate as well. To meet this requirement, applications, when
    applicable, shall be divided where functionality is based on roles and duties.
    Examples of separation of duties include: (i) mission functions and distinct
    information system support functions are divided among different
    individuals/roles; (ii) different individuals perform information system
    support functions (e.g., system management, systems programming, configuration
    management, quality assurance and testing, network security); (iii) security
    personnel who administer access control functions do not administer audit
    functions; and (iv) different administrator accounts for different roles.

        Privileges granted outside the context of the application user job function
    are more likely to go unmanaged or without oversight for authorization.
    Maintenance of privileges using roles defined for discrete job functions offers
    improved oversight of application user privilege assignments and helps to
    protect against unauthorized privilege assignment.
  "
  impact 0.3
  tag "gtitle": 'SRG-APP-000062-DB-000009'
  tag "gid": 'V-61809'
  tag "rid": 'SV-76299r3_rule'
  tag "stig_id": 'O121-C3-003300'
  tag "fix_id": 'F-67725r1_fix'
  tag "cci": ['CCI-000366', 'CCI-002220']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "nist": ['AC-5 c', 'Rev_4']
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
  tag "check": "Obtain a list of privileges assigned to the DBMS user accounts.
    If any direct privilege assignments exist that can be assigned to a role, this
    is a finding.

    SELECT
            'User '
            || grantee
            || ' is directly granted '
            || privilege
            || ' privilege on '
            || table_name value
    FROM    dba_tab_privs
    WHERE   grantee NOT IN (SELECT role FROM dba_roles)
    AND     grantee NOT IN
            (
            'XDB', 'SYSTEM', 'SYS', 'LBACSYS',
            'DVSYS', 'DVF', 'SYSMAN_RO', 'SYSMAN_BIPLATFORM',
            'SYSMAN_MDS', 'SYSMAN_OPSS', 'SYSMAN_STB', 'PUBLIC',
            'DBSNMP', 'SYSMAN', 'APEX_040200', 'WMSYS',
            'SYSDG', 'SYSBACKUP', 'SPATIAL_WFS_ADMIN_USR',
            'SPATIAL_CSW_ADMIN_US',
            'SI_INFORMTN_SCHEMA', 'OUTLN', 'ORDSYS', 'ORDDATA',
            'OJVMSYS', 'ORACLE_OCM', 'MDSYS', 'ORDPLUGINS',
            'GSMADMIN_INTERNAL', 'FLOWS_FILES', 'DIP', 'CTXSYS',
            'AUDSYS', 'APPQOSSYS', 'APEX_PUBLIC_USER',  'ANONYMOUS',
            'SPATIAL_CSW_ADMIN_USR', 'SYSKM', 'SYSMAN_TYPES',
            'MGMT_VIEW', 'EUS_ENGINE_USER', 'GSMCATUSER', 'OLAPSYS',
            'CLOUD_SWLIB_USER',  'GSMUSER', 'MDDATA', 'XS$NULL',
    'CLOUD_ENGINE_USER'
            )
    UNION
    SELECT
            'User '
            || grantee
            || ' is directly granted '
            || privilege
            || ' privilege ' value
    FROM    dba_sys_privs
    WHERE   grantee NOT IN (SELECT role FROM dba_roles)
    AND     privilege NOT IN
            (
            'CREATE SEQUENCE',
            'CREATE TRIGGER',
            'CREATE CLUSTER',
            'CREATE INDEXTYPE',
            'CREATE PROCEDURE',
            'CREATE TYPE',
            'CREATE SESSION',
            'CREATE OPERATOR',
            'CREATE TABLE',
            'UNLIMITED TABLESPACE' )
    AND     grantee NOT IN
            (
            'XDB', 'SYSTEM', 'SYS', 'LBACSYS',
            'DVSYS', 'DVF', 'SYSMAN_RO', 'SYSMAN_BIPLATFORM',
            'SYSMAN_MDS', 'SYSMAN_OPSS', 'SYSMAN_STB', 'PUBLIC',
            'DBSNMP', 'SYSMAN', 'APEX_040200', 'WMSYS',
            'SYSDG', 'SYSBACKUP', 'SPATIAL_WFS_ADMIN_USR',
            'SPATIAL_CSW_ADMIN_US',
            'SI_INFORMTN_SCHEMA', 'OUTLN', 'ORDSYS', 'ORDDATA',
            'OJVMSYS', 'ORACLE_OCM', 'MDSYS', 'ORDPLUGINS',
            'GSMADMIN_INTERNAL', 'FLOWS_FILES', 'DIP', 'CTXSYS',
            'AUDSYS', 'APPQOSSYS', 'APEX_PUBLIC_USER', 'ANONYMOUS',
            'SPATIAL_CSW_ADMIN_USR', 'SYSKM', 'SYSMAN_TYPES',
            'MGMT_VIEW', 'EUS_ENGINE_USER', 'GSMCATUSER', 'OLAPSYS',
            'CLOUD_SWLIB_USER',
            'GSMUSER', 'MDDATA', 'XS$NULL', 'CLOUD_ENGINE_USER'
            )
    UNION
    SELECT
            'User '
            || username
            || ' is granted '
            || privilege
            || ' privilege via role '
            || rp.granted_role value
    FROM    dba_users u,
            dba_role_privs rp,
            dba_sys_privs sp
    WHERE   username = rp.grantee
    AND     rp.granted_role = sp.grantee
    AND     privilege NOT IN
            (
            'CREATE SEQUENCE',
            'CREATE TRIGGER',
            'SET CONTAINER',
            'CREATE CLUSTER',
            'CREATE PROCEDURE',
            'CREATE TYPE',
            'CREATE SESSION',
            'CREATE OPERATOR',
            'CREATE TABLE',
            'CREATE INDEXTYPE'
            )
    AND     username NOT IN
            (
            'XDB', 'SYSTEM', 'SYS', 'LBACSYS',
            'DVSYS', 'DVF', 'SYSMAN_RO', 'SYSMAN_BIPLATFORM',
            'SYSMAN_MDS', 'SYSMAN_OPSS', 'SYSMAN_STB', 'DBSNMP',
            'SYSMAN', 'APEX_040200', 'WMSYS', 'SYSDG',
            'SYSBACKUP', 'SPATIAL_WFS_ADMIN_USR',
            'SPATIAL_CSW_ADMIN_US','GSMCATUSER',
            'OLAPSYS', 'SI_INFORMTN_SCHEMA', 'OUTLN', 'ORDSYS',
            'ORDDATA', 'OJVMSYS', 'ORACLE_OCM', 'MDSYS',
            'ORDPLUGINS', 'GSMADMIN_INTERNAL', 'MDDATA',
            'FLOWS_FILES', 'DIP', 'CTXSYS', 'AUDSYS', 'APPQOSSYS',
            'APEX_PUBLIC_USER', 'ANONYMOUS',
            'SPATIAL_CSW_ADMIN_USR','SYSKM',
            'SYSMAN_TYPES', 'MGMT_VIEW', 'EUS_ENGINE_USER',
            'EXFSYS','SYSMAN_APM' )
    AND     rp.granted_role NOT IN
            (
            'EXP_FULL_DATABASE','AQ_ADMINISTRATOR_ROLE','DV_REALM_RESOURCE',
            'DBA','CDB_DBA','OEM_ADVISOR','RECOVERY_CATALOG_OWNER',
            'EM_EXPRESS_ALL','SCHEDULER_ADMIN','OLAP_USER',
            'RESOURCE','EM_EXPRESS_BASIC','IMP_FULL_DATABASE','CONNECT',
            'AUDIT_ADMIN','DATAPUMP_EXP_FULL_DATABASE','GSMADMIN_ROLE',
            'DV_REALM_OWNER','OLAP_DBA','JAVADEBUGPRIV',
            'DATAPUMP_IMP_FULL_DATABASE','OEM_MONITOR',
            'APEX_GRANTS_FOR_NEW_USERS_ROLE'
            )
    UNION

    SELECT
            'User '
            ||grantee
            ||' is granted '
            ||privilege
            ||' on '
            ||owner
            ||'.'
            ||table_name
            ||'.'
            ||column_name
            ||' by '
            ||grantor
    FROM    dba_col_privs
    WHERE   grantee NOT IN
            (
            'XDB', 'SYSTEM', 'SYS', 'LBACSYS',
            'DVSYS', 'DVF', 'SYSMAN_RO', 'SYSMAN_BIPLATFORM',
            'SYSMAN_MDS', 'SYSMAN_OPSS', 'SYSMAN_STB', 'DBSNMP',
            'SYSMAN', 'APEX_040200', 'WMSYS', 'SYSDG',
            'SYSBACKUP', 'SPATIAL_WFS_ADMIN_USR',
            'SPATIAL_CSW_ADMIN_US','GSMCATUSER',
            'OLAPSYS', 'SI_INFORMTN_SCHEMA', 'OUTLN', 'ORDSYS',
            'ORDDATA', 'OJVMSYS', 'ORACLE_OCM', 'MDSYS',
            'ORDPLUGINS', 'GSMADMIN_INTERNAL', 'MDDATA',
            'FLOWS_FILES', 'IMP_FULL_DATABASE',
            'DIP', 'CTXSYS', 'AUDSYS', 'APPQOSSYS',
            'APEX_PUBLIC_USER', 'ANONYMOUS',
            'SPATIAL_CSW_ADMIN_USR','SYSKM',
            'SYSMAN_TYPES', 'MGMT_VIEW', 'EUS_ENGINE_USER',
            'EXFSYS','SYSMAN_APM'
            )
    ;

    (The lists of special accounts that are excluded from this requirement may not
    be complete.  It is expected that the DBA will edit the lists to suit local
    circumstances, adding other special accounts as necessary, and removing any
    that are not supposed to be in use in the Oracle deployment that is under
    review.  Similarly, the lists of privileges and roles excluded from the
    subqueries may be modified according to circumstances.)"
  tag "fix": "Define DBMS user roles based on privilege and job function
  requirements.

  Assign the required privileges to the role, and assign the role to authorized
  DBMS user accounts.

  Revoke any privileges directly assigned to DBMS user accounts, and assign them
  to a role the DBMS user already has assigned."
  describe 'A manual review is required to ensure the DBMS implements separation of duties through assigned
    information access authorizations' do
    skip 'A manual review is required to ensure the DBMS implements separation of duties through assigned
    information access authorizations'
  end
end
