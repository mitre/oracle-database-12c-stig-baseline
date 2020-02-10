control 'V-61591' do
  title "Administrative privileges must be assigned to database accounts via
  database roles."
  desc "Applications employ the concept of least privilege for specific duties
  and information systems (including specific functions, ports, protocols, and
  services). The concept of least privilege is also applied to information system
  processes, ensuring that the processes operate at privilege levels no higher
  than necessary to accomplish required organizational missions and/or functions.
  Organizations consider the creation of additional processes, roles, and
  information system accounts as necessary to achieve least privilege.
  Organizations also apply least privilege concepts to the design, development,
  implementation, and operations of information systems.

      Privileges granted outside the context of the application user job function
  are more likely to go unmanaged or without oversight for authorization.
  Maintenance of privileges using roles defined for discrete job functions offers
  improved oversight of application user privilege assignments and helps to
  protect against unauthorized privilege assignment.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000062-DB-000034'
  tag "gid": 'V-61591'
  tag "rid": 'SV-76081r3_rule'
  tag "stig_id": 'O121-C2-004000'
  tag "fix_id": 'F-67507r1_fix'
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
  tag "check": "Review accounts for direct assignment of administrative
  privileges.  Connected as SYSDBA, run the query:

  SELECT grantee, privilege
  FROM   dba_sys_privs
  WHERE  grantee IN
  (
  SELECT username
  FROM   dba_users
  WHERE  username NOT IN
  (
  'XDB', 'SYSTEM', 'SYS', 'LBACSYS',
  'DVSYS', 'DVF', 'SYSMAN_RO',
  'SYSMAN_BIPLATFORM', 'SYSMAN_MDS',
  'SYSMAN_OPSS', 'SYSMAN_STB', 'DBSNMP',
  'SYSMAN', 'APEX_040200', 'WMSYS',
  'SYSDG', 'SYSBACKUP', 'SPATIAL_WFS_ADMIN_USR',
  'SPATIAL_CSW_ADMIN_US', 'GSMCATUSER',
  'OLAPSYS', 'SI_INFORMTN_SCHEMA',
  'OUTLN', 'ORDSYS', 'ORDDATA', 'OJVMSYS',
  'ORACLE_OCM', 'MDSYS', 'ORDPLUGINS',
  'GSMADMIN_INTERNAL', 'MDDATA', 'FLOWS_FILES',
  'DIP', 'CTXSYS', 'AUDSYS',
  'APPQOSSYS', 'APEX_PUBLIC_USER', 'ANONYMOUS',
  'SPATIAL_CSW_ADMIN_USR', 'SYSKM',
  'SYSMAN_TYPES', 'MGMT_VIEW',
  'EUS_ENGINE_USER', 'EXFSYS', 'SYSMAN_APM'
  )
  )
  AND privilege NOT IN ('UNLIMITED TABLESPACE'
                   , 'REFERENCES', 'INDEX', 'SYSDBA', 'SYSOPER'
  )
  ORDER  BY 1, 2;

  If any administrative privileges have been assigned directly to a database
  account, this is a finding.

  (The list of special accounts that are excluded from this requirement may not
  be complete.  It is expected that the DBA will edit the list to suit local
  circumstances, adding other special accounts as necessary, and removing any
  that are not supposed to be in use in the Oracle deployment that is under
  review.)"
  tag "fix": "Create roles for administrative function assignments. Assign the
  necessary privileges for the administrative functions to a role.  Do not assign
  administrative privileges directly to users, except for those that Oracle does
  not permit to be assigned via roles."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  database_accounts_with_administrative_privs = sql.query("SELECT grantee
  FROM   dba_sys_privs
  WHERE  grantee IN
  (
  SELECT username
  FROM   dba_users
  WHERE  username NOT IN
  (
  'XDB', 'SYSTEM', 'SYS', 'LBACSYS',
  'DVSYS', 'DVF', 'SYSMAN_RO',
  'SYSMAN_BIPLATFORM', 'SYSMAN_MDS',
  'SYSMAN_OPSS', 'SYSMAN_STB', 'DBSNMP',
  'SYSMAN', 'APEX_040200', 'WMSYS',
  'SYSDG', 'SYSBACKUP', 'SPATIAL_WFS_ADMIN_USR',
  'SPATIAL_CSW_ADMIN_US', 'GSMCATUSER',
  'OLAPSYS', 'SI_INFORMTN_SCHEMA',
  'OUTLN', 'ORDSYS', 'ORDDATA', 'OJVMSYS',
  'ORACLE_OCM', 'MDSYS', 'ORDPLUGINS',
  'GSMADMIN_INTERNAL', 'MDDATA', 'FLOWS_FILES',
  'DIP', 'CTXSYS', 'AUDSYS',
  'APPQOSSYS', 'APEX_PUBLIC_USER', 'ANONYMOUS',
  'SPATIAL_CSW_ADMIN_USR', 'SYSKM',
  'SYSMAN_TYPES', 'MGMT_VIEW',
  'EUS_ENGINE_USER', 'EXFSYS', 'SYSMAN_APM'
  )
  )
  AND privilege NOT IN ('UNLIMITED TABLESPACE'
                   , 'REFERENCES', 'INDEX', 'SYSDBA', 'SYSOPER'
  );").column('grantee').uniq

  describe 'Database accounts with administrative privileges' do
    subject { database_accounts_with_administrative_privs }
    it { should be_empty }
  end
end
