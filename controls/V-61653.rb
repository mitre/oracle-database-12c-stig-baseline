control 'V-61653' do
  title "The system must protect audit information from any type of
  unauthorized access."
  desc "If audit data were to become compromised, then competent forensic
  analysis and discovery of the true source of potentially malicious system
  activity is difficult, if not impossible, to achieve. In addition, access to
  audit records provides information an attacker could potentially use to his or
  her advantage.

      To ensure the veracity of audit data, the information system and/or the
  application must protect audit information from any and all unauthorized
  access. This includes read, write, copy, etc.

      This requirement can be achieved through multiple methods which will depend
  upon system architecture and design. Some commonly employed methods include
  ensuring log files enjoy the proper file system permissions utilizing file
  system protections and limiting log data location.

      Additionally, applications with user interfaces to audit records must not
  allow for the unfettered manipulation of or access to those records via the
  application. If the application provides access to the audit data, the
  application becomes accountable for ensuring that audit information is
  protected from unauthorized access.

      Audit information includes all information (e.g., audit records, audit
  settings, and audit reports) needed to successfully audit information system
  activity.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000118-DB-000059'
  tag "gid": 'V-61653'
  tag "rid": 'SV-76143r2_rule'
  tag "stig_id": 'O121-C2-009300'
  tag "fix_id": 'F-67567r3_fix'
  tag "cci": ['CCI-000162']
  tag "nist": ['AU-9', 'Rev_4']
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
  tag "check": "Review locations of audit logs, both internal to the database
  and database audit logs located at the operating system-level. Verify there are
  appropriate controls and permissions to protect the audit information from
  unauthorized access.

  If appropriate controls and permissions do not exist, this is a finding.

  - - - - -
  If Standard Auditing is used:
  DBA_TAB_PRIVS describes all object grants in the database.  Check to see who
  has permissions on the AUD$ table.

  Related View

  DBA_TAB_PRIVS describes the object grants for which the current user is the
  object owner, grantor, or grantee.
  Column      Datatype        NULL        Description
  GRANTEE     VARCHAR2(30)  NOT NULL   Name of the user to whom access was granted
  OWNER       VARCHAR2(30)  NOT NULL   Owner of the object
  TABLE_NAME  VARCHAR2(30)  NOT NULL   Name of the object
  GRANTOR     VARCHAR2(30)  NOT NULL   Name of the user who performed the grant
  PRIVILEGE   VARCHAR2(40)  NOT NULL   Privilege on the object
  GRANTABLE   VARCHAR2(3)   Indicates whether the privilege was granted with the
  GRANT OPTION (YES) or not (NO)
  HIERARCHY   VARCHAR2(3)   Indicates whether the privilege was granted with the
  HIERARCHY OPTION (YES) or not (NO)
  COMMON      VARCHAR2(3)
  TYPE        VARCHAR2(24)

  sqlplus connect as sysdba;

  SQL>  SELECT GRANTEE, TABLE_NAME, PRIVILEGE
        FROM DBA_TAB_PRIVS where table_name = 'AUD$';

  If Unified Auditing is used:
  DBA_TAB_PRIVS describes all object grants in the database.  Check to see who
  has permissions on the AUDSYS tables.

  Related View

  DBA_TAB_PRIVS describes the object grants for which the current user is the
  object owner, grantor, or grantee.
  Column      Datatype        NULL       Description
  GRANTEE     VARCHAR2(30)    NOT NULL   Name of the user to whom access was
  granted
  OWNER       VARCHAR2(30)    NOT NULL   Owner of the object
  TABLE_NAME  VARCHAR2(30)    NOT NULL   Name of the object
  GRANTOR     VARCHAR2(30)    NOT NULL   Name of the user who performed the grant
  PRIVILEGE   VARCHAR2(40)    NOT NULL   Privilege on the object
  GRANTABLE   VARCHAR2(3)     Indicates whether the privilege was granted with
  the GRANT OPTION (YES) or not (NO)
  HIERARCHY   VARCHAR2(3)     Indicates whether the privilege was granted with
  the HIERARCHY OPTION (YES) or not (NO)
  COMMON      VARCHAR2(3)
  TYPE        VARCHAR2(24)

  sqlplus connect as sysdba;

  SQL>  SELECT GRANTEE, TABLE_NAME, PRIVILEGE
      FROM DBA_TAB_PRIVS where owner='AUDSYS';"
  tag "fix": "Add controls and modify permissions to protect database audit log
  data from unauthorized access, whether stored in the database itself or at the
  OS level."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  users_allowed_access_to_audit_info = sql.query("SELECT GRANTEE, TABLE_NAME, PRIVILEGE
      FROM DBA_TAB_PRIVS where owner='AUDSYS';").column('grantee').uniq
  if users_allowed_access_to_audit_info.empty?
    impact 0.0
    describe 'There are no oracle users allowed access to audit information, control N/A' do
      skip 'There are no oracle users allowed access to audit information'
    end
  else
    users_allowed_access_to_audit_info.each do |user|
      describe "oracle users: #{user} allowed access to audit information" do
        subject { user }
        it { should be_in input('allowed_audit_users') }
      end
    end
  end
end
