control 'V-61651' do
  title 'Attempts to bypass access controls must be audited.'
  desc  "Information system auditing capability is critical for accurate
  forensic analysis. Audit record content that may be necessary to satisfy the
  requirement of this control includes:  timestamps, source and destination
  addresses, user/process identifiers, event descriptions, success/fail
  indications, file names involved, and access control or flow control rules
  invoked.

      Detection of suspicious activity, including access attempts and successful
  access from unexpected places, during unexpected times, or other unusual
  indicators can support decisions to apply countermeasures to deter an attack.
  Without detection, malicious activity may proceed without hindrance.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000115-DB-000056'
  tag "gid": 'V-61651'
  tag "rid": 'SV-76141r1_rule'
  tag "stig_id": 'O121-C2-009000'
  tag "fix_id": 'F-67565r1_fix'
  tag "cci": ['CCI-000158']
  tag "nist": ['AU-7 (1)', 'Rev_4']
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
  tag "check": "Review any audit settings for:
  - Unsuccessful logon attempts;
  - Account locking events;
  - Account disabling from a specific source location;
  - Failed database object attempts or attempts to access objects that do not
  exist; and
  - Other activities that may produce unexpected failures or trigger DBMS
  lockdown actions.

  If any of the above events as applicable to the DBMS are not audited, this is a
  finding.

  - - - - - -
  Check the current users in the database to see what profile they are assigned.
  The logon attempts past a site-defined allowable number, along with account
  locking, is best performed using a profile that defines the limits on these
  activities as designed by the DBA at a specific site.  Failed database object
  access or attempt to access objects is monitored by auditing.  Checking other
  activities that may produce unexpected failures or trigger database lockdown
  procedures is possible, but the check for the existence of those procedures is
  not possible unless they are defined.

  Check to see what profiles exist for the different users of the database.

  SQL>col name format a20
      col username format a21
      col profile format a10
      col \"tmp tba\" format a10
      select u.username,
       u.default_tablespace,
       u.temporary_tablespace \"TMP TBS\",
       u.profile,
       r.granted_role,
       r.admin_option,
       r.default_role
   from sys.dba_users u,
        sys.dba_role_privs r
   where  u.username = r.grantee (+)
   group by u.username,
            u.default_tablespace,
            u.temporary_tablespace,
            u.profile,
            r.granted_role,
            r.admin_option,
            r.default_role;

  View existing profiles and see what their settings are.

  SQL> select profile, resource_name, limit
       from dba_profiles
       order by profile, resource_name;

  This is the audit table.  Specific actions are logged in this table.

  If Standard Auditing is used:
  SQL> desc aud$;
   Name                           Null?         Type
   -----------------             -------       ------
   SESSIONID                     NOT NULL      NUMBER
   ENTRYID                       NOT NULL      NUMBER
   STATEMENT                     NOT NULL      NUMBER
   TIMESTAMP#                                   DATE
   USERID                                      VARCHAR2(30)
   USERHOST                                    VARCHAR2(128)
   TERMINAL                                    VARCHAR2(255)
   ACTION#                       NOT NULL      NUMBER
   RETURNCODE                    NOT NULL      NUMBER
   OBJ$CREATOR                                 VARCHAR2(30)
   OBJ$NAME                                    VARCHAR2(128)
   AUTH$PRIVILEGES                             VARCHAR2(16)
   AUTH$GRANTEE                                VARCHAR2(30)
   NEW$OWNER                                   VARCHAR2(30)
   NEW$NAME                                    VARCHAR2(128)
   SES$ACTIONS                                 VARCHAR2(19)
   SES$TID                                     NUMBER
   LOGOFF$LREAD                                NUMBER
   LOGOFF$PREAD                                NUMBER
   LOGOFF$LWRITE                               NUMBER
   LOGOFF$DEAD                                 NUMBER
   LOGOFF$TIME                                 DATE
   COMMENT$TEXT                                VARCHAR2(4000)
   CLIENTID                                    VARCHAR2(64)
   SPARE1                                      VARCHAR2(255)
   SPARE2                                      NUMBER
   OBJ$LABEL                                   RAW(255)
   SES$LABEL                                   RAW(255)
   PRIV$USED                                   NUMBER
   SESSIONCPU                                  NUMBER
   NTIMESTAMP#                                 TIMESTAMP(6)
   PROXY$SID                                   NUMBER
   USER$GUID                                   VARCHAR2(32)
   INSTANCE#                                   NUMBER
   PROCESS#                                    VARCHAR2(16)
   XID                                         RAW(8)
   AUDITID                                     VARCHAR2(64)
   SCN                                         NUMBER
   DBID                                        NUMBER
   SQLBIND                                     CLOB
   SQLTEXT                                     CLOB
   OBJ$EDITION                                 VARCHAR2(30)

  If Unified Auditing is used:
  SQL> desc unified_audit_trail;
  Name              Null     Type
  --------------   ------   ------
  AUDIT_TYPE                VARCHAR2(64)
  SESSIONID                 NUMBER
  PROXY_SESSIONID           NUMBER
  OS_USERNAME               VARCHAR2(30)
  USERHOST                  VARCHAR2(128)
  TERMINAL                  VARCHAR2(30)
  INSTANCE_ID               NUMBER
  DBID                      NUMBER
  AUTHENTICATION_TYPE       VARCHAR2(1024)
  DBUSERNAME                VARCHAR2(30)
  DBPROXY_USERNAME          VARCHAR2(30)
  EXTERNAL_USERID           VARCHAR2(1024)
  GLOBAL_USERID             VARCHAR2(32)
  CLIENT_PROGRAM_NAME       VARCHAR2(48)
  DBLINK_INFO               VARCHAR2(4000)
  XS_USER_NAME              VARCHAR2(128)
  XS_SESSIONID              RAW(33 BYTE)
  ENTRY_ID                  NUMBER
  STATEMENT_ID              NUMBER
  EVENT_TIMESTAMP           TIMESTAMP(6) WITH LOCAL TIME ZONE
  ACTION_NAME               VARCHAR2(64)
  RETURN_CODE               NUMBER
  OS_PROCESS                VARCHAR2(16)
  TRANSACTION_ID            RAW(8 BYTE)
  SCN                       NUMBER
  EXECUTION_ID              VARCHAR2(64)
  OBJECT_SCHEMA             VARCHAR2(30)
  OBJECT_NAME               VARCHAR2(128)
  SQL_TEXT                  CLOB
  SQL_BINDS                 CLOB
  APPLICATION_CONTEXTS      VARCHAR2(4000)
  CLIENT_IDENTIFIER         VARCHAR2(64)
  NEW_SCHEMA                VARCHAR2(30)
  NEW_NAME                  VARCHAR2(128)
  OBJECT_EDITION            VARCHAR2(30)
  SYSTEM_PRIVILEGE_USED     VARCHAR2(1024)
  SYSTEM_PRIVILEGE          VARCHAR2(40)
  AUDIT_OPTION              VARCHAR2(40)
  OBJECT_PRIVILEGES         VARCHAR2(19)
  ROLE                      VARCHAR2(30)
  TARGET_USER               VARCHAR2(30)
  EXCLUDED_USER             VARCHAR2(30)
  EXCLUDED_SCHEMA           VARCHAR2(30)
  EXCLUDED_OBJECT           VARCHAR2(128)
  ADDITIONAL_INFO           VARCHAR2(4000)
  UNIFIED_AUDIT_POLICIES    VARCHAR2(4000)
  FGA_POLICY_NAME           VARCHAR2(30)
  XS_INACTIVITY_TIMEOUT     NUMBER
  XS_ENTITY_TYPE            VARCHAR2(32)
  XS_TARGET_PRINCIPAL_NAME  VARCHAR2(30)
  XS_PROXY_USER_NAME        VARCHAR2(30)
  XS_DATASEC_POLICY_NAME    VARCHAR2(30)
  XS_SCHEMA_NAME            VARCHAR2(30)
  XS_CALLBACK_EVENT_TYPE    VARCHAR2(32)
  XS_PACKAGE_NAME           VARCHAR2(30)
  XS_PROCEDURE_NAME         VARCHAR2(30)
  XS_ENABLED_ROLE           VARCHAR2(30)
  XS_COOKIE                 VARCHAR2(1024)
  XS_NS_NAME                VARCHAR2(30)
  XS_NS_ATTRIBUTE           VARCHAR2(4000)
  XS_NS_ATTRIBUTE_OLD_VAL   VARCHAR2(4000)
  XS_NS_ATTRIBUTE_NEW_VAL   VARCHAR2(4000)
  DV_ACTION_CODE            NUMBER
  DV_ACTION_NAME            VARCHAR2(30)
  DV_EXTENDED_ACTION_CODE   NUMBER
  DV_GRANTEE                VARCHAR2(30)
  DV_RETURN_CODE            NUMBER
  DV_ACTION_OBJECT_NAME     VARCHAR2(128)
  DV_RULE_SET_NAME          VARCHAR2(90)
  DV_COMMENT                VARCHAR2(4000)
  DV_FACTOR_CONTEXT         VARCHAR2(4000)
  DV_OBJECT_STATUS          VARCHAR2(1)
  OLS_POLICY_NAME           VARCHAR2(30)
  OLS_GRANTEE               VARCHAR2(30)
  OLS_MAX_READ_LABEL        VARCHAR2(4000)
  OLS_MAX_WRITE_LABEL       VARCHAR2(4000)
  OLS_MIN_WRITE_LABEL       VARCHAR2(4000)
  OLS_PRIVILEGES_GRANTED    VARCHAR2(30)
  OLS_PROGRAM_UNIT_NAME     VARCHAR2(30)
  OLS_PRIVILEGES_USED       VARCHAR2(128)
  OLS_STRING_LABEL          VARCHAR2(4000)
  OLS_LABEL_COMPONENT_TYPE  VARCHAR2(12)
  OLS_LABEL_COMPONENT_NAME  VARCHAR2(30)
  OLS_PARENT_GROUP_NAME     VARCHAR2(30)
  OLS_OLD_VALUE             VARCHAR2(4000)
  OLS_NEW_VALUE             VARCHAR2(4000)
  RMAN_SESSION_RECID        NUMBER
  RMAN_SESSION_STAMP        NUMBER
  RMAN_OPERATION            VARCHAR2(20)
  RMAN_OBJECT_TYPE          VARCHAR2(20)
  RMAN_DEVICE_TYPE          VARCHAR2(5)
  DP_TEXT_PARAMETERS1       VARCHAR2(512)
  DP_BOOLEAN_PARAMETERS1    VARCHAR2(512)
  DIRECT_PATH_NUM_COLUMNS_LOADED NUMBER"
  tag "fix": "Configure auditing to capture the events listed below where
  available in the DBMS:
  - Unsuccessful logon attempts
  - Account locking events
  - Account disabling from a specific source location
  - Failed database object attempts or attempts to access objects that do not
  exist
  - Other activities that may produce unexpected failures or trigger DBMS
  lockdown actions"

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  standard_auditing_used = input('standard_auditing_used')
  unified_auditing_used = input('unified_auditing_used')

  describe.one do
    describe 'Standard auditing is in use for audit purposes' do
      subject { standard_auditing_used }
      it { should be true }
    end

    describe 'Unified auditing is in use for audit purposes' do
      subject { unified_auditing_used }
      it { should be true }
    end
  end

  audit_trail = sql.query("select value from v$parameter where name = 'audit_trail';").column('value')
  audit_info_captured = sql.query('SELECT * FROM UNIFIED_AUDIT_TRAIL;').column('EVENT_TIMESTAMP')

  if standard_auditing_used
    describe 'The oracle database audit_trail parameter' do
      subject { audit_trail }
      it { should_not cmp 'NONE' }
    end
  end

  unified_auditing = sql.query("SELECT value FROM V$OPTION WHERE PARAMETER = 'Unified Auditing';").column('value')

  if unified_auditing_used
    describe 'The oracle database unified auditing parameter' do
      subject { unified_auditing }
      it { should_not cmp 'FALSE' }
    end

    describe 'The oracle database unified auditing events captured' do
      subject { audit_info_captured }
      it { should_not be_empty }
    end

  end
end
