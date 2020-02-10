control 'V-61569' do
  title 'The DBMS must  automatically audit account modification.'
  desc  "Once an attacker establishes initial access to a system, they often
  attempt to create a persistent method of re-establishing access. One way to
  accomplish this is for the attacker to simply modify an existing account.

      Auditing of account modification is one method and best practice for
  mitigating this risk. A comprehensive application account management process
  ensures an audit trail automatically documents the modification of application
  user accounts and, as required, notifies administrators, application owners,
  and/or appropriate individuals. Applications must provide this capability
  directly, leveraging complementary technology providing this capability or a
  combination thereof.

      Automated account auditing processes greatly reduces the risk that accounts
  will be surreptitiously modified and provides logging that can be used for
  forensic purposes.

      Note that user authentication and account management should be done via an
  enterprise-wide mechanism whenever possible.  Examples of enterprise-level
  authentication/access mechanisms include, but are not limited to, Active
  Directory and LDAP.

      However, notwithstanding how accounts are managed, Oracle auditing should
  always be configured to capture account modification.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000027-DB-000186'
  tag "gid": 'V-61569'
  tag "rid": 'SV-76059r2_rule'
  tag "stig_id": 'O121-C2-002300'
  tag "fix_id": 'F-67485r3_fix'
  tag "cci": ['CCI-001403']
  tag "nist": ['AC-2 (4)', 'Rev_4']
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
  tag "check": "Check Oracle settings (and also OS settings and/or
  enterprise-level authentication/access mechanisms settings) to determine if
  account modification is being audited. If account modification is not being
  audited by Oracle, this is a finding.

  If Standard Auditing is used:
  To see if Oracle is configured to capture audit data, enter the following
  SQL*Plus command:
  SHOW PARAMETER AUDIT_TRAIL
  or the following SQL query:
  SELECT * FROM SYS.V$PARAMETER WHERE NAME = 'audit_trail';
  If Oracle returns the value 'NONE', this is a finding.

  If Unified Auditing is used:
  To see if Oracle is configured to capture audit data including account
  modification, enter the following SQL*Plus command:
  SELECT ' Account modification is not being audited. '
  FROM   dual
  WHERE  (SELECT Count(*)
          FROM   (select policy_name , audit_option from audit_unified_policies
          WHERE  audit_option = 'ALTER USER'
          and policy_name in (select policy_name from
  audit_unified_enabled_policies where user_name='ALL USERS'))) = 0
          OR (SELECT value
              FROM   v$option
              WHERE  parameter = 'Unified Auditing') != 'TRUE';

  If Oracle returns \"no rows selected\", this is not a finding."
  tag "fix": "Configure Oracle to audit account modifications activities.

  If Standard Auditing is used:
  Use this process to ensure auditable events are captured:
  ALTER SYSTEM SET AUDIT_TRAIL=<audit trail type> SCOPE=SPFILE;
  Audit trail type can be 'OS', 'DB', 'DB,EXTENDED', 'XML' or 'XML,EXTENDED'.
  After executing this statement, it may be necessary to shut down and restart
  the Oracle database.

  If Unified Auditing is used:
  To ensure auditable events are captured:
  Link the oracle binary with uniaud_on, and then restart the database. Oracle
  Database Upgrade Guide describes how to enable unified auditing.  Reference
  V-61625 for information on how to configure a policy to audit account
  modification.

  For more information on the configuration of auditing, refer to the following
  documents:
  \"Auditing Database Activity\" in the Oracle Database 2 Day + Security Guide:
  http://docs.oracle.com/database/121/TDPSG/tdpsg_auditing.htm#TDPSG50000
  \"Monitoring Database Activity with Auditing\" in the Oracle Database Security
  Guide:
  http://docs.oracle.com/database/121/DBSEG/part_6.htm#CCHEHCGI
  \"DBMS_AUDIT_MGMT\" in the Oracle Database PL/SQL Packages and Types Reference:
  http://docs.oracle.com/database/121/ARPLS/d_audit_mgmt.htm#ARPLS241
  Oracle Database Upgrade Guide:
  http://docs.oracle.com/database/121/UPGRD/afterup.htm#UPGRD52810"

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

    unified_auditing_events = sql.query("SELECT ' Account modification is not being audited. '
    FROM   dual
    WHERE  (SELECT Count(*)
          FROM   (select policy_name , audit_option from audit_unified_policies
          WHERE  audit_option = 'ALTER USER'
          and policy_name in (select policy_name from
    audit_unified_enabled_policies where user_name='ALL USERS'))) = 0
          OR (SELECT value
              FROM   v$option
              WHERE  parameter = 'Unified Auditing') != 'TRUE';").column('Account modification is not being audited.').uniq

    describe 'The unified auditing data capture for account modification' do
      subject { unified_auditing_events.to_s }
      it { should_not cmp '[nil]' }
    end
  end
end
