control 'V-61527' do
  title 'Changes to DBMS security labels must be audited.'
  desc  "Some DBMS systems provide the feature to assign security labels to
  data elements. If labeling is required, implementation options include the
  Oracle Label Security package, or a third-party product, or custom-developed
  functionality.  The confidentiality and integrity of the data depends upon the
  security label assignment where this feature is in use. Changes to security
  label assignment may indicate suspicious activity."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61527'
  tag "rid": 'SV-76017r4_rule'
  tag "stig_id": 'O121-BP-026200'
  tag "fix_id": 'F-67443r2_fix'
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
  tag "check": "If no data is identified as being sensitive or classified by
  the Information Owner, in the System Security Plan or in the AIS Functional
  Architecture documentation, this is not a finding.

  If security labeling is not required, this is not a finding.

  If Standard Auditing is used, run the SQL query:

  select * from dba_sa_audit_options;

  If no records are returned or if output from the SQL statement above does not
  show classification labels being audited as required in the System Security
  Plan, this is a finding.

  If Unified Auditing is used:
  To see if Oracle is configured to capture audit data including changes to
  security label assignment, enter the following SQL*Plus command:
  SELECT 'Changes to security label assignment is not being audited. '
  FROM   dual
  WHERE  (SELECT Count(*)
          FROM   (select policy_name , audit_option from audit_unified_policies
          WHERE  audit_option = 'ALL'
    AND audit_option_type = 'OLS ACTION'
          AND policy_name in (select policy_name from
  audit_unified_enabled_policies where user_name='ALL USERS'))) = 0
          OR (SELECT value
              FROM   v$option
              WHERE  parameter = 'Unified Auditing') != 'TRUE';

  If Oracle returns \"no rows selected\", this is not a finding.

  To confirm that Oracle audit is capturing sufficient information to establish
  that changes to classification labels are being audited, perform a successful
  auditable action and an auditable action that results in an SQL error, and then
  view the results in the SYS.UNIFIED_AUDIT_TRAIL view.

  If no ACTION#, or the wrong value, is returned for the auditable actions, this
  is a finding."
  tag "fix": "Define the policy for auditing changes to security labels defined
  for the data.

  Document the audit requirements in the System Security Plan and configure
  database auditing in accordance with the policy.

  If using Standard Auditing:
  If there is no Unified Auditing policy deployed to audit changes to security
  labels, the create one using the following syntax:
  SA_AUDIT_ADMIN.AUDIT (
       policy_name     IN VARCHAR2,
       users           IN VARCHAR2 DEFAULT NULL,
       audit_option    IN VARCHAR2 DEFAULT NULL,
       audit_type      IN VARCHAR2 DEFAULT NULL,
       success         IN VARCHAR2 DEFAULT NULL);

  For additional information on creating audit policies, refer to the Oracle
  Database Security Guide
  http://docs.oracle.com/database/121/OLSAG/packages.htm#i1011868

  If Unified Auditing is used:
  To ensure auditable events are captured:
  Link the oracle binary with uniaud_on, and then restart the database. Oracle
  Database Upgrade Guide describes how to enable unified auditing.
  Reference V-61625 for information on how to configure a policy to audit changes
  to security label assignments.

  For additional information on creating audit policies, refer to the Oracle
  Database Security Guide
  http://docs.oracle.com/database/121/DBSEG/audit_config.htm#CHDGBAAC"

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

    unified_auditing_events = sql.query("SELECT 'Changes to security label assignment is not being audited. '
    FROM   dual
    WHERE  (SELECT Count(*)
          FROM   (select policy_name , audit_option from audit_unified_policies
          WHERE  audit_option = 'ALL'
    AND audit_option_type = 'OLS ACTION'
          AND policy_name in (select policy_name from
    audit_unified_enabled_policies where user_name='ALL USERS'))) = 0
          OR (SELECT value
              FROM   v$option
              WHERE  parameter = 'Unified Auditing') != 'TRUE';").column('Changes to security label assignment is not being audited.').uniq

    describe 'The unified auditing data capture for account creation' do
      subject { unified_auditing_events.to_s }
      it { should_not cmp '[nil]' }
    end
  end

end
