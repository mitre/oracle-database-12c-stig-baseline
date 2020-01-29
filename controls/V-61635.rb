control 'V-61635' do
  title "The DBMS must produce audit records containing sufficient information
  to establish the sources (origins) of the events."
  desc "Information system auditing capability is critical for accurate
  forensic analysis. Audit record content that may be necessary to satisfy the
  requirement of this control, includes, but is not limited to:  timestamps,
  source and destination IP addresses, user/process identifiers, event
  descriptions, application specific events, success/fail indications, file names
  involved, access control or flow control rules invoked.

      Without information establishing the source of activity, the value of audit
  records from a forensics perspective is questionable.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000098-DB-000042'
  tag "gid": 'V-61635'
  tag "rid": 'SV-76125r1_rule'
  tag "stig_id": 'O121-C2-007700'
  tag "fix_id": 'F-67547r1_fix'
  tag "cci": ['CCI-000133']
  tag "nist": ['AU-3', 'Rev_4']
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
  tag "check": "Verify, using vendor and system documentation if necessary,
  that the DBMS is configured to use Oracle's auditing features, or that a
  third-party product or custom code is deployed and configured to satisfy this
  requirement.

  If a third-party product or custom code is used, compare its current
  configuration with the audit requirements. If any of the requirements is not
  covered by the configuration, this is a finding.

  The remainder of this Check is applicable specifically where Oracle auditing is
  in use.

  If Standard Auditing is used:
  To see if Oracle is configured to capture audit data, enter the following
  SQL*Plus command:

  SHOW PARAMETER AUDIT_TRAIL

  or the following SQL query:

  SELECT * FROM SYS.V$PARAMETER WHERE NAME = 'audit_trail';

  If Oracle returns the value 'NONE', this is a finding.

  To confirm that Oracle audit is capturing sufficient information to establish
  the source of events, perform a successful auditable action and an auditable
  action that results in an SQL error, and then view the results in the SYS.AUD$
  table or the audit file, whichever is in use.

  If correct values for User ID, User Host, and Terminal are not returned when
  applicable, this is a finding.

  If Unified Auditing is used:
  To see if Oracle is configured to capture audit data, enter the following
  SQL*Plus command:

  SELECT * FROM V$OPTION WHERE PARAMETER = 'Unified Auditing';

  If Oracle returns the value \"TRUE\", this is not a finding.

  To confirm that Oracle audit is capturing sufficient information to establish
  the source of events, perform a successful auditable action and an auditable
  action that results in an SQL error, and then view the results in the
  SYS.UNIFIED_AUDIT_TRAIL view.

  If correct values for User ID, User Host, and Terminal are not returned when
  applicable, this is a finding."
  tag "fix": "Configure the DBMS's auditing to audit standard and
  organization-defined auditable events, the audit record to include the source
  of the event. If preferred, use a third-party or custom tool.

  If using a third-party product, proceed in accordance with the product
  documentation. If using Oracle's capabilities, proceed as follows.

  If Standard Auditing is used:
  Use this process to ensure auditable events are captured:

  ALTER SYSTEM SET AUDIT_TRAIL=<audit trail type> SCOPE=SPFILE;

  Audit trail type can be 'OS', 'DB', 'DB,EXTENDED', 'XML' or 'XML,EXTENDED'.
  After executing this statement, it may be necessary to shut down and restart
  the Oracle database.

  If Unified Auditing is used:
  To ensure auditable events are captured:
  Link the oracle binary with uniaud_on, and then restart the database.



  Oracle Database Upgrade Guide describes how to enable unified auditing.

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
