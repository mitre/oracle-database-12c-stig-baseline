control 'V-61641' do
  title "The DBMS must include organization-defined additional, more detailed
  information in the audit records for audit events identified by type, location,
  or subject."
  desc "Information system auditing capability is critical for accurate
  forensic analysis. Audit record content that may be necessary to satisfy the
  requirement of this control includes:  timestamps, source and destination
  addresses, user/process identifiers, event descriptions, success/fail
  indications, file names involved, and access control or flow control rules
  invoked.

      In addition, the application must have the capability to include
  organization-defined additional, more detailed information in the audit records
  for audit events. These events may be identified by type, location, or subject.

      An example of detailed information the organization may require in audit
  records is full-text recording of privileged commands or the individual
  identities of shared account users.

      Some organizations may determine that more detailed information is required
  for specific database event types.  If this information is not available, it
  could negatively impact forensic investigations into user actions or other
  malicious events.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000101-DB-000044'
  tag "gid": 'V-61641'
  tag "rid": 'SV-76131r1_rule'
  tag "stig_id": 'O121-C2-008000'
  tag "fix_id": 'F-67553r2_fix'
  tag "cci": ['CCI-000135']
  tag "nist": ['AU-3 (1)', 'Rev_4']
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

  If Oracle returns the value \"NONE\", this is a finding.

  Compare the organization-defined auditable events with the Oracle documentation
  to determine whether standard auditing covers all the requirements.

  If it does, this is not a finding.

  Compare those organization-defined auditable events that are not covered by the
  standard auditing, with the existing Fine-Grained Auditing (FGA) specifications
  returned by the following query:

  SELECT * FROM SYS.DBA_FGA_AUDIT_TRAIL;

  If any such auditable event is not covered by the existing FGA specifications,
  this is a finding.

  If Unified Auditing is used:
  To see if Oracle is configured to capture audit data, enter the following
  SQL*Plus command:

  SELECT * FROM V$OPTION WHERE PARAMETER = 'Unified Auditing';

  If Oracle returns the value \"TRUE\", this is not a finding.

  Compare the organization-defined auditable events with the Oracle documentation
  to determine whether standard auditing covers all the requirements.

  If it does, this is not a finding.

  Compare those organization-defined auditable events that are not covered by the
  standard auditing, with the existing Fine-Grained Auditing (FGA) specifications
  returned by the following query:

  SELECT * FROM SYS.UNIFIED_AUDIT_TRAIL WHERE AUDIT_TYPE = 'FineGrainedAudit';

  If any such auditable event is not covered by the existing FGA specifications,
  this is a finding."
  tag "fix": "Either configure the DBMS's auditing to audit
  organization-defined auditable events, or, if preferred, use a third-party or
  custom tool. The tool must provide the minimum capability to audit the required
  events.

  If using a third-party product, proceed in accordance with the product
  documentation. If using Oracle's capabilities, proceed as follows.

  If Standard Auditing is used:
  Use this process to ensure auditable events are captured:

  ALTER SYSTEM SET AUDIT_TRAIL=<audit trail type> SCOPE=SPFILE;

  Audit trail type can be \"OS\", \"DB\", \"DB,EXTENDED\", \"XML\" or
  \"XML,EXTENDED\".

  After executing this statement, it may be necessary to shut down and restart
  the Oracle database.

  If the organization-defined additional audit requirements are not covered by
  the default audit options, deploy and configure Fine-Grained Auditing. For
  details, refer to Oracle documentation at the location below.

  If the site-specific audit requirements are not covered by the default audit
  options, deploy and configure Fine-Grained Auditing.  For details, refer to
  Oracle documentation, at the location below.

  If Unified Auditing is used:
  Use this process to ensure auditable events are captured:

  SELECT * FROM V$OPTION WHERE PARAMETER = 'Unified Auditing';

  If Oracle returns the value \"TRUE\", this is not a finding.

  Otherwise,
  Link the oracle binary with uniaud_on, and then restart the database. Oracle
  Database Upgrade Guide describes how to enable unified auditing.

  If the organization-defined additional audit requirements are not covered by
  the default audit options, deploy and configure Fine-Grained Auditing. For
  details, refer to Oracle documentation at the location below.

  If the site-specific audit requirements are not covered by the default audit
  options, deploy and configure Fine-Grained Auditing. For details, refer to
  Oracle documentation, at the location below.

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
  fga_audit_events = sql.query(" SELECT * FROM SYS.UNIFIED_AUDIT_TRAIL WHERE AUDIT_TYPE = 'FineGrainedAudit';").column('TIMESTAMP')

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

    describe 'The oracle database fine grained  auditing events captured' do
      subject { fga_audit_events }
      it { should_not be_empty }
    end

  end
end
