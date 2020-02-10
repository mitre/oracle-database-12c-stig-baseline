control 'V-61595' do
  title 'All use of privileged accounts must be audited.'
  desc  "This is intended to limit exposure, by making it possible to trace any
  unauthorized access, by a privileged user account or role that has permissions
  on security functions or security-relevant information, to other data or
  functionality."
  impact 0.5
  tag "gtitle": 'SRG-APP-000063-DB-000018'
  tag "gid": 'V-61595'
  tag "rid": 'SV-76085r2_rule'
  tag "stig_id": 'O121-C2-004200'
  tag "fix_id": 'F-67511r1_fix'
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
  tag "check": "Review auditing configuration.

  If it is possible for a privileged user/role to access non-security functions
  or information without having the action recorded in the audit log, this is a
  finding.

  To obtain a list of unified auditing policies that have been defined, run the
  query:
  SELECT unique policy_name from AUDIT_UNIFIED_POLICIES;

  To obtain a list of unified auditing policies that have been enabled and the
  users for which it has been enabled, run the query:
  SELECT unique policy_name, user_name from AUDIT_UNIFIED_ENABLED_POLICIES;

  Unless otherwise required, verify that user_name is set to 'ALL USERS' to
  insure that the activity of administrative users is being logged."
  tag "fix": "Configure DBMS auditing so that all use of privileged accounts is
  recorded in the audit log."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  unified_auditing_policies_defined = sql.query('SELECT unique policy_name from AUDIT_UNIFIED_POLICIES;').column('policy_name')

  describe 'The list of unified auditing policies defined' do
    subject { unified_auditing_policies_defined }
    it { should_not be_empty }
  end

  users_being_audited = sql.query('SELECT unique user_name from AUDIT_UNIFIED_ENABLED_POLICIES;').column('user_name')

  describe 'The list of users being audited' do
    subject { users_being_audited }
    it { should include 'ALL USERS' }
  end
end
