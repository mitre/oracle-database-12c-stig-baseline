control 'V-61803' do
  title "The DBMS must notify appropriate individuals when accounts are
  terminated."
  desc "When application accounts are terminated, user accessibility is
  affected.  Accounts are utilized for identifying individual application users
  or for identifying the application processes themselves.

      In order to detect and respond to events that affect user accessibility and
  application processing, applications must notify the appropriate individuals
  when an account is terminated so they can investigate the event. Such a
  capability greatly reduces the risk that application accessibility will be
  negatively affected for extended periods of time and provides logging that can
  be used for forensic purposes.

      Note that user authentication and account management must be done via an
  enterprise-wide mechanism whenever possible.  Examples of enterprise-level
  authentication/access mechanisms include, but are not limited to, Active
  Directory and LDAP.  This requirement applies to cases where accounts are
  directly managed by Oracle.

      Notwithstanding how accounts are normally managed, the DBMS must support
  the requirement to notify appropriate individuals upon account termination
  within Oracle.  Indeed, in a configuration where accounts are managed
  externally, the manipulation of an account within Oracle may indicate hostile
  activity.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000294-DB-000129'
  tag "gid": 'V-61803'
  tag "rid": 'SV-76293r2_rule'
  tag "stig_id": 'O121-C2-020700'
  tag "fix_id": 'F-67719r1_fix'
  tag "cci": ['CCI-001686']
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
  tag "check": "Check DBMS settings to determine whether it will notify
  appropriate individuals when accounts are terminated.

  If the DBMS does not notify appropriate individuals when accounts are
  terminated, this is a finding."
  tag "fix": "Working with the DBA and site management, determine the
  appropriate individuals (by job role) to be notified.

  If Oracle Audit Vault is available, configure it to notify the appropriate
  individuals when accounts are terminated.

  If Oracle Audit Vault is not available, configure the Oracle DBMS's auditing
  feature to record termination of accounts.

  If Standard Auditing is used:
  Create and deploy a mechanism, such as a frequently-run job, to monitor the
  SYS.AUD$ table for these records and notify the appropriate individuals.

  If unified Auditing is used:
  Create and deploy a mechanism, such as a frequently-run job, to monitor the
  SYS.UNIFIED_AUDIT_TRAIL view for these records and notify the appropriate
  individuals."
  describe 'A manual review is required to ensure the DBMS notifies the appropriate individuals when accounts are
    terminated' do
    skip 'A manual review is required to ensure the DBMS notifies the appropriate individuals when accounts are
    terminated'
  end
end
