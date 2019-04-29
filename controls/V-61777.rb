control 'V-61777' do
  title "The DBMS must automatically terminate emergency accounts after an
  organization-defined time period for each type of account."
  desc "Emergency application accounts are typically created due to an
  unforeseen operational event or could ostensibly be used in the event of a
  vendor support visit where a support representative requires a temporary unique
  account in order to perform diagnostic testing or conduct some other
  support-related activity. When these types of accounts are created, there is a
  risk that the temporary account may remain in place and active after the
  support representative has left.

      In the event emergency application accounts are required, the application
  must ensure accounts that are designated as temporary in nature shall
  automatically terminate these accounts after an organization-defined time
  period.  Such a process and capability greatly reduces the risk that accounts
  will be misused, hijacked, or application data compromised.

      Note that user authentication and account management must be done via an
  enterprise-wide mechanism whenever possible.  Examples of enterprise-level
  authentication/access mechanisms include, but are not limited to, Active
  Directory and LDAP. This requirement applies to cases where it is necessary to
  have accounts directly managed by Oracle.

      If it is possible for any temporary emergency accounts to be created and
  managed by Oracle, then the DBMS or application must provide or utilize a
  mechanism to automatically terminate such accounts after an
  organization-defined time period.

      Emergency database accounts must be automatically terminated after an
  organization-defined time period in order to mitigate the risk of the account
  being misused.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000234-DB-000157'
  tag "gid": 'V-61777'
  tag "rid": 'SV-76267r1_rule'
  tag "stig_id": 'O121-C2-018600'
  tag "fix_id": 'F-67693r1_fix'
  tag "cci": ['CCI-001682']
  tag "nist": ['AC-2 (2)', 'Rev_4']
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
  tag "check": "If the organization has a policy, consistently enforced,
  forbidding the creation of emergency or temporary accounts, this is not a
  finding.

  Check DBMS settings, OS settings, and/or enterprise-level authentication/access
  mechanisms settings to determine if emergency accounts are being automatically
  terminated by the system after an organization-defined time period. Check also
  for custom code (scheduled jobs, procedures, triggers, etc.) for achieving
  this.

  If emergency accounts are not being terminated after an organization-defined
  time period, this is a finding."
  tag "fix": "Create a profile specifically for emergency or temporary
  accounts.  When creating the accounts, assign them to this profile.  Configure
  DBMS, OS, and/or enterprise-level authentication/access mechanisms, or
  implement custom code, to terminate accounts with this profile after an
  organization-defined time period."
  describe 'A manual review is required to ensure the DBMS automatically terminates emergency accounts after an
    organization-defined time period for each type of account' do
    skip 'A manual review is required to ensure the DBMS automatically terminates emergency accounts after an
    organization-defined time period for each type of account'
  end
end
