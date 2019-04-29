control 'V-61865' do
  title 'Use of the DBMS software installation account must be restricted.'
  desc  "This requirement is intended to limit exposure due to operating from
  within a privileged account or role. The inclusion of role is intended to
  address those situations where an access control policy, such as Role Based
  Access Control (RBAC), is being implemented and where a change of role provides
  the same degree of assurance in the change of access authorizations for both
  the user and all processes acting on behalf of the user as would be provided by
  a change between a privileged and non-privileged account.

      To limit exposure when operating from within a privileged account or role,
  the application must support organizational requirements that users of
  information system accounts, or roles, with access to organization-defined
  lists of security functions or security-relevant information, use
  non-privileged accounts, or roles, when accessing other (non-security) system
  functions.

      Use of privileged accounts for non-administrative purposes puts data at
  risk of unintended or unauthorized loss, modification, or exposure. In
  particular, DBA accounts if used for non-administration application development
  or application maintenance can lead to miss-assignment of privileges where
  privileges are inherited by object owners. It may also lead to loss or
  compromise of application data where the elevated privileges bypass controls
  designed in and provided by applications.

      The DBMS software installation account may require privileges not required
  for database administration or other functions. Use of accounts configured with
  excess privileges may result in the loss or compromise of data or system
  settings due to elevated privileges that bypass controls designed to protect
  them.

      This requirement is particularly important because Oracle equates the
  installation account with the SYS account - the super-DBA.  Once logged on to
  the operating system, this account can connect to the database AS SYSDBA
  without further authentication.  It is very powerful and, by virtue of not
  being linked to any one person, cannot be audited to the level of the
  individual.
  "
  impact 0.7
  tag "gtitle": 'SRG-APP-000063-DB-000022'
  tag "gid": 'V-61865'
  tag "rid": 'SV-76355r2_rule'
  tag "stig_id": 'O121-OS-004600'
  tag "fix_id": 'F-67781r4_fix'
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
  tag "check": "Review system documentation to identify the installation
  account.

  Verify whether the account is used for anything involving interactive activity
  beyond DBMS software installation, upgrade, and maintenance actions.

  If the account is used for anything involving interactive activity beyond DBMS
  software installation, upgrade, and maintenance actions, this is a finding."
  tag "fix": "Restrict interactive use of the DBMS software installation
  account to DBMS software installation, upgrade, and maintenance actions only.

  If possible, disable installation accounts when authorized actions are not
  being performed. Otherwise, disable the use of the account(s) for interactive
  activity."
  describe 'A manual review is required to ensure the use of the DBMS software installation account is restricted' do
    skip 'A manual review is required to ensure the use of the DBMS software installation account is restricted'
  end
end
