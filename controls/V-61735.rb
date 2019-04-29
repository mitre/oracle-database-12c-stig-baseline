control 'V-61735' do
  title "Procedures for establishing temporary passwords that meet DoD password
  requirements for new accounts must be defined, documented, and implemented."
  desc "Password maximum lifetime is  the maximum period of time, (typically
  in days) a user's password may be in effect before the user is forced to change
  it.

      Passwords need to be changed at specific policy-based intervals as per
  policy. Any password, no matter how complex, can eventually be cracked.

      One method of minimizing this risk is to use complex passwords and
  periodically change them. If the application does not limit the lifetime of
  passwords and force users to change their passwords, there is the risk that the
  system and/or application passwords could be compromised.

      New accounts authenticated by passwords that are created without a password
  or with an easily guessed password are vulnerable to unauthorized access.
  Procedures for creating new accounts with passwords should include the required
  assignment of a temporary password to be modified by the user upon first use.

      Note that user authentication and account management must be done via an
  enterprise-wide mechanism whenever possible.  Examples of enterprise-level
  authentication/access mechanisms include, but are not limited to, Active
  Directory and LDAP  With respect to Oracle, this requirement applies to cases
  where it is necessary to have accounts directly managed by Oracle.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000174-DB-000077'
  tag "gid": 'V-61735'
  tag "rid": 'SV-76225r1_rule'
  tag "stig_id": 'O121-C2-014900'
  tag "fix_id": 'F-67651r1_fix'
  tag "cci": ['CCI-000199']
  tag "nist": ['IA-5 (1) (d)', 'Rev_4']
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
  tag "check": "If all user accounts are authenticated by the OS or an
  enterprise-level authentication/access mechanism, and not by Oracle, this is
  not a finding.

  Where accounts are authenticated using passwords, review procedures and
  implementation evidence for creation of temporary passwords.

  If the procedures or evidence do not exist or do not enforce passwords to meet
  DoD password requirements, this is a finding."
  tag "fix": "Implement procedures for assigning temporary passwords to user
  accounts.

  Procedures should include instructions to meet current DoD password length and
  complexity requirements and provide a secure method to relay the temporary
  password to the user."
  describe 'A manual review is required to ensure procedures for establishing temporary passwords that meet DoD password
    requirements for new accounts are defined, documented, and implemented' do
    skip 'A manual review is required to ensure procedures for establishing temporary passwords that meet DoD password
    requirements for new accounts are defined, documented, and implemented'
  end
end
