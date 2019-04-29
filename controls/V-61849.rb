control 'V-61849' do
  title 'DBMS default accounts must be protected from misuse.'
  desc  "The Security Requirements Guide says, Default accounts are usually
  accounts that have special privileges required to administer the database.
  Well-known DBMS account names are targeted most frequently by attackers and are
  thus more prone to providing unauthorized access to the database.

      If default account names are not changed, an attacker has a predefined
  list of accounts to target.  Since most default accounts are administrative in
  nature, the compromise of a default account can have catastrophic consequences,
  including the complete loss of control over the information system.

      However, Oracle does not provide for changing user names directly.
  Workarounds to achieve the effect of a name change are cumbersome.  In
  addition, names of essential system accounts such as SYS are baked into the
  product, with thousands of dependencies involved.  Making such a change would
  risk making the DBMS inoperative, and would interfere with getting support from
  Oracle.

      The Check and Fix, therefore, relate to good practices for protecting the
  essential system accounts from misuse.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000063-DB-000023'
  tag "gid": 'V-61849'
  tag "rid": 'SV-76339r1_rule'
  tag "stig_id": 'O121-N2-004701'
  tag "fix_id": 'F-67765r1_fix'
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
  tag "check": "Review the use of the essential system accounts with the
  DBA(s).  Request evidence that administrators have individual administrative
  accounts and that they use these rather than SYS, SYSTEM, SYSMAN, etc., in
  carrying out their duties.

  If the evidence indicates otherwise, this is a finding.

  Review the status of the essential system accounts, in the view DBA_USERS.  If
  any of these accounts is not locked, or is not documented as a requirement,
  this is a finding."
  tag "fix": "Ensure that all individuals with DBA responsibilities always log
  on under their individual administrative accounts.

  Ensure that the passwords for essential system accounts such as SYS are
  available only to authorized administrators and tightly guarded to avoid
  misuse.  Ensure that these accounts are kept locked except when it is
  specifically necessary to use them."
  describe 'A manual review is required to ensure the DBMS default accounts are protected from misuse' do
    skip 'A manual review is required to ensure the DBMS default accounts are protected from misuse'
  end
end
