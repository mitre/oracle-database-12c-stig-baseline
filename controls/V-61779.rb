control 'V-61779' do
  title "The DBMS must employ automated mechanisms to alert security personnel
  of inappropriate or unusual activities with security implications."
  desc "Applications will typically utilize logging mechanisms for maintaining
  a historical log of activity that occurs within the application. This
  information can then be used for diagnostic purposes, forensics purposes, or
  other purposes relevant to ensuring the availability and integrity of the
  application.

      While it is important to log events identified as being critical and
  relevant to security, it is equally important to notify the appropriate
  personnel in a timely manner, so they are able to respond to events as they
  occur.

      Solutions that include a manual notification procedure do not offer the
  reliability and speed of an automated notification solution. Applications must
  employ automated mechanisms to alert security personnel of inappropriate or
  unusual activities that have security implications. If this capability is not
  built directly into the application, the application must be able to integrate
  with existing security infrastructure that provides this capability.

      Database management systems that do not automatically alert security
  personnel of unusual activities run the risk of security incidents going
  unnoticed for long periods of time. This can allow security breaches to be
  ongoing and more serious.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000237-DB-000158'
  tag "gid": 'V-61779'
  tag "rid": 'SV-76269r1_rule'
  tag "stig_id": 'O121-C2-018800'
  tag "fix_id": 'F-67695r1_fix'
  tag "cci": ['CCI-001274']
  tag "nist": ['SI-4 (12)', 'Rev_4']
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
  tag "check": "Check DBMS settings to determine whether security personnel are
  alerted automatically when unusual or security-related activities (threats
  identified by authoritative sources (e.g., CTOs) and IAW with CJCSM 6510.01A)
  are detected on the database.

  If security personnel are not automatically alerted, this is a finding."
  tag "fix": "Configure database to automatically alert security personnel of
  inappropriate or unusual activities with security implications.

  Oracle provides this capability with the Audit Vault.  Install and configure
  Oracle Audit Vault if it is available.

  If Audit Vault is not available, implement custom code or deploy a third-party
  product to satisfy this requirement."
  describe 'A manual review is required to ensure the DBMS employs automated mechanisms to alert security personnel
    of inappropriate or unusual activities with security implications' do
    skip 'A manual review is required to ensure the DBMS employs automated mechanisms to alert security personnel
    of inappropriate or unusual activities with security implications'
  end
end
