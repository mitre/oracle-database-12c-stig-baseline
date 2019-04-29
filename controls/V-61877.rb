control 'V-61877' do
  title 'The DBMS software libraries must be periodically backed up.'
  desc  "Information system backup is a critical step in maintaining data
  assurance and availability.

      System-level information includes:  system-state information, operating
  system and application software, and licenses.

      Backups shall be consistent with organizational recovery time and recovery
  point objectives.

      The DBMS application depends upon the availability and integrity of its
  software libraries. Without backups, compromise or loss of the software
  libraries can prevent a successful recovery of DBMS operations.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000146-DB-000100'
  tag "gid": 'V-61877'
  tag "rid": 'SV-76367r1_rule'
  tag "stig_id": 'O121-P2-012700'
  tag "fix_id": 'F-67793r1_fix'
  tag "cci": ['CCI-000537']
  tag "nist": ['CP-9 (b)', 'Rev_4']
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
  tag "check": "Review evidence of inclusion of the DBMS libraries in current
  backup records.

  If any DBMS library files are not included in regular backups, this is a
  finding."
  tag "fix": "Configure backups to include all DBMS application and third-party
  database application software libraries."
  describe 'A manual review is required to ensure the DBMS software libraries are periodically backed up' do
    skip 'A manual review is required to ensure the DBMS software libraries are periodically backed up'
  end
end
