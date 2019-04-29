control 'V-61701' do
  title "DBMS must conduct backups of system-level information per
  organization-defined frequency that is consistent with recovery time and
  recovery point objectives."
  desc "Information system backup is a critical step in maintaining data
  assurance and availability.

      System-level information includes:  system-state information, operating
  system and application software, and licenses.

      Backups shall be consistent with organizational recovery time and recovery
  point objectives.

      Databases that do not back up information regularly risk the loss of that
  information in the event of a system failure. Most databases contain
  functionality to allow regular backups; it is important that this functionality
  is enabled and configured correctly to prevent data loss.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000146-DB-000099'
  tag "gid": 'V-61701'
  tag "rid": 'SV-76191r1_rule'
  tag "stig_id": 'O121-C2-012600'
  tag "fix_id": 'F-67617r1_fix'
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
  tag "check": "Review DBMS and OS backup configuration to determine that
  system-level data is backed up in according with organization-defined frequency.

  If the system-level data of the DBMS is not backed up to the
  organization-defined frequency, this is a finding."
  tag "fix": "Utilize DBMS, OS, or third-party product(s) to meet the
  requirement of backing up system data according to the organization-defined
  frequency."
  describe 'A manual is required to ensure the DBMS conducts backups of system-level information per
    organization-defined frequency that is consistent with recovery time and
    recovery point objectives' do
    skip 'A manual is required to ensure the DBMS conducts backups of system-level information per
    organization-defined frequency that is consistent with recovery time and
    recovery point objectives'
  end
end
