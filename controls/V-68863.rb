control 'V-68863' do
  title "Logic modules within the database (to include packages, procedures,
  functions and triggers) must be monitored to discover unauthorized changes."
  desc "Any changes to the hardware, software, and/or firmware components of
  the information system and/or application can potentially have significant
  effects on the overall security of the system.  This includes the logic modules
  implemented within the database, such as packages, procedures, functions and
  triggers.

      If the DBMS were to allow any user to make changes to these, then those
  changes might be implemented without undergoing the appropriate testing and
  approvals that are part of a robust change management process.

      Accordingly, only qualified and authorized individuals shall be allowed to
  obtain access to information system components for purposes of initiating
  changes, including upgrades and modifications.

      Unmanaged changes that occur to the database logic modules can lead to
  unauthorized or compromised installations.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000133-DB-000179'
  tag "gid": 'V-68863'
  tag "rid": 'SV-83467r1_rule'
  tag "stig_id": 'O121-OS-010710'
  tag "fix_id": 'F-75045r1_fix'
  tag "cci": ['CCI-001499']
  tag "nist": ['CM-5 (6)', 'Rev_4']
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
  tag "check": "Review monitoring procedures and implementation evidence to
  verify that monitoring of changes to database logic modules is done.

  Verify the list of objects (packages, procedures, functions, and triggers)
  being monitored is complete. If monitoring does not occur or is not complete,
  this is a finding."
  tag "fix": "Implement procedures to monitor for unauthorized changes to
  database logic modules. If a third-party automated tool is not employed, an
  automated job that reports on the objects of interest and compares them to the
  baseline report for the same will meet the requirement."
  describe 'A manual review is required to ensure the logic modules within the database (to include packages, procedures,
    functions and triggers) are monitored to discover unauthorized changes' do
    skip 'A manual review is required to ensure the logic modules within the database (to include packages, procedures,
    functions and triggers) are monitored to discover unauthorized changes'
  end
end
