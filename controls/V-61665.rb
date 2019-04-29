control 'V-61665' do
  title "The DBMS must support the requirement to back up audit data and
  records onto a different system or media than the system being audited on an
  organization-defined frequency."
  desc "Protection of log data includes assuring log data is not accidentally
  lost or deleted. Backing up audit records to a different system or onto media
  separate from the system being audited on an organizational-defined frequency
  helps to assure, in the event of a catastrophic system failure, the audit
  records will be retained."
  impact 0.5
  tag "gtitle": 'SRG-APP-000125-DB-000170'
  tag "gid": 'V-61665'
  tag "rid": 'SV-76155r1_rule'
  tag "stig_id": 'O121-C2-010000'
  tag "fix_id": 'F-67579r1_fix'
  tag "cci": ['CCI-001348']
  tag "nist": ['AU-9 (2)', 'Rev_4']
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
  tag "check": "Check with the database administrator, storage administrator or
  system administrator, as applicable at the site, to verify that Oracle is
  configured EITHER to perform backups of the audit data specifically, OR, with
  appropriate permissions granted, to permit a third-party tool to do so.  Test
  the backup process.  Test the restore process (using a non-production system as
  the target).

  If Oracle is not so configured, this is a finding.

  If the test run of the backup and restore fails, this is a finding."
  tag "fix": "Utilize DBMS features or other software that supports the ability
  to back up audit data and records onto a system or media different from the
  system being audited on an organization-defined frequency.

  EITHER use Oracle features (such as Backup or Data Pump) to perform backups of
  the audit data specifically, OR grant appropriate permissions to permit a
  third-party tool to do so."
  describe 'A manual review is required to ensure the DBMS supports the requirement to back up audit data and
    records onto a different system or media than the system being audited on an
    organization-defined frequency' do
    skip 'A manual review is required to ensure the DBMS supports the requirement to back up audit data and
    records onto a different system or media than the system being audited on an
    organization-defined frequency'
  end
end
