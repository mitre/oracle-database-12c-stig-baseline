control 'V-61963' do
  title "The DBMS data files, transaction logs and audit files must be stored
  in dedicated directories or disk partitions separate from software or other
  application files."
  desc "Protection of DBMS data, transaction and audit data files stored by
  the host operating system is dependent on OS controls. When different
  applications share the same database process, resource contention and differing
  security controls may be required to isolate and protect one application's data
  and audit logs from another. DBMS software libraries and configuration files
  also require differing access control lists."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61963'
  tag "rid": 'SV-76453r1_rule'
  tag "stig_id": 'O121-BP-025100'
  tag "fix_id": 'F-67883r1_fix'
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
  tag "check": "Review the disk/directory specification where database data,
  transaction log and audit files are stored.

  If DBMS data, transaction or audit data files are stored in the same directory,
  this is a finding.

  If separation of data, transaction and audit data is not supported by the DBMS,
  this check is not a finding.

  If stored separately and access permissions for each directory is the same,
  this is a finding."
  tag "fix": "Product-specific fix pending development. Use Generic Fix listed
  below:

  Specify dedicated host system disk directories to store database data,
  transaction and audit files.

  Configure DBMS default file storage locations to use dedicated disk directories
  where supported by the DBMS."
  describe 'A manual review is required to ensure the DBMS data files, transaction logs and audit files are stored
    in dedicated directories or disk partitions separate from software or other
    application files' do
    skip 'A manual review is required to ensure the DBMS data files, transaction logs and audit files are stored
    in dedicated directories or disk partitions separate from software or other
    application files'
  end
end
