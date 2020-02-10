control 'V-61539' do
  title "Oracle software must be evaluated and patched against newly found
  vulnerabilities."
  desc "Security faults with software applications and operating systems are
  discovered daily. Vendors are constantly updating and patching their products
  to address newly discovered security vulnerabilities. Organizations (including
  any contractor to the organization) are required to promptly install
  security-relevant software updates (e.g., patches, service packs, and hot
  fixes). Flaws discovered during security assessments, continuous monitoring,
  incident response activities, or information system error handling, must also
  be  addressed expeditiously.

      Anytime new software code is introduced to a system there is the potential
  for unintended consequences. There have been documented instances where the
  application of a patch has caused problems with system integrity or
  availability.  Due to information system integrity and availability concerns,
  organizations must give careful consideration to the methodology used to carry
  out automatic updates.

      Unsupported software versions are not patched by vendors to address newly
  discovered security versions. An unpatched version is vulnerable to attack.
  "
  impact 0.7
  tag "gtitle": 'SRG-APP-000133-DB-000205'
  tag "gid": 'V-61539'
  tag "rid": 'SV-76029r2_rule'
  tag "stig_id": 'O121-C1-011100'
  tag "fix_id": 'F-67455r4_fix'
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
  tag "check": "When the Quarterly CPU is released, check the CPU Notice and
  note the specific patch number for the system.

  Then, issue the following command:

  SELECT patch_id, version, action, status, description from
  dba_registry_sqlpatch;

  This will generate the patch levels for the home and any specific patches that
  have been applied to it.

  If the currently installed patch levels are lower than the latest, this is a
  finding."
  tag "fix": "Follow the process below to apply the security patch.

  Log on to My Oracle Support.

  Select patches and download the specific patch number and corresponding MD5
  checksum. Once the patch is downloaded to the server, check the MD5 checksum to
  make sure the patch is valid.

  To check the MD5 Checksum in Linux/UNIX, the command is:
  $md5sum absolute_path_of_file_name - file_name is the complete location of the
  downloaded file.
  $md5sum /home/oracle/test.zip
  a34d8cd98f00cf24e9800998ecf823e4 /home/oracle/test.zip

  Once the checksum is validated, apply the patch:
  $ cd $ORACLE_HOME
  $ opatch apply

  Check that the patch was applied and the inventory was updated with the
  following command (UNIX/Linux):
  $ opatch lsinventory -detail

  Windows:
  opatch lsinventory –detail"

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  patches = sql.query('SELECT patch_id from dba_registry_sqlpatch;').column('patch_id')

  describe 'The oracle database installed patches' do
    subject { patches }
    it { should_not cmp nil }
  end
end
