control 'V-61417' do
  title "A minimum of two Oracle control files must be defined and configured
  to be stored on separate, archived disks (physical or virtual) or archived
  partitions on a RAID device."
  desc "Oracle control files are used to store information critical to Oracle
database integrity. Oracle uses these files to maintain time synchronization of
database files as well as at system startup to verify the validity of system
data and log files. Loss of access to the control files can affect database
availability, integrity and recovery."
  impact 0.3
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61417'
  tag "rid": 'SV-75907r3_rule'
  tag "stig_id": 'O121-BP-021500'
  tag "fix_id": 'F-67333r1_fix'
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
  tag "check": "From SQL*Plus:

  select name from v$controlfile;

  DoD guidance recommends:

  2a. Each control file is to be located on separate, archived physical or
  virtual storage devices.

  OR

  2b. Each control file is to be located on separate, archived directories within
  one or more RAID devices.

  3. The Logical Paths for each control file should differ at the highest level
  supported by the configuration, for example:

  UNIX
  /ora03/app/oracle/{SID}/control/control01.ctl
  /ora04/app/oracle/{SID}/control/control02.ctl

  Windows
  D:/oracle/{SID}/control/control01.ctl
  E:/oracle/{SID}/control/control02.ctl

  If the minimum listed above is not met, this is a finding.

  Consult with the SA or DBA to determine that the mount points or partitions
  referenced in the file paths indicate separate physical disks or directories on
  RAID devices.

  Note: Distinct does not equal dedicated. May share directory space with other
  Oracle database instances if present."
  tag "fix": "To prevent loss of service during disk failure, multiple copies
  of Oracle control files must be maintained on separate disks in archived
  directories or on separate, archived directories within one or more RAID
  devices.

  Adding or moving a control file requires careful planning and execution.

  Consult and follow the instructions for creating control files in the Oracle
  Database Administrator's Guide, under Steps for Creating New Control Files."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  controlfiles = sql.query('select name from v$controlfile;').column('name')
  partitions = []

  controlfiles.each do |files|
    file = files[1..-1]
    get_pos_slash = file.index('/')
    partition = file[0..get_pos_slash]
    partitions.push(partition)
  end

  control_file1_partition = partitions[0]
  control_file2_partition = partitions[1]

  describe "The oracable control file permission: #{control_file1_partition}" do
    subject { control_file1_partition }
    it { should_not cmp control_file2_partition }
  end
end
