control 'V-61419' do
  title "A minimum of two Oracle redo log groups/files must be defined and
  configured to be stored on separate, archived physical disks or archived
  directories on a RAID device."
  desc "The Oracle redo log files store the detailed information on changes
  made to the database. This information is critical to database recovery in case
  of a database failure."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61419'
  tag "rid": 'SV-75909r1_rule'
  tag "stig_id": 'O121-BP-021600'
  tag "fix_id": 'F-67335r1_fix'
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

  select count(*) from V$LOG;

  If the value of the count returned is less than 2, this is a finding.

  From SQL*Plus:

    select count(*) from V$LOG where members > 1;

  If the value of the count returned is less than 2 and a RAID storage device is
  not being used, this is a finding."
  tag "fix": "To define additional redo log file groups:

  From SQL*Plus (Example):

    alter database add logfile group 2
      ('diska:log2.log' ,
       'diskb:log2.log') size 50K;

  To add additional redo log file [members] to an existing redo log file group:

  From SQL*Plus (Example):

    alter database add logfile member 'diskc:log2.log'
    to group 2;

  Replace diska, diskb, diskc with valid, different disk drive specifications.

  Replace log#.log file with valid or custom names for the log files."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  describe sql.query('select count(*) from V$LOG;').column('count(*)') do
    it { should cmp >= 2 }
  end
end
