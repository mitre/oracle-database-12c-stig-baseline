control 'V-61853' do
  title "Disk space used by audit trail(s) must be monitored; audit records
  must be regularly or continuously off-loaded to a centralized log management
  system."
  desc "It is critical when a system is at risk of failing to process audit
  logs as required; it detects and takes action to mitigate the failure. Audit
  processing failures include:  software/hardware errors, failures in the audit
  capturing mechanisms, and audit storage capacity being reached or exceeded.
  Applications are required to be capable of either directly performing or
  calling system-level functionality performing defined actions upon detection of
  an application audit log processing failure.

      The Security Requirements Guide says, \"A failure of database auditing will
  result in either the database continuing to function without auditing or in a
  complete halt to database operations. The database must be capable of taking
  organization-defined actions to avoid either a complete halt to processing or
  processing transactions in an unaudited manner.\"

      This STIG requirement mandates the implementation of a method to mitigate
  Oracle's inability to automatically reuse audit trail space on a first-in,
  first-out basis.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000109-DB-000049'
  tag "gid": 'V-61853'
  tag "rid": 'SV-76343r1_rule'
  tag "stig_id": 'O121-N2-008601'
  tag "fix_id": 'F-67769r1_fix'
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
  tag "check": "Review the procedures, manual and/or automated, for monitoring
  the space used by audit trail(s) and for off-loading audit records to a
  centralized log management system.

  If the procedures do not exist, this is a finding.

  If the procedures exist, request evidence that they are followed.  If the
  evidence indicates that the procedures are not followed, this is a finding.

  If the procedures exist, inquire if the system has ever run out of audit trail
  space in the last two years or since the last system upgrade, whichever is more
  recent.  If it has run out of space in this period, and the procedures have not
  been updated to compensate, this is a finding."
  tag "fix": "Modify DBMS, OS, or third-party logging application settings to
  alert appropriate personnel when a specific percentage of log storage capacity
  is reached.

  For ease of management, it is recommended that the audit tables be kept in a
  dedicated tablespace.

  If Oracle Enterprise Manager is in use, the capability to issue such an alert
  is built in and configurable via the console so an email can be sent to a
  designated administrator.

  If Enterprise Manager is unavailable, the following script can be used to
  monitor storage space; this can be combined with additional code to email the
  appropriate administrator so they can take action.

  sqlplus connect as sysdba

  set pagesize 300
  set linesize 120
  column sumb format 9,999,999,999,999
  column extents format 999999
  column bytes format 9,999,999,999,999
  column largest format 9,999,999,999,999
  column Tot_Size format 9,999,999,999,999
  column Tot_Free format 9,999,999,999,999
  column Pct_Free format 9,999,999,999,999
  column Chunks_Free format 9,999,999,999,999
  column Max_Free format 9,999,999,999,999
  set echo off
  spool TSINFO.txt
  PROMPT  SPACE AVAILABLE IN TABLESPACES
  select a.tablespace_name,sum(a.tots) Tot_Size,
  sum(a.sumb) Tot_Free,
  sum(a.sumb)*100/sum(a.tots) Pct_Free,
  sum(a.largest) Max_Free,sum(a.chunks) Chunks_Free
  from
  (
  select tablespace_name,0 tots,sum(bytes) sumb,
  max(bytes) largest,count(*) chunks
  from dba_free_space a
  group by tablespace_name
  union
  select tablespace_name,sum(bytes) tots,0,0,0 from
  dba_data_files
  group by tablespace_name) a
  group by a.tablespace_name;

   Sample Output

  SPACE AVAILABLE IN TABLESPACES

   TABLESPACE_NAME                     TOT_SIZE     TOT_FREE     PCT_FREE
  MAX_FREE     CHUNKS_FREE
   ------------------------------      ------------ ------------ ------------
  ------------ ------------
  DES2                                 41,943,040   30,935,040       74
  30,935,040        1
  DES2_I                               31,457,280   23,396,352       74
  23,396,352        1
  RBS                                  60,817,408   57,085,952       94
  52,426,752       16
  SYSTEM                               94,371,840    5,386,240        6
  5,013,504        3
  TEMP                                    563,200      561,152      100
  133,120        5
  TOOLS                               120,586,240   89,407,488       74
  78,190,592       12
  USERS                                 1,048,576       26,624        3
  26,624        1"
  describe 'A manual review is required to ensure the Disk space used by audit trail(s) is monitored, and that audit records
    are regularly or continuously off-loaded to a centralized log management system' do
    skip 'A manual review is required to ensure the Disk space used by audit trail(s) is monitored, and that audit records
    are regularly or continuously off-loaded to a centralized log management system'
  end
end
