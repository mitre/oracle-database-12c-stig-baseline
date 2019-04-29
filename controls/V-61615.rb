control 'V-61615' do
  title 'The DBMS must have allocated audit record storage capacity.'
  desc  "Applications need to be cognizant of potential audit log storage
  capacity issues. During the installation and/or configuration process,
  applications should detect and determine if adequate storage capacity has been
  allocated for audit logs.

      During the installation process, a notification may be provided to the
  installer indicating, based on the auditing configuration chosen and the amount
  of storage space allocated for audit logs, the amount of storage capacity
  available is not sufficient to meet storage requirements.

      When insufficient space in directories is allocated for audit records,
  database audit logs can fill up and begin to overwrite earlier logs, database
  activity can stop altogether, or auditing could fail and crucial tracking data
  could be lost.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000072-DB-000046'
  tag "gid": 'V-61615'
  tag "rid": 'SV-76105r1_rule'
  tag "stig_id": 'O121-C2-005700'
  tag "fix_id": 'F-67531r1_fix'
  tag "cci": ['CCI-001849']
  tag "nist": ['AU-4', 'Rev_4']
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
  tag "check": "Review the DBMS settings to determine whether audit logging is
  configured to produce logs consistent with the amount of space allocated for
  logging. If auditing will generate excessive logs so that they may outgrow the
  space reserved for logging, this is a finding.

  If file-based auditing is in use, check that sufficient space is available to
  support the file(s).  If not, this is a finding

  If standard, table-based auditing is used:  The audit logs are written to a
  table called AUD$, and if a Virtual Private Database is deployed, we also
  create a table called FGA_LOG$.  First check the current location of the audit
  trail tables.

      CONN / AS SYSDBA

      SELECT table_name, tablespace_name
      FROM   dba_tables
      WHERE  table_name IN ('AUD$', 'FGA_LOG$')
      ORDER BY table_name;

      TABLE_NAME                     TABLESPACE_NAME
      ------------------------------ ------------------------------
      AUD$                           SYSTEM
      FGA_LOG$                       SYSTEM

  If the tablespace name is SYSTEM, the table needs to be relocated to its own
  tablespace. Ensure that adequate space is allocated to that tablespace.

  If Unified Auditing is used:
  Audit logs are written to tables in the AUDSYS schema. The default tablespace
  for AUDSYS is USERS. A separate tablespace should be created to contain audit
  data. Ensure that adequate space is allocated to that tablespace."
  tag "fix": "Allocate sufficient disk space for file-based audit.

  Ensure that audit tables are in their own tablespaces and that the tablespaces
  have enough room for the volume of log data that will be produced."
  describe 'A manual review is required to ensure the DBMS has allocated audit record storage capacity' do
    skip 'A manual review is required to ensure the DBMS has allocated audit record storage capacity'
  end
end
