control 'V-61689' do
  title "Recovery procedures and technical system features must exist to ensure
  recovery is done in a secure and verifiable manner."
  desc "Application recovery and reconstitution constitutes executing an
information system contingency plan comprised of activities that restore
essential missions and business functions.

    Database management systems and transaction-based processing systems are
examples of information systems that are transaction-based. Transaction
rollback and transaction journaling are examples of mechanisms supporting
transaction recovery.

    A DBMS may be vulnerable to use of compromised data or other critical files
during recovery. Use of compromised files could introduce maliciously altered
application code, relaxed security settings or loss of data integrity. Where
available, DBMS mechanisms to ensure use of only trusted files can help protect
the database from this type of compromise during DBMS recovery.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000144-DB-000101'
  tag "gid": 'V-61689'
  tag "rid": 'SV-76179r1_rule'
  tag "stig_id": 'O121-C2-012000'
  tag "fix_id": 'F-67603r1_fix'
  tag "cci": ['CCI-000553']
  tag "nist": ['CP-10 (2)', 'Rev_4']
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
  tag "check": "Review DBMS recovery procedures and technical system features
  to determine if mechanisms exist and are in place to specify use of trusted
  files during DBMS recovery.

  If recovery procedures do not exist or are not sufficient to ensure recovery is
  done in a secure and verifiable manner, this is a finding.

  If system features exist and are not employed or not employed sufficiently,
  this is a finding.

  If circumstances that can inhibit a trusted recovery are not documented and
  appropriate mitigating procedures have not been put in place, this is a finding.

  Review the database backup strategy with the system administrator.  Consider
  using Oracle RMAN with an encrypted backup to insure the backed up files can be
  trusted not to be compromised."
  tag "fix": "Implement DBMS recovery procedures and employ technical system
  features to specify trusted files during DBMS recovery.  Test the solution and
  review the site-specific criteria to ensure that the backup and recovery
  process uses trusted files.

  Ensure circumstances that can inhibit a trusted recovery are documented and
  appropriate mitigating procedures have been put in place.

  Oracle recommends using RMAN Backup and encrypting backup files.  With
  encrypted files stored on a mount point with limited access, the integrity of
  the files can be trusted.

  - - - - -
  Notes on Oracle Backup and Recovery Solutions

  When implementing a backup and recovery strategy, have the following solutions
  available:

  --  Recovery Manager (RMAN)
  Recovery Manager is fully integrated with the Oracle database to perform a
  range of backup and recovery activities, including maintaining an RMAN
  repository of historical data about backups. Can access RMAN through the
  command line or through Oracle Enterprise Manager.

  --  User-managed backup and recovery
  In this solution, perform backup and recovery with a mixture of host operating
  system commands and SQL*Plus recovery commands. Responsible for determining all
  aspects of when and how backups and recovery are done.

  --  Media management
  If not wanting to use RMAN with an encrypted backup, consider configuring RMAN
  to make backups to a media manager.  On most platforms, to back up to and
  restore from sequential media such as tape, must integrate a media manager with
  the Oracle database. Can use Oracle Secure Backup, which supports both database
  and file system backups to tape, as the media manager. See Oracle Secure Backup
  Administrator's Guide to learn how to set up RMAN for use specifically with
  Oracle Secure Backup.

  These solutions are supported by Oracle and are fully documented, but RMAN is
  the preferred solution for database backup and recovery. RMAN provides a common
  interface for backup tasks across different host operating systems and offers
  several backup techniques not available through user-managed methods.

  --  Incremental backups:
  An incremental backup stores only blocks changed since a previous backup.
  Thus, they provide more compact backups and faster recovery, thereby reducing
  the need to apply redo during data file media recovery. If enabling block
  change tracking, then can improve performance by avoiding full scans of every
  input data file. Can use the BACKUP INCREMENTAL command to perform incremental
  backups.

  --  Block media recovery:
  Can repair a data file with only a small number of corrupt data blocks without
  taking it off-line or restoring it from backup. Can use the RECOVER BLOCK
  command to perform block media recovery.

  --  Binary compression:
  A binary compression mechanism integrated into Oracle Database reduces the size
  of backups.

  --  Encrypted backups:
  RMAN uses backup encryption capabilities integrated into Oracle Database to
  store backup sets in an encrypted format. To create encrypted backups on disk,
  the database must use the Advanced Security Option. To create encrypted backups
  directly on tape, RMAN must use the Oracle Secure Backup SBT interface but does
  not require the Advanced Security Option.

  --  Automated database duplication:
  Easily creates a copy of the database, supporting various storage
  configurations, including direct duplication between ASM databases.

  --  Cross-platform data conversion:
  Whether using RMAN or user-managed methods, can supplement physical backups
  with logical backups of schema objects made with Data Pump Export utility. Can
  later use Data Pump Import to re-create data after restore and recovery.
  Logical backups are mostly beyond the scope of the backup and recovery
  documentation."
  describe 'A manual review is required to ensure recovery procedures and technical system features exist to ensure
    recovery is done in a secure and verifiable manner' do
    skip 'A manual review is required to ensure recovery procedures and technical system features exist to ensure
    recovery is done in a secure and verifiable manner'
  end
end
