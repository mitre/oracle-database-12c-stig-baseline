control 'V-61667' do
  title "The DBMS must protect audit data records and integrity by using
  cryptographic mechanisms."
  desc "Protection of audit records and audit data is of critical importance.
  Cryptographic mechanisms are the industry-established standard used to protect
  the integrity of audit data. An example of a cryptographic mechanism is the
  computation and application of a cryptographic-signed hash using asymmetric
  cryptography.

      Non-repudiation protects individuals against later claims by an author of
  not having performed a particular action, a sender of not having transmitted a
  message, a receiver of not having received a message, or a signatory of not
  having signed a document.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000126-DB-000171'
  tag "gid": 'V-61667'
  tag "rid": 'SV-76157r2_rule'
  tag "stig_id": 'O121-C2-010100'
  tag "fix_id": 'F-67581r5_fix'
  tag "cci": ['CCI-001350']
  tag "nist": ['AU-9 (3)', 'Rev_4']
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
  logging.

  If auditing will generate excessive logs so that they may outgrow the space
  reserved for logging, this is a finding.

  If file-based auditing is in use, check that the file(s) is/are encrypted by
  the operating system/file system.

  If not, this is a finding

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
  tag "fix": "For file-based auditing (OS, XML, or XML,EXTENDED), implement
  operating system/file system encryption for the audit file.

  For table-based auditing, deploy the audit tables in an encrypted tablespace.

  - - - - -
  If auditing is not enabled, use the following steps to enable auditing.

  sqlplus connect as sysdba

  Turn on Oracle audit

  a. If the database uses an spfile

  SQL> alter system set audit_trail=DB,EXTENDED scope=spfile ;
  System altered.

  b. if database uses pfile, modify init<Sid>.ora directly.
  For these changes to take place, the database must be restarted.

  Next we create an encrypted tablespace. Before tablespaces can be encrypted or
  decrypted, a master encryption key must be generated or set. The tablespace
  master encryption key is stored in an external security module and is used to
  encrypt the TDE tablespace encryption keys.

  - - - - -

  Caution: Do not attempt to encrypt Oracle internal objects such as the SYSTEM,
  SYSAUX, UNDO, or TEMP tablespaces.  Oracle does not support this with TDE.
  When moving AUD$ to a new tablespace, be aware that associated LOB objects will
  also need to be moved. Finally, when upgrading, the AUD$ table and LOBs will
  need to be moved back to the SYSTEM tablespace or the upgrade will fail.

  - - - - -

  Check to ensure that the ENCRYPTION_WALLET_LOCATION (or WALLET_LOCATION)
  parameter in the sqlnet.ora file points to the correct software wallet
  location. (Note: This assumes that a single sqlnet.ora file, in the default
  location, is in use. Please see the supplemental file \"Non-default sqlnet.ora
  configurations.pdf\" for how to find multiple and/or differently located
  sqlnet.ora files.) For example:

  ENCRYPTION_WALLET_LOCATION=
  (SOURCE=(METHOD=FILE)(METHOD_DATA=
  (DIRECTORY=/app/wallet)))

  If the ENCRYPTION_WALLET_LOCATION parameter is not set, then it attempts to use
  the keystore in the location that is specified by the parameter WALLET_LOCATION.

  If the WALLET_LOCATION parameter is also not set, then Oracle Database looks
  for a keystore at the default database location, which is
  ORACLE_BASE/admin/DB_UNIQUE_NAME/wallet or
  ORACLE_HOME/admin/DB_UNIQUE_NAME/wallet. (DB_UNIQUE_NAME is the unique name of
  the database specified in the initialization parameter file.) When the keystore
  location is not set in the sqlnet.ora file, then the V$ENCRYPTION_WALLET view
  displays the default location. Can check the location and status of the
  keystore in the V$ENCRYPTION_WALLET view.

  Oracle Database 12c Release 1 (12.1) uses the same master encryption key for
  both TDE column encryption and TDE tablespace encryption. When issuing the
  ALTER SYSTEM SET ENCRYPTION KEY command, a unified master encryption key is
  created for both TDE column encryption and TDE tablespace encryption.

  Resetting the Tablespace Master Encryption Key

  Oracle Database 12c Release 1 (12.1) uses a unified master encryption key for
  both TDE column encryption and TDE tablespace encryption. When resetting
  (rekeying) the master encryption key for TDE column encryption, the master
  encryption key for TDE tablespace encryption also gets reset. The ALTER SYSTEM
  SET ENCRYPTION KEY command resets the tablespace master encryption key. Before
  creating an encrypted tablespace, the Oracle wallet containing the tablespace
  master encryption key must be open. The wallet must also be open before
  accessing data in an encrypted tablespace. The security administrator needs to
  open the Oracle wallet after starting the Oracle instance. A restart of the
  Oracle instance requires the security administrator to open the wallet again.
  The security administrator also needs to open the wallet before performing
  database recovery operations. This is because background processes may require
  access to encrypted redo and undo logs. When performing database recovery, the
  wallet must be opened before opening the database. This is illustrated in the
  following statements:

  SQL> STARTUP MOUNT;
  SQL> ALTER SYSTEM SET ENCRYPTION WALLET OPEN IDENTIFIED BY \"password\";
  SQL> ALTER DATABASE OPEN;

  Can also choose to use auto logon wallets if the environment does not require
  the extra security provided by a wallet that needs to be explicitly opened;
  however, this is not the recommended practice.

  Creating the wallet/keystore

  SQL> ADMINISTER KEY MANAGEMENT CREATE KEYSTORE '/app/wallet' IDENTIFIED BY
  password;

  keystore altered.

  Set the TDE Master Encryption Key in the Software Keystore

  SQL> ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY password WITH BACKUP USING
  'backup_identifier';

  keystore altered.

  Creating an Encrypted Tablespace

  The CREATE TABLESPACE command enables the creation of an encrypted tablespace.
  The permanent_tablespace_clause enables choosing the encryption algorithm and
  the key length for encryption. The ENCRYPT keyword in the storage_clause
  encrypts the tablespace. The following syntax illustrates this:

  CREATE
  [ BIGFILE | SMALLFILE ]
  { permanent_tablespace_clause
  | temporary_tablespace_clause
  | undo_tablespace_clause
  } ;

  Where, permanent_tablespace_clause=TABLESPACE , ENCRYPTION [USING algorithm]
  storage_clause
  Where, storage_clause=[ENCRYPT] where:

  The encryption algorithm can have one of the following values:

  3DES168
  AES128
  AES192
  AES256

  The key lengths are included in the names of the algorithms themselves. If no
  encryption algorithm is specified, the default encryption algorithm is used.
  The default encryption algorithm is AES128.

  Note: The ENCRYPTION keyword in the permanent_tablespace_clause is used to
  specify the encryption algorithm. The ENCRYPT keyword in the storage_clause
  actually encrypts the tablespace. For security reasons, a tablespace cannot be
  encrypted with the NO SALT option.

  Commands to create Encrypted Tablespace

  CREATE TABLESPACE securespace
  DATAFILE '/home/user/oradata/secure01.dbf'
  SIZE 150M
  ENCRYPTION USING '3DES168'
  DEFAULT STORAGE(ENCRYPT);

  This creates a tablespace called securespace2 using an algorithm of 3DES168.

  Cannot encrypt an existing tablespace. However, can import data into an
  encrypted tablespace using the Oracle Data Pump utility. Can also use SQL
  commands like CREATE TABLE...AS SELECT...or ALTER TABLE...MOVE... to move data
  into an encrypted tablespace. The CREATE TABLE...AS SELECT... command enables
  the creation of a table from an existing table. The ALTER TABLE...MOVE...
  command enables the move of a table into the encrypted tablespace.

  Then we move the sys.aud$ from system tablespace to securespace tablespace.

  SQL> exec DBMS_AUDIT_MGMT.SET_AUDIT_TRAIL_LOCATION(audit_trail_type =>
  DBMS_AUDIT_MGMT.AUDIT_TRAIL_AUD_STD, audit_trail_location_value =>
  'securespace');

  PL/SQL procedure successfully completed.

  Then check the tablespace the table is stored in.

  SQL> SELECT table_name, tablespace_name FROM dba_tables WHERE table_name
  ='AUD$';

  TABLE_NAME TABLESPACE_NAME
  ---------------------------- ------------------------
  AUD$ SECURESPACE"
  describe 'A manual review is required to ensure the DBMS must protect audit data records and integrity by using
    cryptographic mechanisms' do
    skip 'A manual review is required to ensure the DBMS must protect audit data records and integrity by using
    cryptographic mechanisms'
  end
end
