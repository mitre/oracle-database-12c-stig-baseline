control 'V-61763' do
  title "The DBMS must protect the integrity of publicly available information
  and applications."
  desc "The purpose of this control is to ensure organizations explicitly
  address the protection needs for public information and applications with such
  protection likely being implemented as part of other security controls.

      Databases designed to contain publicly available information, though not
  concerned with confidentiality, must still maintain the integrity of the data
  they house. If data available to the public is not protected from unauthorized
  modification, then it cannot be trusted by those accessing it.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000201-DB-000145'
  tag "gid": 'V-61763'
  tag "rid": 'SV-76253r1_rule'
  tag "stig_id": 'O121-C2-017100'
  tag "fix_id": 'F-67679r1_fix'
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
  tag "check": "Determine whether the database houses and distributes
  information to the public. Review DBMS settings to determine whether controls
  exist to protect the integrity of publicly available information.

  If not, this is a finding.

  - - - - -
  All of the permissions and policies we would employ to protect information
  would be in play, like access control mechanisms, auditing, and password
  protection.  For data that is for display or download to the public for their
  informational needs, it may be appropriate to place the data in a read-only
  tablespace.  This will provide the DBA with the ability to modify content as
  needed by modifying the tablespace from read-only to read-write in the event
  the content needs to be modified.  Check with the Application Developer to see
  what tables are used to store the data and/or content that is displayed to the
  public.  Then find the tablespace name the data objects are stored in.

  $ sqlplus connect as sysdba

  SQL> SELECT table_name, tablespace_name from dba_tables where upper(table_name)
  like &tablename_from_developer;

  For better performance while accessing data in a read-only tablespace, can
  issue a query that accesses all of the blocks of the tables in the tablespace
  just before making it read-only. A simple query, such as SELECT COUNT (*),
  executed against each table ensures that the data blocks in the tablespace can
  be subsequently accessed most efficiently. This eliminates the need for the
  database to check the status of the transactions that most recently modified
  the blocks.

  The following statement makes the flights tablespace read-only:

  ALTER TABLESPACE flights READ ONLY;

  Can issue the ALTER TABLESPACE...READ ONLY statement while the database is
  processing transactions. After the statement is issued, the tablespace is put
  into a transitional read-only state. No transactions are allowed to make
  further changes (using DML statements) to the tablespace.

  If a transaction attempts further changes, it is terminated and rolled back.
  However, transactions that already made changes and that attempt no further
  changes are allowed to commit or roll back.

  The ALTER TABLESPACE...READ ONLY statement waits for the following transactions
  to either commit or roll back before returning: transactions that have pending
  or uncommitted changes to the tablespace and that were started before the
  statement was issued.

  If a transaction started before the statement remains active, but rolls back to
  a savepoint, rolling back its changes to the tablespace, then the statement no
  longer waits for this active transaction."
  tag "fix": "Apply appropriate controls to protect the integrity of publicly
  available information.

  - - - - -
  If the appropriate controls include placing the data in a read-only tablespace,
  proceed as follows.

  After we figure out the tablespace the data object is stored in:
  $ sqlplus connect as sysdba
  SQL> SELECT table_name, tablespace_name from dba_tables where upper(table_name)
  like &tablename_from_developer;

  Once we get the name of the tablespace where all of the important data is
  stored, alter the tablespace to be read-only.
  SQL> ALTER TABLESPACE &tablespace_where_data_is READ ONLY;

  The following statement makes the flights tablespace read-only:
   ALTER TABLESPACE flights READ ONLY;

  Can issue the ALTER TABLESPACE...READ ONLY statement while the database is
  processing transactions. After the statement is issued, the tablespace is put
  into a transitional read-only state. No transactions are allowed to make
  further changes (using DML statements) to the tablespace. If a transaction
  attempts further changes, it is terminated and rolled back. However,
  transactions that already made changes and that attempt no further changes are
  allowed to commit or roll back.

  The ALTER TABLESPACE...READ ONLY statement waits for the following transactions
  to either commit or roll back before returning: transactions that have pending
  or uncommitted changes to the tablespace and that were started before the
  statement was issued. If a transaction started before the statement remains
  active, but rolls back to a savepoint, rolling back its changes to the
  tablespace, then the statement no longer waits for this active transaction."
  describe 'A manual review is required to ensure the DBMS protects the integrity of publicly available information
    and applications.' do
    skip 'A manual review is required to ensure the DBMS protects the integrity of publicly available information
    and applications.'
  end
end
