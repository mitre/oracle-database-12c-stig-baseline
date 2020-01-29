control 'V-61755' do
  title "The DBMS must support organizational requirements to encrypt
  information stored in the database and information extracted or derived from
  the database and stored on digital media."
  desc "When data is written to digital media, such as hard drives, mobile
  computers, external/removable hard drives, personal digital assistants,
  flash/thumb drives, etc., there is risk of data loss and/or compromise.

      An organizational assessment of risk guides the selection of media and
  associated information contained on that media requiring restricted access.
  Organizations need to document in policy and procedures the media requiring
  restricted access, individuals authorized to access the media, and the specific
  measures taken to restrict access.

      Fewer protection measures are needed for media containing information
  determined by the organization to be in the public domain, to be publicly
  releasable, or to have limited or no adverse impact if accessed by other than
  authorized personnel. In these situations, it is assumed the physical access
  controls where the media resides provide adequate protection.

      As part of a defense-in-depth strategy, the organization considers
  routinely encrypting information at rest on selected secondary storage devices.
  The decision whether to employ cryptography is the responsibility of the
  information owner/steward, who exercises discretion within the framework of
  applicable rules, policies, and law. The selection of the cryptographic
  mechanisms used is based upon maintaining the confidentiality and integrity of
  the information.

      The strength of mechanisms is commensurate with the classification and
  sensitivity of the information.

      Information at rest, when not encrypted, is open to compromise from
  attackers who have gained unauthorized access to the data files.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000188-DB-000121'
  tag "gid": 'V-61755'
  tag "rid": 'SV-76245r2_rule'
  tag "stig_id": 'O121-C2-016400'
  tag "fix_id": 'F-67671r1_fix'
  tag "cci": ['CCI-002262']
  tag "nist": ['AC-16 a', 'Rev_4']
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
  tag "check": "If encryption is not required for the database and data derived
  from it, this is not a finding.

  Review DBMS settings to determine whether data stored on the database is
  encrypted according to organizational requirements.

  If not, this is a finding.

  Check the following settings to see if FIPS 140-2 encryption is configured.  If
  encryption is not configured, check with the DBA and SYSTEM Administrator to
  see if other mechanisms or third-party products are deployed to encrypt data
  stored in the database.

  To see if Oracle is configured for FIPS 140-2 Transparent Data Encryption
  and/or DBMS_CRYPTO, enter the following SQL*Plus command:
  SHOW PARAMETER DBFIPS_140
  or the following SQL query:
  SELECT * FROM SYS.V$PARAMETER WHERE NAME = 'DBFIPS_140';
  If Oracle returns the value 'FALSE', or returns no rows, this is a finding.

  To see if there are encrypted tablespaces enter the following SQL*Plus command:
  SELECT * FROM V$ENCRYPTED_TABLESPACES;
  If no rows are returned, then there are no encrypted tablespaces.

  To see if there are encrypted columns within existing tables, enter the
  following SQL*Plus command:
  SELECT * FROM DBA_ENCRYPTED_COLUMNS;
  If no rows are returned, then there are no encrypted columns within existing
  tables.

  Note: For the Solaris platform, when DBFIPS_140 is FALSE, TDE (but not
  DBMS_CRYPTO) can still operate
  in a FIPS 140-compliant manner if FIPS 140 operation is enabled for the Solaris
  Cryptographic Framework."
  tag "fix": "Configure cryptographic functions to use FIPS 140-2-compliant
  algorithms and hashing functions.

  Configure the DBMS and/or the OS to encrypt data at rest according to the
  requirements of the organization.

  The strength requirements are dependent upon data classification.

  For unclassified data, where cryptography is required:
  AES 128 for encryption
  SHA 256 for hashing

  NSA has established the suite B encryption requirements for protecting National
  Security Systems (NSS) as follows.
  AES 128 for Secret
  AES 256 for Top Secret
  SHA 256 for Secret
  SHA 384 for Top Secret

  National Security System is defined as:
  (OMB Circular A-130) Any telecommunications or information system operated by
  the United States Government, the function, operation, or use of which (1)
  involves intelligence activities; (2) involves cryptologic activities related
  to national security; (3) involves command and control of military forces; (4)
  involves equipment that is an integral part of a weapon or weapons system; or
  (5) is critical to the direct fulfillment of military or intelligence missions,
  but excluding any system that is to be used for routine administrative and
  business applications (including payroll, finance, logistics, and personnel
  management applications).

  There is more information on this topic in the Oracle Database 12c Advanced
  Security Administrator's Guide, which may be found at
  https://docs.oracle.com/database/121/DBSEG/E48135-11.pdf.  (Note, however, that
  because of changes in Oracle's licensing policy, it is no longer necessary to
  purchase Oracle Advanced Security to use network encryption and advanced
  authentication.)

  FIPS 140-2 documentation can be downloaded from
  http://csrc.nist.gov/publications/PubsFIPS.html#140-2"

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("select * from v$parameter where name = 'DBFIPS_140c';").column('value')

  describe 'The oracle database DBFIPS_140c parameter' do
    subject { parameter }
    it { should_not be_empty }
  end

  encrypted_tablespaces = sql.query('SELECT * FROM V$ENCRYPTED_TABLESPACES;').column('MASTERKEYID')

  describe 'The oracle tablespaces that are encrypted' do
    subject { encrypted_tablespaces }
    it { should_not be_empty }
  end

  encrypted_colums = sql.query('SELECT * FROM DBA_ENCRYPTED_COLUMNS;').column('COLUMN_NAME')

  describe 'The oracle table columns that are encrypted' do
    subject { encrypted_colums }
    it { should_not be_empty }
  end
end
