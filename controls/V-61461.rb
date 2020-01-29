control 'V-61461' do
  title "Application owner accounts must have a dedicated application
  tablespace."
  desc "Separation of tablespaces by application helps to protect the
  application from resource contention and unauthorized access that could result
  from storage space reuses or host system access controls. Application data must
  be stored separately from system and custom user-defined objects to facilitate
  administration and management of its data storage. The SYSTEM tablespace must
  never be used for application data storage in order to prevent resource
  contention and performance degradation."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61461'
  tag "rid": 'SV-75951r3_rule'
  tag "stig_id": 'O121-BP-023700'
  tag "fix_id": 'F-67377r1_fix'
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
  tag "check": "Run the SQL query:

  select distinct owner, tablespace_name
  from dba_SEGMENTS
  where owner not in
  (<list of non-applicable accounts>)
  order by tablespace_name;

  (With respect to the list of special accounts that are excluded from this
  requirement, it is expected that the DBA will maintain the list to suit local
  circumstances, adding special accounts as necessary and removing any that are
  not supposed to be in use in the Oracle deployment that is under review.)

  Review the list of returned table owners with the tablespace used.

  If any of the owners listed are not default Oracle accounts and use the SYSTEM
  or any other tablespace not dedicated for the application’s use, this is a
  finding.

  Look for multiple applications that may share a tablespace.

  If no records were returned, ask the DBA if any applications use this database.

  If no applications use the database, this is not a finding.

  If there are applications that do use the database or if the application uses
  the SYS or other default account and SYSTEM tablespace to store its objects,
  this is a finding."
  tag "fix": "Create and assign dedicated tablespaces for the storage of data
  by each application using the CREATE TABLESPACE command."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  application_owners = sql.query("select distinct owner
  from dba_SEGMENTS;").column('owner').uniq
  if application_owners.empty?
    impact 0.0
    describe 'There are no oracle db application owners, therefore control N/A' do
      skip 'There are no oracle db application owners, therefore control N/A'
    end
  else
    application_owners.each do |user|
      describe "oracle db application owners: #{user}" do
        subject { user }
        it { should be_in input('allowed_application_owners') }
      end
    end
  end
end
