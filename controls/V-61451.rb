control 'V-61451' do
  title 'Unauthorized database links must not be defined and active.'
  desc  "DBMS links provide a communication and data transfer path definition
  between two databases that may be used by malicious users to discover and
  obtain unauthorized access to remote systems. Database links between production
  and development DBMSs provide a means for developers to access production data
  not authorized for their access or to introduce untested or unauthorized
  applications to the production database. Only protected, controlled, and
  authorized downloads of any production data to use for development may be
  allowed. Only applications that have completed the configuration management
  process may be introduced by the application object owner account to the
  production system."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61451'
  tag "rid": 'SV-75941r1_rule'
  tag "stig_id": 'O121-BP-023200'
  tag "fix_id": 'F-67367r1_fix'
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
  select db_link||': '||host from dba_db_links;

  If no links are returned, this check is not a finding.

  Review documentation for definitions of authorized database links to external
  interfaces.

  The documentation should include:

  - Any remote access to the database
  - The purpose or function of the remote connection
  - Any access to data or procedures stored externally to the local DBMS
  - Any network ports or protocols used by remote connections, whether the remote
  connection is to a production, test, or development system
  - Any security accounts used by DBMS to access remote resources or objects

  If any unauthorized database links are defined or the definitions do not match
  the documentation, this is a finding.

  Note: findings for production-development links under this check are assigned
  to the production database only.

  If any database links are defined between the production database and any test
  or development databases, this is a finding.

  If remote interface documentation does not exist or is incomplete, this is a
  finding."
  tag "fix": "Document all remote or external interfaces used by the DBMS to
  connect to or allow connections from remote or external sources.

  Include with the documentation as appropriate, any network ports or protocols,
  security accounts, and the sensitivity of any data exchanged.

  Do not define or configure database links between production databases and test
  or development databases.

  Note: Oracle Database Advanced Replication is deprecated in Oracle Database
  12c. Use Oracle GoldenGate to replace all features of Advanced Replication,
  including multimaster replication, updatable materialized views, hierarchical
  materialized views, and deployment templates."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  db_links = sql.query('SELECT DB_LINK FROM DBA_DB_LINKS;').column('db_link').uniq
  if db_links.empty?
    impact 0.0
    describe 'There are no oracle database links defined, control N/A' do
      skip 'There are no oracle database links defined, control N/A'
    end
  else
    db_links.each do |link|
      describe "The defined oracle database link: #{link}" do
        subject { link }
        it { should be_in input('allowed_db_links') }
      end
    end
  end
end
