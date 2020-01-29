control 'V-61415' do
  title 'Fixed user and public database links must be authorized for use.'
  desc  "Database links define connections that may be used by the local
  database to access remote Oracle databases. These links provide a means for a
  compromise to the local database to spread to remote databases in the
  distributed database environment. Limiting or eliminating use of database links
  where they are not required to support the operational system can help isolate
  compromises to the local or a limited number of databases."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61415'
  tag "rid": 'SV-75905r2_rule'
  tag "stig_id": 'O121-BP-021400'
  tag "fix_id": 'F-67331r1_fix'
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

  select owner||': '||db_link from dba_db_links;

  If no records are returned from the first SQL statement, this check is not a
  finding.

  Confirm the public and fixed user database links listed are documented in the
  System Security Plan, are authorized by the ISSO, and are used for replication
  or operational system requirements.

  If any are not, this is a finding.
  "
  tag "fix": "Document all authorized connections from the database to remote
  databases in the System Security Plan.

  Remove all unauthorized remote database connection definitions from the
  database.

  From SQL*Plus:

    drop database link [link name];
  OR
    drop public database link [link name];

  Review remote database connection definitions periodically and confirm their
  use is still required and authorized."

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
