control 'V-61507' do
  title "Credentials stored and used by the DBMS to access remote databases or
  applications must be authorized and restricted to authorized users."
  desc "Credentials defined for access to remote databases or applications may
  provide unauthorized access to additional databases and applications to
  unauthorized or malicious users."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61507'
  tag "rid": 'SV-75997r1_rule'
  tag "stig_id": 'O121-BP-025200'
  tag "fix_id": 'F-67423r1_fix'
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
  tag "check": "Review the list of defined database links generated from the
  DBMS.

  Compare to the list in the System Security Plan with the DBA.

  If no database links are listed in the database and in the System Security
  Plan, this check is not a finding.

  If any database links are defined in the DBMS, verify the authorization for the
  definition in the System Security Plan.

  If any database links exist that are not authorized or not listed in the System
  Security Plan, this is a finding."
  tag "fix": "Grant access to database links to authorized users or
  applications only.

  Document all database links access authorizations in the System Security Plan."

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
