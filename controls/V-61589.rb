USERS_ALLOWED_ACCESS_TO_DICTIONARY_TABLE = input('users_allowed_access_to_dictionary_table')
control 'V-61589' do
  title "The DBMS must restrict access to system tables and other configuration
  information or metadata to DBAs or other authorized users."
  desc "Applications employ the concept of least privilege for specific duties
  and information systems (including specific functions, ports, protocols, and
  services). The concept of least privilege is also applied to information system
  processes, ensuring that the processes operate at privilege levels no higher
  than necessary to accomplish required organizational missions and/or functions.
  Organizations consider the creation of additional processes, roles, and
  information system accounts as necessary to achieve least privilege.
  Organizations also apply least privilege concepts to the design, development,
  implementation, and operations of information systems.

      Administrative data includes DBMS metadata and other configuration and
  management data.  Unauthorized access to this data could result in unauthorized
  changes to database objects, access controls, or DBMS configuration.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000062-DB-000016'
  tag "gid": 'V-61589'
  tag "rid": 'SV-76079r2_rule'
  tag "stig_id": 'O121-C2-003900'
  tag "fix_id": 'F-67505r1_fix'
  tag "cci": ['CCI-000366', 'CCI-002220']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "nist": ['AC-5 c', 'Rev_4']
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
  tag "check": "Review user privileges to system tables and configuration data
  stored in the Oracle database.

  If non-DBA users are assigned privileges to access system tables and tables
  containing configuration data, this is a finding.

  To obtain a list of users and roles that have been granted access to any
  dictionary table, run the query:
  SELECT unique grantee from dba_tab_privs where table_name in
  (select table_name from dictionary)
  order by grantee;

  To obtain a list of dictionary tables and assigned privileges granted to a
  specific user or role, run the query:
  SELECT grantee, table_name, privilege from dba_tab_privs where table_name in
  (select table_name from dictionary)
  and grantee = '<applicable account>';"
  tag "fix": "Restrict accessibility of Oracle system tables and other
  configuration information or metadata to DBAs or other authorized users."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  users_with_dictionary_table_access = sql.query("SELECT unique grantee from dba_tab_privs where table_name in
  (select table_name from dictionary)
  order by grantee;").column('grantee').uniq
  if users_with_dictionary_table_access.empty?
    impact 0.0
    describe 'There are no oracle users allowed access to the dictionary table, control N/A' do
      skip 'There are no oracle users allowed access to the dictionary table, control N/A'
    end
  else
    users_with_dictionary_table_access.each do |user|
      describe "oracle users: #{user} with access to the dictionary table" do
        subject { user }
        it { should be_in USERS_ALLOWED_ACCESS_TO_DICTIONARY_TABLE }
      end
    end
  end
end
