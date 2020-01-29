control 'V-61529' do
  title "Remote database or other external access must use fully-qualified
  names."
  desc  "The Oracle GLOBAL_NAMES parameter is used to set the requirement for
  database link names to be the same name as the remote database whose connection
  they define. By using the same name for both, ambiguity is avoided and
  unauthorized or unintended connections to remote databases are less likely."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61529'
  tag "rid": 'SV-76019r1_rule'
  tag "stig_id": 'O121-BP-026300'
  tag "fix_id": 'F-67445r1_fix'
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

  select value from v$parameter where name = 'global_names';

  If the value returned is FALSE, this is a finding."
  tag "fix": "From SQL*Plus:

  alter system set global_names = TRUE scope = spfile;

  Note: This parameter, if changed, will affect all currently defined Oracle
  database links.

  The above SQL*Plus command will set the parameter to take effect at next system
  startup."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("select value from v$parameter where name = 'global_names';").column('value')

  describe 'The oracle database GLOBAL_NAMES parameter' do
    subject { parameter }
    it { should_not cmp 'FALSE' }
  end
end
