control 'V-61427' do
  title 'The Oracle REMOTE_OS_ROLES parameter must be set to FALSE.'
  desc  "Setting REMOTE_OS_ROLES to TRUE allows operating system groups to
  control Oracle roles. The default value of FALSE causes roles to be identified
  and managed by the database. If REMOTE_OS_ROLES is set to TRUE, a remote user
  could impersonate another operating system user over a network connection."
  impact 0.7
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61427'
  tag "rid": 'SV-75917r1_rule'
  tag "stig_id": 'O121-BP-022000'
  tag "fix_id": 'F-67343r1_fix'
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

  select value from v$parameter where name = 'remote_os_roles';

  If the returned value is not FALSE or not documented in the System Security
  Plan as required, this is a finding."
  tag "fix": "Document remote OS roles in the System Security Plan.

  If not required, disable use of remote OS roles.

  From SQL*Plus:

    alter system set remote_os_roles = FALSE scope = spfile;

  The above SQL*Plus command will set the parameter to take effect at next system
  startup."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("select value from v$parameter where name = 'remote_os_roles';").column('value')

  describe 'The oracle database REMOTE_OS_ROLES parameter' do
    subject { parameter }
    it { should cmp 'FALSE' }
  end
end
