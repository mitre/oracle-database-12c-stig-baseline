control 'V-61425' do
  title 'The Oracle REMOTE_OS_AUTHENT parameter must be set to FALSE.'
  desc  "Setting this value to TRUE allows operating system authentication over
  an unsecured connection. Trusting remote operating systems can allow a user to
  impersonate another operating system user and connect to the database without
  having to supply a password. If REMOTE_OS_AUTHENT is set to true, the only
  information a remote user needs to connect to the database is the name of any
  user whose account is setup to be authenticated by the operating system."
  impact 0.7
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61425'
  tag "rid": 'SV-75915r1_rule'
  tag "stig_id": 'O121-BP-021900'
  tag "fix_id": 'F-67341r1_fix'
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

  select value from v$parameter where name = 'remote_os_authent';

  If the value returned does not equal FALSE, this is a finding."
  tag "fix": "Document remote OS authentication in the System Security Plan.

  If not required or not mitigated to an acceptable level, disable remote OS
  authentication.

  From SQL*Plus:

    alter system set remote_os_authent = FALSE scope = spfile;

  The above SQL*Plus command will set the parameter to take effect at next system
  startup."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("select value from v$parameter where name = 'remote_os_authent';").column('value')

  describe 'The oracle database REMOTE_OS_AUTHENT parameter' do
    subject { parameter }
    it { should cmp 'FALSE' }
  end
end
