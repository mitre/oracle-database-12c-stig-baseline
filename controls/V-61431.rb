control 'V-61431' do
  title "The Oracle REMOTE_LOGIN_PASSWORDFILE parameter must be set to
  EXCLUSIVE or NONE."
  desc "The REMOTE_LOGIN_PASSWORDFILE setting of \"NONE\" disallows remote
  administration of the database. The REMOTE_LOGIN_PASSWORDFILE setting of
  \"EXCLUSIVE\" allows for auditing of individual DBA logons to the SYS account.
  If not set to \"EXCLUSIVE\", remote connections to the database as \"internal\"
  or \"as SYSDBA\" are not logged to an individual account."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61431'
  tag "rid": 'SV-75921r2_rule'
  tag "stig_id": 'O121-BP-022200'
  tag "fix_id": 'F-67347r2_fix'
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

  select value from v$parameter where upper(name) = 'REMOTE_LOGIN_PASSWORDFILE';

  If the value returned does not equal 'EXCLUSIVE' or 'NONE', this is a finding."
  tag "fix": "Disable use of the REMOTE_LOGIN_PASSWORDFILE where remote
  administration is not authorized by specifying a value of NONE.

  If authorized, restrict use of a password file to exclusive use by each
  database by specifying a value of EXCLUSIVE.

  From SQL*Plus:

   alter system set REMOTE_LOGIN_PASSWORDFILE = 'EXCLUSIVE' scope = spfile;

    OR

  alter system set REMOTE_LOGIN_PASSWORDFILE = 'NONE' scope = spfile;

  The above SQL*Plus command will set the parameter to take effect at next system
  startup."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("select value from v$parameter where upper(name) = 'REMOTE_LOGIN_PASSWORDFILE';").column('value')

  describe.one do
    describe 'The oracle database REMOTE_LOGIN_PASSWORDFILE parameter' do
      subject { parameter }
      it { should cmp 'EXCLUSIVE' }
    end

    describe 'The oracle database REMOTE_LOGIN_PASSWORDFILE parameter' do
      subject { parameter }
      it { should cmp 'NONE' }
    end
  end
end
