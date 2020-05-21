control 'V-61605' do
  title "The DBMS must limit the number of consecutive failed logon attempts to
  3."
  desc "Anytime an authentication method is exposed,  to allow for the
  utilization of an application, there is a risk that attempts will be made to
  obtain unauthorized access.

      To defeat these attempts, organizations define the number of times a user
  account may consecutively fail a logon attempt. The organization also defines
  the period of time in which these consecutive failed attempts may occur.

      By limiting the number of failed logon attempts, the risk of unauthorized
  system access via user password guessing, otherwise known as brute forcing, is
  reduced. Limits are imposed by locking the account.

      More recent brute force attacks make attempts over long periods of time to
  circumvent intrusion detection systems and system account lockouts based
  entirely on the number of failed logons that are typically reset after a
  successful logon.

      Note that user authentication and account management must be done via an
  enterprise-wide mechanism whenever possible.  Examples of enterprise-level
  authentication/access mechanisms include, but are not limited to, Active
  Directory and LDAP.  This requirement applies to cases where it is necessary to
  have accounts directly managed by Oracle.

      Note also that a policy that places no limit on the length of the timeframe
  (for counting consecutive invalid attempts) does satisfy this requirement.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000065-DB-000025'
  tag "gid": 'V-61605'
  tag "rid": 'SV-76095r2_rule'
  tag "stig_id": 'O121-C2-005000'
  tag "fix_id": 'F-67521r3_fix'
  tag "cci": ['CCI-000044']
  tag "nist": ['AC-7 a', 'Rev_4']
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
  tag "check": "(This addresses both O121-C2-005000 and O121-C2-005200.)

  The limit on the number of consecutive failed logon attempts is defined in the
  profile assigned to a user.

  To see what profile is assigned to a user, enter the following query:
  SQL>SELECT profile FROM dba_users WHERE username = '&USERNAME'
  This will return the profile name assigned to that user.

  Now check the values assigned to the profile returned from the query above:
  SQL>SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE PROFILE LIKE
  '&PROFILE_NAME'

  Check the settings for FAILED_LOGIN_ATTEMPTS - this is the number of
  consecutive failed logon attempts before locking the Oracle user account. If
  the value is greater than 3, this is a finding."
  tag "fix": "(This addresses both O121-C2-005000 and O121-C2-005200.)

  Configure the DBMS settings to specify the maximum number of consecutive failed
  logon attempts to 3 (or less):
  ALTER PROFILE ORA_STIG_PROFILE LIMIT FAILED_LOGIN_ATTEMPTS 3;

  (ORA_STIG_PROFILE is available in DBA_PROFILES, starting with Oracle 12.1.0.2.
  Note: It remains necessary to create a customized replacement for the password
  validation function, ORA12C_STRONG_VERIFY_FUNCTION, if relying on this
  technique to verify password complexity.)"

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query = %{
    SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE PROFILE =
  '%<profile>s' AND RESOURCE_NAME = 'FAILED_LOGIN_ATTEMPTS'
  }

  user_profiles = sql.query('SELECT profile FROM dba_users;').column('profile').uniq

  user_profiles.each do |profile|
    password_lock_time = sql.query(format(query, profile: profile)).column('limit')

    describe "The oracle database limit for failed login attempts for profile: #{profile}" do
      subject { password_lock_time.first }
      it { should cmp <= input('failed_logon_attempts') }
    end
  end
  if user_profiles.empty?
    describe 'There are no user profiles, therefore this control is NA' do
      skip 'There are no user profiles, therefore this control is NA'
    end
  end
end
