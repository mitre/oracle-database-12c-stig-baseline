control 'V-61717' do
  title 'The DBMS must disable user accounts after 35 days of inactivity.'
  desc  "Password complexity, or strength, is a measure of the effectiveness of
  a password in resisting attempts at guessing and brute-force attacks.

      To meet password policy requirements, passwords need to be changed at
  specific policy-based intervals.

      If the information system or application allows the user to consecutively
  reuse their password when that password has exceeded its defined lifetime, the
  end result is a password that is not changed as per policy requirements.

      Unused or expired DBMS accounts provide a means for undetected,
  unauthorized access to the database.

      Note that user authentication and account management must be done via an
  enterprise-wide mechanism whenever possible.  Examples of enterprise-level
  authentication/access mechanisms include, but are not limited to, Active
  Directory and LDAP  This requirement applies to cases where it is necessary to
  have accounts directly managed by Oracle.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000163-DB-000113'
  tag "gid": 'V-61717'
  tag "rid": 'SV-76207r2_rule'
  tag "stig_id": 'O121-C2-013800'
  tag "fix_id": 'F-67633r3_fix'
  tag "cci": ['CCI-000795']
  tag "nist": ['IA-4 e)', 'Rev_4']
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
  tag "check": "If all user accounts are managed and authenticated by the OS or
  an enterprise-level authentication/access mechanism, and not by Oracle, this is
  not a finding.

  For accounts managed by Oracle, check DBMS settings to determine if accounts
  can be automatically disabled by the system after 35 days of inactivity. Also,
  ask the DBA if an alternative method, such as a stored procedure run daily, to
  disable Oracle-managed accounts inactive for more than 35 days, has been
  deployed.

  If the ability to disable accounts after 35 days of inactivity, by either of
  these means, does not exist, this is a finding.

  - - - - -

  Check to see what profile each user is associated with, if any, with this query:

  select username, profile from dba_users order by 1,2;

  Then check the profile to see what the password_life_time is set to in the
  table dba_profiles; the password_life_time is a value stored in the LIMIT
  column, and identified by the value PASSWORD_LIFE_TIME in the RESOURCE_NAME
  column.

  SQL>select profile, resource_name, resource_type, limit from dba_profiles where
  upper(resource_name) = 'PASSWORD_LIFE_TIME';"
  tag "fix": "For accounts managed by Oracle, determine if it is practical and
  acceptable to require a password change every 35 days or fewer, rather than the
  standard 60 days (as specified in SRG-APP-000174-DB-000080).  If it is, issue
  the statement:

  ALTER PROFILE PPPPPP LIMIT PASSWORD_LIFE_TIME 35;
  (See the Oracle-provided $ORACLE_HOME/rdbms/admin/secconf.sql script for
  examples.)

  If password changes every 35 days or fewer are unacceptable or impractical,
  implement an alternative method, such as a stored procedure run daily, to
  disable accounts inactive for more than 35 days."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query = %{
    SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE PROFILE =
  '%<profile>s' AND RESOURCE_NAME = 'PASSWORD_LIFE_TIME'
  }

  user_profiles = sql.query('SELECT profile FROM dba_users;').column('profile').uniq

  user_profiles.each do |profile|
    password_life_time = sql.query(format(query, profile: profile)).column('limit')

    describe "The oracle database account password life time for profile: #{profile}" do
      subject { password_life_time }
      it { should cmp <= input('account_inactivity_age') }
    end
  end
  if user_profiles.empty?
    describe 'There are no user profiles, therefore this control is NA' do
      skip 'There are no user profiles, therefore this control is NA'
    end
  end
end
