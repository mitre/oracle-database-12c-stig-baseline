control 'V-61729' do
  title "The DBMS must support organizational requirements to enforce password
  complexity by the number of special characters used."
  desc "Password complexity or strength is a measure of the effectiveness of a
  password in resisting attempts at guessing and brute-force attacks.

      Password complexity is one factor of several that determine how long it
  takes to crack a password. The more complex the password is, the greater the
  number of possible combinations that need to be tested before the password is
  compromised.

      Use of a complex password helps to increase the time and resources required
  to compromise the password.

      Note that user authentication and account management must be done via an
  enterprise-wide mechanism whenever possible.  Examples of enterprise-level
  authentication/access mechanisms include, but are not limited to, Active
  Directory and LDAP  This requirement applies to cases where it is necessary to
  have accounts directly managed by Oracle.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000169-DB-000176'
  tag "gid": 'V-61729'
  tag "rid": 'SV-76219r1_rule'
  tag "stig_id": 'O121-C2-014400'
  tag "fix_id": 'F-67645r1_fix'
  tag "cci": ['CCI-001619']
  tag "nist": ['IA-5 (1) (a)', 'Rev_4']
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

  For each profile that can be applied to accounts where authentication is under
  Oracle's control, determine the password verification function, if any, that is
  in use:

  SELECT * FROM SYS.DBA_PROFILES
  WHERE RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION'
  [AND PROFILE NOT IN (<list of non-applicable profiles>)]
  ORDER BY PROFILE;
  Bearing in mind that a profile can inherit from another profile, and the root
  profile is called DEFAULT, determine the name of the password verification
  function effective for each profile.

  If, for any profile, the function name is null, this is a finding.

  For each password verification function, examine its source code.

  If it does not enforce the organization-defined minimum number of special
  characters (1 unless otherwise specified), this is a finding."
  tag "fix": "If all user accounts are authenticated by the OS or an
  enterprise-level authentication/access mechanism, and not by Oracle, no fix to
  the DBMS is required.

  If any user accounts are managed by Oracle:  Develop, test and implement a
  password verification function that enforces DoD requirements.

  (Oracle supplies a sample function called ORA12C_STRONG_VERIFY_FUNCTION, in the
  script file
  <oracle_home>/RDBMS/ADMIN/utlpwdmg.sql.  This can be used as the starting point
  for a customized function.)"

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query = %{
    SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE PROFILE =
  '%<profile>s' AND RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION'
  }

  user_profiles = sql.query('SELECT profile FROM dba_users;').column('profile').uniq

  user_profiles.each do |profile|
    password_verify_function = sql.query(format(query, profile: profile)).column('limit')

    describe "The oracle database account password verify function for profile: #{profile}" do
      subject { password_verify_function }
      it { should_not eq ['NULL'] }
    end
  end
  if user_profiles.empty?
    describe 'There are no user profiles, therefore this control is NA' do
      skip 'There are no user profiles, therefore this control is NA'
    end
  end
end
