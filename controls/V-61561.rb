control 'V-61561' do
  title "The DBMS must provide a mechanism to automatically terminate accounts
  designated as temporary or emergency accounts after an organization-defined
  time period."
  desc "Temporary application accounts could ostensibly be used in the event
  of a vendor support visit where a support representative requires a temporary
  unique account in order to perform diagnostic testing or conduct some other
  support related activity. When these types of accounts are created, there is a
  risk that the temporary account may remain in place and active after the
  support representative has left.

      To address this, in the event temporary application accounts are required,
  the application must ensure accounts designated as temporary in nature shall
  automatically terminate these accounts after an organization-defined time
  period. Such a process and capability greatly reduces the risk that accounts
  will be misused, hijacked, or data compromised.

      Note that user authentication and account management should be done via an
  enterprise-wide mechanism whenever possible.  Examples of enterprise-level
  authentication/access mechanisms include, but are not limited to, Active
  Directory and LDAP. This requirement applies to cases where it is necessary to
  have accounts directly managed by Oracle.

      Temporary database accounts must be automatically terminated after an
  organization-defined time period in order to mitigate the risk of the account
  being used beyond its original purpose or timeframe.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000024-DB-000003'
  tag "gid": 'V-61561'
  tag "rid": 'SV-76051r3_rule'
  tag "stig_id": 'O121-C2-002000'
  tag "fix_id": 'F-67477r1_fix'
  tag "cci": ['CCI-000016']
  tag "nist": ['AC-2 (2)', 'Rev_4']
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
  tag "check": "If the organization has a policy, consistently enforced,
  forbidding the creation of emergency or temporary accounts, this is not a
  finding.

  If all user accounts are authenticated by the OS or an enterprise-level
  authentication/access mechanism, and not by Oracle, this is not a finding.

  Check DBMS settings, OS settings, and/or enterprise-level authentication/access
  mechanisms settings to determine if the site utilizes a mechanism whereby
  temporary or emergency accounts can be terminated after an organization-defined
  time period. If not, this is a finding.

  Check the profiles to see what the password_life_time is set to in the table
  dba_profiles. The password_life_time is a value stored in the LIMIT column, and
  identified by the value PASSWORD_LIFE_TIME in the RESOURCE_NAME column.

  SQL>select
  profile,
  resource_name,
  resource_type,
  limit
  from dba_profiles
  where upper(resource_name) like 'PASSWORD_LIFE_TIME';

  Verify that the user in question is assigned to a profile with the
  PASSWORD_LIFE_TIME set to the amount of time the user is expected to be using
  the password.  If not, this is a finding."
  tag "fix": "If using database mechanisms to satisfy this requirement, use a
  profile with a distinctive name (for example, TEMPORARY_USERS), so that
  temporary users can be easily identified.  Whenever a temporary user account is
  created, assign it to this profile.

  Create a job to lock accounts under this profile that are more than n days old,
  where n is the organization-defined time period."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))
  query = %{
    SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE PROFILE =
  '%<profile>s' AND RESOURCE_NAME = 'PASSWORD_LIFE_TIME'
  }

  user_profiles = sql.query('SELECT profile FROM dba_users;').column('profile').uniq

  if user_profiles.empty?
    describe 'There are no oracle user profiles, therefore this control is N/A' do
      skip 'There are no oracle user profiles, therefore this control is N/A'
    end
  end

  if !user_profiles.empty?
    user_profiles.each do |profile|
      unless input('emergency_profile_list').include?(profile)
      	describe "The profile #{profile} " do
	  subject { profile }
	  it "should not be in the org-defined list of profiles for emergency or temporary account management" do
	    expect(subject).should_not be_in(input('emergency_profile_list')) 
	  end
        end
	next
      end
      password_life_time = sql.query(format(query, profile: profile)).column('limit')

      describe "The oracle database account password life time for profile: #{profile}" do
        subject { password_life_time }
        it { should cmp <= input('password_life_time') }
      end
    end
  end
end
