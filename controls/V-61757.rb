control 'V-61757' do
  title "The DBMS must terminate the network connection associated with a
  communications session at the end of the session or 15 minutes of inactivity."
  desc "Non-local maintenance and diagnostic activities are those activities
  conducted by individuals communicating through a network, either an external
  network (e.g., the Internet) or an internal network.

      The act of managing systems and applications includes the ability to access
  sensitive application information, such as system configuration details,
  diagnostic information, user information, and potentially sensitive application
  data.

      When applications provide a remote management capability inherent to the
  application, the application needs to ensure all sessions and network
  connections are terminated when non-local maintenance is completed.

      When network connections are left open after the database session has
  closed, the network session is open to session hijacking.

      The Oracle Listener inherently meets most of this SRG requirement.  When a
  user logs off, or times out, or encounters an unrecoverable network fault, the
  Oracle Listener terminates all sessions and network connections.  The remaining
  aspect of the requirement, the timeout because of inactivity, is configurable.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000190-DB-000137'
  tag "gid": 'V-61757'
  tag "rid": 'SV-76247r2_rule'
  tag "stig_id": 'O121-C2-016500'
  tag "fix_id": 'F-67673r2_fix'
  tag "cci": ['CCI-001133']
  tag "nist": ['SC-10', 'Rev_4']
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
  tag "check": "Review DBMS settings, OS settings, and vendor documentation to
  verify network connections are terminated when a database communications
  session is ended or after 15 minutes of inactivity.

  If the network connection is not terminated, this is a finding.

  The defined duration for these timeouts 15 minutes, except to fulfill
  documented and validated mission requirements."
  tag "fix": "Configure DBMS and/or OS settings to disconnect network sessions
  when database communication sessions have ended or after the DoD-defined period
  of inactivity.

  To configure this in Oracle, modify each relevant profile.  The resource name
  is IDLE_TIME, which is expressed in minutes.  Using PPPPPP as an example of a
  profile, set the timeout to 15 minutes with:
  ALTER PROFILE PPPPPP LIMIT IDLE_TIME 15;"

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query = %{
    SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE PROFILE =
  '%<profile>s' AND RESOURCE_NAME = 'IDLE_TIME'
  }

  user_profiles = sql.query('SELECT profile FROM dba_users;').column('profile').uniq

  user_profiles.each do |profile|
    idle_time = sql.query(format(query, profile: profile)).column('limit')

    describe "The oracle database idele time for profile: #{profile}" do
      subject { idle_time }
      it { should cmp <= 15 }
    end
  end
  if user_profiles.empty?
    describe 'There are no user profiles, therefore this control is NA' do
      skip 'There are no user profiles, therefore this control is NA'
    end
  end
end
