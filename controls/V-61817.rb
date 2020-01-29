control 'V-61817' do
  title "The DBMS must manage resources to limit the effects of information
  flooding types of Denial of Service (DoS) incidents."
  desc "In the case of application DoS incidents, care must be taken when
  designing the application to ensure the application makes the best use of
  system resources. SQL queries have the potential to consume large amounts of
  CPU cycles if they are not tuned for optimal performance. Web services
  containing complex calculations requiring large amounts of time to complete can
  bog down if too many requests for the service are encountered within a short
  period of time.

      The methods employed to meet this requirement will vary depending upon the
  technology the application utilizes. However, a variety of technologies exist
  to limit, or in some cases, eliminate the effects of application-related DoS
  incidents. Employing increased capacity and bandwidth combined with specialized
  application layer protection devices and service redundancy may reduce the
  susceptibility to some DoS problems.

      Databases are particularly susceptible to SQL-related DoS issues. Databases
  that do not protect against resource-intensive SQL queries may experience
  dramatic slowdowns from malicious attacks or accidental DoS incidents related
  to SQL queries.  What constitutes a resource-intensive query has to be
  determined locally, taking into account the purpose of the database and the
  needs of the various classes of user.
  "
  impact 0.3
  tag "gtitle": 'SRG-APP-000247-DB-000134'
  tag "gid": 'V-61817'
  tag "rid": 'SV-76307r3_rule'
  tag "stig_id": 'O121-C3-019300'
  tag "fix_id": 'F-67733r8_fix'
  tag "cci": ['CCI-001095']
  tag "nist": ['SC-5 (2)', 'Rev_4']
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
  tag "check": "Review Oracle user profiles.  Connect to Oracle as SYSDBA. Use
  the following query to determine the established profiles and the users and
  resource limits assigned to them.

  select a.username, a.profile, b.resource_name, b.resource_type, b.limit
  from dba_users a, dba_profiles b
  where a.profile = b.profile and resource_type='KERNEL'
  order by a.profile;

  If the configuration does not include profile limits on resource-intensive SQL
  queries, or if users are not assigned to profiles appropriate to their needs,
  this is a finding."
  tag "fix": "Configure Oracle profile(s) to set resource limits appropriate to
  each class of user.

  SESSIONS_PER_USER
  Specify the number of concurrent sessions to which you want to limit the user.

  CPU_PER_SESSION
  Specify the CPU time limit for a session, expressed in hundredth of seconds.

  CPU_PER_CALL
  Specify the CPU time limit for a call (a parse, execute, or fetch), expressed
  in hundredths of seconds.

  CONNECT_TIME
  Specify the total elapsed time limit for a session, expressed in minutes.

  IDLE_TIME
  Specify the permitted periods of continuous inactive time during a session,
  expressed in minutes. Long-running queries and other operations are not subject
  to this limit.

  LOGICAL_READS_PER_SESSION
  Specify the permitted number of data blocks read in a session, including blocks
  read from memory and disk.

  LOGICAL_READS_PER_CALL
  Specify the permitted number of data blocks read for a call to process a SQL
  statement (a parse, execute, or fetch).

  PRIVATE_SGA
  Specify the amount of private space a session can allocate in the shared pool
  of the system global area (SGA). Refer to size_clause for information on that
  clause.

  COMPOSITE_LIMIT
  (This limit applies only when using shared server architecture. The private
  space for a session in the SGA includes private SQL and PL/SQL areas, but not
  shared SQL and PL/SQL areas.) Specify the total resource cost for a session,
  expressed in service units. Oracle Database calculates the total service units
  as a weighted sum of CPU_PER_SESSION, CONNECT_TIME, LOGICAL_READS_PER_SESSION,
  and PRIVATE_SGA.


  The user profile, ORA_STIG_PROFILE, has been provided (starting with Oracle
  12.1.0.2) to satisfy the STIG requirements pertaining to the profile
  parameters. Oracle recommends that this profile be customized with any
  site-specific requirements and assigned to all users where applicable.  Note:
  It remains necessary to create a customized replacement for the password
  validation function, ORA12C_STRONG_VERIFY_FUNCTION, if relying on this
  technique to verify password complexity."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  limit = sql.query("select DISTINCT b.limit from dba_users a, dba_profiles b where a.profile = b.profile and resource_type='KERNEL';").column('limit')

  describe 'The oracle database user profile limit' do
    subject { limit }
    it { should_not include 'UNLIMITED' }
  end
end
