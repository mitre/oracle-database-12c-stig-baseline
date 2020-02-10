control 'V-61819' do
  title "The DBMS must limit the use of resources by priority and not impede
  the host from servicing processes designated as a higher-priority."
  desc "Priority protection helps prevent a lower-priority process from
  delaying or interfering with the information system servicing any
  higher-priority process. This control does not apply to components in the
  information system for which there is only a single user/role. The application
  must limit the use of resources by priority.

      The DBMS is often running queries for multiple users. If lower-priority
  processes are utilizing a disproportionately high amount of database resources,
  this can severely impact higher-priority processes.
  "
  impact 0.3
  tag "gtitle": 'SRG-APP-000248-DB-000135'
  tag "gid": 'V-61819'
  tag "rid": 'SV-76309r2_rule'
  tag "stig_id": 'O121-C3-019400'
  tag "fix_id": 'F-67735r5_fix'
  tag "cci": ['CCI-002394']
  tag "nist": ['SC-6', 'Rev_4']
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
  tag "check": "Review DBMS settings and documentation to determine if the DBMS
  restricts resource usage by priority.

  If the DBMS does not restrict resource usage by priority, this is a finding.

  - - - - -
  This capability is available in Oracle at both the user and database level.

  At the user level, we create resource profiles for users of the database.

  Resource Parameters
  SESSIONS_PER_USER - Specify the number of concurrent sessions to which to limit
  the user.
  CPU_PER_SESSION - Specify the CPU time limit for a session, expressed in
  hundredths of seconds.
  CPU_PER_CALL - Specify the CPU time limit for a call (a parse, execute, or
  fetch), expressed in hundredths of seconds.
  CONNECT_TIME - Specify the total elapsed time limit for a session, expressed in
  minutes.
  IDLE_TIME - Specify the permitted periods of continuous inactive time during a
  session, expressed in minutes. Long-running queries and other operations are
  not subject to this limit.
  LOGICAL_READS_PER_SESSION - Specify the permitted number of data blocks read in
  a session, including blocks read from memory and disk.
  LOGICAL_READS_PER_CALL - Specify the permitted number of data blocks read for a
  call to process a SQL statement (a parse, execute, or fetch).
  PRIVATE_SGA - Specify the amount of private space a session can allocate in the
  shared pool of the system global area (SGA).
  COMPOSITE_LIMIT - Specify the total resource cost for a session, expressed in
  service units.

  To check the resource controls assigned to a user, query the DBA_PROFILES and
  DBA_USERS tables in the following manner.

  set linesize 121
  col username format a20
  col profile format a20
  col resource_name format a25
  col resource_type format a14
  col limit format a10
  select a.username,
     a.profile,
     b.resource_name,
     b.limit
  from dba_users a,
       dba_profiles b
  where b.resource_type is not null and
        a.profile = b.profile order by username;

  The output should look like the output below and display the users and the
  contents of their profiles.

  USERNAME        PROFILE       RESOURCE NAME      LIMIT
  --------        -------       -------------      -----
  SCOTT           DEFAULT       SESSIONS_PER_USER  UNLIMITED
  SCOTT           DEFAULT       CPU_PER_SESSION    UNLIMITED"
  tag "fix": "Implement measures to restrict the usage of resources by priority.

  - - - - -
  To implement security at the user level, assign users a profile that limits
  their resources:

  The user profile, ORA_STIG_PROFILE, has been provided (starting with Oracle
  12.1.0.2) to satisfy the STIG requirements pertaining to the profile
  parameters. Oracle recommends that this profile be customized with any
  site-specific requirements and assigned to all users where applicable.  Note:
  It remains necessary to create a customized replacement for the password
  validation function, ORA12C_STRONG_VERIFY_FUNCTION, if relying on this
  technique to verify password complexity.

  Example

  $ sqlplus connect as sysdba

  ALTER PROFILE ORA_STIG_PROFILE LIMIT
  SESSIONS_PER_USER    1
  IDLE_TIME           30
  CPU_PER_SESSION    100
  CPU_PER_CALL       100
  CONNECT_TIME       600;"

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  limit = sql.query("select
    DISTINCT b.limit
  from dba_users a,
       dba_profiles b
  where b.resource_type is not null and
        a.profile = b.profile;").column('limit')

  describe 'The oracle database user limit' do
    subject { limit }
    it { should_not include 'UNLIMITED' }
  end
end
