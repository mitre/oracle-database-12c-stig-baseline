control 'V-61519' do
  title 'Changes to configuration options must be audited.'
  desc  "The AUDIT_SYS_OPERATIONS parameter is used to enable auditing of
  actions taken by the user SYS. The SYS user account is a shared account by
  definition and holds all privileges in the Oracle database. It is the account
  accessed by users connecting to the database with SYSDBA or SYSOPER privileges."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61519'
  tag "rid": 'SV-76009r1_rule'
  tag "stig_id": 'O121-BP-025800'
  tag "fix_id": 'F-67435r1_fix'
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

  select value from v$parameter where name = 'audit_sys_operations';

  If the value returned is FALSE, this is a finding."
  tag "fix": "From SQL*Plus:

  alter system set audit_sys_operations = TRUE scope = spfile;

  The above SQL*Plus command will set the parameter to take effect at next system
  startup."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("select value from v$parameter where name = 'audit_sys_operations';").column('value')

  describe 'The oracle database AUDIT_SYS_OPERATIONS parameter' do
    subject { parameter }
    it { should_not cmp 'FALSE' }
  end
end
