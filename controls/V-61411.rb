control 'V-61411' do
  title "Access to default accounts used to support replication must be
  restricted to authorized DBAs."
  desc "Replication database accounts are used for database connections
  between databases. Replication requires the configuration of these accounts
  using the same username and password on all databases participating in the
  replication. Replication connections use fixed user database links. This means
  that access to the replication account on one server provides access to the
  other servers participating in the replication. Granting unauthorized access to
  the replication account provides unauthorized and privileged access to all
  databases participating in the replication group."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61411'
  tag "rid": 'SV-75901r1_rule'
  tag "stig_id": 'O121-BP-021200'
  tag "fix_id": 'F-67327r1_fix'
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

  select 'The number of replication objects defined is: '||
  count(*) from all_tables
  where table_name like 'REPCAT%';

  If the count returned is 0, then Oracle Replication is not installed and this
  check is not a finding.

  Otherwise:

  From SQL*Plus:

    select count(*) from sys.dba_repcatlog;

  If the count returned is 0, then Oracle Replication is not in use and this
  check is not a finding.

  If any results are returned, ask the ISSO or DBA if the replication account
  (the default is REPADMIN, but may be customized) is restricted to
  ISSO-authorized personnel only.

  If it is not, this is a finding.

  If there are multiple replication accounts, confirm that all are justified and
  documented with the ISSO.

  If they are not, this is a finding.

  Note: Oracle Database Advanced Replication is deprecated in Oracle Database
  12c. Use Oracle GoldenGate to replace all features of Advanced Replication,
  including multimaster replication, updatable materialized views, hierarchical
  materialized views, and deployment templates."
  tag "fix": "Change the password for default and custom replication accounts
  and provide the password to ISSO-authorized users only."
  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  is_oracle_replication_used = sql.query("select count(*) from all_tables
  where table_name like 'REPCAT%';").column('count(*)')

  oracle_replication_accounts = sql.query('select * from sys.dba_repcatlog;').column('gname')

  if !is_oracle_replication_used.include?('0')
    describe "The ISSO or DBA must manually ensure the following replication accounts are justified: #{oracle_replication_accounts}" do
      skip "The ISSO or DBA must manually ensure the following replication accounts are justified: #{oracle_replication_accounts}"
    end
  else
    describe 'The number of replication accounts defined' do
      subject { is_oracle_replication_used }
      it { should cmp 0 }
    end
  end
end
