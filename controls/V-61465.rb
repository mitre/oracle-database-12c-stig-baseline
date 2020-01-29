control 'V-61465' do
  title "The Oracle _TRACE_FILES_PUBLIC parameter if present must be set to
  FALSE."
  desc  "The _TRACE_FILES_PUBLIC parameter is used to make trace files used for
  debugging database applications and events available to all database users. Use
  of this capability precludes the discrete assignment of privileges based on job
  function. Additionally, its use may provide access to external files and data
  to unauthorized users."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61465'
  tag "rid": 'SV-75955r1_rule'
  tag "stig_id": 'O121-BP-023900'
  tag "fix_id": 'F-67381r1_fix'
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

  select value from v$parameter where name = '_trace_files_public';

  If the value returned is TRUE, this is a finding.

  If the parameter does not exist or is set to FALSE, this is not a finding."
  tag "fix": "From SQL*Plus (shutdown database instance):

  shutdown immediate

  From SQL*Plus (create a pfile from spfile):

  create pfile='[PATH]init[SID].ora' from spfile;

  Edit the init[SID].ora file and remove the following line:

  *._trace_files_public=TRUE

  From SQL*Plus (update the spfile using the pfile):

  create spfile from pfile='[PATH]init[SID].ora';

  From SQL*Plus (start the database instance):

  startup

  Note: [PATH] depends on the platform (Windows or UNIX).

  Ensure the file is directed to a writable location.

  [SID] is equal to the oracle SID or database instance ID."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("select value from v$parameter where name = '_trace_files_public';").column('value')

  describe 'The oracle database _TRACE_FILES_PUBLIC parameter' do
    subject { parameter }
    it { should_not cmp 'TRUE' }
  end
end
