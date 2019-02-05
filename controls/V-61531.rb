control "V-61531" do
  title "The /diag subdirectory under the directory assigned to the
  DIAGNOSTIC_DEST parameter must be protected from unauthorized access."
  impact 0.5
  tag "gtitle": "SRG-APP-000516-DB-999900"
  tag "gid": "V-61531"
  tag "rid": "SV-76021r2_rule"
  tag "stig_id": "O121-BP-026400"
  tag "fix_id": "F-67447r2_fix"
  tag "cci": ["CCI-000366"]
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

  select value from v$parameter where name='diagnostic_dest';

  On UNIX Systems:

  ls -ld [pathname]/diag

  Substitute [pathname] with the directory path listed from the above SQL
  command, and append \"/diag\" to it, as shown.

  If permissions are granted for world access, this is a Finding.

  If any groups that include members other than the Oracle process and software
  owner accounts, DBAs, auditors, or backup accounts are listed, this is a
  Finding.

  On Windows Systems (From Windows Explorer):

  Browse to the \\diag directory under the directory specified.

  Select and right-click on the directory, select Properties, select the Security
  tab.

  If permissions are granted to everyone, this is a Finding.

  If any account other than the Oracle process and software owner accounts,
  Administrators, DBAs, System group or developers authorized to write and debug
  applications on this database are listed, this is a Finding."
  tag "fix": "Alter host system permissions to the <DIAGNOSTIC_DEST>/diag
  directory to the Oracle process and software owner accounts, DBAs, SAs (if
  required) and developers or other users that may specifically require access
  for debugging or other purposes.

  Authorize and document user access requirements to the directory outside of the
  Oracle, DBA and SA account list."
end

