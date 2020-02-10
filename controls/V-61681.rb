control 'V-61681' do
  title "Unused database components that are integrated in the DBMS and cannot
  be uninstalled must be disabled."
  desc "Information systems are capable of providing a wide variety of
  functions and services. Some of the functions and services, provided by
  default, may not be necessary to support essential organizational operations
  (e.g., key missions, functions).

      It is detrimental for applications to provide, or install by default,
  functionality exceeding requirements or mission objectives. Examples include,
  but are not limited to, installing advertising software, demonstrations, or
  browser plug-ins not related to requirements or providing a wide array of
  functionality not required for the mission.

      Applications must adhere to the principles of least functionality by
  providing only essential capabilities.

      Unused, unnecessary DBMS components increase the attack vector for the DBMS
  by introducing additional targets for attack. By minimizing the services and
  applications installed on the system, the number of potential vulnerabilities
  is reduced. Components of the system that are unused and cannot be uninstalled
  must be disabled.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000141-DB-000092'
  tag "gid": 'V-61681'
  tag "rid": 'SV-76171r2_rule'
  tag "stig_id": 'O121-C2-011700'
  tag "fix_id": 'F-67595r3_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']
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
  tag "check": "Run this query to check to see what integrated components are
  installed in the database:

  SELECT parameter, value
  from v$option
  where parameter in
  (
  'Data Mining',
  'Oracle Database Extensions for .NET',
  'OLAP',
  'Partitioning',
  'Real Application Testing'
  );

  This will return all of the relevant database options and their status. TRUE
  means that the option is installed. If the option is not installed, the option
  will be set to FALSE.

  Review the options and check the system documentation to see what is required.
  If all listed components are authorized to be in use, this is not a finding.

  If any unused components or features are listed by the query as TRUE, this is a
  finding."
  tag "fix": "In the system documentation list the integrated components
  required for operation of applications that will be accessing the DBMS.

  For Oracle Database 12.1, only the following components can be enabled/disabled:

  Oracle Data Mining (dm)
  Oracle Database Extensions for .NET (ode_net)
  Oracle OLAP (olap)
  Oracle Partitioning (partitioning)
  Real Application Testing (rat)

  Use the chopt utility (an Oracle-supplied operating system command that resides
  in the <Oracle Home path>/bin directory) to disable each option that should not
  be available.  The command format is

              chopt <enable|disable> <option>
  where <option> is any of the abbreviations in parentheses in the list above.
  For example, to disable Real Application Testing, issue the following command
  at an OS prompt:

              chopt disable rat

  Restart the Oracle service.

  (See My Oracle Support Document 948061.1 for more on the chopt command.)"

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  list_of_installed_components_integrated_into_dbms = sql.query("SELECT parameter, value
  from v$option
  where parameter in
  (
  'Data Mining',
  'Oracle Database Extensions for .NET',
  'OLAP',
  'Partitioning',
  'Real Application Testing'
  );").column('parameter').uniq
  if list_of_installed_components_integrated_into_dbms.empty?
    impact 0.0
    describe 'There are no oracle database components integrated into the DBMS, control N/A' do
      skip 'TThere are no oracle database components integrated into the DBMS, control N/A'
    end
  else
    list_of_installed_components_integrated_into_dbms.each do |component|
      describe "The installed oracle database components integrated into the DBMS: #{component}" do
        subject { component }
        it { should be_in input('allowed_oracledb_components_integrated_into_dbms') }
      end
    end
  end
end
