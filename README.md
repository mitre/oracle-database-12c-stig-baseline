# oracle-database-12c-stig-baseline

InSpec profile to validate the secure configuration of Oracle 12c, against [DISA](https://iase.disa.mil/stigs/)'s Oracle Database 12c Security Technical Implementation Guide (STIG) Version 1, Release 12.

#### Container-Ready: Profile updated to adapt checks when the running against a containerized instance of Oracle 12c, based on reference container: (docker pull tekintian/oracle12c)

## Getting Started  

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Tailoring to Your Environment
The following inputs must be configured in an inputs file for the profile to run correctly. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```yaml
# description: Username Oracle DB (e.g., 'system')
user: ''

# description: Password Oracle DB (e.g., 'xvIA7zonxGM=1')
password: ''

# description: Hostname Oracle DB (e.g., 'localhost')
host: ''

# description: Service name Oracle DB (e.g., 'ORCLCDB')
service: ''

# description: Location of sqlplus tool (e.g., '/opt/oracle/product/12.2.0.1/dbhome_1/bin/sqlplus')
sqlplus_bin: ''

# description: Set to true if standard auditing is used
standard_auditing_used: false 

# description: Set to true if unified auditing is used
unified_auditing_used: false

# description: List of allowed database links
allowed_db_links: []

# description: List of allowed database admins
allowed_dbadmin_users: []

# description: List of users allowed access to PUBLIC
users_allowed_access_to_public: []

# description: List of users allowed the dba role
allowed_users_dba_role: []

# description: List of users allowed the system tablespace
allowed_users_system_tablespace: []

# description: List of application owners
allowed_application_owners: []

# description: List of allowed unlocked Oracle db accounts
allowed_unlocked_oracledb_accounts: []

# description: List of users allowed access to the dictionary table
users_allowed_access_to_dictionary_table: []

# description: List of users allowed admin privileges
allowed_users_with_admin_privs: []

# description: List of users allowed audit access
allowed_audit_users: []

# description: List of allowed dba object owners
allowed_dbaobject_owners: []

# description: List of allowed Oracle db components
allowed_oracledb_components: []

# description: List of Oracle db components allowed to be intregrated into the dbms
allowed_oracledb_components_integrated_into_dbms: []

# description: List of allowed Oracle dba's
oracle_dbas: []
```

## Running This Profile

### Using winrm

    inspec exec https://github.com/mitre/oracle-database-12c-stig-baseline/archive/master.tar.gz -t winrm://<hostip> --user '<admin-account>' --password=<password> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter cli json:<filename>.json

Runs this profile over winrm to the host at IP address <hostip> as a privileged user account (i.e., an account with administrative privileges), reporting results to both the command line interface (cli) and to a machine-readable JSON file. 
    
The following is an example of using this command. 

    inspec exec https://github.com/mitre/oracle-database-12c-stig-baseline/archive/master.tar.gz -t winrm://$winhostip --user '<admin-account>' --password=<password> --input-file oracle-database-input-file.yml --reporter cli json:oracle-database-12c-stig-baseline-results.json

### Using SSH

    inspec exec https://github.com/mitre/oracle-database-12c-stig-baseline/archive/master.tar.gz -t ssh://<hostip> --user '<admin-account>' --password=<password> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter cli json:<filename>.json

Runs this profile over ssh to the host at IP address <hostip> as a privileged user account (i.e., an account with administrative privileges), reporting results to both the command line interface (cli) and to a machine-readable JSON file. 
    
The following is an example of using this command. 

    inspec exec https://github.com/mitre/oracle-database-12c-stig-baseline/archive/master.tar.gz -t ssh://$hostip --user '<admin-account>' --password=<password> --input-file oracle-database-input-file.yml --reporter cli json:oracle-database-12c-stig-baseline-results.json

### Using Docker

    inspec exec https://github.com/mitre/oracle-database-12c-stig-baseline/archive/master.tar.gz -t docker://<containerid> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter cli json:<filename>.json

Runs this profile over docker transport to the container ID <containerid>, reporting results to both the command line interface (cli) and to a machine-readable JSON file. 
    
The following is an example of using this command. 

    inspec exec https://github.com/mitre/oracle-database-12c-stig-baseline/archive/master.tar.gz -t docker://<containerid> --input-file oracle-database-input-file.yml --reporter cli json:oracle-database-12c-stig-baseline-results.json


### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Baseline from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this baseline and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile baseline for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/oracle-database-12c-stig-baseline
inspec archive oracle-database-12c-stig-baseline
inspec exec <name of generated archive> -t ssh://$hostip --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this baseline:

```
cd oracle-database-12c-stig-baseline
git pull
cd ..
inspec archive oracle-database-12c-stig-baseline --overwrite
inspec exec <name of generated archive> -t ssh://$hostip --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Alicia Sturtevant - [asturtevant](https://github.com/asturtevant)
* Krishna Kola, DIFZ

## Special Thanks 
* Mohamed El-Sharkawi - [HackerShark](https://github.com/HackerShark)
* Shivani Karikar - [karikarshivani](https://github.com/karikarshivani)

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/oracle-database-12c-stig-baseline/issues/new).

### NOTICE

© 2018-2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  

### NOTICE

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx   
