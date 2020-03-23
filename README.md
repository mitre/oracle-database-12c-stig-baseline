# oracle-database-12c-stig-baseline

InSpec profile to validate the secure configuration of MongoDB Enterprised Advanced, against [DISA](https://iase.disa.mil/stigs/)'s **Oracle Database 12c Security Technical Implementation Guide (STIG) Version 1, Release 12**.

## Getting Started  
It is intended and recommended that InSpec run this profile from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __winrm__ or __SSH__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

The following inputs must be configured in an inputs file for the profile to run correctly. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

### Configuring the inputs in your inputs.yml file
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

    inspec exec https://github.com/mitre/oracle-database-12c-stig-baseline/archive/master.tar.gz -t winrm://<hostip> --user '<admin-account>' --password=<password> --reporter cli json:<filename>.json

Runs this profile over winrm to the host at IP address <hostip> as a privileged user account (i.e., an account with administrative privileges), reporting results to both the command line interface (cli) and to a machine-readable JSON file. 
    
The following is an example of using this command. 

    inspec exec https://github.com/mitre/oracle-database-12c-stig-baseline/archive/master.tar.gz -t winrm://$winhostip --user 'Administrator' --password=Pa55w0rd --reporter cli json:oracle-database-12c-stig-baseliner-results.json

### Using SSH

    inspec exec https://github.com/mitre/oracle-database-12c-stig-baseline/archive/master.tar.gz -t ssh://<hostip> --user '<admin-account>' --password=<password> --reporter cli json:<filename>.json

Runs this profile over ssh to the host at IP address <hostip> as a privileged user account (i.e., an account with administrative privileges), reporting results to both the command line interface (cli) and to a machine-readable JSON file. 
    
The following is an example of using this command. 

    inspec exec https://github.com/mitre/oracle-database-12c-stig-baseline/archive/master.tar.gz -t ssh://$hostip --user 'Administrator' --password=Pa55w0rd --reporter cli json:oracle-database-12c-stig-baseliner-results.json

### Additional InSpec Exec commands depending on your target
How to run on a remote target using ssh
```bash
# How to run 
$ inspec exec oracle-database-12c-stig-baseline -t ssh://TARGET_USERNAME:TARGET_PASSWORD@TARGET_IP:TARGET_PORT --input-file oracle-database-12c-stig-baseline/inputs.example.yml --reporter cli json:oracle-database-12c-stig-baseliner-results.json
```

If you need to run your profile with escalated privileges
```bash
# How to run 
$ inspec exec oracle-database-12c-stig-baseline -t ssh://TARGET_USERNAME:TARGET_PASSWORD@TARGET_IP:TARGET_PORT --input-file oracle-database-12c-stig-baseline/inputs.example.yml --sudo --reporter cli json:oracle-database-12c-stig-baseliner-results.json
```

How to run on a remote target using pem key
```bash
# How to run 
$ inspec exec oracle-database-12c-stig-baseline -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT -i PEM_KEY --input-file oracle-database-12c-stig-baseline/inputs.example.yml --reporter cli json:oracle-database-12c-stig-baseliner-results.json
```

How to run on docker container
```bash
Inspec exec oracle-database-12c-stig-baseline -t docker://DOCKER_CONTAINER_ID --input-file oracle-database-12c-stig-baseline/inputs.example.yml --reporter cli json:oracle-database-12c-stig-baseliner-results.json
```

To run it locally on the target with InSpec installed (Oracle and InSpec installed on same box)
```bash
# How to run 
$ inspec exec oracle-database-12c-stig-baseline --input-file oracle-database-12c-stig-baseline/inputs.example.yml --reporter cli json:oracle-database-12c-stig-baseliner-results.json
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://mitre.github.io/heimdall-lite/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __full heimdall server__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
- Alicia Sturtevant
- Krishna Kola, DIFZ

## Special Thanks

- The MITRE InSpec Team

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/oracle-database-12c-stig-baseline/issues/new).

For other help, please send a message to [inspec@mitre.org](mailto:inspec@mitre.org).

To contribute, please review the [contribution guidelines](https://github.com/mitre/docs-mitre-inspec/blob/master/CONTRIBUTING.md).

## License 

This project is licensed under the terms of the [Apache 2.0 license](https://github.com/mitre/oracle-database-12c-stig-baseline/blob/master/LICENSE.md).

### NOTICE

© 2019 The MITRE Corporation.  

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.  

### NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  

### NOTICE

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx   
