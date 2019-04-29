control 'V-61583' do
  title "A single database connection configuration file must not be used to
  configure all database clients."
  desc "Applications employ the concept of least privilege for specific duties
  and information systems (including specific functions, ports, protocols, and
  services). The concept of least privilege is also applied to information system
  processes, ensuring that the processes operate at privilege levels no higher
  than necessary to accomplish required organizational missions and/or functions.
  Organizations consider the creation of additional processes, roles, and
  information system accounts as necessary to achieve least privilege.
  Organizations also apply least privilege concepts to the design, development,
  implementation, and operations of information systems.

    Many sites distribute a single client database connection configuration
  file to all site database users that contains network access information for
  all databases on the site. Such a file provides information to access databases
  not required by all users that may assist in unauthorized access attempts.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000062-DB-000012'
  tag "gid": 'V-61583'
  tag "rid": 'SV-76073r1_rule'
  tag "stig_id": 'O121-C2-003600'
  tag "fix_id": 'F-67499r1_fix'
  tag "cci": ['CCI-000366', 'CCI-002220']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "nist": ['AC-5 c', 'Rev_4']
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
  tag "check": "Review procedures for providing database connection information
  to users/user workstations. If procedures do not indicate or implement
  restrictions to connections required by the particular user, this is a finding.

  Note: This check is specific for the DBMS host system and not directed at
  client systems (client systems are included in the Application STIG/Checklist);
  however, detection of unauthorized client connections to the DBMS host system
  obtained through log files should be performed regularly and documented where
  authorized."
  tag "fix": "Implement procedures to supply database connection information to
  only those databases authorized for the user."
  describe 'A manual review is required to ensure a single database connection configuration file is not used to
    configure all database clients' do
    skip 'A manual review is required to ensure a single database connection configuration file is not used to
    configure all database clients'
  end
end
