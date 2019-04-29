control 'V-61509' do
  title "The DBMS must not share a host supporting an independent security
  service."
  desc "The Security Support Structure is a security control function or
  service provided by an external system or application. An example of this would
  be a Windows domain controller that provides identification and authentication
  that can be used by other systems to control access. The associated risk of a
  DBMS installed on a system that provides security support is significantly
  higher than when installed on separate systems. In cases where the DBMS is
  dedicated to local support of a security support function (e.g. a directory
  service), separation may not be possible."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61509'
  tag "rid": 'SV-75999r1_rule'
  tag "stig_id": 'O121-BP-025300'
  tag "fix_id": 'F-67425r1_fix'
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
  tag "check": "Review the services and processes active on the DBMS host
  system.

  If the host system is a Windows domain controller, this is a finding.

  If the host system is supporting any other security or directory services that
  do not use the DBMS to store information, this is a finding.

  Note: This does not include client security applications like firewall and
  antivirus software."
  tag "fix": "Either move the DBMS installation to a dedicated host system or
  move the directory or security services to another host system.

  A dedicated host system in this case refers to an instance of the operating
  system at a minimum.

  The operating system may reside on a virtual host machine where supported by
  the DBMS vendor."
  describe 'A manual review is required to ensure the DBMS does not share a host supporting an independent security
  service' do
    skip 'A manual review is required to ensure the DBMS does not share a host supporting an independent security
   service'
  end
end
