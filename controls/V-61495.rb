control 'V-61495' do
  title "The database must not be directly accessible from public or
  unauthorized networks."
  desc "Databases often store critical and/or sensitive information used by
  the organization. For this reason, databases are targeted for attacks by
  malicious users. Additional protections provided by network defenses that limit
  accessibility help protect the database and its data from unnecessary exposure
  and risk."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61495'
  tag "rid": 'SV-75985r1_rule'
  tag "stig_id": 'O121-BP-024500'
  tag "fix_id": 'F-67411r1_fix'
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
  tag "check": "Review the System Security Plan to determine if the DBMS serves
  data to users or applications outside the local enclave.

  If the DBMS is not accessed outside of the local enclave, this check is not a
  finding.

  If the DBMS serves applications available from a public network (e.g. the
  Internet), then confirm that the application servers are located in a DMZ.

  If the DBMS is located inside the local enclave and is directly accessible to
  public users, this is a finding.

  If the DBMS serves public-facing applications and is not protected from direct
  client connections and unauthorized networks, this is a finding.

  If the DBMS serves public-facing applications and contains sensitive or
  classified information, this is a finding."
  tag "fix": "Do not allow direct connections from users originating from the
  Internet or other public network to the DBMS.

  Include in the System Security Plan for the system whether the DBMS serves
  public-facing applications or applications serving users from other untrusted
  networks.

  Do not store sensitive or classified data on a DBMS server that serves
  public-facing applications."
  describe 'A manual review is required to ensure the database is not directly accessible from public or
    unauthorized networks.' do
    skip 'A manual review is required to ensure the database is not directly accessible from public or
    unauthorized networks.'
  end
end
