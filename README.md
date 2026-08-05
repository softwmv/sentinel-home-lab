## <span style="color:rgb(0, 176, 240)">Microsoft Sentinel Home Lab</span>
Welcome! This repository serves as documentation for my Microsoft Sentinel Home Lab. Microsoft Sentinel is a cloud-native SIEM and is widely used in modern SOC centers. Essentially, Microsoft Sentinel ingests logs from the environment (in this case, Windows Security Events from our exposed VM) into a Log Analytics Workspace. We can then query the data with Kusto Query Language (KQL) and develop rules, visualizations, and automated responses.
## <span style="color:rgb(0, 176, 240)">Objective</span>
The purpose of this home lab was to gain hands-on experience with Microsoft Sentinel by building a monitoring pipeline and custom detection visualization. This project includes:
- Creating Microsoft Sentinel dashboards to monitor logon failures and malicious traffic using threat intelligence.
- Using KQL to query logs within the SIEM platform.
- Developing custom detection rules to automate isolation and investigation of attacks.
## <span style="color:rgb(0, 176, 240)">Architecture Diagram</span>
![Sentinel Lab Architecture](https://github.com/softwmv/sentinel-home-lab/blob/main/files/architecture.jpg)
## <span style="color:rgb(0, 176, 240)">Steps Taken</span>
### 1. Infrastructure provisioning
- Created a dedicated resource group in Azure to contain all lab resources.
- Deployed a virtual network and connected a virtual machine to it, configured with a public IP and RDP/SSH intentionally left open to attract real internet scanning and brute-force traffic.

### 2. SIEM deployment
- Provisioned a Log Analytics workspace to serve as the central log repository.
- Deployed Microsoft Sentinel and linked it to the workspace.
- Enabled the **Security Events** data connector to ingest Windows authentication logs (event IDs 4624/4625) from the VM.

### 3. Custom GeoIP watchlist
- Sourced a GeoIP dataset (network, latitude, longitude, city name, country name) and imported it into Sentinel as a custom watchlist.
- Used the watchlist to enrich source IPs from `SecurityEvent` with geographic context via `ipv4_lookup` against the CIDR ranges in the `network` column.

### 4. Workbook and Visualization
- Deployed a community-built attack map [Workbook](https://drive.google.com/file/d/1ErlVEK5cQjpGyOcu4T02xYy7F31dWuir/view) (created by [Josh Madakor](https://joshmadakor.tech/)) and configured it against my own environment.
- Created "Top 10 Target Usernames," "Failed Logons Over Time," and "Countries by Attempt Volume" visualizations.

### 5. Detection engineering
Built three custom analytics rules on top of the ingested data, in addition to two pre-existing rules (multi-failure-then-success, service principal manipulation):

- **Failed logon burst (brute-force volume):** flags a single source IP generating 10+ failed logons in a rolling window, grouped by target account count to distinguish single-account brute-forcing from username spraying.
- **Geo diversity - discovery/noise:** flags an account receiving logon attempts from 5+ distinct countries in an hour with no successful logon, scoped explicitly to unsuccessful attempts to separate background scanning from actionable compromise.
- **Geo diversity - success:** the high-severity counterpart of the above, firing only when a logon _succeeds_ within a geographically diverse targeting pattern.

The KQL queries for these rules are available here: [Analytic Rules](https://github.com/softwmv/sentinel-home-lab/blob/main/files/Analytics%20Rules.md)


For each rule, I also configured:
- **Entity mapping** (IP/Host for the volume rule, Account/Host for the geo-diversity rules) to enable Sentinel's investigation graph and cross-incident correlation.
- **Event grouping** set to trigger an alert per result row, preserving one alert per offending IP or account rather than collapsing multiple distinct sources into a single alert.
- **Incident grouping** to consolidate repeated alerts from the same entity (IP or account) into a single incident over a defined time window, reducing noise from a single persistent scanning source.
- **MITRE ATT&CK mappings** (Credential Access for the volume/success rules, Discovery/Reconnaissance for the noise rule) to align detection with a standard framework.

### 6. Validation
- Ran each rule's query manually against live workspace data to confirm thresholds matched real observed traffic volumes before enabling the rules.
- Used Sentinel's "Test with current data" simulation and manual rule reruns to validate rule logic against historical data without waiting on the natural schedule.
## <span style="color:rgb(0, 176, 240)">Data Analysis</span>
### Attack Map (7 days)
![Attack Map (7 days)](https://github.com/softwmv/sentinel-home-lab/blob/main/files/activity-map-7d.png)

### Attack Map (30 days)
![Attack Map (7 days)](https://github.com/softwmv/sentinel-home-lab/blob/main/files/activity-map-30d.png)

### Attempts by Country (7 days)
![Attempts by Country (7 days)](https://github.com/softwmv/sentinel-home-lab/blob/main/files/attempts-by-country-7d.png)

### Attempts by Country (30 days)
![Attempts by Country (30 days)](https://github.com/softwmv/sentinel-home-lab/blob/main/files/attempts-by-country-30d.png)

A small number of countries account for the majority of traffic, namely the United States, Australia, and Hong Kong. Out of the 784,000+ failed attempts, these countries accounted for about 78% of these attempts **(top 3 = 0.78)**. Because adversaries commonly route via proxies/VPNs and cloud infrastructure, country-level results indicate where traffic appears to originate, not necessarily the attacker’s true location. Thus, we should treat country heatmaps as a "routing footprint" rather a proxy for attacker residency.
### Logon Attempts Timeline
![Logon Timeline](https://github.com/softwmv/sentinel-home-lab/blob/main/files/logon-timeline.png)

### Targeted Usernames (7 days)
![Targeted Usernames (7 days)](https://github.com/softwmv/sentinel-home-lab/blob/main/files/targeted-usernames-7d.png)

### Targeted Usernames (30 days)
![Targeted Usernames (30 days)](https://github.com/softwmv/sentinel-home-lab/blob/main/files/targeted-usernames-30d.png)

Analysis of failed logon attempts revealed two distinct targeting patterns: the majority were concentrated on specific usernames, primarily "COMP" and various admin/administrator variants, suggesting attackers may be guessing common Windows default or hostname-derived accounts. A smaller subset of activity resembled username spraying, targeting generic account names such as "user," "PC," "HP," "BACKUP," and "SERVER." 
## <span style="color:rgb(0, 176, 240)">Next Steps</span>
Overall, the SIEM data suggests focused probing with concentration by both geography (apparent source) and username targets; cloud routing likely explains part of the geo distribution. Next steps are to enrich with ASN/hosting/VPN indicators and correlate username clusters with source clusters for higher-confidence detection and prioritization.

For automated response, I would like to implement automated response playbooks, specifically:
- **Brute-Force Burst**: trigger a playbook that posts an enriched alert to Teams/Slack/email with the offending IP, attempt count, and target accounts.
- **(Geo Diversity + Successful Logon):** disable the account via a Logic App calling the Azure AD/Entra API, or isolate the VM at the network level. Given the risk of a false positive triggering an unnecessary account lockout or VM isolation, I'd gate this behind a manual approval step.
- A playbook to add additional information to each incident by pulling the AbuseIPDB reputation on the `SourceIP` and attaching it to the incident as a comment.
