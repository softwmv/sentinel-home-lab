**Failed logon burst (brute-force volume):**
```kql
SecurityEvent
| where EventID == 4625
| where AccountType == "User"
| extend SourceIP = IpAddress
| summarize
    FailedAttempts = count(),
    TargetAccounts = make_set(TargetUserName, 10),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by SourceIP, Computer
| where FailedAttempts >= 10
| extend TargetAccountCount = array_length(TargetAccounts)
| project FirstAttempt, LastAttempt, SourceIP, Computer, FailedAttempts, TargetAccountCount, TargetAccounts
```

**Geo diversity - discovery/noise:**
```kql
let GeoWatchlist = (_GetWatchlist('geoip') | project network, countryname);
SecurityEvent
| where EventID in (4625, 4624)
| where AccountType == "User"
| extend SourceIP = IpAddress
| evaluate ipv4_lookup(GeoWatchlist, SourceIP, network, return_unmatched = false)
| extend LogonResult = iff(EventID == 4624, "Success", "Failure")
| summarize
    DistinctCountries = dcount(countryname),
    Countries = make_set(countryname, 20),
    DistinctIPs = dcount(SourceIP),
    Attempts = count(),
    Successes = countif(LogonResult == "Success")
    by TargetUserName, Computer, bin(TimeGenerated, 1h)
| where DistinctCountries >= 5
| where Successes == 0
| order by DistinctCountries desc
```

**Geo diversity - success:**
```kql
let GeoWatchlist = (_GetWatchlist('geoip') | project network, countryname);
SecurityEvent
| where EventID in (4625, 4624)
| where AccountType == "User"
| extend SourceIP = IpAddress
| evaluate ipv4_lookup(GeoWatchlist, SourceIP, network, return_unmatched = false)
| extend LogonResult = iff(EventID == 4624, "Success", "Failure")
| summarize
    DistinctCountries = dcount(countryname),
    Countries = make_set(countryname, 20),
    DistinctIPs = dcount(SourceIP),
    Attempts = count(),
    Successes = countif(LogonResult == "Success")
    by TargetUserName, Computer, bin(TimeGenerated, 1h)
| where DistinctCountries >= 5
| where Successes > 0
| order by Successes desc
```
