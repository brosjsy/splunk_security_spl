# splunk_security_spl
This is based on my knowledge and scenario, you can use this to investigate against threat and incident in your organization.
<! --- Count the number of failed login attempts in the last 24 hours: --->
index=security sourcetype=auth failed | stats count as Failed_Login_Attempts
<! --- Identify successful logins from a specific user --->
index=security sourcetype=auth action=login status=success user=joseph.olawoyin | table _time, user, src_ip
<! --- Monitor failed login attempts from multiple IP addresses ---> you can copy multiple ip address that are known for malicious activities from various Threat intelligence
index=security sourcetype=auth action=login status=failure | stats count by src_ip | sort -count | head 10
<! --- Detect potential security threats by analyzing multiple log sources--->
(index=web_logs OR index=firewall_logs OR index=vpn_logs) status=403 OR status=404 OR action=block | stats count by sourcetype, status, action
<! --- Identify security events related to malware infections --->
index=security malware | stats count by signature | sort -count | head 10
<! --- Monitor changes in user permissions --->
index=security sourcetype=auditd action=chown OR action=chmod OR action=acl | table _time, user, action, path
<! --- Search for potential DDoS attacks--->
index=network_traffic status=200 | stats count by src_ip | where count > 1000
<! --- Identify top failed login attempts by user --->
index=security sourcetype=auth action=login status=failure | stats count by user | sort -count
<! --- Search for suspicious user account creations --->
index=security sourcetype=auth action=account_create status=success | table _time, user, src_ip
<! --- Monitor successful privilege escalation attempts --->
index=security sourcetype=auth action=priv_escalation status=success | table _time, user, src_ip
<! --- Detect brute force attacks on a specific service --->
index=security sourcetype=auth action=login status=failure service=ssh | stats count by src_ip | sort -count
<! --- Find malicious processes executed on a system --->
index=security sourcetype=process status=terminated parent_process_name=cmd.exe NOT process_name=explorer.exe | table _time, process_name, user, src_ip
<! ---Monitor changes to critical system files--->
index=security sourcetype=change_audit action=modify NOT path="C:\\Windows\\System32" | table _time, user, path
<! --- Search for HTTP status codes indicating potential web attacks --->
index=web_logs status=404 OR status=500 OR status=403 | stats count by status
<! --- Identify the most accessed URLs in web logs --->
index=web_logs | top 10 uri
<! --- Monitor firewall events for blocked traffic--->
index=firewall_logs action=block | table _time, src_ip, dest_ip, dest_port
<! --- Detect suspicious DNS queries --->
index=dns_logs | search query="*malware* OR *ransomware* OR *botnet*" | table _time, src_ip, query
<! --- Analyze SSL certificate expirations--->
index=ssl_logs | eval expiration_days=(expiration_time-_time)/86400 | search expiration_days < 30 | table _time, host, subject, issuer, expiration_time
<! ---Monitor login activity from new or unusual locations --->
index=security sourcetype=auth | iplocation src_ip | stats count by src_ip, Country | where Country!="United States" | sort -count
<! ---Detect potential insider threats by monitoring data exfiltration --->
index=network_traffic action=upload | stats count by src_ip, dest_ip, dest_port | sort -count
<! --- Search for signs of lateral movement in network logs --->
index=network_traffic | stats count by src_ip, dest_ip | sort -count
<! --- Analyze failed login attempts from a specific country --->
index=security sourcetype=auth action=login status=failure | iplocation src_ip | stats count by Country | where Country="China" | sort -count
<! --- Monitor VPN logs for multiple login attempts from a single IP --->
index=security sourcetype=auth action=login status=failure | iplocation src_ip | stats count by Country | where Country="China" | sort -count
<! --- Identify large file transfers from a specific user --->
index=network_traffic action=upload | stats sum(bytes) as total_bytes by user | sort -total_bytes
<! --- Monitor Windows Security logs for account lockouts --->
index=win_security EventCode=4740 | table _time, user, src_ip
<! --- Search for potential SQL injection attempts --->
index=web_logs "SELECT * FROM" | stats count by src_ip, uri | sort -count
<! --- Detect potential phishing URLs in web logs --->
index=web_logs | search uri="/login" AND query!="*legitimate_domain.com*" | table _time, src_ip, uri, query
<! ---  http bad request --->
index=<your_index_name> sourcetype=<your_sourcetype_name> status=400 
<! ---  potential ransomware attack  --->
index=<your_index_name> sourcetype=<your_sourcetype_name> ( "ransomware" OR "crypto" OR "decrypt_instructions" ) OR ( "encryption" AND "warning" ) OR ( "file_encrypted" AND "readme" )
<! --- Ransomware activity --->
index=<your_index_name> sourcetype=<your_sourcetype_name> (".encrypted" OR "readme_files" OR "DECRYPT_INSTRUCTIONS" OR "HOW_TO_DECRYPT")
<! --- Identify suspicious file modifications--->
index=<your_index_name> sourcetype=<your_sourcetype_name> (".encrypted" OR "readme_files" OR "DECRYPT_INSTRUCTIONS" OR "HOW_TO_DECRYPT")
<! --- Monitor processes known to be associated with ransomware --->
index=<your_index_name> sourcetype=<your_sourcetype_name> (process_name=ransom* OR process_name=crypt* OR process_name=encrypt*)
<! --- Look for large amounts of file deletions or renames --->
index=<your_index_name> sourcetype=<your_sourcetype_name> action=delete OR action=rename | stats count by action
<! --- Detect failed login attempts or privilege escalations --->
index=<your_index_name> sourcetype=<your_sourcetype_name> action=login OR action=priv_escalation status=failure 
<! --- Monitor network traffic for suspicious communication --->
index=<your_index_name> sourcetype=<your_sourcetype_name> (dest_ip=<known_ransomware_c2_ip> OR dest_port=<known_ransomware_c2_port>)
<! --- Identify file encryption or decryption activities: --->
index=<your_index_name> sourcetype=<your_sourcetype_name> (action=encrypt OR action=decrypt) status=success
<! ---Look for increased logon activity during non-business hours--->
index=<your_index_name> sourcetype=<your_sourcetype_name> (action=logon OR action=auth) NOT time_hour=8-17

<! --- Wrap text --->
<! --- Wrap text --->
<! --- Wrap text --->
<! --- Wrap text --->
<! --- Wrap text --->
<! --- Wrap text --->
<! --- Wrap text --->
