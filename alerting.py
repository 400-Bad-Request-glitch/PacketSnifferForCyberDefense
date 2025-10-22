import pandas as pd
from datetime import datetime, timedelta

# Load your CSV file
df = pd.read_csv("network_packets_export.csv")

# --- Convert timestamps to datetime objects ---
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

# --- Initialize results list ---
alerts = []

# --- 1. Port Scan Detection ---
time_window = timedelta(seconds=10)
for src_ip, group in df.groupby('src_ip'):
    group = group.sort_values('timestamp')
    for i, row in group.iterrows():
        start_time = row['timestamp']
        end_time = start_time + time_window
        ports = group[(group['timestamp'] >= start_time) & (group['timestamp'] <= end_time)]['dst_port'].nunique()
        if ports > 10:
            alerts.append({
                'Anomaly': 'Port Scan',
                'src_ip': src_ip,
                'Details': f'{ports} unique destination ports in 10 sec',
                'Time': start_time
            })
            break  # alert once per IP

# --- 2. SYN Flood Detection ---
syn_flood = df[(df['protocol'] == 'TCP') & (df['direction'] == 'out') & (df.get('flags') == 'S')]
if not syn_flood.empty:
    syn_counts = syn_flood.groupby('src_ip').size()
    for ip, count in syn_counts.items():
        if count > 100:
            alerts.append({
                'Anomaly': 'SYN Flood',
                'src_ip': ip,
                'Details': f'{count} SYN packets sent in 5 sec',
            })

# --- 3. ICMP Flood / Ping Sweep ---
icmp_packets = df[df['protocol'].str.contains('ICMP', case=False, na=False)]
icmp_counts = icmp_packets.groupby('src_ip').size()
for ip, count in icmp_counts.items():
    if count > 50:
        alerts.append({
            'Anomaly': 'ICMP Flood',
            'src_ip': ip,
            'Details': f'{count} ICMP packets in 10 sec',
        })

# --- 4. ARP Spoofing ---
mac_per_ip = df.groupby('src_ip')['src_mac'].nunique()
for ip, macs in mac_per_ip.items():
    if macs > 1:
        alerts.append({
            'Anomaly': 'ARP Spoofing',
            'src_ip': ip,
            'Details': f'{macs} unique MAC addresses for same IP',
        })

# --- 5. Data Exfiltration ---
# assuming 'length' column represents packet size (bytes)
df['length'] = pd.to_numeric(df['length'], errors='coerce').fillna(0)
bytes_sent = df.groupby('src_ip')['length'].sum()
for ip, total_bytes in bytes_sent.items():
    if total_bytes > 10 * 1024 * 1024:  # >10 MB
        alerts.append({
            'Anomaly': 'Data Exfiltration',
            'src_ip': ip,
            'Details': f'{total_bytes / (1024*1024):.2f} MB sent',
        })

# --- Display results ---
alerts_df = pd.DataFrame(alerts)
if alerts_df.empty:
    print(" No anomalies detected.")
else:
    print(" Detected Anomalies:")
    print(alerts_df)

# --- Optional: Save alerts to CSV ---
alerts_df.to_csv("detected_anomalies.csv", index=False)
print("\nResults saved to detected_anomalies.csv")
