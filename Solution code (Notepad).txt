# Log Analyzer: Finds bot (non-human) traffic in server logs
# ---------------------------------------------------------
# This script reads the server log and checks:
#   - Which IPs make lots of requests fast (bots often do this)
#   - User-Agent reveals the software making the request; bots often use headers like curl, wget, python-requests, or known crawlers (Googlebot, Bingbot, etc.)
#   - How many errors (like 404 or 500) each IP causes (bots often make more errors)
# It helps find IPs that might be causing too much traffic or crashing the site.

log_file = 'sample-log.log'  # Log file to read

# Dictionaries to track counts and User-Agent info by IP
ip_counter = {}
error_counter = {}
user_agents_by_ip = {}
ip_country = {}  # Store country info for each IP

# Known bot keywords categorized by bot type for detection
bot_types = {
    "Search Bot": ["googlebot", "bingbot", "yandex", "duckduckbot"],
    "Scraper Tool": ["python", "scrapy", "requests"],
    "Command-line Bot": ["curl", "wget", "httpclient"],
    "Generic Bot": ["bot", "spider", "crawl"]
}

bot_classification = {}  # Will hold IP to bot type mapping

# Thresholds for flagging suspicious activity
REQUEST_THRESHOLD = 100
ERROR_THRESHOLD = 10

# Read the log file line by line
with open(log_file) as log:
    for line in log:
        parts = line.split()
        if len(parts) < 9:  # Skip malformed lines
            continue

        ip = parts[0]  # IP is the first element
        status_code = parts[8]  # HTTP status code at position 9

        ip_counter[ip] = ip_counter.get(ip, 0) + 1

        if status_code in ['404', '500']:
            error_counter[ip] = error_counter.get(ip, 0) + 1

        # Store the country if available
        if len(parts) > 2:
            ip_country[ip] = parts[2]

        quote_parts = line.split('"')
        if len(quote_parts) > 5:
            user_agent = quote_parts[5].lower()
            user_agents_by_ip[ip] = user_agent

            for bot_type, keywords in bot_types.items():
                if any(keyword in user_agent for keyword in keywords):
                    bot_classification[ip] = bot_type
                    break

bot_report = {}  # Stores flagged IPs with reasons for suspicion

# Combine all IPs seen in requests, errors, or User-Agents
all_ips = set(ip_counter) | set(user_agents_by_ip) | set(error_counter)

for ip in all_ips:
    reasons = []
    bot_type = bot_classification.get(ip, "Unknown Bot")

    if ip_counter.get(ip, 0) > REQUEST_THRESHOLD:
        reasons.append(f"High request volume: {ip_counter[ip]} requests")

    if ip in user_agents_by_ip and ip in bot_classification:
        reasons.append(f"Suspicious User-Agent: {user_agents_by_ip[ip]}")

    if error_counter.get(ip, 0) > ERROR_THRESHOLD:
        reasons.append(f"High error count: {error_counter[ip]} errors")

    if reasons:
        bot_report[ip] = {
            "bot_type": bot_type,
            "user_agent": user_agents_by_ip.get(ip, "N/A"),
            "reasons": reasons
        }

# Print summary of traffic data
print("\n========== TRAFFIC REPORT ==========\n")

print("Top 5 IPs by Request Count:")
for ip, count in sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:5]:
    print(f"  - {ip} made {count} requests")

print("\nDetected Bot Traffic:")
if bot_report:
    for ip, info in bot_report.items():
        print(f"  - {ip} is flagged as {info['bot_type']}")
else:
    print("  - No obvious bots found.")

print("\nIPs Causing the Most 404/500 Errors:")
if error_counter:
    for ip, count in sorted(error_counter.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  - {ip} caused {count} errors")
else:
    print("  - No major errors found.")

# Detailed bot report with recommendations
print("\n========== FINAL BOT TRAFFIC REPORT ==========\n")

if bot_report:
    print("Bots detected:\n")
    for ip, info in bot_report.items():
        country = ip_country.get(ip, "Unknown")
        print(f"IP Address: {ip} (Country: {country})")  # Added country info here
        print(f"  - Type of bot: {info['bot_type']}")
        print(f"  - Reason(s):")
        for reason in info['reasons']:
            print(f"      - {reason}")

        # Showing the country helps identify where bot traffic is coming from
        if info['bot_type'] == "Search Bot":
            print("  - Recommendation: Allow but control with robots.txt\n")
        elif info['bot_type'] == "Scraper Tool":
            print("  - Recommendation: Block or rate-limit this scraping tool.\n")
        elif info['bot_type'] == "Command-line Bot":
            print("  - Recommendation: Likely scripted — block or throttle.\n")
        elif info['bot_type'] == "Generic Bot":
            print("  - Recommendation: Unknown intent — monitor or challenge with CAPTCHA.\n")
        else:
            print("  - Recommendation: Unknown bot — investigate and monitor.\n")
else:
    print("No bot-like traffic detected.\n")

# General advice for protecting the website
print("========== GENERAL RECOMMENDATIONS ==========\n")

print("Consider:")
print("   - Using a CDN to filter bad traffic")
print("   - Deploying a Web Application Firewall (WAF)")
print("   - Blocking bad User-Agents in nginx/apache")
print("   - Logging for long-term analysis\n")

print("Log analysis complete.\n")
