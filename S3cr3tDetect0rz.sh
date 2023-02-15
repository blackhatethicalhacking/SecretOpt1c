#!/bin/bash
# Take input for URL and path to wordlist
read -p "Enter the URL: " url
read -p "Enter path to wordlist: " wordlist

# Check if wordlist exists
echo "Checking and confirming your wordlist exists and proceeding with the attacks..." | lolcat
sleep 1
if [ ! -f "$wordlist" ]; then
  echo "Error: wordlist file $wordlist does not exist." | lolcat
  exit 1
fi

# Create a directory to store the results of curl using the domain name of the URL provided by the user
domain="$(echo "$url" | cut -d/ -f3)"
mkdir -p "$domain"

# Start gobuster with given URL and wordlist
echo "Starting GoBuster with active scan against the target searching for specific extensions, filtering with 200 & 301 status codes..." | lolcat
sleep 1
gobuster dir -u "$url" -w "$wordlist" -x .js,.php,.yml,.env,.txt,.xml,.html,.config -e -s 200,204,301,302,307,401,403 --wildcard -o "$domain/gobuster.txt"

# Extract the discovered URLs for further testing
grep "Status: 200" "$domain/gobuster.txt" | grep -oE "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u > "$domain/discovered_urls.txt"
grep "Status: 301" "$domain/gobuster.txt" | grep -oE "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u >> "$domain/discovered_urls.txt"

# Use xargs and curl to fetch the content of each discovered URL in parallel
echo "Performing curl on every URL I found to fetch the content..." | lolcat
sleep 1
cat "$domain/discovered_urls.txt" | xargs -I{} -P 10 sh -c 'curl -sS -# -n {} > "$domain/discovered_urls_for_$(echo {} | awk -F/ '\''{print $3}'\'').txt" 2>&1'

# Search for secrets in the output of curl and save the result in secrets.csv
echo "Searching for secrets using secrethub.json and saving the results in secrets.csv for you..." | lolcat
sleep 1
if [ ! -f "$domain/discovered_urls.txt" ]; then
  echo "No discovered URLs file found."
  exit 1
fi

while read discovered_url; do
  discovered_url_file="$domain/discovered_urls_for_$(echo $discovered_url | awk -F/ '{print $3}').txt"
  if [ ! -f "$discovered_url_file" ]; then
    echo "File $discovered_url_file does not exist."
    continue
  fi
  secrets_found=$(grep -E "$(cat secrethub.json | jq -r '.patterns | join("|")')" "$discovered_url_file" | awk '!seen[$0]++ { print $0 }')
  count=$(echo "$secrets_found" | wc -l)
  if [ "$count" -gt 0 ]; then
    echo "URL Affected: $discovered_url" >> "$domain/secrets.csv"
    echo "$secrets_found" | awk '{print "\"" $0 "\""}' | paste -sd "," - >> "$domain/secrets.csv"
  fi
done < "$domain/discovered_urls.txt"

echo "Scan complete." | lolcat
echo "You can view the results of the scan in the directory named $domain" | lolcat

