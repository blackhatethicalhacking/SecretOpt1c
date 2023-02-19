#!/bin/bash
curl --silent "https://raw.githubusercontent.com/blackhatethicalhacking/Subdomain_Bruteforce_bheh/main/ascii.sh" | lolcat
echo ""
# Generate a random Sun Tzu quote for offensive security
# Array of Sun Tzu quotes
quotes=("The supreme art of war is to subdue the enemy without fighting." "All warfare is based on deception." "He who knows when he can fight and when he cannot, will be victorious." "The whole secret lies in confusing the enemy, so that he cannot fathom our real intent." "To win one hundred victories in one hundred battles is not the acme of skill. To subdue the enemy without fighting is the acme of skill.")
# Get a random quote from the array
random_quote=${quotes[$RANDOM % ${#quotes[@]}]}
# Print the quote
echo "Offensive Security Tip: $random_quote - Sun Tzu" | lolcat
sleep 1
echo "MEANS, IT'S ☕ 1337 ⚡ TIME, 369 ☯ " | lolcat
sleep 1
figlet -w 80 -f small S3cr3tDetect0rz | lolcat
echo ""
echo "[YOUR ARE USING S3cr3tDetect0rz.sh] - (v1.0) CODED BY Chris 'SaintDruG' Abou-Chabké WITH ❤ FOR blackhatethicalhacking.com for Educational Purposes only!" | lolcat
sleep 1
#check if the user is connected to the internet
tput bold;echo "CHECKING IF YOU ARE CONNECTED TO THE INTERNET!" | lolcat
# Check connection
wget -q --spider https://google.com
if [ $? -ne 0 ];then
    echo "++++ CONNECT TO THE INTERNET BEFORE RUNNING S3cr3tDetect0rz.sh!" | lolcat
    exit 1
fi
tput bold;echo "++++ CONNECTION FOUND, LET'S GO!" | lolcat
# Take input for URL and path to wordlist
read -p "Enter the URL: " url
read -p "Enter path to wordlist: " wordlist
# Check if wordlist exists
echo "Checking and Confirming your wordlist exist and proceeding with the attacks..." | lolcat
sleep 1
if [ ! -f $wordlist ]; then
  echo "Error: wordlist file $wordlist does not exist."  | lolcat
  exit 1
fi
# Create a directory to store the results of curl using the domain name of the URL provided by the user
domain="$(echo $url | cut -d/ -f3)"
mkdir -p "$domain"
# Start gobuster with given URL and wordlist
echo "Starting GoBuster with ACTIVE Scan against the target searching for specific extensions, filtering with 200 & 301 status codes..." | lolcat
sleep 1
gobuster dir -u $url -w $wordlist -x .js,.php,.yml,.env,.txt,.xml,.html,.config -e -d --random-agent -s 200,204,301,302,307,401,403 -o $domain/gobuster.txt
# Extract the discovered URLs for further testing
grep "Status: 200" $domain/gobuster.txt | grep -oE "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u > $domain/discovered_urls.txt
grep "Status: 301" $domain/gobuster.txt | grep -oE "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u >> $domain/discovered_urls.txt

# Fetch additional URLs from waybackurls with the same extensions as gobuster
echo "Fetching additional URLs from waybackurls with the same extensions as gobuster..." | lolcat
sleep 1
waybackurls "$url" | grep -E "\.js$|\.php$|\.yml$|\.env$|\.txt$|\.xml$|\.config$" | sed -E "s#(https?://)?(www\.)?$domain.*#\1\2$domain#g" | sort -u | httpx -verbose -o "$domain/waybackurls.txt" | lolcat

# Combine the discovered URLs from gobuster and waybackurls, removing duplicates
echo "Combining discovered URLs from gobuster and waybackurls..." | lolcat
sleep 1
cat $domain/waybackurls.txt $domain/discovered_urls.txt | sort -u > $domain/combined_urls.txt
mv $domain/combined_urls.txt $domain/discovered_urls.txt

# Set the starting count to 0
count=0
# Loop through each URL and run curl with xargs and parallel processing
echo "Performing curl on every URL I found to fetch the content..." | lolcat
sleep 1
while read url; do
  echo "Fetching content from $url..." | lolcat
  curl -vsS -n "$url" > "$domain/discovered_urls_for_$(echo $url | awk -F/ '{print $3}').txt" 2>&1
done < "$domain/discovered_urls.txt"
# Search for secrets in the output of curl and save the result in secrets.csv
echo "I am now searching for secrets using secrethub.json and saving the results in secrets.csv for you..." | lolcat
sleep 1
if [ ! -f "$domain/discovered_urls_for_$domain.txt" ]; then
  echo "No discovered_urls_for_$domain file found."
  exit 1
fi
while read discovered_url; do
  discovered_url_file="$domain/discovered_urls_for_$(echo $discovered_url | awk -F/ '{print $3}').txt"
  if [ ! -f "$discovered_url_file" ]; then
    echo "File $discovered_url_file does not exist."
    continue
  fi
secret_found=$(grep -E $(cat secrethub.json | jq -r '.patterns | join("|")') "$domain/discovered_urls_for_$(echo $discovered_url | awk -F/ '{print $3}').txt" | awk '!seen[$0]++ { print $0 }')
  count=$(echo "$secret_found" | wc -l)
  echo "URL Affected: $discovered_url, Secret Found: $secret_found" >> "$domain/secrets.csv"
  echo "Total secrets found: $count" >> "$domain/secrets.csv"
done < "$domain/discovered_urls.txt"
# Print Summary
echo "Scan & Analysis has completed! Results saved under $domain" | lolcat
echo "Total secrets found for $domain: $count" | lolcat
# Matrix effect
echo "Exiting the Matrix for 5 seconds in:" | toilet --metal -f term -F border
sleep 1
echo "3" | toilet --gay -f term -F border
sleep 1
echo "2" | toilet --metal -f term -F border
sleep 1
echo "1" | toilet --gay -f term -F border
sleep 1

R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
B='\033[0;34m'
P='\033[0;35m'
C='\033[0;36m'
W='\033[1;37m'

for ((i=0; i<5; i++)); do
    echo -ne "${R}10 ${G}01 ${Y}11 ${B}00 ${P}01 ${C}10 ${W}00 ${G}11 ${P}01 ${B}10 ${Y}11 ${C}00\r"
    sleep 0.2
    echo -ne "${R}01 ${G}10 ${Y}00 ${B}11 ${P}10 ${C}01 ${W}11 ${G}00 ${P}10 ${B}01 ${Y}00 ${C}11\r"
    sleep 0.2
    echo -ne "${R}11 ${G}00 ${Y}10 ${B}01 ${P}00 ${C}11 ${W}01 ${G}10 ${P}00 ${B}11 ${Y}10 ${C}01\r"
    sleep 0.2
    echo -ne "${R}00 ${G}11 ${Y}01 ${B}10 ${P}11 ${C}00 ${W}10 ${G}01 ${P}11 ${B}00 ${Y}01 ${C}10\r"
    sleep 0.2
done
echo -e "\033[2J\033[?25h" # reset screen
