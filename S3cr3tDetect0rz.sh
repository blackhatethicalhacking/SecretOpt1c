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
if [ ! -f $wordlist ]; then
  echo "Error: wordlist file $wordlist does not exist."  | lolcat
  exit 1
fi
# Create a directory to store the results of curl using the domain name of the URL provided by the user
echo "Creating a directory to save all results..." | lolcat
domain=`echo $url | awk -F/ '{print $3}'`
mkdir -p $domain
# Start gobuster with given URL and wordlist
echo "Starting GoBuster with ACTIVE Scan against the target searching for specific extensions, filtering with 200 & 301 status codes..." | lolcat
gobuster dir -u $url -w $wordlist -x .js,.php,.yml,.env,.txt,.xml,.html,.config -e -s 200,204,301,302,307,401,403 --wildcard -o $domain/gobuster.txt
# Extract the discovered URLs for further testing
grep "Status: 200" $domain/gobuster.txt | grep -oE "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u > $domain/discovered_urls.txt
grep "Status: 301" $domain/gobuster.txt | grep -oE "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u >> $domain/discovered_urls.txt
# Loop through each URL and run curl
echo "Performing curl on every URL I found to fetch the content..." | lolcat
while read discovered_url; do
  curl -s $discovered_url > $domain/discovered_urls_for_$(echo $discovered_url | awk -F/ '{print $3}').txt
done < $domain/discovered_urls.txt
# Search for secrets in the output of curl and save the result in secrets.csv
echo "I am now searching for Secrets using secrethub.json and saving the results in secrets.csv for you..." | lolcat
if [ ! -f $domain/discovered_urls_for_* ]; then
  echo "No discovered_urls_for_* file found for $domain."
  exit 1
fi
for file in $domain/discovered_urls_for_*; do
  while read -r url; do
    count=$(grep -E $(cat secrethub.json | jq -r '.patterns | join("|")') "$file" | awk -v url="$url" 'BEGIN {count=0} {count++; print url "," $0} END {print count}')
    if [ $count -ne 0 ]; then
      echo "I have completed the task for $url successfully!"
      echo "$count" >> $domain/secrets.csv
    fi
  done < "$file"
done
# Print summary of secrets found
echo "Total secrets found:"
cat $domain/secrets.csv | column -t
echo "Offense is the best Defense baby!" | lolcat
