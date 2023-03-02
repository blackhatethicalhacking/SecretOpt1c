# BHEH's SecretOpt1c

<p align="center">
<a href="https://www.blackhatethicalhacking.com"><img src="https://pbs.twimg.com/profile_banners/770898848197795840/1650879597/1500x500" width="600px" alt="BHEH"></a>
</p>
<p align="center">
<a href="https://www.blackhatethicalhacking.com"><img src="https://www.blackhatethicalhacking.com/wp-content/uploads/2022/06/BHEH_logo.png" width="300px" alt="BHEH"></a>
</p>

<p align="center">

**Unleashing secrets, for a successful attack with pinpoint accuracy**

SecretOpt1c is written by Chris "SaintDruG" Abou-Chabke from Black Hat Ethical Hacking and is designed for Red Teams and Bug Bounty Hunters!
</p>

# Description

SecretOpt1c is designed for Red Team, Pentesters, and Bug Bounty Hunters. It is a very powerful and versatile tool that helps uncover sensitive information on websites using ACTIVE and PASSIVE Techniques for Superior Accuracy!  It utilizes a payload wordlist that you provide and has a built-in powerful regex pattern matching engine that is written for you based on a lot of research which is included as ‘secrethub.json‘ file to accurately identify secrets hidden within a website's pages. We use Both Active, and Passive recon using ‘Gobuster‘ and ‘Waybackurls‘ to fetch a lot of URLs then use grep for specific extensions such as Javascript and other juicy matching patterns, which gets piped to ‘httpx‘ to find valid URLs, and then everything gets merged into one final URL removing duplicates, which we then run ‘curl’ and fetch all the content analyzing them with our patterns and then saving only the secrets found with the snippet in a CSV file..

# Features:

- Input: The first step is to take input from the user for the URL and wordlist. This is done using the read command, which prompts the user to enter the URL and the path to the wordlist.
- Wordlist existence check: The next step is to check if the wordlist file exists or not. This is done using the if [ ! -f $wordlist ]; then command, which checks if the file at the specified path does not exist. If the file does not exist, an error message is displayed, and the script exits.
- Directory creation: The next step is to create a directory to store the results of the curl command. This is done using the mkdir -p $domain command, where $domain is the domain name of the URL extracted using the awk command.
- Gobuster: The fourth step is to run gobuster, which is a tool for discovering directories and files in websites. This is done using the gobuster dir command, with the following options:
- -u $url: specifies the URL to be tested
- -w $wordlist: specifies the path to the wordlist
- -x .js,.php,.yml,.env,.txt,.xml,.html,.config: specifies the file extensions to be tested
- -e: enables the extension testing
- -s 200,204,301,302,307,401,403: specifies the status codes to be considered as successful
- --random-agent: sets a random user agent in each request
- -o $domain/gobuster.txt: saves the output to a file in the directory created in step 3
- Waybackurls also takes place just after Gobuster, it uses the same extensions and uses httpx and then combines both results sorting them into one final big discovery!
- Displays a cool progress bar as it analyses secrets
- URL extraction: The fifth step is to extract the discovered URLs from the gobuster output. This is done using the grep command with the -oE option, which extracts the URLs that match the regular expression "(http|https)://[a-zA-Z0-9./?=_-]*". The extracted URLs are then sorted and stored in a file using the sort -u > $domain/discovered_urls.txt command. It will fetch both 200 and 301 responses adding the redirected URL to the list.
- Loop through URLs: The sixth step is to loop through each of the discovered URLs and run the curl command to retrieve the content of the URL. This is done using a while loop and the read command, which reads each line of the discovered_urls.txt file. For each URL, the curl command is run with the -s option, which suppresses output, and the output is saved to a file with the name discovered_urls_for_$(echo $discovered_url | awk -F/ '{print $3}').txt.
- Secrets discovery: The seventh step is to search for secrets in the output of the curl command. This is done using the grep and awk commands. The secrets are searched for using regular expressions specified in the secrethub.json file, which is processed using the jq command. The grep command searches the content. It is highly configured to also print each URL + Full Path before each secret found to know where it found it.

It is also, our little S3cr3t...

![giphy](https://user-images.githubusercontent.com/13942386/220763198-c2a91923-c21d-4ede-851d-ce8aa983708a.gif)

# Requirements:

To use SecretOpt1c, you need to have the following tools installed:

- figlet & lolcat: `pip install lolcat` & `apt-get install figlet`

- (Pipe Viewer) utility to display a progress bar in the terminal. You can install "pv" by running: `sudo apt-get install pv`

- Gobuster: Gobuster is a tool used to brute force subdomains and directories. It is the core component of S3cr3tDetect0rz and is required for the tool to function.
You can install Gobuster on Kali Linux by running the following command:

`sudo apt-get install gobuster`

- Waybackurls : `go install github.com/tomnomnom/waybackurls@latest`

- Wordlists: SecretOpt1c uses wordlists to brute force subdomains and directories. There are several good wordlists available online, such as the SecLists project (https://github.com/danielmiessler/SecLists) and the FuzzDB project (https://github.com/fuzzdb-project/fuzzdb).

- SecretHub.json: SecretHub.json is a custom regex pattern matching engine that is included in the S3cr3tDetect0rz GitHub repository

# Installation

`git clone https://github.com/blackhatethicalhacking/SecretOpt1c.git`

`cd SecretOpt1c`

`chmod +x SecretOpt1c.sh`

`./SecretOpt1c.sh`

- The script will prompt you to provide the target URL(s) to test for open redirect vulnerabilities.
- Enter the wordlist Path

# Screenshot

**Main Menu**

<img width="960" alt="SecretOpt1c" src="https://user-images.githubusercontent.com/13942386/220762924-f9f98746-ef87-469c-b4dd-2dfaec9ade7b.png">

# Compatibility: 

This tool has been tested on Kali Linux, Ubuntu and MacOS.

# Disclaimer

This tool is provided for educational and research purpose only. The author of this project are no way responsible for any misuse of this tool. 
We use it to test under NDA agreements with clients and their consents for pentesting purposes and we never encourage to misuse or take responsibility for any damage caused !

# Support

If you would like to support us, you can always buy us coffee(s)! :blush:

<a href="https://www.buymeacoffee.com/bheh" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>

