# VT_BulkHashCheker
This is a basic python script which can be used for static analysis of suspicious files in bulk. It utilises VirusTotal API V3 for checking the hashes. 
The VT_BulkHashChecker creates a table out of API's json output and writes it down to a file of your choice. 
Hashes can be fed via another csv or txt file. Due to 4 lookups/min limitation, there is a 20 seconds sleep command in between checking hashes.  

## Virus Total API
For more information about Virus Total API please visit https://developers.virustotal.com/reference/overview. For this script you will need a Virus Total standard free public API key.
This key can be obtained in Virus Total by creating an account. Under the account you will see API key where you can find your API key and other information about Virus Total API including daily and historical usage. 
