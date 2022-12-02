import requests
import json
import time

apikey = '<YOUR API KEY>'
hashes = open("/input/file/here") # the hashes to check
analysis = open("/output/file/here", "w") # the file to save to the result
analysis.write("\t\t\tLink,File Name,File Type,Undetected,Detected_Suspicious,Detected_Malicious,Threat Label,Tag1,Tag2,Tag3,Tag4"
               "\n")
for hashn in hashes:
        print('Checking hash ' + hashn)
        url = "https://www.virustotal.com/api/v3/files/"
        VTlink= "https://www.virustotal.com/gui/file/"
        headers = {
             "accept": "application/json",
             "x-apikey": "8011dab2fe52005cd3badc6f20205e7cac37062321a993edcf4423b8d92b058f"
             }
        response= requests.get(url+hashn, headers=headers, timeout= 120)
       
        if response.status_code == 404:
          result = response.json()         
          analysis.write(VTlink+hashn.strip() + ","+ "Not Found in Virus Total Database"+"\n")

        elif response.status_code == 200:
         result = response.json()
# write only the files recognized as malicious
         analysis.write((((((((VTlink+hashn.strip() + "," + str(result['data']['attributes']['names'][0])+ ",") +str(result['data']['attributes']['type_description'])+",") + str(result['data']['attributes']['last_analysis_stats']['undetected'])+",")
                   +str(result['data']['attributes']['last_analysis_stats']['suspicious'])+",")+str(result['data']['attributes']['last_analysis_stats']['malicious'])+",")
                   + str(result['data']['attributes']['popular_threat_classification']['suggested_threat_label'])+",")
                   +str(result['data']['attributes']['tags'])+",")+"\n")
        time.sleep(1 * 20)
