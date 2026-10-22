

import requests
import json
import time
import os
import ipaddress
import re
from datetime import datetime
from dotenv import load_dotenv





load_dotenv()



from colorama import Fore, Style, init
init()


from colorama import init, Fore, Style
init(autoreset=True)





def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
    






def is_vaild_email(email):
    pattern = (r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]+\.[a-zA-Z]{2,}$')
    return re.match(pattern, email) is not None







def is_vaild_phone(phone):
    pattern = r'^\+\d{8,15}$'
    return re.match(pattern, phone) is not None







def is_vaild_website(url_to_scan):
    return url_to_scan.startswith("http://") or url_to_scan.startswith("https://")

    




def log_scan(scan_type, details_block):
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

    with open("scan_log.txt", "a") as file:
        file.write("=" * 40 + "\n")
        file.write(f"[{timestamp}] {scan_type} SCAN\n")
        file.write("-" * 40 + "\n")
        file.write(details_block)
        file.write("=" * 40 + "\n\n")










ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
EMAIL_KEY = os.getenv("EMAIL_KEY")
PHONE_KEY = os.getenv("PHONE_KEY")
URLSCAN_KEY = os.getenv("URLSCAN_KEY")







def print_banner():
    banner = """
┌─────────────────────────────────────┐
│                                     │
│        🛡️  SOC SCANNER TOOL  🛡️     │
│                                     │
│   Threat Intelligence Lookup Tool   │
│                                     │
│   ▸ IP Address                      │
│   ▸ Email Address                   │
│   ▸ Phone Number                    │
│   ▸ Website URL                     │
│                                     │
└─────────────────────────────────────┘
    """
    print(Fore.GREEN + banner + Style.RESET_ALL)








def check_ip(ip):

    
    url = "https://api.abuseipdb.com/api/v2/check"
   


    headers = {

      "Key": ABUSEIPDB_KEY,
      "Accept": "application/json"

    }


    params = {

      "ipAddress": ip,
      "maxAgeInDays": 90,
      
    }

    response = requests.get(url, headers=headers, params=params)
    data = response.json()


    try:
       score = data["data"]["abuseConfidenceScore"]
       isp = data["data"]["isp"] 
       country = data["data"]["countryCode"]
       total_Reports = data["data"]["totalReports"]

       

       print(Fore.CYAN + "=" * 40 + Style.RESET_ALL)
       print(f"IP: {ip}")
       print(f"Score: {score}%")
       print(f"ISP: {isp}")
       print(f"Contry: {country}")
       print(f"Total_Reports: {total_Reports}") 


       if score > 80:
           print(Fore.RED + "Recommendation: BLOCK IMMEDIATELY" + Style.RESET_ALL)
           details_block = f"IP: {ip}\nScore: {score}%\nISP: {isp}\nCountry: {country}\nTotal Reports: {total_Reports}\nRecommendation: BLOCK IMMEDIATELY\n"
           log_scan("IP", details_block)



       elif score > 40:
           print(Fore.YELLOW + "Recommendation: MONITOR CLOSELY" + Style.RESET_ALL)
           details_block = f"IP: {ip}\nScore: {score}%\nISP: {isp}\nCountry: {country}\nTotal Reports: {total_Reports}\nRecommendation: MONITOR CLOSELY\n"
           log_scan("IP", details_block)



       else:
           print(Fore.GREEN + "Recommendation: LOW RISK" + Style.RESET_ALL)
           details_block = f"IP: {ip}\nScore: {score}%\nISP: {isp}\nCountry: {country}\nTotal Reports: {total_Reports}\nRecommendation: LOW RISK\n"
           log_scan("IP", details_block)

       print(Fore.CYAN + "=" * 40 + Style.RESET_ALL)

    except KeyError:
        print("KeyError")



def check_email(email):
    
    url = "https://emailreputation.abstractapi.com/v1/"
    
    
    params = {
    
         "api_key": EMAIL_KEY,
         "email": email
    
    
    }
    
    
    response = requests.get(url, params=params)
    data = response.json()
   

    try:
      
       status = data["email_deliverability"]["status"]
       domain_age = data["email_domain"]["domain_age"]
       is_username_suspicious = data["email_quality"]["is_username_suspicious"]
       disposable = data["email_quality"]["is_disposable"]
       quality_score = data["email_quality"]["score"]
       risk_status = data["email_risk"]["address_risk_status"]
      
      
       print(Fore.CYAN + "=" * 40 + Style.RESET_ALL)
       print(f"Status: {status}")
       print(f"Domain_age: {domain_age}")
       print(f"Is_username_suspicious: {is_username_suspicious}")
       print(f"Disposable: {disposable}")
       print(f"Quality_score: {quality_score}")
       print(f"Risk_status: {risk_status}")
       
      
      
       if risk_status == "high":
          print(Fore.RED + "BLOCK / INVESTIGATE" + Style.RESET_ALL)
          details_block = f"Email: {email}\nStatus: {status}\nDomain Age: {domain_age}\nSuspicious Username: {is_username_suspicious}\nDisposable: {disposable}\nQuality Score: {quality_score}\nRisk Status: {risk_status}\nRecommendation: BLOCK / INVESTIGATE\n"
          log_scan("EMAIL", details_block)



       elif risk_status == "medium": 
          print(Fore.YELLOW + "MONITOR" + Style.RESET_ALL)
          details_block = f"Email: {email}\nStatus: {status}\nDomain Age: {domain_age}\nSuspicious Username: {is_username_suspicious}\nDisposable: {disposable}\nQuality Score: {quality_score}\nRisk Status: {risk_status}\nRecommendation: MONITOR\n"
          log_scan("EMAIL", details_block)




       else:
          print(Fore.GREEN + "LOW RISK" + Style.RESET_ALL)
          details_block = f"Email: {email}\nStatus: {status}\nDomain Age: {domain_age}\nSuspicious Username: {is_username_suspicious}\nDisposable: {disposable}\nQuality Score: {quality_score}\nRisk Status: {risk_status}\nRecommendation: LOW RISK\n"
          log_scan("EMAIL", details_block)




          print(Fore.CYAN + "=" * 40 + Style.RESET_ALL)
          

    except KeyError:
      print("try agian")
      


def check_phone(phone):
    
    url = "https://phoneintelligence.abstractapi.com/v1/?"


    params = {

      "api_key": PHONE_KEY,
      "phone": phone

    }


    response = requests.get(url, params=params)
    data = response.json()


    
    try:


       is_valid = data["phone_validation"]["is_valid"]
       line_status = data["phone_validation"]["line_status"]
       is_voip = data["phone_validation"]["is_voip"]
       line_type = data["phone_carrier"]["line_type"]
       phone_carrier = data["phone_carrier"]["name"]
       is_disposable = data["phone_risk"]["is_disposable"]
       risk_level = data["phone_risk"]["risk_level"]




       print(Fore.CYAN + "=" * 40 + Style.RESET_ALL)
       print(f"is_valid: {is_valid}")
       print(f"line_status: {line_status}")
       print(f"is_voip: {is_voip}")
       print(f"line_type: {line_type}")
       print(f"phone_carrier: {phone_carrier}")
       print(f"is_disposable: {is_disposable}")
       print(f"risk_level: {risk_level}")
       
    

       if risk_level == "high":
           print(Fore.RED + "Recommendation: BLOCK / INVESTIGATE" + Style.RESET_ALL)
           details_block = f"Phone: {phone}\nValid: {is_valid}\nLine Status: {line_status}\nVOIP: {is_voip}\nLine Type: {line_type}\nCarrier: {phone_carrier}\nDisposable: {is_disposable}\nRisk Level: {risk_level}\nRecommendation: BLOCK / INVESTIGATE\n"
           log_scan("PHONE", details_block)



       elif risk_level == "medium":
           print(Fore.YELLOW + "Recommendation: MONITOR CLOSELY" + Style.RESET_ALL)
           details_block = f"Phone: {phone}\nValid: {is_valid}\nLine Status: {line_status}\nVOIP: {is_voip}\nLine Type: {line_type}\nCarrier: {phone_carrier}\nDisposable: {is_disposable}\nRisk Level: {risk_level}\nRecommendation: MONITOR CLOSELY\n"
           log_scan("PHONE", details_block)




       elif is_voip == True:
           print(Fore.LIGHTMAGENTA_EX + "Recommendation: CAUTION - VOIP number, verify manually" + Style.RESET_ALL)
           details_block = f"Phone: {phone}\nValid: {is_valid}\nLine Status: {line_status}\nVOIP: {is_voip}\nLine Type: {line_type}\nCarrier: {phone_carrier}\nDisposable: {is_disposable}\nRisk Level: {risk_level}\nRecommendation: CAUTION - VOIP number\n"
           log_scan("PHONE", details_block)




       else:
           print(Fore.GREEN + "Recommendation: LOW RISK" + Style.RESET_ALL)
           details_block = f"Phone: {phone}\nValid: {is_valid}\nLine Status: {line_status}\nVOIP: {is_voip}\nLine Type: {line_type}\nCarrier: {phone_carrier}\nDisposable: {is_disposable}\nRisk Level: {risk_level}\nRecommendation: LOW RISK\n"
           log_scan("PHONE", details_block)

 
           print(Fore.CYAN + "=" * 40 + Style.RESET_ALL)

    except KeyError:
        print("try agian")



def check_website(url_to_scan):

    
    supmet_url = "https://urlscan.io/api/v1/scan/"



    headars = {

       "API-key": URLSCAN_KEY,
       "Content-Type": "application/json"

    }


    data_to_send = {

        "url": url_to_scan,
        "visibility": "public"

    }



    response = requests.post(supmet_url, data=json.dumps(data_to_send), headers=headars)
    result = response.json()


    print("requests is done... ")
    print(result)

    if "uuid" not in result:
        print(Fore.RED + "Scan was blocked or failed: " + result.get("message", "Unknown errorew") + Style.RESET_ALL)
        return

    scan_id = result["uuid"]
    print("wait")
    time.sleep(15)



    result_url = f"https://urlscan.io/api/v1/result/{scan_id}/"
    final_respons = requests.get(result_url, headers=headars)
    final_data = final_respons.json()
    print(final_data)
   
   
    try:

        overall_malicious = final_data["verdicts"]["overall"]["malicious"]
        engines_malicious = final_data["verdicts"]["engines"]["malicious"]
        engines_score = final_data["verdicts"]["engines"]["score"]
        domain = final_data["page"]["domain"]
        domain_age = final_data["page"]["apexDomainAgeDays"]
        stats_malicious = final_data["stats"]["malicious"]
    
    
        domains_list = final_data["lists"]["domains"]
        countries_list = final_data["lists"]["countries"]
        console_errors = final_data["data"]["console"]
    
    
        print(Fore.CYAN + "=" * 40 + Style.RESET_ALL)
        print(f"Domain: {domain}")
        print(f"Domain Age (days): {domain_age}")
        print(f"Overall Malicious: {overall_malicious}")
        print(f"Engines Malicious: {engines_malicious}")
        print(f"Engines Score: {engines_score}")
        print(f"Malicious Requests Count: {stats_malicious}")
        print(f"External Domains Contacted: {len(domains_list)}")
        print(f"Countries Involved: {countries_list}")
        print(f"Console Errors Count: {len(console_errors)}")
        


        if overall_malicious or engines_malicious:
            print(Fore.RED + "Recommendation: BLOCK / INVESTIGATE" + Style.RESET_ALL)
            details_block = f"Domain: {domain}\nDomain Age: {domain_age}\nOverall Malicious: {overall_malicious}\nEngines Malicious: {engines_malicious}\nEngines Score: {engines_score}\nMalicious Requests: {stats_malicious}\nExternal Domains: {len(domains_list)}\nCountries: {countries_list}\nConsole Errors: {len(console_errors)}\nRecommendation: BLOCK / INVESTIGATE\n"
            log_scan("WEBSITE", details_block)




        elif domain_age < 90:
            print(Fore.YELLOW + "Recommendation: CAUTION - new domain, verify manually" + Style.RESET_ALL)
            details_block = f"Domain: {domain}\nDomain Age: {domain_age}\nOverall Malicious: {overall_malicious}\nEngines Malicious: {engines_malicious}\nEngines Score: {engines_score}\nMalicious Requests: {stats_malicious}\nExternal Domains: {len(domains_list)}\nCountries: {countries_list}\nConsole Errors: {len(console_errors)}\nRecommendation: CAUTION - new domain\n"
            log_scan("WEBSITE", details_block)



        else:
            print(Fore.GREEN + "Recommendation: LOW RISK" + Style.RESET_ALL)
            details_block = f"Domain: {domain}\nDomain Age: {domain_age}\nOverall Malicious: {overall_malicious}\nEngines Malicious: {engines_malicious}\nEngines Score: {engines_score}\nMalicious Requests: {stats_malicious}\nExternal Domains: {len(domains_list)}\nCountries: {countries_list}\nConsole Errors: {len(console_errors)}\nRecommendation: LOW RISK\n"
            log_scan("WEBSITE", details_block)

        print(Fore.CYAN + "=" * 40 + Style.RESET_ALL) 

    except KeyError:
        print("Scan not ready yet - try again in a moment")





print_banner()




while True:
    choise = input(Fore.GREEN + "ip / email / phone / website / exit : " + Style.RESET_ALL).lower()


    
    if choise == "ip":

        user_ip = input(Fore.GREEN + "\nIP: " + Style.RESET_ALL)

        if  is_valid_ip(user_ip):
           print(Fore.GREEN + "Valid IP! Scanning..." + Style.RESET_ALL)
           check_ip(user_ip)

        else:
            print(Fore.RED + "Invalid IP format! Try again" + Style.RESET_ALL)
            continue






        
    elif choise == "email":

        user_email = input(Fore.GREEN + "\nEmail: " + Style.RESET_ALL)

        if is_vaild_email(user_email):
            print(Fore.GREEN + "Valid Email! Scanning..." + Style.RESET_ALL)
            check_email(user_email)

        else:
            print(Fore.RED + "Invalid Email format! Try again" + Style.RESET_ALL)
            continue











    elif choise == "phone":

        user_phone = input(Fore.GREEN + "\nphone: " + Style.RESET_ALL)

        if is_vaild_phone(user_phone):
            print(Fore.GREEN + "Valid PhoneNum! Scanning..." + Style.RESET_ALL)
            check_phone(user_phone)


        else:
            print(Fore.RED + "Invalid Numper format! Try again" + Style.RESET_ALL)
            continue






  



    elif choise == "website":

        user_website = input(Fore.GREEN + "\nWebsite: " + Style.RESET_ALL)

        if is_vaild_website(user_website):
            print(Fore.GREEN + "Valid Website! Scanning...")
            check_website(user_website)
        else:
            print(Fore.RED + "Invalid Website format! Try again" + Style.RESET_ALL)



    elif choise == "exit":
         print(Fore.MAGENTA + "\nGoodbay!\n" + Style.RESET_ALL)
         break

    else:
        print("Wrong choice; try again.")



