# Mini-Project-4-30-Day-MyDFIR-Microsoft-Challenge

In this project I will have complete these two tasks and create report using these two tasks. 

1.	Phishing Simulation – Create a fake phishing email and send it to one of your test accounts.
2.	Risky Sign-In – Log in to your tenant/mailbox with your test account from a different region or use a VPN to simulate a suspicious sign-in from another country.



# Creating a fake phishing email 

<img width="454" height="397" alt="1 creating a fake phishing emails" src="https://github.com/user-attachments/assets/3952b0cf-ed10-481b-a73b-4851d5bef73f" />


# Quarantine the email using anti-phishing policy now release it and investigate further 
<img width="790" height="334" alt="2 quarintine  emails" src="https://github.com/user-attachments/assets/7dfcc088-f9a2-49ad-813c-5617224bdf84" />

# Investigate the phishing email <img width="761" height="358" alt="03 investigate the phishing emails " src="https://github.com/user-attachments/assets/c8de00ae-1c55-4165-9ad0-f5fb18e9a398" />


# Check out the Risky Sign-In 

<img width="519" height="308" alt="04 risky sign in " src="https://github.com/user-attachments/assets/27cdc601-65cf-4b52-aeb4-67484a889b77" />


# Create a  CApolicy for risky sign-in 

<img width="806" height="329" alt="05 condition access policy" src="https://github.com/user-attachments/assets/5b55f0fc-df97-42c6-9548-907dbca8fa9c" />



# Block the access from  risky sing-in location

<img width="329" height="298" alt="05 you can not access" src="https://github.com/user-attachments/assets/24aeec99-3ed2-4a7d-b7c5-82783ba07d7a" />


# check the url links in the advance hunting using kql queries

<img width="557" height="302" alt="06 emial delivery advance hunting" src="https://github.com/user-attachments/assets/67026ad6-8cd1-4ab6-a9d4-2202aedf8695" />

# investigation a phishing email 

<img width="761" height="383" alt="07  phihsing email investigation" src="https://github.com/user-attachments/assets/cd587e80-9a80-4b0e-ba88-beb7986fb178" />


# Now Create a final report for using phishing emails and sign in risky location


I**ncident Report: User-Reported Phishing Email**

Date of Report: August 28, 2025

Report ID: IR-20250828-EmailPhish

Incident Severity: Low

**Executive Summary**

On August 28, 2025, a user within the organization reported a suspicious email as phishing via the Microsoft reporting mechanism. The automated security system subsequently triggered an alert. The email, which attempted to impersonate a legitimate user, was successfully blocked and quarantined by the email security systems upon delivery. No malicious payload was executed, and no further suspicious activity was identified on the affected user's account. The incident was contained quickly with no data exfiltration or system compromise.

**5W's and 1H Analysis**

•	Who:

    o	Attacker: The sender used the display name "shahid ali" from the email address khambro12@outlook.com.
    o	Impacted User: The internal user shahid ali (mailbox: khambro@khambro.onmicrosoft.com).
    
**•	What:**
    
    o	A phishing email was delivered to a user's mailbox. The email was designed to impersonate another user within the organization (shahid ali) 
    to lend it credibility. The user correctly identified the email as suspicious and reported it using the "Report Phish" function.

**•	When:**

    o	Email Received: August 28, 2025, at 1:32 PM (UTC+05:00).
    o	User Reported: Between 3:51:00 AM and 3:52:00 AM UTC on August 28, 2025 (this aligns with the "Last activity" timestamp of the alert).
    o	Investigation Period: The system's automated investigation ran from 3:54 AM to 4:25 AM UTC.
    
**•	Where:**

      o	The email was an Inbound message from an external sender (outlook.com) to the internal Microsoft 365 mailbox.
      o	The sender's IP address (2a01:111:f403:2804::825) is associated with Google LLC in Mountain View, California, 
      USA, suggesting the use of a cloud-based email service or VPN.
      
**•	Why:**

        o	The objective was likely credential phishing or social engineering. The use of impersonation (shahid ali sending to khambro) and 
        a link to a legitimate but commonly spoofed service (docusign.com) are classic hallmarks of an attempt to trick the user into
        entering their credentials on a fake login page or opening a malicious document.

**•	How:**

      o	Initial Access Vector: The vector was Phishing via Email. The attacker sent a crafted email designed to deceive the recipient into interacting
      with a malicious element (likely a link, though the specific threat was not detailed in the provided URLs).
      o	The email passed standard authentication checks (SPF, DKIM, DMARC = Pass), meaning it was spoofed in content (display name) rather than 
      through domain forgery, a technique known as "display name spoofing."

**Detailed Findings**

**1. What triggered the incident?**
            The incident was triggered by a user (shahid ali) using the "Report Message" feature to classify a specific email as malware or phishing.
            This user action activated the alert policy "Email reported by user as malware or phish."
            
**3. What was the initial access vector?**

    The initial access vector was a phishing email. The attacker attempted to gain a foothold by tricking a user into clicking a link, likely leading to a credential-harvesting page.
    
**4. What user accounts were impacted?**

One user account was impacted: shahid ali (mailbox: khambro@khambro.onmicrosoft.com). The account was the recipient of the phishing email.
There is no evidence of account compromise; the impact is defined as being targeted by the attack.

**5. Was there a suspicious sign-in or unusual behavior?**

    The provided data does not include any sign-in logs or behavioral analytics. Therefore, based solely on this email alert, no suspicious
    sign-in or post-delivery unusual behavior was detected. The investigation focused solely on the email itself.

**6. What kind of actions were taken on the endpoint if any?**

      The provided data is from an email security product (Microsoft Defender for Office 365) and does not contain endpoint detection and response (EDR) data. 
      Therefore, no endpoint actions are documented in this specific alert. The actions taken were confined to the email environment:
      
  •	Original Action: The email was Blocked and placed in Quarantine upon delivery.
  •	Subsequent Action: The email was released from Quarantine (likely by an admin for analysis) and moved to the user's Inbox/folder. This is noted as "Allowed by organization policy : Quarantine release."
  
**8. What timeline can you build from the evidence?**

  •	~Aug 28, 1:32 PM (Local Time): Phishing email is delivered to the user's mailbox and immediately quarantined by the system.
  •	Aug 28, 3:51:00 AM - 3:52:00 AM (UTC): User discovers the quarantined email (or it is released to their inbox) and reports it as phishing.
  •	Aug 28, 3:54 AM (UTC): Automated investigation begins based on the user report.
  •	Aug 28, 4:25 AM (UTC): Automated investigation concludes after ~31 minutes.

**9. Were there any activities that seemed unrelated or maybe surprising?**

  •	Surprising (But Likely Benign): The sender's IP address resolved to a Google ASN in the United States, not Microsoft (Outlook.com).
  This could indicate the attacker was using a VPN or Google Cloud infrastructure to send the mail, which is a common evasion tactic.
  •	Concerning Process: The email was initially successfully blocked and quarantined but was later released from quarantine by an "organization policy" or 
  an administrator. While this is a legitimate action (e.g., for false positive analysis), it introduced risk by placing the malicious email back into the user's inbox,    which is what ultimately led to the user report. The policy governing automatic quarantine releases should be reviewed.


**Conclusion & Recommendations**

This was a low-severity phishing attempt that was successfully identified by both automated systems and the end-user. The company's layered defense worked as intended.
Recommendations:

1.	**User Training**: Commend the user (shahid ali) for their vigilance in reporting the suspicious email. Consider highlighting this as a positive example in ongoing security awareness training.
   
3.	**Review Quarantine Policies**: Investigate the policy that automatically released this email from quarantine. Ensure releases are only done after thorough analysis to prevent potentially malicious emails from reaching end-users.
   
5.	**URL Analysis**: Although the URLs point to docusign.com and a ctfassets.net (Contentful CDN) domain, these could be used for baiting or obfuscation. A deeper analysis of the exact URL structure is recommended to rule out homograph attacks or subdomain spoofing.
   
7.	**Continue Monitoring:** Maintain vigilance for further phishing campaigns using similar impersonation tactics, particularly those spoofing internal employees.
