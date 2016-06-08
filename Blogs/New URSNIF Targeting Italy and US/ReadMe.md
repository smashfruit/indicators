# [New Ursnif Variant Targeting Italy and U.S](http://www.threatgeek.com/2016/06/new-ursnif-variant-targeting-italy-and-us.html)
Fidelis Cybersecurity has been investigating a new variant of Ursnif, a family of trojans that captures and reports information about user activity back to the attacker. We recently observed the variant distributed in phishing runs designed to appear as legitimate banking-related emails. On infected hosts, it attempts to perform webinjects to capture credentials for major U.S. banking sites, including Citibank, JPMorgan Chase, USAA and Capital One. Interestingly, it takes screenshots when victims visit a variety of Italian sites, such as Unicredit, Poste and Relax Banking. To evade detection, it also blocks access to a surprisingly large number of security-related websites. What specifically grabbed our attention was the change in command-and-control traffic that distinguishes it from standard Ursnif.

Even as ransomware dominates the headlines, banking trojans are a profitable mainstay of the criminal domain. As recently reported, ransomware like CryptXXX has acquired credential-theft capabilities, signaling a marriage of sorts within the crime family. Banking trojans have been the vehicle for numerous innovations in malware over the years. These developments in Ursnif show us that technical investment across the crime domain continues. The targeting of Italian and U.S. financial institutions also points to the global scope of opportunity for such criminal actors.

[Read our post on ThreatGeek as it covers our analysis of these changes and how we reversed them. Further, we share configuration details as well as IOCs.](http://www.threatgeek.com/2016/06/new-ursnif-variant-targeting-italy-and-us.html)

### Indicators (md5/sha256)
	Ursnif targeting US and Italy:
	  e8d104c97287ba98d3b750bf91a0b9c1
	  d14ab7f83936d614346750fc83718b1b247cf36c148056d807f18b5685793abb
		
	  c3427fdb8003ba47f75a65df125f4ff3 
	  5e64011e7f61ee8738f49da42ca591a85b714c169ec6a74d60e9b8282d8ad050
	 
	JavaScript Downloaders:
	  4cf51d138bcace95fd0e280cdb02b038
	  22ce1f05b4531f6b312f6fc24246f5318b90b5366dcd647a42d680676db1cd73
	  
	  4d72b546d1031dff9acf2c5a24ba4d12
	  34ad04778a5a1d50b55a6cd15663bf6433aea0608eb6349f5a18b96bd1e4ebc9
	 
	Andromeda JavaScript downloader from "fuchsias[.]net/New_Folder/icq.scr":
	  dd724d8f1f173b0d7ff0d5b0505b8eb7
	  6928891dfcf54ad70c5bf29aa1e518b1ab5f74a560099d9c9cc3e4a468811e59
	  
	Andromeda binary from "antoniocaroli[.]it/prova/sd/LnMSLFOfwwout.exe":
	  e8d104c97287ba98d3b750bf91a0b9c1
	  d14ab7f83936d614346750fc83718b1b247cf36c148056d807f18b5685793abb


### Yara Rule for Ursnif variant detection

	rule Ursnif_report_variant_memory
	{
	meta:
	 description = "Ursnif"
	 author = "Fidelis Cybersecurity"
	 reference = "New Ursnif Variant Targeting Italy and U.S - June 7, 2016"
	
	strings:
	 $isfb1 = "/data.php?version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s"
	 $isfb2 = "client.dll"
	 $ursnif1 = "soft=1&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x"
	 $a1 = "grabs="
	 $a2 = "HIDDEN"
	 $ursnif2 = "/images/"
	 $randvar = "%s=%s&"
	 $specialchar = "%c%02X" nocase
	 $serpent_setkey = {8b 70 ec 33 70 f8 33 70 08 33 30 33 f1 81 f6 b9 79 37 9e c1 c6 0b 89 70 08 41 81 f9 84 [0-3] 72 db}
	condition:
	7 of them
	}

