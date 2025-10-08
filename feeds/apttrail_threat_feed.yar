/*
   Maltrail APT Threat Feed - YARA Rules
   Source: https://github.com/stamparm/maltrail
   
   IMPORTANT: These are automatically generated rules for threat detection
   Review and test before deploying to production
*/

import "hash"
import "pe"

rule APT_12
{
    meta:
        description = "Detects IOCs associated with APT 12"
        author = "APTtrail Automated Collection"
        apt_group = "12"
        aliases = "apt-c-12, apt12, bluemushroom"
        reference = "https://bitofhex.com/2020/02/10/sapphire-mushroom-lnk-files/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "icc\.ignorelist\.com" ascii wide nocase
        $domain1 = "video\.csmcpr\.com" ascii wide nocase
        $ip2 = "178.128.110.214" ascii wide

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_17
{
    meta:
        description = "Detects IOCs associated with APT 17"
        author = "APTtrail Automated Collection"
        apt_group = "17"
        aliases = "apt-c-17, apt17, blackcoffee"
        reference = "https://github.com/fireeye/iocs/blob/master/APT17/7b9e87c5-b619-4a13-b862-0145614d359a.ioc"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "equitaligaiustizia\.it" ascii wide nocase
        $domain1 = "meeting\.equitaligaiustizia\.it" ascii wide nocase
        $domain2 = "news\.jusched\.net" ascii wide nocase
        $domain3 = "themicrosoftnow\.com" ascii wide nocase
        $domain4 = "translate\.wordraference\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_18
{
    meta:
        description = "Detects IOCs associated with APT 18"
        author = "APTtrail Automated Collection"
        apt_group = "18"
        reference = "https://github.com/fireeye/iocs/blob/master/APT18/0ae061d7-c624-4a84-8adf-00281b97797b.ioc"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "128\.er1620\.com" ascii wide nocase
        $domain1 = "223-25-233-248\.revdns\.8toinfinity\.com\.sg" ascii wide nocase
        $domain2 = "admin\.er1620\.com" ascii wide nocase
        $domain3 = "exp0day\.com" ascii wide nocase
        $domain4 = "ftp\.exp0day\.com" ascii wide nocase
        $domain5 = "gmail\.bkz88\.com" ascii wide nocase
        $domain6 = "good\.myftp\.org" ascii wide nocase
        $domain7 = "hello\.mjw\.bz" ascii wide nocase
        $domain8 = "info\.imly\.org" ascii wide nocase
        $domain9 = "login\.3bz\.org" ascii wide nocase
        $domain10 = "logo\.mjw\.bz" ascii wide nocase
        $domain11 = "suck\.er1620\.com" ascii wide nocase
        $domain12 = "test\.3bz\.org" ascii wide nocase
        $domain13 = "zip\.redirectme\.net" ascii wide nocase
        $ip14 = "223.25.233.248" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_1877TEAM
{
    meta:
        description = "Detects IOCs associated with APT 1877TEAM"
        author = "APTtrail Automated Collection"
        apt_group = "1877TEAM"
        reference = "https://otx.alienvault.com/pulse/64524a56a61ad32b77d042d9"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "1877\.krd" ascii wide nocase
        $domain1 = "1877\.team" ascii wide nocase
        $domain2 = "4567987654345265\.tk" ascii wide nocase
        $domain3 = "asadohostma\.cf" ascii wide nocase
        $domain4 = "asadohostma\.tk" ascii wide nocase
        $domain5 = "balotelaras\.gq" ascii wide nocase
        $domain6 = "bjigcdrfbbcx\.ml" ascii wide nocase
        $domain7 = "bjigcdrfbbcx\.tk" ascii wide nocase
        $domain8 = "bruthoosbxyxio\.gq" ascii wide nocase
        $domain9 = "bruthoosbxyxio\.tk" ascii wide nocase
        $domain10 = "bsidbxiooohzu\.ga" ascii wide nocase
        $domain11 = "bsidbxiooohzu\.gq" ascii wide nocase
        $domain12 = "bsidbxiooohzu\.ml" ascii wide nocase
        $domain13 = "buhgdkurd444\.ga" ascii wide nocase
        $domain14 = "coalermallwive\.ga" ascii wide nocase
        $domain15 = "dxfcvhhgfgcv\.dnsfailover\.net" ascii wide nocase
        $domain16 = "facebookmessages\.serveuser\.com" ascii wide nocase
        $domain17 = "facebooktie\.faqserv\.com" ascii wide nocase
        $domain18 = "forever0g\.tk" ascii wide nocase
        $domain19 = "gartytrgfredsw\.sexidude\.com" ascii wide nocase
        $domain20 = "gatasawatoyo\.dumb1\.com" ascii wide nocase
        $domain21 = "ghiiidueebsxiis\.ml" ascii wide nocase
        $domain22 = "ghiiidueebsxiis\.tk" ascii wide nocase
        $domain23 = "hgtgerfdrty\.onedumb\.com" ascii wide nocase
        $domain24 = "hsushzidooonsnx\.gq" ascii wide nocase
        $domain25 = "htetryfugyioiyut\.ml" ascii wide nocase
        $domain26 = "hunchifigkf\.wikaba\.com" ascii wide nocase
        $domain27 = "huncho\.ml" ascii wide nocase
        $domain28 = "hunchooo\.zzux\.com" ascii wide nocase
        $domain29 = "hunchoooof\.2waky\.com" ascii wide nocase
        $domain30 = "incxzsdcuuwqag\.serveuser\.com" ascii wide nocase
        $domain31 = "inlinkedlnmessagesdigiter\.serveuser\.com" ascii wide nocase
        $domain32 = "jagajaga\.ga" ascii wide nocase
        $domain33 = "jfueytg7yghg\.ga" ascii wide nocase
        $domain34 = "jhdfgdjkdg\.dynamic-dns\.net" ascii wide nocase
        $domain35 = "jhssales\.dynamic-dns\.net" ascii wide nocase
        $domain36 = "jhuyghft\.dynamic-dns\.net" ascii wide nocase
        $domain37 = "jihugkyfjtdsrytsrd\.cf" ascii wide nocase
        $domain38 = "jihugkyfjtdsrytsrd\.gq" ascii wide nocase
        $domain39 = "jnhbvgcfxdzsdzdsxd\.dns2\.us" ascii wide nocase
        $domain40 = "juyhtrdwski\.sexidude\.com" ascii wide nocase
        $domain41 = "kbbkbkuu\.dynamic-dns\.net" ascii wide nocase
        $domain42 = "kjuhygtrfdewsa\.onedumb\.com" ascii wide nocase
        $domain43 = "linkedlndeed\.fartit\.com" ascii wide nocase
        $domain44 = "linkup\.pics" ascii wide nocase
        $domain45 = "mail\.bsabshjlinacafs\.serveuser\.com" ascii wide nocase
        $domain46 = "mail\.facebookmessages\.serveuser\.com" ascii wide nocase
        $domain47 = "mail\.guyyyeyb\.youdontcare\.com" ascii wide nocase
        $domain48 = "mail\.inlinkedlnmessagesdigiter\.serveuser\.com" ascii wide nocase
        $domain49 = "mail\.jhdfgdjkdg\.dynamic-dns\.net" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_23
{
    meta:
        description = "Detects IOCs associated with APT 23"
        author = "APTtrail Automated Collection"
        apt_group = "23"
        aliases = "AirdViper, apt-c-23, apt23"
        reference = "https://about.fb.com/news/2021/04/taking-action-against-hackers-in-palestine/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "1jve\.com" ascii wide nocase
        $domain1 = "9oo91e\.co" ascii wide nocase
        $domain2 = "aamir-khan\.site" ascii wide nocase
        $domain3 = "accaunts-googlc\.com" ascii wide nocase
        $domain4 = "account-gocgle\.com" ascii wide nocase
        $domain5 = "account-googlc\.com" ascii wide nocase
        $domain6 = "accountforuser\.website" ascii wide nocase
        $domain7 = "accountforusers\.website" ascii wide nocase
        $domain8 = "accounts-gocgle\.com" ascii wide nocase
        $domain9 = "accounts-goog-le\.com" ascii wide nocase
        $domain10 = "accounts-googlc\.com" ascii wide nocase
        $domain11 = "accountusers\.website" ascii wide nocase
        $domain12 = "accuant-googlc\.com" ascii wide nocase
        $domain13 = "acount-manager\.com" ascii wide nocase
        $domain14 = "acount-manager\.info" ascii wide nocase
        $domain15 = "acount-manager\.net" ascii wide nocase
        $domain16 = "acount-manager\.org" ascii wide nocase
        $domain17 = "activedardash\.club" ascii wide nocase
        $domain18 = "adamnews\.for\.ug" ascii wide nocase
        $domain19 = "advanced-files\.club" ascii wide nocase
        $domain20 = "ahnlabin\.com" ascii wide nocase
        $domain21 = "akashipro\.com" ascii wide nocase
        $domain22 = "al-amalhumandevelopment\.com" ascii wide nocase
        $domain23 = "alain\.ps" ascii wide nocase
        $domain24 = "alishatnixon\.site" ascii wide nocase
        $domain25 = "alisonparker\.club" ascii wide nocase
        $domain26 = "alttaeb\.info" ascii wide nocase
        $domain27 = "amanda-hart\.website" ascii wide nocase
        $domain28 = "amyacunningham\.us" ascii wide nocase
        $domain29 = "android-settings\.info" ascii wide nocase
        $domain30 = "angeladeloney\.info" ascii wide nocase
        $domain31 = "anifondnet\.club" ascii wide nocase
        $domain32 = "anna-sanchez\.online" ascii wide nocase
        $domain33 = "ansonwhitmore\.live" ascii wide nocase
        $domain34 = "apkapps\.pro" ascii wide nocase
        $domain35 = "apkapps\.site" ascii wide nocase
        $domain36 = "app-market\.online" ascii wide nocase
        $domain37 = "appchecker\.us" ascii wide nocase
        $domain38 = "appppure\.info" ascii wide nocase
        $domain39 = "appppure\.net" ascii wide nocase
        $domain40 = "appppure\.pro" ascii wide nocase
        $domain41 = "apppure\.info" ascii wide nocase
        $domain42 = "apps-download\.store" ascii wide nocase
        $domain43 = "apps-market\.site" ascii wide nocase
        $domain44 = "apps-store\.online" ascii wide nocase
        $domain45 = "appuree\.info" ascii wide nocase
        $domain46 = "arnani\.info" ascii wide nocase
        $domain47 = "arthursaito\.club" ascii wide nocase
        $domain48 = "artlifelondon\.com" ascii wide nocase
        $domain49 = "aryastark\.info" ascii wide nocase
        $ip50 = "198.54.117.211" ascii wide
        $ip51 = "198.54.117.212" ascii wide
        $ip52 = "198.54.117.215" ascii wide
        $ip53 = "198.54.117.217" ascii wide
        $ip54 = "198.54.117.218" ascii wide
        $ip55 = "68.65.121.44" ascii wide
        $ip56 = "68.65.121.44" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_27
{
    meta:
        description = "Detects IOCs associated with APT 27"
        author = "APTtrail Automated Collection"
        apt_group = "27"
        aliases = "apt 27, apt27, bronze union"
        reference = "https://app.any.run/tasks/949f2624-505c-4f10-a304-1671492f9a22/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "24h\.tinthethaoi\.com" ascii wide nocase
        $domain1 = "265g\.site" ascii wide nocase
        $domain2 = "36106g\.com" ascii wide nocase
        $domain3 = "88tech\.me" ascii wide nocase
        $domain4 = "activity\.maacson\.com" ascii wide nocase
        $domain5 = "adobesys\.com" ascii wide nocase
        $domain6 = "aibeichen\.cn" ascii wide nocase
        $domain7 = "amazonawsgarages\.com" ascii wide nocase
        $domain8 = "analyaze\.s3amazonbucket\.com" ascii wide nocase
        $domain9 = "analysis\.windowstearns\.com" ascii wide nocase
        $domain10 = "api\.youkesdt\.asia" ascii wide nocase
        $domain11 = "atlas-sian\.net" ascii wide nocase
        $domain12 = "awvsf7esh\.dellrescue\.com" ascii wide nocase
        $domain13 = "bbs\.maacson\.com" ascii wide nocase
        $domain14 = "bbs\.sonypsps\.com" ascii wide nocase
        $domain15 = "buy\.teamviewsoft\.com" ascii wide nocase
        $domain16 = "cat\.toonganuh\.com" ascii wide nocase
        $domain17 = "cdn\.laokpl\.com" ascii wide nocase
        $domain18 = "center\.veryssl\.org" ascii wide nocase
        $domain19 = "chatsecure\.uk\.to" ascii wide nocase
        $domain20 = "chatsecurelite\.uk\.to" ascii wide nocase
        $domain21 = "chatsecurelite\.us\.to" ascii wide nocase
        $domain22 = "chinhsech\.com" ascii wide nocase
        $domain23 = "chototem\.com" ascii wide nocase
        $domain24 = "chrome-upgrade\.com" ascii wide nocase
        $domain25 = "ckvyk\.com" ascii wide nocase
        $domain26 = "ckvyk\.net" ascii wide nocase
        $domain27 = "cloud\.cutepaty\.com" ascii wide nocase
        $domain28 = "cloudservicesdevc\.tk" ascii wide nocase
        $domain29 = "coco\.sodexoa\.com" ascii wide nocase
        $domain30 = "conglyan\.com" ascii wide nocase
        $domain31 = "cooodkord\.com" ascii wide nocase
        $domain32 = "cophieu\.dcsvnqvmn\.com" ascii wide nocase
        $domain33 = "coreders\.com" ascii wide nocase
        $domain34 = "cornm100\.io" ascii wide nocase
        $domain35 = "cutepaty\.com" ascii wide nocase
        $domain36 = "cv3sa\.gicp\.net" ascii wide nocase
        $domain37 = "daikynguyen21\.com" ascii wide nocase
        $domain38 = "dangquanwatch\.com" ascii wide nocase
        $domain39 = "dataanalyticsclub\.com" ascii wide nocase
        $domain40 = "datacache\.cloudservicesdevc\.tk" ascii wide nocase
        $domain41 = "dcsvnqvmn\.com" ascii wide nocase
        $domain42 = "dev\.gitlabs\.me" ascii wide nocase
        $domain43 = "diendanlichsu\.com" ascii wide nocase
        $domain44 = "dn\.dulichbiendao\.org" ascii wide nocase
        $domain45 = "dns\.itbaydns\.com" ascii wide nocase
        $domain46 = "dongaruou\.com" ascii wide nocase
        $domain47 = "dongnain\.com" ascii wide nocase
        $domain48 = "dulichculao\.com" ascii wide nocase
        $domain49 = "encryptit\.qc\.to" ascii wide nocase
        $ip50 = "103.243.26.213" ascii wide
        $ip51 = "103.79.77.200" ascii wide
        $ip52 = "104.168.211.246" ascii wide
        $ip53 = "104.168.236.46" ascii wide
        $ip54 = "115.214.104.26" ascii wide
        $ip55 = "139.180.216.65" ascii wide
        $ip56 = "154.93.7.99" ascii wide
        $ip57 = "185.12.45.134" ascii wide
        $ip58 = "27.124.26.136" ascii wide
        $ip59 = "27.124.26.136" ascii wide
        $ip60 = "35.187.148.253" ascii wide
        $ip61 = "35.220.135.85" ascii wide
        $ip62 = "38.54.119.239" ascii wide
        $ip63 = "45.142.214.193" ascii wide
        $ip64 = "45.32.33.17" ascii wide
        $ip65 = "45.77.250.141" ascii wide
        $ip66 = "47.75.49.32" ascii wide
        $ip67 = "80.92.206.158" ascii wide
        $ip68 = "85.204.74.143" ascii wide
        $ip69 = "87.98.190.184" ascii wide
        $ip70 = "89.35.178.105" ascii wide
        $url71 = "/ajax" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_30
{
    meta:
        description = "Detects IOCs associated with APT 30"
        author = "APTtrail Automated Collection"
        apt_group = "30"
        reference = "https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2015/05/20081935/rpt-apt30.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "appsecnic\.com" ascii wide nocase
        $domain1 = "aseanm\.com" ascii wide nocase
        $domain2 = "autoapec\.com" ascii wide nocase
        $domain3 = "bigfixtools\.com" ascii wide nocase
        $domain4 = "bluesixnine\.com" ascii wide nocase
        $domain5 = "cbkjdxf\.com" ascii wide nocase
        $domain6 = "creammemory\.com" ascii wide nocase
        $domain7 = "gordeneyes\.com" ascii wide nocase
        $domain8 = "iapfreecenter\.com" ascii wide nocase
        $domain9 = "kabadefender\.com" ascii wide nocase
        $domain10 = "km-nyc\.com" ascii wide nocase
        $domain11 = "km153\.com" ascii wide nocase
        $domain12 = "lisword\.com" ascii wide nocase
        $domain13 = "newpresses\.com" ascii wide nocase
        $domain14 = "techmicrost\.com" ascii wide nocase
        $ip15 = "103.233.10.152" ascii wide
        $ip16 = "103.233.10.152" ascii wide
        $ip17 = "103.233.10.152" ascii wide
        $ip18 = "172.247.197.189" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_33
{
    meta:
        description = "Detects IOCs associated with APT 33"
        author = "APTtrail Automated Collection"
        apt_group = "33"
        reference = "https://app.any.run/tasks/c761d00f-4897-4c9e-8468-9172fcce21d7/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "admindirector\.com" ascii wide nocase
        $domain1 = "akadnsplugin\.com" ascii wide nocase
        $domain2 = "alsalam\.ddns\.net" ascii wide nocase
        $domain3 = "aramcojobs\.ddns\.net" ascii wide nocase
        $domain4 = "availsqaapi\.premieredigital\.net" ascii wide nocase
        $domain5 = "azure-dnszones\.com" ascii wide nocase
        $domain6 = "backupaccount\.net" ascii wide nocase
        $domain7 = "backupnet\.ddns\.net" ascii wide nocase
        $domain8 = "becomestateman\.com" ascii wide nocase
        $domain9 = "bistbotsproxies\.ddns\.net" ascii wide nocase
        $domain10 = "boeing\.servehttp\.com" ascii wide nocase
        $domain11 = "businessscards\.com" ascii wide nocase
        $domain12 = "cardchsk\.com" ascii wide nocase
        $domain13 = "cardkuys\.com" ascii wide nocase
        $domain14 = "ceoadminoffice\.com" ascii wide nocase
        $domain15 = "chromup\.com" ascii wide nocase
        $domain16 = "customermgmt\.net" ascii wide nocase
        $domain17 = "dailystudy\.org" ascii wide nocase
        $domain18 = "digitalcodecrafters\.com" ascii wide nocase
        $domain19 = "diplomatsign\.com" ascii wide nocase
        $domain20 = "dyn-corp\.ddns\.net" ascii wide nocase
        $domain21 = "dyncorp\.ddns\.net" ascii wide nocase
        $domain22 = "eventmonitoring\.org" ascii wide nocase
        $domain23 = "fucksaudi\.ddns\.net" ascii wide nocase
        $domain24 = "gefurrinn\.com" ascii wide nocase
        $domain25 = "global-careers\.org" ascii wide nocase
        $domain26 = "googlechromehost\.ddns\.net" ascii wide nocase
        $domain27 = "googlmail\.net" ascii wide nocase
        $domain28 = "groupchiefexecutive\.com" ascii wide nocase
        $domain29 = "hellocookies\.ddns\.net" ascii wide nocase
        $domain30 = "hyperservice\.ddns\.net" ascii wide nocase
        $domain31 = "imap-outlook\.com" ascii wide nocase
        $domain32 = "inboxsync\.org" ascii wide nocase
        $domain33 = "lovememories\.org" ascii wide nocase
        $domain34 = "mailsarchive\.com" ascii wide nocase
        $domain35 = "managehelpdesk\.com" ascii wide nocase
        $domain36 = "managementdirector\.com" ascii wide nocase
        $domain37 = "microsoftupdated\.com" ascii wide nocase
        $domain38 = "microsoftupdated\.net" ascii wide nocase
        $domain39 = "moreonlineshopping\.com" ascii wide nocase
        $domain40 = "mynetwork\.cf" ascii wide nocase
        $domain41 = "mynetwork\.ddns\.net" ascii wide nocase
        $domain42 = "mynetwork2\.ddns\.net" ascii wide nocase
        $domain43 = "mypsh\.ddns\.net" ascii wide nocase
        $domain44 = "mywinnetwork\.ddns\.net" ascii wide nocase
        $domain45 = "n3tc4t\.hopto\.com" ascii wide nocase
        $domain46 = "newhost\.hopto\.org" ascii wide nocase
        $domain47 = "ngaaksa\.ddns\.net" ascii wide nocase
        $domain48 = "ngaaksa\.ga" ascii wide nocase
        $domain49 = "ngaaksa\.sytes\.net" ascii wide nocase
        $ip50 = "188.166.55.116" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_37
{
    meta:
        description = "Detects IOCs associated with APT 37"
        author = "APTtrail Automated Collection"
        apt_group = "37"
        aliases = "Red Eyes, RokRAT, TA-RedAnt"
        reference = "http://blogs.360.cn/post/analysis-of-apt-c-37.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "0member-services\.hol\.es" ascii wide nocase
        $domain1 = "1006ieudneu\.atwebpages\.com" ascii wide nocase
        $domain2 = "1995ieudneu\.atwebpages\.com" ascii wide nocase
        $domain3 = "acddesigns\.com\.au" ascii wide nocase
        $domain4 = "acl-medias\.fr" ascii wide nocase
        $domain5 = "acount-pro\.club" ascii wide nocase
        $domain6 = "acount-pro\.live" ascii wide nocase
        $domain7 = "adamnews\.for\.ug" ascii wide nocase
        $domain8 = "admin\.mobonad\.com" ascii wide nocase
        $domain9 = "admin\.primgs\.lol" ascii wide nocase
        $domain10 = "ahnlab\.check\.pe\.hu" ascii wide nocase
        $domain11 = "ahooc\.com" ascii wide nocase
        $domain12 = "alireza\.traderfree\.online" ascii wide nocase
        $domain13 = "anlysis-info\.xyz" ascii wide nocase
        $domain14 = "annstyle\.ru" ascii wide nocase
        $domain15 = "api\.jquery\.services" ascii wide nocase
        $domain16 = "app-wallet\.com" ascii wide nocase
        $domain17 = "app\.cleanos\.online" ascii wide nocase
        $domain18 = "asia-studies\.net" ascii wide nocase
        $domain19 = "attachdown\.000webhostapp\.com" ascii wide nocase
        $domain20 = "attachdownload\.000webhostapp\.com" ascii wide nocase
        $domain21 = "attachdownload\.99on\.com" ascii wide nocase
        $domain22 = "atusay\.lat" ascii wide nocase
        $domain23 = "bajut\.pro" ascii wide nocase
        $domain24 = "bellissues\.live" ascii wide nocase
        $domain25 = "benefitinfo\.live" ascii wide nocase
        $domain26 = "benefitinfo\.pro" ascii wide nocase
        $domain27 = "benefiturl\.pro" ascii wide nocase
        $domain28 = "bian0151\.cafe24\.com" ascii wide nocase
        $domain29 = "bigfilemail\.net" ascii wide nocase
        $domain30 = "bignaver\.com" ascii wide nocase
        $domain31 = "bigwnet\.com" ascii wide nocase
        $domain32 = "bitwoll\.com" ascii wide nocase
        $domain33 = "blockochain\.info" ascii wide nocase
        $domain34 = "btcaes2\.duckdns\.org" ascii wide nocase
        $domain35 = "busyday\.atwebpages\.com" ascii wide nocase
        $domain36 = "buttyfly\.000webhostapp\.com" ascii wide nocase
        $domain37 = "careagency\.online" ascii wide nocase
        $domain38 = "carnegieinsider\.com" ascii wide nocase
        $domain39 = "cdns\.jquery\.services" ascii wide nocase
        $domain40 = "cerebrovascular\.net" ascii wide nocase
        $domain41 = "cexrout\.com" ascii wide nocase
        $domain42 = "change-pw\.com" ascii wide nocase
        $domain43 = "checkprofie\.com" ascii wide nocase
        $domain44 = "cheth\.lol" ascii wide nocase
        $domain45 = "christinadudley\.com" ascii wide nocase
        $domain46 = "cleanos\.online" ascii wide nocase
        $domain47 = "clonesec\.us" ascii wide nocase
        $domain48 = "cloudnaver\.com" ascii wide nocase
        $domain49 = "cloudocument\.com" ascii wide nocase
        $ip50 = "208.85.16.88" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_38
{
    meta:
        description = "Detects IOCs associated with APT 38"
        author = "APTtrail Automated Collection"
        apt_group = "38"
        reference = "https://content.fireeye.com/apt/rpt-apt38"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "a\.updatesinfos\.com" ascii wide nocase
        $domain1 = "b\.updatesinfos\.com" ascii wide nocase
        $domain2 = "bitdefs\.ignorelist\.com" ascii wide nocase
        $domain3 = "gphi-adhaswe\.xyz" ascii wide nocase
        $domain4 = "gphi-gsaeyheq\.top" ascii wide nocase
        $domain5 = "gphi\.site" ascii wide nocase
        $domain6 = "ip1\.gphi-adhaswe\.xyz" ascii wide nocase
        $domain7 = "ip1\.gphi-gsaeyheq\.top" ascii wide nocase
        $domain8 = "ip1\.s\.gphi\.site" ascii wide nocase
        $domain9 = "ip2\.s\.gphi\.site" ascii wide nocase
        $domain10 = "updatesinfos\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_45
{
    meta:
        description = "Detects IOCs associated with APT 45"
        author = "APTtrail Automated Collection"
        apt_group = "45"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/apt45-north-korea-digital-military-machine"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "84.38.134.56" ascii wide
        $ip1 = "84.38.134.56" ascii wide

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_48
{
    meta:
        description = "Detects IOCs associated with APT 48"
        author = "APTtrail Automated Collection"
        apt_group = "48"
        aliases = "apt-c-48"
        reference = "https://app.validin.com/detail?find=b0caff7b71c1e189a304b3420d6315c34af4476777845cfc95fde03f9a5b1d1a&type=hash&ref_id=316ceb33ab1#tab=host_pairs"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "panbaiclu\.com" ascii wide nocase
        $domain1 = "vpn616865750\.softether\.net" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_5
{
    meta:
        description = "Detects IOCs associated with APT 5"
        author = "APTtrail Automated Collection"
        apt_group = "5"
        aliases = "apt-c-5"
        reference = "https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2013/04/20082912/C5_APT_SKHack.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "4jslg\.diggfunny\.com" ascii wide nocase
        $domain1 = "alyac\.org" ascii wide nocase
        $domain2 = "bbs\.edsplan\.com" ascii wide nocase
        $domain3 = "bbs\.ezxsoft\.com" ascii wide nocase
        $domain4 = "bomuls\.com" ascii wide nocase
        $domain5 = "cache\.mindplat\.com" ascii wide nocase
        $domain6 = "daumfan\.com" ascii wide nocase
        $domain7 = "dig\.edsplan\.com" ascii wide nocase
        $domain8 = "diggfunny\.com" ascii wide nocase
        $domain9 = "dnf\.diggfunny\.com" ascii wide nocase
        $domain10 = "download\.bomuls\.com" ascii wide nocase
        $domain11 = "duamlive\.com" ascii wide nocase
        $domain12 = "edsplan\.com" ascii wide nocase
        $domain13 = "expre\.dyndns\.tv" ascii wide nocase
        $domain14 = "ezxsoft\.com" ascii wide nocase
        $domain15 = "fh\.edsplan\.com" ascii wide nocase
        $domain16 = "file1\.nprotects\.org" ascii wide nocase
        $domain17 = "finalcover\.com" ascii wide nocase
        $domain18 = "fr\.duamlive\.com" ascii wide nocase
        $domain19 = "gl\.edsplan\.com" ascii wide nocase
        $domain20 = "l\.finalcover\.com" ascii wide nocase
        $domain21 = "mindplat\.com" ascii wide nocase
        $domain22 = "n\.duamlive\.com" ascii wide nocase
        $domain23 = "natefan\.com" ascii wide nocase
        $domain24 = "nateon\.duamlive\.com" ascii wide nocase
        $domain25 = "nprotects\.org" ascii wide nocase
        $domain26 = "path\.alyac\.org" ascii wide nocase
        $domain27 = "pc\.nprotects\.org" ascii wide nocase
        $domain28 = "projectxz\.com" ascii wide nocase
        $domain29 = "ro\.diggfunny\.com" ascii wide nocase
        $domain30 = "smartnet\.edsplan\.com" ascii wide nocase
        $domain31 = "soucesp\.com" ascii wide nocase
        $domain32 = "t\.finalcover\.com" ascii wide nocase
        $domain33 = "text\.edsplan\.com" ascii wide nocase
        $domain34 = "trendmicros\.net" ascii wide nocase
        $domain35 = "unix\.edsplan\.com" ascii wide nocase
        $domain36 = "update\.alyac\.org" ascii wide nocase
        $domain37 = "update\.nprotects\.org" ascii wide nocase
        $domain38 = "us\.duamlive\.com" ascii wide nocase
        $domain39 = "vn\.edsplan\.com" ascii wide nocase
        $domain40 = "wf\.edsplan\.com" ascii wide nocase
        $ip41 = "116.127.121.41" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_60
{
    meta:
        description = "Detects IOCs associated with APT 60"
        author = "APTtrail Automated Collection"
        apt_group = "60"
        aliases = "apt-c-60, apt-q-12, spyglace"
        reference = "https://app.validin.com/detail?find=WIN-9M19PDUO1OV&type=raw#tab=host_pairs_v2"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "juanjuan\.cesy\.top" ascii wide nocase
        $domain1 = "milfbate\.com" ascii wide nocase
        $domain2 = "nimdsrt\.com" ascii wide nocase
        $domain3 = "rammenale\.com" ascii wide nocase
        $ip4 = "103.187.26.174" ascii wide
        $ip5 = "103.187.26.175" ascii wide
        $ip6 = "103.187.26.176" ascii wide
        $ip7 = "103.187.26.177" ascii wide
        $ip8 = "203.174.87.18" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_68
{
    meta:
        description = "Detects IOCs associated with APT 68"
        author = "APTtrail Automated Collection"
        apt_group = "68"
        aliases = "apt-c-68, apt-q-15"
        reference = "https://twitter.com/Timele9527"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "softwarediskservice\.com" ascii wide nocase
        $domain1 = "star\.softwarediskservice\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_73
{
    meta:
        description = "Detects IOCs associated with APT 73"
        author = "APTtrail Automated Collection"
        apt_group = "73"
        aliases = "eraleig ransomware"
        reference = "https://github.com/marktsec/Ransomware_Official_Domains#apt73"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "bashe4aec32kr6zbifwd5x6xgjsmhg4tbowrbx4pneqhc5mqooyifpid\.onion" ascii wide nocase
        $domain1 = "basheqtvzqwz4vp6ks5lm2ocq7i6tozqgf6vjcasj4ezmsy4bkpshhyd\.onion" ascii wide nocase
        $domain2 = "basherq53eniermxovo3bkduw5qqq5bkqcml3qictfmamgvmzovykyqd\.onion" ascii wide nocase
        $domain3 = "eraleignews\.com" ascii wide nocase
        $domain4 = "fleqwmg7xnanypt5km2m75l72q7nlcvlp2m4sdmgjxorsn6tb3zyp3qd\.onion" ascii wide nocase
        $domain5 = "ns1\.eraleignews\.com" ascii wide nocase
        $domain6 = "ns2\.eraleignews\.com" ascii wide nocase
        $domain7 = "ns3\.eraleignews\.com" ascii wide nocase
        $domain8 = "ns4\.eraleignews\.com" ascii wide nocase
        $domain9 = "qcgv5tfer4f46ns6ohh72zeyyh5uavoiybypzpt3lmwk5ecyqykptgqd\.onion" ascii wide nocase
        $domain10 = "wn6vonooq6fggjdgyocp7bioykmfjket7sbp47cwhgubvowwd7ws5pyd\.onion" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_AOQINDRAGON
{
    meta:
        description = "Detects IOCs associated with APT AOQINDRAGON"
        author = "APTtrail Automated Collection"
        apt_group = "AOQINDRAGON"
        aliases = "Heyoka, Mongall, UNC94"
        reference = "https://twitter.com/AndreGironda/status/1757929271962550534"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "adsoft\.name" ascii wide nocase
        $domain1 = "back\.satunusa\.org" ascii wide nocase
        $domain2 = "baomoi\.vnptnet\.info" ascii wide nocase
        $domain3 = "bbw\.fushing\.org" ascii wide nocase
        $domain4 = "bca\.zdungk\.com" ascii wide nocase
        $domain5 = "bkav\.manlish\.net" ascii wide nocase
        $domain6 = "bkav\.welikejack\.com" ascii wide nocase
        $domain7 = "bkavonline\.vnptnet\.info" ascii wide nocase
        $domain8 = "bluesky1234\.com" ascii wide nocase
        $domain9 = "bush2015\.net" ascii wide nocase
        $domain10 = "cl\.weststations\.com" ascii wide nocase
        $domain11 = "cloundvietnam\.com" ascii wide nocase
        $domain12 = "comnnet\.net" ascii wide nocase
        $domain13 = "cpt\.vnptnet\.inf" ascii wide nocase
        $domain14 = "cvb\.hotcup\.pw" ascii wide nocase
        $domain15 = "dellyou\.com" ascii wide nocase
        $domain16 = "dinhk\.net" ascii wide nocase
        $domain17 = "dns\.foodforthought1\.com" ascii wide nocase
        $domain18 = "dns\.lioncity\.top" ascii wide nocase
        $domain19 = "dns\.satunusa\.org" ascii wide nocase
        $domain20 = "dns\.zdungk\.com" ascii wide nocase
        $domain21 = "ds\.vdcvn\.com" ascii wide nocase
        $domain22 = "ds\.xrayccc\.top" ascii wide nocase
        $domain23 = "dungk\.com" ascii wide nocase
        $domain24 = "facebookmap\.top" ascii wide nocase
        $domain25 = "fbcl2\.adsoft\.name" ascii wide nocase
        $domain26 = "fbcl2\.softad\.net" ascii wide nocase
        $domain27 = "flower2\.yyppmm\.com" ascii wide nocase
        $domain28 = "followag\.org" ascii wide nocase
        $domain29 = "foodforthought1\.com" ascii wide nocase
        $domain30 = "fushing\.org" ascii wide nocase
        $domain31 = "game\.vietnamflash\.com" ascii wide nocase
        $domain32 = "hello\.bluesky1234\.com" ascii wide nocase
        $domain33 = "hotcup\.pw" ascii wide nocase
        $domain34 = "ipad\.vnptnet\.info" ascii wide nocase
        $domain35 = "ks\.manlish\.net" ascii wide nocase
        $domain36 = "lepad\.fushing\.org" ascii wide nocase
        $domain37 = "lllyyy\.adsoft\.name" ascii wide nocase
        $domain38 = "longvn\.net" ascii wide nocase
        $domain39 = "lucky\.manlish\.net" ascii wide nocase
        $domain40 = "ma550\.adsoft\.name" ascii wide nocase
        $domain41 = "ma550\.softad\.net" ascii wide nocase
        $domain42 = "mail\.comnnet\.net" ascii wide nocase
        $domain43 = "mail\.tiger1234\.com" ascii wide nocase
        $domain44 = "mail\.vdcvn\.com" ascii wide nocase
        $domain45 = "manlish\.net" ascii wide nocase
        $domain46 = "mass\.longvn\.net" ascii wide nocase
        $domain47 = "mcafee\.bluesky1234\.com" ascii wide nocase
        $domain48 = "media\.vietnamflash\.com" ascii wide nocase
        $domain49 = "mil\.dungk\.com" ascii wide nocase
        $ip50 = "64.27.4.157" ascii wide
        $ip51 = "64.27.4.157" ascii wide
        $ip52 = "67.210.114.99" ascii wide
        $ip53 = "67.210.114.99" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_APPIN
{
    meta:
        description = "Detects IOCs associated with APT APPIN"
        author = "APTtrail Automated Collection"
        apt_group = "APPIN"
        aliases = "whiteelephant"
        reference = "https://www.sentinelone.com/labs/elephant-hunting-inside-an-indian-hack-for-hire-group/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "abdupdates\.com" ascii wide nocase
        $domain1 = "alr3ady\.net" ascii wide nocase
        $domain2 = "antivirusreviewratings\.com" ascii wide nocase
        $domain3 = "authorisedsecurehost\.com" ascii wide nocase
        $domain4 = "bksrv3r001\.com" ascii wide nocase
        $domain5 = "bluecreams\.com" ascii wide nocase
        $domain6 = "bookshopmarket\.com" ascii wide nocase
        $domain7 = "brandsons\.net" ascii wide nocase
        $domain8 = "braninfall\.net" ascii wide nocase
        $domain9 = "c00lh0sting\.com" ascii wide nocase
        $domain10 = "c0ttenc0unty\.com" ascii wide nocase
        $domain11 = "cr3ator01\.net" ascii wide nocase
        $domain12 = "crowcatcher\.com" ascii wide nocase
        $domain13 = "crvhostia\.net" ascii wide nocase
        $domain14 = "currentnewsstore\.com" ascii wide nocase
        $domain15 = "customauthentication\.com" ascii wide nocase
        $domain16 = "devinmartin\.net" ascii wide nocase
        $domain17 = "directsupp0rt\.com" ascii wide nocase
        $domain18 = "divinepower\.info" ascii wide nocase
        $domain19 = "draganheart\.com" ascii wide nocase
        $domain20 = "easyhost-ing\.com" ascii wide nocase
        $domain21 = "easyslidesharing\.net" ascii wide nocase
        $domain22 = "f00dlover\.info" ascii wide nocase
        $domain23 = "filetrusty\.net" ascii wide nocase
        $domain24 = "follow-ship\.com" ascii wide nocase
        $domain25 = "forest-fire\.net" ascii wide nocase
        $domain26 = "foxypredators\.com" ascii wide nocase
        $domain27 = "freensecurehost\.com" ascii wide nocase
        $domain28 = "freesecurehostings\.com" ascii wide nocase
        $domain29 = "freewebdomainhost\.com" ascii wide nocase
        $domain30 = "freewebuserhost\.com" ascii wide nocase
        $domain31 = "gauzpie\.com" ascii wide nocase
        $domain32 = "gmail-loginchk\.freehostia\.com" ascii wide nocase
        $domain33 = "h3helnsupp0ort\.com" ascii wide nocase
        $domain34 = "hatemewhy\.com" ascii wide nocase
        $domain35 = "hostingserveronline\.net" ascii wide nocase
        $domain36 = "hotmasalanewssite\.com" ascii wide nocase
        $domain37 = "islam-jindabad\.blogspot\.com" ascii wide nocase
        $domain38 = "jasminjorden\.com" ascii wide nocase
        $domain39 = "karzontheway\.com" ascii wide nocase
        $domain40 = "kungfu-panda\.info" ascii wide nocase
        $domain41 = "matrixnotloaded\.com" ascii wide nocase
        $domain42 = "msfileshare\.net" ascii wide nocase
        $domain43 = "msoftweb\.com" ascii wide nocase
        $domain44 = "myt3mple\.com" ascii wide nocase
        $domain45 = "newamazingfacts\.com" ascii wide nocase
        $domain46 = "nitr0rac3\.com" ascii wide nocase
        $domain47 = "pc-technsupport\.com" ascii wide nocase
        $domain48 = "piegauz\.net" ascii wide nocase
        $domain49 = "r3gistration\.net" ascii wide nocase
        $ip50 = "212.72.189.74" ascii wide
        $ip51 = "212.72.189.74" ascii wide
        $ip52 = "64.186.132.165" ascii wide
        $ip53 = "65.75.243.251" ascii wide
        $ip54 = "65.75.243.251" ascii wide
        $ip55 = "65.75.250.66" ascii wide
        $ip56 = "65.75.250.66" ascii wide
        $ip57 = "69.197.147.146" ascii wide
        $ip58 = "69.197.147.146" ascii wide
        $ip59 = "75.127.111.165" ascii wide
        $ip60 = "75.127.111.165" ascii wide
        $ip61 = "75.127.78.100" ascii wide
        $ip62 = "75.127.78.100" ascii wide
        $ip63 = "75.127.91.16" ascii wide
        $ip64 = "84.243.201.254" ascii wide
        $ip65 = "84.243.201.254" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_ARIDVIPER
{
    meta:
        description = "Detects IOCs associated with APT ARIDVIPER"
        author = "APTtrail Automated Collection"
        apt_group = "ARIDVIPER"
        aliases = "arid gopher, arid viper, spyc23"
        reference = "http://blog.talosintelligence.com/2022/02/arid-viper-targets-palestine.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "accountforuser\.website" ascii wide nocase
        $domain1 = "acs-group\.net" ascii wide nocase
        $domain2 = "almoshell\.website" ascii wide nocase
        $domain3 = "alwaysgoodidea\.com" ascii wide nocase
        $domain4 = "analyticsandroid\.com" ascii wide nocase
        $domain5 = "angela-bishop\.com" ascii wide nocase
        $domain6 = "anime-con\.net" ascii wide nocase
        $domain7 = "baldwin-gonzalez\.live" ascii wide nocase
        $domain8 = "benyallen\.club" ascii wide nocase
        $domain9 = "chad-jessie\.info" ascii wide nocase
        $domain10 = "chloe-boreman\.com" ascii wide nocase
        $domain11 = "cooperron\.me" ascii wide nocase
        $domain12 = "crashstoreplayer\.website" ascii wide nocase
        $domain13 = "cricket-live\.net" ascii wide nocase
        $domain14 = "criston-cole\.com" ascii wide nocase
        $domain15 = "dabliardogame\.com" ascii wide nocase
        $domain16 = "deangelomcnay\.news" ascii wide nocase
        $domain17 = "delooyp\.com" ascii wide nocase
        $domain18 = "dslam\.net" ascii wide nocase
        $domain19 = "earlahenry\.com" ascii wide nocase
        $domain20 = "elsilvercloud\.com" ascii wide nocase
        $domain21 = "escanor\.live" ascii wide nocase
        $domain22 = "gameservicesplay\.com" ascii wide nocase
        $domain23 = "gmesc\.com" ascii wide nocase
        $domain24 = "godeutalk\.com" ascii wide nocase
        $domain25 = "grace-fraser\.site" ascii wide nocase
        $domain26 = "gsstar\.net" ascii wide nocase
        $domain27 = "haroldramsey\.icu" ascii wide nocase
        $domain28 = "im-inter\.net" ascii wide nocase
        $domain29 = "it-franch-result\.info" ascii wide nocase
        $domain30 = "izocraft\.com" ascii wide nocase
        $domain31 = "jaime-martinez\.info" ascii wide nocase
        $domain32 = "jasondixon\.net" ascii wide nocase
        $domain33 = "jolia-16e7b\.appspot\.com" ascii wide nocase
        $domain34 = "judystevenson\.info" ascii wide nocase
        $domain35 = "jumpstartmail\.com" ascii wide nocase
        $domain36 = "katesacker\.club" ascii wide nocase
        $domain37 = "krasil-anthony\.icu" ascii wide nocase
        $domain38 = "labeepuzz\.com" ascii wide nocase
        $domain39 = "leaf-japan\.net" ascii wide nocase
        $domain40 = "lightroom-61eb2\.firebaseio\.com" ascii wide nocase
        $domain41 = "london-sport\.ne" ascii wide nocase
        $domain42 = "lrxzklwmzxe\.com" ascii wide nocase
        $domain43 = "luis-dubuque\.in" ascii wide nocase
        $domain44 = "mozelllittel\.com" ascii wide nocase
        $domain45 = "nicoledotson\.icu" ascii wide nocase
        $domain46 = "nortirchats\.com" ascii wide nocase
        $domain47 = "officeappslive\.site" ascii wide nocase
        $domain48 = "orientflags\.com" ascii wide nocase
        $domain49 = "palcivilreg\.com" ascii wide nocase
        $ip50 = "213.184.123.144" ascii wide
        $ip51 = "5.181.23.41" ascii wide
        $ip52 = "5.181.23.41" ascii wide
        $ip53 = "91.199.147.84" ascii wide
        $ip54 = "91.199.147.84" ascii wide
        $ip55 = "91.219.150.123" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_ATLASCROSS
{
    meta:
        description = "Detects IOCs associated with APT ATLASCROSS"
        author = "APTtrail Automated Collection"
        apt_group = "ATLASCROSS"
        reference = "https://nsfocusglobal.com/warning-newly-discovered-apt-attacker-atlascross-exploits-red-cross-blood-drive-phishing-for-cyberattack/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "activequest\.goautodial\.com" ascii wide nocase
        $domain1 = "chat\.thedresscodeapp\.com" ascii wide nocase
        $domain2 = "crm\.cardabel\.com" ascii wide nocase
        $domain3 = "data\.vectorse\.com" ascii wide nocase
        $domain4 = "engage\.adaptqe\.com" ascii wide nocase
        $domain5 = "ops-ca\.mioying\.com" ascii wide nocase
        $domain6 = "order\.staging\.photobookworldwide\.com" ascii wide nocase
        $domain7 = "public\.pusulait\.com" ascii wide nocase
        $domain8 = "search\.allaccountingcareers\.com" ascii wide nocase
        $domain9 = "secure\.poliigon\.com" ascii wide nocase
        $domain10 = "superapi-staging\.mlmprotec\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_BABYSHARK
{
    meta:
        description = "Detects IOCs associated with APT BABYSHARK"
        author = "APTtrail Automated Collection"
        apt_group = "BABYSHARK"
        reference = "https://github.com/Neo23x0/signature-base/blob/master/yara/apt_babyshark.yar"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "beastmodser\.club" ascii wide nocase
        $domain1 = "frebough\.com" ascii wide nocase
        $domain2 = "hodbeast\.com" ascii wide nocase
        $domain3 = "retmodul\.com" ascii wide nocase
        $domain4 = "worldinfocontact\.club" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_BADMAGIC
{
    meta:
        description = "Detects IOCs associated with APT BADMAGIC"
        author = "APTtrail Automated Collection"
        apt_group = "BADMAGIC"
        reference = "https://bi.zone/eng/expertise/blog/core-werewolf-protiv-opk-i-kriticheskoy-infrastruktury/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "01yakutsk\.ru" ascii wide nocase
        $domain1 = "asteriskx\.ru" ascii wide nocase
        $domain2 = "astita\.ru" ascii wide nocase
        $domain3 = "autotimesvc\.com" ascii wide nocase
        $domain4 = "clodmail\.ru" ascii wide nocase
        $domain5 = "contileservices\.net" ascii wide nocase
        $domain6 = "kassperskylaw\.ru" ascii wide nocase
        $domain7 = "kb6ns\.ru" ascii wide nocase
        $domain8 = "licensecheckout\.net" ascii wide nocase
        $domain9 = "mail\.01yakutsk\.ru" ascii wide nocase
        $domain10 = "mail\.russexportlogistics\.ru" ascii wide nocase
        $domain11 = "passportyandex\.net" ascii wide nocase
        $domain12 = "russexportlogistics\.ru" ascii wide nocase
        $domain13 = "savebrowsing\.net" ascii wide nocase
        $domain14 = "securitysearch\.ddns\.net" ascii wide nocase
        $domain15 = "servicehost-update\.net" ascii wide nocase
        $domain16 = "softdownloaderonline\.net" ascii wide nocase
        $domain17 = "statusgeotrust\.com" ascii wide nocase
        $domain18 = "tapiservicemgr\.com" ascii wide nocase
        $domain19 = "uploaderonline\.com" ascii wide nocase
        $domain20 = "uploadingonline\.com" ascii wide nocase
        $domain21 = "versusmain\.com" ascii wide nocase
        $domain22 = "webservice-srv\.online" ascii wide nocase
        $domain23 = "webservice-srv1\.online" ascii wide nocase
        $domain24 = "winupdateronline\.com" ascii wide nocase
        $domain25 = "winuptodate\.com" ascii wide nocase
        $ip26 = "185.166.217.184" ascii wide
        $ip27 = "5.35.100.31" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_BAHAMUT
{
    meta:
        description = "Detects IOCs associated with APT BAHAMUT"
        author = "APTtrail Automated Collection"
        apt_group = "BAHAMUT"
        reference = "https://about.fb.com/wp-content/uploads/2023/05/Meta-Quarterly-Adversarial-Threat-Report-Q1-2023.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "32e6dwbbpg\.de" ascii wide nocase
        $domain1 = "32player\.com" ascii wide nocase
        $domain2 = "5iw68rugwfcir37uj8z3r6rfaxwd8g8cdcfcqw62\.de" ascii wide nocase
        $domain3 = "96r1yh643o\.de" ascii wide nocase
        $domain4 = "account-googie\.com" ascii wide nocase
        $domain5 = "accountvalidate\.com" ascii wide nocase
        $domain6 = "airfitgym\.com" ascii wide nocase
        $domain7 = "ambicluster\.com" ascii wide nocase
        $domain8 = "appswonder\.info" ascii wide nocase
        $domain9 = "aspnet\.dyndns\.info" ascii wide nocase
        $domain10 = "aspnet\.dyndns\.infoassurecom\.info" ascii wide nocase
        $domain11 = "assurecom\.info" ascii wide nocase
        $domain12 = "ay3a9j7pc3\.de" ascii wide nocase
        $domain13 = "bulletinalerts\.com" ascii wide nocase
        $domain14 = "by4mode\.com" ascii wide nocase
        $domain15 = "capsnit\.com" ascii wide nocase
        $domain16 = "cdn-icloud\.co" ascii wide nocase
        $domain17 = "cdn-icloud\.cocelebsnightmares\.com" ascii wide nocase
        $domain18 = "cdw1ir0dc9g3dwl5oh1y\.de" ascii wide nocase
        $domain19 = "celebsnightmares\.com" ascii wide nocase
        $domain20 = "citrusquad\.com" ascii wide nocase
        $domain21 = "classmunch\.com" ascii wide nocase
        $domain22 = "cloud-authorize\.com" ascii wide nocase
        $domain23 = "cocahut\.com" ascii wide nocase
        $domain24 = "cocelebsnightmares\.com" ascii wide nocase
        $domain25 = "cocoka\.info" ascii wide nocase
        $domain26 = "cocoka\.infocrawloofle\.com" ascii wide nocase
        $domain27 = "cohealthclubfun\.com" ascii wide nocase
        $domain28 = "crawloofle\.com" ascii wide nocase
        $domain29 = "cyroonline\.com" ascii wide nocase
        $domain30 = "datahost\.click" ascii wide nocase
        $domain31 = "devicesupport-rnicrosoft\.com" ascii wide nocase
        $domain32 = "domforworld\.com" ascii wide nocase
        $domain33 = "electrobric\.com" ascii wide nocase
        $domain34 = "everification-session-load\.com" ascii wide nocase
        $domain35 = "fastfiterzone\.com" ascii wide nocase
        $domain36 = "fjasfjfas89e\.gkcx6ye4t4zafw8ju2xdr5na5\.de" ascii wide nocase
        $domain37 = "flux2key\.com" ascii wide nocase
        $domain38 = "freepunjab2020\.info" ascii wide nocase
        $domain39 = "freesexvideos\.ch" ascii wide nocase
        $domain40 = "frexinq\.com" ascii wide nocase
        $domain41 = "ft8hua063okwfdcu21pw\.de" ascii wide nocase
        $domain42 = "fvbyavgyea\.com" ascii wide nocase
        $domain43 = "gateway-yahoo\.com" ascii wide nocase
        $domain44 = "ghelp\.co" ascii wide nocase
        $domain45 = "ghelp\.cohealthclubfun\.com" ascii wide nocase
        $domain46 = "gkcx6ye4t4zafw8ju2xdr5na5\.de" ascii wide nocase
        $domain47 = "h94xnghlldx6a862moj3\.de" ascii wide nocase
        $domain48 = "hbx5adg6vk\.de" ascii wide nocase
        $domain49 = "healthclubfun\.com" ascii wide nocase
        $ip50 = "134.255.231.233" ascii wide
        $ip51 = "14.16.88.35" ascii wide
        $ip52 = "162.55.103.211" ascii wide
        $ip53 = "162.55.103.211" ascii wide
        $ip54 = "162.55.103.211" ascii wide
        $ip55 = "162.55.103.212" ascii wide
        $ip56 = "162.55.103.212" ascii wide
        $ip57 = "162.55.103.212" ascii wide
        $ip58 = "172.64.168.30" ascii wide
        $ip59 = "172.64.168.30" ascii wide
        $ip60 = "193.23.161.164" ascii wide
        $ip61 = "194.156.88.235" ascii wide
        $ip62 = "45.156.84.129" ascii wide
        $ip63 = "45.156.85.161" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_BANISHEDKITTEN
{
    meta:
        description = "Detects IOCs associated with APT BANISHEDKITTEN"
        author = "APTtrail Automated Collection"
        apt_group = "BANISHEDKITTEN"
        aliases = "aa22-264a, banished kitten, homeland justice"
        reference = "https://apt.etda.or.th/cgi-bin/showcard.cgi?g=HomeLand%20Justice"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "screenai\.online" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_BARIUM
{
    meta:
        description = "Detects IOCs associated with APT BARIUM"
        author = "APTtrail Automated Collection"
        apt_group = "BARIUM"
        aliases = "AXIOMATICASYMPTOTE, RedEcho, apt-c-41"
        reference = "https://app.any.run/tasks/2c3b303a-b412-449e-b380-f1e7de76d452"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "111111\.note\.down-flash\.com" ascii wide nocase
        $domain1 = "2f2640fb\.dns\.1433\.eu\.org" ascii wide nocase
        $domain2 = "335b5282\.dns\.1433\.eu\.org" ascii wide nocase
        $domain3 = "360photo\.oss-cn-hongkong\.aliyuncs\.com" ascii wide nocase
        $domain4 = "64-176-59-232\.ipv4\.staticdns3\.io" ascii wide nocase
        $domain5 = "64\.176\.65\.49\.sslip\.io" ascii wide nocase
        $domain6 = "91newai\.com" ascii wide nocase
        $domain7 = "a\.linuxupdate\.info" ascii wide nocase
        $domain8 = "accounts\.longmusic\.com" ascii wide nocase
        $domain9 = "admin\.netbill\.pk" ascii wide nocase
        $domain10 = "adobe-cdn\.org" ascii wide nocase
        $domain11 = "aejava\.ddns\.net" ascii wide nocase
        $domain12 = "aejva\.ddns\.net" ascii wide nocase
        $domain13 = "afdentry\.workstation\.eu\.org" ascii wide nocase
        $domain14 = "agegamepay\.com" ascii wide nocase
        $domain15 = "ageofwuxia\.com" ascii wide nocase
        $domain16 = "ageofwuxia\.info" ascii wide nocase
        $domain17 = "ageofwuxia\.net" ascii wide nocase
        $domain18 = "ageofwuxia\.org" ascii wide nocase
        $domain19 = "akacur\.tk" ascii wide nocase
        $domain20 = "akamaixed\.net" ascii wide nocase
        $domain21 = "alibaba\.zzux\.com" ascii wide nocase
        $domain22 = "aliyun\.com\.co" ascii wide nocase
        $domain23 = "alxc\.tbtianyan\.com" ascii wide nocase
        $domain24 = "amazonlivenews\.com" ascii wide nocase
        $domain25 = "andropwn\.xyz" ascii wide nocase
        $domain26 = "aone\.ddns\.net" ascii wide nocase
        $domain27 = "ap\.philancourts\.com" ascii wide nocase
        $domain28 = "api\.emazemedia\.com" ascii wide nocase
        $domain29 = "api\.googleauthenticatoronline\.com" ascii wide nocase
        $domain30 = "app\.kaspersky-scan\.com" ascii wide nocase
        $domain31 = "app\.microsoftstaticapi\.com" ascii wide nocase
        $domain32 = "arestc\.net" ascii wide nocase
        $domain33 = "asdasw21\.icu" ascii wide nocase
        $domain34 = "ashcrack\.freetcp\.com" ascii wide nocase
        $domain35 = "assistcustody\.xyz" ascii wide nocase
        $domain36 = "astudycarsceu\.net" ascii wide nocase
        $domain37 = "asushotfix\.com" ascii wide nocase
        $domain38 = "atomiclampco\.com" ascii wide nocase
        $domain39 = "auth\.microsoftsservice\.com" ascii wide nocase
        $domain40 = "back\.rooter\.tk" ascii wide nocase
        $domain41 = "backdoor\.apt\.photo" ascii wide nocase
        $domain42 = "bingsearches\.com" ascii wide nocase
        $domain43 = "bobs8\.oss-cn-hongkong\.aliyuncs\.com" ascii wide nocase
        $domain44 = "bold-hamilton\.207-246-119-197\.plesk\.page" ascii wide nocase
        $domain45 = "boopainc\.com" ascii wide nocase
        $domain46 = "box\.xxe\.pw" ascii wide nocase
        $domain47 = "browser-events-data-microsoft\.com" ascii wide nocase
        $domain48 = "bugcheck\.xigncodeservice\.com" ascii wide nocase
        $domain49 = "buildhosting\.club" ascii wide nocase
        $ip50 = "1.12.224.214" ascii wide
        $ip51 = "1.92.75.200" ascii wide
        $ip52 = "1.92.75.200" ascii wide
        $ip53 = "1.92.75.200" ascii wide
        $ip54 = "1.92.75.200" ascii wide
        $ip55 = "1.92.75.200" ascii wide
        $ip56 = "1.92.75.200" ascii wide
        $ip57 = "1.92.75.200" ascii wide
        $ip58 = "1.92.75.200" ascii wide
        $ip59 = "1.92.91.219" ascii wide
        $ip60 = "1.92.91.219" ascii wide
        $ip61 = "1.92.91.219" ascii wide
        $ip62 = "1.92.91.219" ascii wide
        $ip63 = "1.92.91.219" ascii wide
        $ip64 = "1.92.91.219" ascii wide
        $ip65 = "1.92.91.219" ascii wide
        $ip66 = "1.92.91.219" ascii wide
        $ip67 = "1.94.125.189" ascii wide
        $ip68 = "1.94.125.189" ascii wide
        $ip69 = "1.94.125.189" ascii wide
        $ip70 = "1.94.125.189" ascii wide
        $ip71 = "1.94.125.189" ascii wide
        $ip72 = "1.94.125.189" ascii wide
        $ip73 = "1.94.125.189" ascii wide
        $ip74 = "1.94.125.189" ascii wide
        $ip75 = "101.132.147.163" ascii wide
        $ip76 = "101.132.147.163" ascii wide
        $ip77 = "101.132.147.163" ascii wide
        $ip78 = "101.132.147.163" ascii wide
        $ip79 = "101.200.77.210" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_BATSHADOW
{
    meta:
        description = "Detects IOCs associated with APT BATSHADOW"
        author = "APTtrail Automated Collection"
        apt_group = "BATSHADOW"
        aliases = "vampirebot"
        reference = "https://github.com/blackorbird/APT_REPORT/blob/master/cybercrime/BatShadow/batshadow-vietnamese-threat-group-vampire-bot-report.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "djactuallsbuilds\.com" ascii wide nocase
        $domain1 = "ftp\.spaceq\.ovh" ascii wide nocase
        $domain2 = "get-reponse-subt1\.duckdns\.org" ascii wide nocase
        $domain3 = "get-reponse-subt2\.duckdns\.org" ascii wide nocase
        $domain4 = "get-reponse-subt3\.duckdns\.org" ascii wide nocase
        $domain5 = "get-reponse-subt4\.duckdns\.org" ascii wide nocase
        $domain6 = "jobs-infomarriott\.com" ascii wide nocase
        $domain7 = "jobs-marriott\.com" ascii wide nocase
        $domain8 = "mail\.jobs-infomarriott\.com" ascii wide nocase
        $domain9 = "mail\.jobs-marriott\.com" ascii wide nocase
        $domain10 = "mysupportnetflix\.com" ascii wide nocase
        $domain11 = "samsung-work\.com" ascii wide nocase
        $domain12 = "samsungcareers\.work" ascii wide nocase
        $domain13 = "spaceq\.ovh" ascii wide nocase
        $domain14 = "workjobs\.net" ascii wide nocase
        $ip15 = "5.252.235.172" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_BISONAL
{
    meta:
        description = "Detects IOCs associated with APT BISONAL"
        author = "APTtrail Automated Collection"
        apt_group = "BISONAL"
        aliases = "bisonal, tonto, tontoteam"
        reference = "https://app.any.run/tasks/4c751168-358a-49c9-b751-e5b4aad9b060/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "0906\.toh\.info" ascii wide nocase
        $domain1 = "21kmg\.my-homeip\.net" ascii wide nocase
        $domain2 = "abulasha-banama\.onedumb\.com" ascii wide nocase
        $domain3 = "acivo\.serveblog\.net" ascii wide nocase
        $domain4 = "adobe-online\.com" ascii wide nocase
        $domain5 = "adoberevise\.com" ascii wide nocase
        $domain6 = "adobeupdata\.zzux\.com" ascii wide nocase
        $domain7 = "adobeupdate\.dns04\.com" ascii wide nocase
        $domain8 = "agent\.my-homeip\.net" ascii wide nocase
        $domain9 = "alleyk\.onthewifi\.com" ascii wide nocase
        $domain10 = "amanser951\.otzo\.com" ascii wide nocase
        $domain11 = "anna111\.epac\.to" ascii wide nocase
        $domain12 = "anrnet\.servegame\.com" ascii wide nocase
        $domain13 = "applejp\.myfw\.us" ascii wide nocase
        $domain14 = "asheepa\.sytes\.net" ascii wide nocase
        $domain15 = "attachdaum\.servecounterstrike\.com" ascii wide nocase
        $domain16 = "attachmaildaum\.serveblog\.net" ascii wide nocase
        $domain17 = "attachmaildaum\.servecounterstrike\.com" ascii wide nocase
        $domain18 = "babyhome\.lflink\.com" ascii wide nocase
        $domain19 = "babyhome\.mefound\.com" ascii wide nocase
        $domain20 = "baekmaonline\.com" ascii wide nocase
        $domain21 = "bbc\.xxxy\.info" ascii wide nocase
        $domain22 = "beatidc\.com" ascii wide nocase
        $domain23 = "best\.indoingwulearn\.com" ascii wide nocase
        $domain24 = "bitsshare\.com" ascii wide nocase
        $domain25 = "bizmeka\.viewdns\.net" ascii wide nocase
        $domain26 = "bluecat\.mefound\.com" ascii wide nocase
        $domain27 = "bluesky\.jkub\.com" ascii wide nocase
        $domain28 = "bravojack\.justdied\.com" ascii wide nocase
        $domain29 = "bucketnec\.bounceme\.net" ascii wide nocase
        $domain30 = "chrgeom\.system-ns\.net" ascii wide nocase
        $domain31 = "chromeupdate\.lflink\.com" ascii wide nocase
        $domain32 = "chsoun\.serveftp\.com" ascii wide nocase
        $domain33 = "ckstar\.zapto\.org" ascii wide nocase
        $domain34 = "cnnmirror\.com" ascii wide nocase
        $domain35 = "comunity\.system-ns\.org" ascii wide nocase
        $domain36 = "connts\.zzux\.com" ascii wide nocase
        $domain37 = "creepbeforeyouwalk\.com" ascii wide nocase
        $domain38 = "daecheol\.myvnc\.com" ascii wide nocase
        $domain39 = "daum\.xxuz\.com" ascii wide nocase
        $domain40 = "daummail\.otzo\.com" ascii wide nocase
        $domain41 = "dds\.walshdavis\.com" ascii wide nocase
        $domain42 = "developman\.ocry\.com" ascii wide nocase
        $domain43 = "dnsdns1\.passas\.us" ascii wide nocase
        $domain44 = "doctor-s\.dhcp\.biz" ascii wide nocase
        $domain45 = "doctor-s\.edns\.biz" ascii wide nocase
        $domain46 = "eburim\.viewdns\.net" ascii wide nocase
        $domain47 = "eduin21\.zapto\.org" ascii wide nocase
        $domain48 = "elecinfonec\.servehalflife\.com" ascii wide nocase
        $domain49 = "emsit\.serveirc\.com" ascii wide nocase
        $ip50 = "103.231.14.134" ascii wide
        $ip51 = "103.85.20.194" ascii wide
        $ip52 = "137.220.176.165" ascii wide
        $ip53 = "153.234.77.155" ascii wide
        $ip54 = "45.133.194.135" ascii wide
        $url55 = "/chapter1/user\.html/" ascii wide nocase
        $url56 = "/chapter1/user\.html/" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_BITTER
{
    meta:
        description = "Detects IOCs associated with APT BITTER"
        author = "APTtrail Automated Collection"
        apt_group = "BITTER"
        aliases = "AlmondRAT, BDarkRAT, Hazy Tiger"
        reference = "https://about.fb.com/wp-content/uploads/2022/08/Quarterly-Adversarial-Threat-Report-Q2-2022.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "1drivestorage\.com" ascii wide nocase
        $domain1 = "55five\.lol" ascii wide nocase
        $domain2 = "888toto\.com" ascii wide nocase
        $domain3 = "8toto\.co" ascii wide nocase
        $domain4 = "918slot\.top" ascii wide nocase
        $domain5 = "99togel\.org" ascii wide nocase
        $domain6 = "99toto\.shop" ascii wide nocase
        $domain7 = "a\.churchill91\.com" ascii wide nocase
        $domain8 = "aadresourcing\.com" ascii wide nocase
        $domain9 = "abelewebconnect\.com" ascii wide nocase
        $domain10 = "activemobistore\.ddns\.net" ascii wide nocase
        $domain11 = "adamsresearchshare\.com" ascii wide nocase
        $domain12 = "aday\.primeservices\.mobi" ascii wide nocase
        $domain13 = "aduhoki88\.com" ascii wide nocase
        $domain14 = "affinitycapitalgp\.com" ascii wide nocase
        $domain15 = "affinitycapitalgr\.com" ascii wide nocase
        $domain16 = "alfiehealtcareservice\.com" ascii wide nocase
        $domain17 = "alfiehealthcareservice\.com" ascii wide nocase
        $domain18 = "alkhaleejpk\.info" ascii wide nocase
        $domain19 = "alvesbarcelona\.com" ascii wide nocase
        $domain20 = "andbouncersclub\.com" ascii wide nocase
        $domain21 = "apifilestore\.net" ascii wide nocase
        $domain22 = "app\.chabaka\.com" ascii wide nocase
        $domain23 = "app2\.appvlc\.com" ascii wide nocase
        $domain24 = "appbriar\.com" ascii wide nocase
        $domain25 = "appprotonvpn\.com" ascii wide nocase
        $domain26 = "appsupdate\.net" ascii wide nocase
        $domain27 = "archiverst\.com" ascii wide nocase
        $domain28 = "aroundtheworld123\.net" ascii wide nocase
        $domain29 = "autodefragapp\.com" ascii wide nocase
        $domain30 = "bakuackermannfashions\.com" ascii wide nocase
        $domain31 = "balkanclan\.com" ascii wide nocase
        $domain32 = "bartelemarks\.com" ascii wide nocase
        $domain33 = "benclickstudio\.com" ascii wide nocase
        $domain34 = "bensnewfashionstyles\.com" ascii wide nocase
        $domain35 = "bheragreens\.com" ascii wide nocase
        $domain36 = "bickrickneoservice\.com" ascii wide nocase
        $domain37 = "biocons\.pk" ascii wide nocase
        $domain38 = "blth32serv\.net" ascii wide nocase
        $domain39 = "blucollinsoutien\.com" ascii wide nocase
        $domain40 = "bluelotus\.mail-gdrive\.com" ascii wide nocase
        $domain41 = "botanoolifeapp\.net" ascii wide nocase
        $domain42 = "box\.livevideosonlinepk\.com" ascii wide nocase
        $domain43 = "briarapppro\.org" ascii wide nocase
        $domain44 = "bsdqcaptureman\.com" ascii wide nocase
        $domain45 = "btappclientsvc\.net" ascii wide nocase
        $domain46 = "bulltrader\.vip" ascii wide nocase
        $domain47 = "camncryptsvc\.net" ascii wide nocase
        $domain48 = "care\.autodefragapp\.com" ascii wide nocase
        $domain49 = "carlminiclub\.com" ascii wide nocase
        $ip50 = "107.173.63.218" ascii wide
        $ip51 = "110.42.64.137" ascii wide
        $ip52 = "135.125.242.211" ascii wide
        $ip53 = "141.94.68.169" ascii wide
        $ip54 = "147.124.223.140" ascii wide
        $ip55 = "151.236.14.173" ascii wide
        $ip56 = "151.236.21.48" ascii wide
        $ip57 = "151.236.9.75" ascii wide
        $ip58 = "151.236.9.75" ascii wide
        $ip59 = "158.255.215.45" ascii wide
        $ip60 = "162.0.216.229" ascii wide
        $ip61 = "162.0.216.229" ascii wide
        $ip62 = "162.252.172.67" ascii wide
        $ip63 = "162.252.175.131" ascii wide
        $ip64 = "162.252.175.131" ascii wide
        $ip65 = "167.88.15.93" ascii wide
        $ip66 = "185.106.123.198" ascii wide
        $ip67 = "185.117.73.195" ascii wide
        $ip68 = "185.117.73.209" ascii wide
        $ip69 = "185.141.25.244" ascii wide
        $ip70 = "185.193.48.135" ascii wide
        $ip71 = "185.237.166.24" ascii wide
        $ip72 = "185.76.79.30" ascii wide
        $ip73 = "192.71.249.194" ascii wide
        $ip74 = "193.142.58.38" ascii wide
        $ip75 = "193.29.58.210" ascii wide
        $ip76 = "194.71.227.222" ascii wide
        $ip77 = "209.74.80.194" ascii wide
        $ip78 = "23.106.122.149" ascii wide
        $ip79 = "23.254.128.22" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_BLACKGEAR
{
    meta:
        description = "Detects IOCs associated with APT BLACKGEAR"
        author = "APTtrail Automated Collection"
        apt_group = "BLACKGEAR"
        reference = "https://documents.trendmicro.com/assets/appendix-blackgear-cyberespionage-campaign-resurfaces-abuses-social-media-for-c&c-communication.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "abcdns\.bounceme\.net" ascii wide nocase
        $domain1 = "abcpees\.webhop\.net" ascii wide nocase
        $domain2 = "ancelon\.webhop\.net" ascii wide nocase
        $domain3 = "anitacxb\.servebbs\.com" ascii wide nocase
        $domain4 = "bi-apple\.net" ascii wide nocase
        $domain5 = "bitdefender\.minidns\.net" ascii wide nocase
        $domain6 = "ccc\.th-fish\.com" ascii wide nocase
        $domain7 = "ccuugo\.8866\.org" ascii wide nocase
        $domain8 = "checkerror\.obama20009\.com" ascii wide nocase
        $domain9 = "cheng\.pc-officer\.com" ascii wide nocase
        $domain10 = "cometocome\.8866\.org" ascii wide nocase
        $domain11 = "computerupdate\.servegame\.com" ascii wide nocase
        $domain12 = "cooperlzh\.liondrive\.com" ascii wide nocase
        $domain13 = "d1c2f3\.3322\.org" ascii wide nocase
        $domain14 = "data\.lovequintet\.com" ascii wide nocase
        $domain15 = "divineart\.dyndns\.org" ascii wide nocase
        $domain16 = "domain\.uyghuri\.com" ascii wide nocase
        $domain17 = "enterdia\.zyns\.com" ascii wide nocase
        $domain18 = "erbilin\.blogdns\.com" ascii wide nocase
        $domain19 = "feng\.pc-officer\.com" ascii wide nocase
        $domain20 = "fifaoopp\.webhop\.net" ascii wide nocase
        $domain21 = "fisu\.rr\.nu" ascii wide nocase
        $domain22 = "gmail\.servebbs\.com" ascii wide nocase
        $domain23 = "goodhope\.no-ip\.org" ascii wide nocase
        $domain24 = "googleads\.serveftp\.com" ascii wide nocase
        $domain25 = "handinhand\.blogdns\.org" ascii wide nocase
        $domain26 = "harris\.3322\.org" ascii wide nocase
        $domain27 = "hinetrouter\.serveftp\.org" ascii wide nocase
        $domain28 = "hongzong\.xicp\.net" ascii wide nocase
        $domain29 = "hzcj\.8866\.org" ascii wide nocase
        $domain30 = "hzong\.welikejack\.com" ascii wide nocase
        $domain31 = "ie-update\.sytes\.net" ascii wide nocase
        $domain32 = "ifsbsa\.bounceme\.net" ascii wide nocase
        $domain33 = "ihe1979\.3322\.org" ascii wide nocase
        $domain34 = "intershare\.zapto\.net" ascii wide nocase
        $domain35 = "intershare\.zapto\.org" ascii wide nocase
        $domain36 = "introy\.toh\.info" ascii wide nocase
        $domain37 = "ius\.uyghuri\.com" ascii wide nocase
        $domain38 = "japanisok\.selfip\.org" ascii wide nocase
        $domain39 = "jmjm\.bounceme\.net" ascii wide nocase
        $domain40 = "killabcd\.9966\.org" ascii wide nocase
        $domain41 = "kingcoast\.3322\.org" ascii wide nocase
        $domain42 = "kingcoast\.6688\.org" ascii wide nocase
        $domain43 = "kingcoast\.homedns\.org" ascii wide nocase
        $domain44 = "kmtzh\.zyns\.com" ascii wide nocase
        $domain45 = "ksforever\.no-ip\.org" ascii wide nocase
        $domain46 = "liumingzhen\.myftp\.org" ascii wide nocase
        $domain47 = "liumingzhen\.zapto\.org" ascii wide nocase
        $domain48 = "liveupdate\.dyndns\.biz" ascii wide nocase
        $domain49 = "lovemoney\.2288\.org" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_BLACKTECH
{
    meta:
        description = "Detects IOCs associated with APT BLACKTECH"
        author = "APTtrail Automated Collection"
        apt_group = "BLACKTECH"
        reference = "https://app.validin.com/detail?find=212.115.54.194&type=ip4&ref_id=fd9bbd3c264#tab=resolutions (# 2025-03-01)"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "activate\.linkblackclover\.com" ascii wide nocase
        $domain1 = "adobeupdate\.serveusers\.com" ascii wide nocase
        $domain2 = "amazon\.panasocin\.com" ascii wide nocase
        $domain3 = "centos\.onthewifi\.com" ascii wide nocase
        $domain4 = "centos1\.chinabrands\.xyz" ascii wide nocase
        $domain5 = "centos2\.chinabrands\.xyz" ascii wide nocase
        $domain6 = "centosupdate\.dynamic-dns\.net" ascii wide nocase
        $domain7 = "centosupdates\.com" ascii wide nocase
        $domain8 = "centrosupdate\.proxydns\.com" ascii wide nocase
        $domain9 = "config\.zapto\.org" ascii wide nocase
        $domain10 = "em\.totalpople\.info" ascii wide nocase
        $domain11 = "evergo\.dnset\.com" ascii wide nocase
        $domain12 = "fibtec\.jkub\.com" ascii wide nocase
        $domain13 = "gstrap\.jkub\.com" ascii wide nocase
        $domain14 = "harb\.bbsindex\.com" ascii wide nocase
        $domain15 = "herace\.https443\.org" ascii wide nocase
        $domain16 = "idonotknow\.lflinkup\.com" ascii wide nocase
        $domain17 = "idonotknow\.lflinkup\.net" ascii wide nocase
        $domain18 = "idonotknow\.serveusers\.com" ascii wide nocase
        $domain19 = "inkeslive\.com" ascii wide nocase
        $domain20 = "linuxhome\.jkub\.com" ascii wide nocase
        $domain21 = "macfee-update\.serveftp\.com" ascii wide nocase
        $domain22 = "microsoftonline\.com\.authorizeddns\.net" ascii wide nocase
        $domain23 = "ns1001\.centosupdates\.com" ascii wide nocase
        $domain24 = "office\.panasocin\.com" ascii wide nocase
        $domain25 = "okinawas\.ssl443\.org" ascii wide nocase
        $domain26 = "org\.misecure\.com" ascii wide nocase
        $domain27 = "panasocin\.com" ascii wide nocase
        $domain28 = "redhatstate\.hopto\.org" ascii wide nocase
        $domain29 = "rutentw\.com" ascii wide nocase
        $domain30 = "securitycenter\.kozow\.com" ascii wide nocase
        $domain31 = "systeminfo\.centosupdates\.com" ascii wide nocase
        $domain32 = "totalpople\.info" ascii wide nocase
        $domain33 = "update\.centosupdates\.com" ascii wide nocase
        $domain34 = "update\.panasocin\.com" ascii wide nocase
        $domain35 = "updates\.centosupdates\.com" ascii wide nocase
        $domain36 = "web2008\.rutentw\.com" ascii wide nocase
        $domain37 = "wg1\.inkeslive\.com" ascii wide nocase
        $domain38 = "woc\.yasonbin\.info" ascii wide nocase
        $domain39 = "yasonbin\.info" ascii wide nocase
        $ip40 = "172.104.109.217" ascii wide
        $ip41 = "212.115.54.194" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_BLADEDFELINE
{
    meta:
        description = "Detects IOCs associated with APT BLADEDFELINE"
        author = "APTtrail Automated Collection"
        apt_group = "BLADEDFELINE"
        aliases = "laret, pinar"
        reference = "https://www.welivesecurity.com/en/eset-research/bladedfeline-whispering-dark/"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "178.209.51.61" ascii wide
        $ip1 = "178.209.51.61" ascii wide
        $ip2 = "178.209.51.61" ascii wide
        $ip3 = "185.76.78.177" ascii wide
        $ip4 = "185.76.78.177" ascii wide
        $ip5 = "185.76.78.177" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_BLINDEAGLE
{
    meta:
        description = "Detects IOCs associated with APT BLINDEAGLE"
        author = "APTtrail Automated Collection"
        apt_group = "BLINDEAGLE"
        aliases = "aguilaciega, apt-c-36, apt-q-98"
        reference = "https://gist.github.com/kirk-sayre-work/354d875086bb533b3095dc06b7537869"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "ajaxcoder\.polycomusa\.com" ascii wide nocase
        $domain1 = "aseguradotelle\.duckdns\.org" ascii wide nocase
        $domain2 = "autgerman\.autgerman\.com" ascii wide nocase
        $domain3 = "autgerman\.com" ascii wide nocase
        $domain4 = "axu87794\.polycomusa\.com" ascii wide nocase
        $domain5 = "ceoempresarialsas\.com" ascii wide nocase
        $domain6 = "ceosas\.linkpc\.net" ascii wide nocase
        $domain7 = "ceoseguros\.com" ascii wide nocase
        $domain8 = "chileimportaciones\.cl" ascii wide nocase
        $domain9 = "cryptersandtools\.minhacasa\.tv" ascii wide nocase
        $domain10 = "defenderav\.con-ip\.com" ascii wide nocase
        $domain11 = "dian\.server\.tl" ascii wide nocase
        $domain12 = "diangovcomuiscia\.com" ascii wide nocase
        $domain13 = "edificiobaldeares\.linkpc\.net" ascii wide nocase
        $domain14 = "enero2022\.con-ip\.com" ascii wide nocase
        $domain15 = "envio02-04\.duckdns\.org" ascii wide nocase
        $domain16 = "envio14-03\.duckdns\.org" ascii wide nocase
        $domain17 = "envio1414\.duckdns\.org" ascii wide nocase
        $domain18 = "envio19-05\.duckdns\.org" ascii wide nocase
        $domain19 = "envio21-05\.duckdns\.org" ascii wide nocase
        $domain20 = "envio2333\.duckdns\.org" ascii wide nocase
        $domain21 = "envio26-03\.duckdns\.org" ascii wide nocase
        $domain22 = "envio28-003\.duckdns\.org" ascii wide nocase
        $domain23 = "envio29\.duckdns\.org" ascii wide nocase
        $domain24 = "envio31-03\.duckdns\.org" ascii wide nocase
        $domain25 = "equipo\.linkpc\.net" ascii wide nocase
        $domain26 = "febenvi\.duckdns\.org" ascii wide nocase
        $domain27 = "giraffebear\.polycomusa\.com" ascii wide nocase
        $domain28 = "hellmagers\.polycomusa\.com" ascii wide nocase
        $domain29 = "host-rami\.polycomusa\.com" ascii wide nocase
        $domain30 = "ismaboli\.com" ascii wide nocase
        $domain31 = "laminascol\.linkpc\.net" ascii wide nocase
        $domain32 = "marzo72022\.con-ip\.com" ascii wide nocase
        $domain33 = "medicosco\.publicvm\.com" ascii wide nocase
        $domain34 = "medicosempresa\.com" ascii wide nocase
        $domain35 = "mega\.polycomusa\.com" ascii wide nocase
        $domain36 = "mentes\.publicvm\.com" ascii wide nocase
        $domain37 = "ojosostenerfebrero\.duckdns\.org" ascii wide nocase
        $domain38 = "perfect5\.publicvm\.com" ascii wide nocase
        $domain39 = "perfect8\.publicvm\.com" ascii wide nocase
        $domain40 = "polycomusa\.com" ascii wide nocase
        $domain41 = "pub-4c182737706e41d29aee6cc5517f834d\.r2\.dev" ascii wide nocase
        $domain42 = "pub-6346c84860d5480393a1799fb277dfdc\.r2\.dev" ascii wide nocase
        $domain43 = "qua25q\.duckdns\.org" ascii wide nocase
        $domain44 = "qua25qua\.duckdns\.org" ascii wide nocase
        $domain45 = "respaldito01\.duckdns\.org" ascii wide nocase
        $domain46 = "respaldito03\.duckdns\.org" ascii wide nocase
        $domain47 = "respaldomax3\.duckdns\.org" ascii wide nocase
        $domain48 = "respaldomax4\.duckdns\.org" ascii wide nocase
        $domain49 = "respaldomx1\.duckdns\.org" ascii wide nocase
        $ip50 = "103.151.124.233" ascii wide
        $ip51 = "128.90.108.115" ascii wide
        $ip52 = "128.90.115.167" ascii wide
        $ip53 = "128.90.115.93" ascii wide
        $ip54 = "128.90.115.95" ascii wide
        $ip55 = "128.90.130.185" ascii wide
        $ip56 = "177.255.89.112" ascii wide
        $ip57 = "177.255.89.112" ascii wide
        $ip58 = "181.130.5.112" ascii wide
        $ip59 = "181.130.9.145" ascii wide
        $ip60 = "181.130.9.145" ascii wide
        $ip61 = "181.131.217.174" ascii wide
        $ip62 = "2.56.57.27" ascii wide
        $ip63 = "2.56.59.208" ascii wide
        $ip64 = "35.34.5.27" ascii wide
        $ip65 = "45.147.231.85" ascii wide
        $ip66 = "62.197.136.252" ascii wide
        $ip67 = "69.167.10.207" ascii wide
        $ip68 = "69.167.11.9" ascii wide
        $ip69 = "69.167.8.118" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_BLUENOROFF
{
    meta:
        description = "Detects IOCs associated with APT BLUENOROFF"
        author = "APTtrail Automated Collection"
        apt_group = "BLUENOROFF"
        aliases = "CoreKit, NimDoor, RTV4"
        reference = "https://app.any.run/tasks/8d5e66c9-3942-4e00-bfdf-8f2c24054a92/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "163qiye\.top" ascii wide nocase
        $domain1 = "1driv\.org" ascii wide nocase
        $domain2 = "1drv\.email" ascii wide nocase
        $domain3 = "1drvmail\.work" ascii wide nocase
        $domain4 = "256ventures\.us" ascii wide nocase
        $domain5 = "31ventures\.info" ascii wide nocase
        $domain6 = "abf-cap\.co" ascii wide nocase
        $domain7 = "abf-cap\.com" ascii wide nocase
        $domain8 = "abiesvc\.com" ascii wide nocase
        $domain9 = "abiesvc\.info" ascii wide nocase
        $domain10 = "abiesvc\.jp\.net" ascii wide nocase
        $domain11 = "adiclas-nft\.quest" ascii wide nocase
        $domain12 = "aidpartners\.org" ascii wide nocase
        $domain13 = "ajayplamingo\.com" ascii wide nocase
        $domain14 = "aleslosev\.workers\.dev" ascii wide nocase
        $domain15 = "altair-vc\.co\.uk" ascii wide nocase
        $domain16 = "altair-vc\.com" ascii wide nocase
        $domain17 = "altair\.linkpc\.net" ascii wide nocase
        $domain18 = "amazonaws1\.info" ascii wide nocase
        $domain19 = "amzonnews\.club" ascii wide nocase
        $domain20 = "analysis\.arkinvst\.com" ascii wide nocase
        $domain21 = "angelbridge\.capital" ascii wide nocase
        $domain22 = "angelbridge\.jp" ascii wide nocase
        $domain23 = "ankanimatoka\.com" ascii wide nocase
        $domain24 = "anobaka\.info" ascii wide nocase
        $domain25 = "anobaka\.jp" ascii wide nocase
        $domain26 = "antcapital\.us" ascii wide nocase
        $domain27 = "api\.zerodev\.pro" ascii wide nocase
        $domain28 = "api\.zoom-sdk\.com" ascii wide nocase
        $domain29 = "app-wechat\.xyz" ascii wide nocase
        $domain30 = "app\.baiduweb\.pro" ascii wide nocase
        $domain31 = "app\.developcore\.org" ascii wide nocase
        $domain32 = "app\.republicrypto\.vc" ascii wide nocase
        $domain33 = "app\.thorwsap\.finance" ascii wide nocase
        $domain34 = "appleaccess\.pro" ascii wide nocase
        $domain35 = "appleupdate\.datauploader\.site" ascii wide nocase
        $domain36 = "arbordeck\.co\.in" ascii wide nocase
        $domain37 = "arborventures\.capital" ascii wide nocase
        $domain38 = "arkinvst\.com" ascii wide nocase
        $domain39 = "armzon\.onmypc\.org" ascii wide nocase
        $domain40 = "association\.linkpc\.net" ascii wide nocase
        $domain41 = "atajerefoods\.com" ascii wide nocase
        $domain42 = "atom\.publicvm\.com" ascii wide nocase
        $domain43 = "att\.gdrvupload\.xyz" ascii wide nocase
        $domain44 = "authenticate\.azure-drive\.com" ascii wide nocase
        $domain45 = "autodynamics\.work\.gd" ascii wide nocase
        $domain46 = "automatic-update\.online" ascii wide nocase
        $domain47 = "autoprotect\.com\.de" ascii wide nocase
        $domain48 = "autoprotect\.com\.se" ascii wide nocase
        $domain49 = "autoprotect\.gb\.net" ascii wide nocase
        $ip50 = "104.168.145.52" ascii wide
        $ip51 = "104.168.151.70" ascii wide
        $ip52 = "104.168.198.145" ascii wide
        $ip53 = "118.70.116.154" ascii wide
        $ip54 = "140.117.91.22" ascii wide
        $ip55 = "140.136.134.201" ascii wide
        $ip56 = "163.25.24.44" ascii wide
        $ip57 = "186.183.185.94" ascii wide
        $ip58 = "23.254.202.223" ascii wide
        $ip59 = "41.85.145.164" ascii wide
        $ip60 = "45.238.25.2" ascii wide
        $ip61 = "45.61.140.26" ascii wide
        $ip62 = "66.181.166.15" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_BLUEPRINT
{
    meta:
        description = "Detects IOCs associated with APT BLUEPRINT"
        author = "APTtrail Automated Collection"
        apt_group = "BLUEPRINT"
        reference = "https://otx.alienvault.com/pulse/5cf63c5f1c20b24747675033"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "cloud\.yourdocument\.biz" ascii wide nocase
        $domain1 = "swift-fraud\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_BOOKWORM
{
    meta:
        description = "Detects IOCs associated with APT BOOKWORM"
        author = "APTtrail Automated Collection"
        apt_group = "BOOKWORM"
        reference = "http://researchcenter.paloaltonetworks.com/2015/11/bookworm-trojan-a-model-of-modular-architecture/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "bkmail\.blogdns\.com" ascii wide nocase
        $domain1 = "debain\.servehttp\.com" ascii wide nocase
        $domain2 = "linuxdns\.sytes\.net" ascii wide nocase
        $domain3 = "news\.nhknews\.hk" ascii wide nocase
        $domain4 = "sswmail\.gotdns\.com" ascii wide nocase
        $domain5 = "sswwmail\.gotdns\.com" ascii wide nocase
        $domain6 = "sysnc\.sytes\.net" ascii wide nocase
        $domain7 = "systeminfothai\.gotdns\.ch" ascii wide nocase
        $domain8 = "thailandbbs\.ddns\.net" ascii wide nocase
        $domain9 = "ubuntudns\.sytes\.net" ascii wide nocase
        $domain10 = "web12\.nhknews\.hk" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_BOTEAM
{
    meta:
        description = "Detects IOCs associated with APT BOTEAM"
        author = "APTtrail Automated Collection"
        apt_group = "BOTEAM"
        aliases = "black owl, brockendoor, hoody hyena"
        reference = "https://securelist.ru/bo-team-upgrades-brockendoor-and-zeronetkit-backdoors/113536"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "easybussy\.space" ascii wide nocase
        $domain1 = "icecoldwind\.online" ascii wide nocase
        $domain2 = "invuln\.xyz" ascii wide nocase
        $domain3 = "lizzardsnails\.online" ascii wide nocase
        $domain4 = "mgutu-vf\.ru" ascii wide nocase
        $domain5 = "railradman\.site" ascii wide nocase
        $domain6 = "urbantvpn\.online" ascii wide nocase
        $domain7 = "wholewell\.online" ascii wide nocase
        $ip8 = "213.165.60.118" ascii wide
        $ip9 = "213.165.60.118" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_BUHTRAP
{
    meta:
        description = "Detects IOCs associated with APT BUHTRAP"
        author = "APTtrail Automated Collection"
        apt_group = "BUHTRAP"
        aliases = "UAC-0008"
        reference = "https://cert.gov.ua/article/37246"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "allwomens\.eu" ascii wide nocase
        $domain1 = "alt-2cdn\.net" ascii wide nocase
        $domain2 = "avidium\.ru\.com" ascii wide nocase
        $domain3 = "corp-microsoft\.com" ascii wide nocase
        $domain4 = "cs1\.wpc-v0cdn\.org" ascii wide nocase
        $domain5 = "edinstvennaya\.eu" ascii wide nocase
        $domain6 = "hdfilm-seyret\.com" ascii wide nocase
        $domain7 = "ipv6-microsoft\.org" ascii wide nocase
        $domain8 = "ipv6-wpnc\.net" ascii wide nocase
        $domain9 = "khabmama\.eu" ascii wide nocase
        $domain10 = "mail\.nais-gov\.org" ascii wide nocase
        $domain11 = "nais-gov\.com" ascii wide nocase
        $domain12 = "nais-gov\.org" ascii wide nocase
        $domain13 = "ns2-dns\.com" ascii wide nocase
        $domain14 = "ns3-dns\.com" ascii wide nocase
        $domain15 = "redmond\.corp-microsoft\.com" ascii wide nocase
        $domain16 = "secure-telemetry\.net" ascii wide nocase
        $domain17 = "services-glbdns2\.com" ascii wide nocase
        $domain18 = "shkolazhizni\.eu" ascii wide nocase
        $domain19 = "sibmama\.eu" ascii wide nocase
        $domain20 = "slingshop\.ru\.com" ascii wide nocase
        $domain21 = "widget\.forum-pokemon\.com" ascii wide nocase
        $domain22 = "wpc-v0cdn\.org" ascii wide nocase
        $domain23 = "zhenskoe-mnenie\.eu" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_CADETBLIZZARD
{
    meta:
        description = "Detects IOCs associated with APT CADETBLIZZARD"
        author = "APTtrail Automated Collection"
        apt_group = "CADETBLIZZARD"
        reference = "https://explore.avertium.com/resource/threat-actor-profile-cadet-blizzard"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "justiceua\.org" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_CALYPSO
{
    meta:
        description = "Detects IOCs associated with APT CALYPSO"
        author = "APTtrail Automated Collection"
        apt_group = "CALYPSO"
        reference = "https://otx.alienvault.com/pulse/60638f7aff63f9956797e899"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "aztecoo\.com" ascii wide nocase
        $domain1 = "blog\.globnewsline\.com" ascii wide nocase
        $domain2 = "clark\.l8t\.net" ascii wide nocase
        $domain3 = "dealsgle\.com" ascii wide nocase
        $domain4 = "draconess\.com" ascii wide nocase
        $domain5 = "etheraval\.com" ascii wide nocase
        $domain6 = "globnewsline\.com" ascii wide nocase
        $domain7 = "krgod\.qqm8\.com" ascii wide nocase
        $domain8 = "mail\.globnewsline\.com" ascii wide nocase
        $domain9 = "mail\.sultris\.com" ascii wide nocase
        $domain10 = "membrig\.com" ascii wide nocase
        $domain11 = "pop3\.wordmoss\.com" ascii wide nocase
        $domain12 = "prowesoo\.com" ascii wide nocase
        $domain13 = "r01\.etheraval\.com" ascii wide nocase
        $domain14 = "rawfuns\.com" ascii wide nocase
        $domain15 = "rosyfund\.com" ascii wide nocase
        $domain16 = "streleases\.com" ascii wide nocase
        $domain17 = "sultris\.com" ascii wide nocase
        $domain18 = "surfanny\.com" ascii wide nocase
        $domain19 = "tc\.streleases\.com" ascii wide nocase
        $domain20 = "teldcomtv\.com" ascii wide nocase
        $domain21 = "tv\.teldcomtv\.com" ascii wide nocase
        $domain22 = "usergetacss\.com" ascii wide nocase
        $domain23 = "uv\.usergetacss\.com" ascii wide nocase
        $domain24 = "waxgon\.com" ascii wide nocase
        $domain25 = "webmail\.surfanny\.com" ascii wide nocase
        $domain26 = "wordmoss\.com" ascii wide nocase
        $domain27 = "yolkish\.com" ascii wide nocase
        $domain28 = "youtubemail\.club" ascii wide nocase
        $domain29 = "zmail\.wordmoss\.com" ascii wide nocase
        $ip30 = "103.224.82.47" ascii wide
        $ip31 = "103.224.82.47" ascii wide
        $ip32 = "46.105.227.110" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_CAMARODRAGON
{
    meta:
        description = "Detects IOCs associated with APT CAMARODRAGON"
        author = "APTtrail Automated Collection"
        apt_group = "CAMARODRAGON"
        reference = "https://research.checkpoint.com/2023/the-dragon-who-sold-his-camaro-analyzing-custom-router-implant/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "cremessage\.com" ascii wide nocase
        $domain1 = "m\.cremessage\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_CARACALKITTEN
{
    meta:
        description = "Detects IOCs associated with APT CARACALKITTEN"
        author = "APTtrail Automated Collection"
        apt_group = "CARACALKITTEN"
        aliases = "apt-q-58"
        reference = "https://twitter.com/RexorVc0/status/1712725980924518898"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "65.109.157.77" ascii wide

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_CARBONSPIDER
{
    meta:
        description = "Detects IOCs associated with APT CARBONSPIDER"
        author = "APTtrail Automated Collection"
        apt_group = "CARBONSPIDER"
        reference = "https://app.any.run/tasks/d40e13a1-f17a-449c-8ac4-a7fd947f986b/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "againcome\.com" ascii wide nocase
        $domain1 = "alphalanding\.com" ascii wide nocase
        $domain2 = "besaintegration\.com" ascii wide nocase
        $domain3 = "charjackyum\.com" ascii wide nocase
        $domain4 = "chauvinistable\.com" ascii wide nocase
        $domain5 = "colahasch\.com" ascii wide nocase
        $domain6 = "electroncador\.com" ascii wide nocase
        $domain7 = "gemmiparalyzed\.com" ascii wide nocase
        $domain8 = "jaglamorous\.com" ascii wide nocase
        $domain9 = "judicialance\.com" ascii wide nocase
        $domain10 = "neighborhoodlumish\.com" ascii wide nocase
        $domain11 = "petshopbook\.com" ascii wide nocase
        $domain12 = "podestablished\.com" ascii wide nocase
        $domain13 = "spontaneousance\.com" ascii wide nocase
        $domain14 = "spoolopedia\.com" ascii wide nocase
        $domain15 = "temptationone\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_CARDERBEE
{
    meta:
        description = "Detects IOCs associated with APT CARDERBEE"
        author = "APTtrail Automated Collection"
        apt_group = "CARDERBEE"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/carderbee-software-supply-chain-certificate-abuse"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "active-microsoft\.com" ascii wide nocase
        $domain1 = "cdn\.ofo\.ac" ascii wide nocase
        $domain2 = "cdn\.stream-amazon\.com" ascii wide nocase
        $domain3 = "githubassets\.akamaixed\.net" ascii wide nocase
        $domain4 = "gobay\.info" ascii wide nocase
        $domain5 = "ms-f7-sites-prod-cdn\.akamaixed\.net" ascii wide nocase
        $domain6 = "ms-g9-sites-prod-cdn\.akamaixed\.net" ascii wide nocase
        $domain7 = "ofo\.ac" ascii wide nocase
        $domain8 = "tjj\.active-microsoft\.com" ascii wide nocase
        $ip9 = "103.151.28.11" ascii wide
        $ip10 = "111.231.100.228" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_CARETO
{
    meta:
        description = "Detects IOCs associated with APT CARETO"
        author = "APTtrail Automated Collection"
        apt_group = "CARETO"
        reference = "http://kernelmode.info/forum/viewtopic.php?f=16&t=3159"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "appleupdt\.com" ascii wide nocase
        $domain1 = "carrus\.gotdns\.com" ascii wide nocase
        $domain2 = "cherry1962\.dyndns\.org" ascii wide nocase
        $domain3 = "ctronlinenews\.dyndns\.tv" ascii wide nocase
        $domain4 = "dfup\.selfip\.org" ascii wide nocase
        $domain5 = "fast8\.homeftp\.org" ascii wide nocase
        $domain6 = "gx5639\.dyndns\.tv" ascii wide nocase
        $domain7 = "helpcenter1it6238\.cz\.cc" ascii wide nocase
        $domain8 = "helpcenter2br6932\.cc" ascii wide nocase
        $domain9 = "isaserver\.minrex\.gov\.cu" ascii wide nocase
        $domain10 = "karpeskmon\.dyndns\.org" ascii wide nocase
        $domain11 = "linkconf\.net" ascii wide nocase
        $domain12 = "mango66\.dyndns\.org" ascii wide nocase
        $domain13 = "msupdate\.ath\.cx" ascii wide nocase
        $domain14 = "msupdt\.com" ascii wide nocase
        $domain15 = "nav1002\.ath\.cx" ascii wide nocase
        $domain16 = "nthost\.shacknet\.nu" ascii wide nocase
        $domain17 = "oco-231-ms\.xns01\.com" ascii wide nocase
        $domain18 = "pininfarina\.dynalias\.com" ascii wide nocase
        $domain19 = "pl400\.dyndns\.org" ascii wide nocase
        $domain20 = "prosoccer1\.dyndns\.info" ascii wide nocase
        $domain21 = "prosoccer2\.dyndns\.info" ascii wide nocase
        $domain22 = "redirserver\.net" ascii wide nocase
        $domain23 = "ricush\.ath\.cx" ascii wide nocase
        $domain24 = "services\.serveftp\.org" ascii wide nocase
        $domain25 = "sv\.serveftp\.org" ascii wide nocase
        $domain26 = "swupdt\.com" ascii wide nocase
        $domain27 = "takami\.podzone\.net" ascii wide nocase
        $domain28 = "tunga\.homedns\.org" ascii wide nocase
        $domain29 = "updates\.homeftp\.org" ascii wide nocase
        $domain30 = "wqq\.dyndns\.org" ascii wide nocase
        $domain31 = "wwnav\.selfip\.net" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_CDT
{
    meta:
        description = "Detects IOCs associated with APT CDT"
        author = "APTtrail Automated Collection"
        apt_group = "CDT"
        reference = "https://citizenlab.ca/2017/07/insider-information-an-intrusion-campaign-targeting-chinese-language-news-sites/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "bowenpres\.com" ascii wide nocase
        $domain1 = "bowenpress\.net" ascii wide nocase
        $domain2 = "bowenpress\.org" ascii wide nocase
        $domain3 = "bowenpross\.com" ascii wide nocase
        $domain4 = "chinadagitaltimes\.net" ascii wide nocase
        $domain5 = "datalink\.one" ascii wide nocase
        $domain6 = "epochatimes\.com" ascii wide nocase
        $domain7 = "nhknews\.hk" ascii wide nocase
        $domain8 = "rooter\.tk" ascii wide nocase
        $domain9 = "secuerserver\.com" ascii wide nocase
        $domain10 = "tibetonline\.info" ascii wide nocase
        $domain11 = "vancouversun\.us" ascii wide nocase
        $domain12 = "vnews\.hk" ascii wide nocase
        $domain13 = "voanews\.hk" ascii wide nocase
        $domain14 = "yomiuri\.us" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_CHAFER
{
    meta:
        description = "Detects IOCs associated with APT CHAFER"
        author = "APTtrail Automated Collection"
        apt_group = "CHAFER"
        aliases = "apt39, chafer, itg07"
        reference = "https://blog.reversinglabs.com/blog/rana-android-malware"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "0ffice36o\.com" ascii wide nocase
        $domain1 = "100ostad\.ir" ascii wide nocase
        $domain2 = "acrobatverify\.com" ascii wide nocase
        $domain3 = "adobelicence\.com" ascii wide nocase
        $domain4 = "adpolicer\.org" ascii wide nocase
        $domain5 = "anyportals\.com" ascii wide nocase
        $domain6 = "apigoogle-accounts\.biz" ascii wide nocase
        $domain7 = "ccloudflare\.com" ascii wide nocase
        $domain8 = "chembook\.ir" ascii wide nocase
        $domain9 = "cloudipnameserver\.com" ascii wide nocase
        $domain10 = "ctci\.ir" ascii wide nocase
        $domain11 = "defender-update\.com" ascii wide nocase
        $domain12 = "dnmails\.gq" ascii wide nocase
        $domain13 = "dnrslv\.gq" ascii wide nocase
        $domain14 = "dropboxengine\.com" ascii wide nocase
        $domain15 = "elfdomainone\.com" ascii wide nocase
        $domain16 = "eseses\.tk" ascii wide nocase
        $domain17 = "facedomainpc\.com" ascii wide nocase
        $domain18 = "facedomaintv\.com" ascii wide nocase
        $domain19 = "fullplayersoftware\.com" ascii wide nocase
        $domain20 = "googie\.email" ascii wide nocase
        $domain21 = "hpserver\.online" ascii wide nocase
        $domain22 = "idc-team\.net" ascii wide nocase
        $domain23 = "irchemistry\.com" ascii wide nocase
        $domain24 = "irchemistry\.net" ascii wide nocase
        $domain25 = "j-alam\.com" ascii wide nocase
        $domain26 = "jevxvideo\.com" ascii wide nocase
        $domain27 = "jscript\.online" ascii wide nocase
        $domain28 = "ktci\.ir" ascii wide nocase
        $domain29 = "lifedomainwar\.com" ascii wide nocase
        $domain30 = "lowconnectivity\.com" ascii wide nocase
        $domain31 = "mailservice-verify\.stream" ascii wide nocase
        $domain32 = "microsoftcert\.xyz" ascii wide nocase
        $domain33 = "microsoftfixer\.com" ascii wide nocase
        $domain34 = "milanionline\.ir" ascii wide nocase
        $domain35 = "mobily-sa\.com" ascii wide nocase
        $domain36 = "msn-com\.dynu\.net" ascii wide nocase
        $domain37 = "msnconnection\.com" ascii wide nocase
        $domain38 = "mycrossweb\.com" ascii wide nocase
        $domain39 = "nvidia-services\.com" ascii wide nocase
        $domain40 = "offsetweb\.com" ascii wide nocase
        $domain41 = "redjewelry\.biz" ascii wide nocase
        $domain42 = "sabre-airlinesolutions\.com" ascii wide nocase
        $domain43 = "sabre-css\.com" ascii wide nocase
        $domain44 = "sadostad\.com" ascii wide nocase
        $domain45 = "sadostad\.ir" ascii wide nocase
        $domain46 = "saveingone\.com" ascii wide nocase
        $domain47 = "skf-group\.info" ascii wide nocase
        $domain48 = "softwareplayertop\.com" ascii wide nocase
        $domain49 = "srvuptcloud\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_CHAMELGANG
{
    meta:
        description = "Detects IOCs associated with APT CHAMELGANG"
        author = "APTtrail Automated Collection"
        apt_group = "CHAMELGANG"
        aliases = "camofei"
        reference = "https://otx.alienvault.com/pulse/64907e470e46bba8d3b68d52"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "api\.microsofed\.com" ascii wide nocase
        $domain1 = "app\.centralgoogle\.com" ascii wide nocase
        $domain2 = "app\.tstartel\.org" ascii wide nocase
        $domain3 = "appupdate\.ibmlotus\.net" ascii wide nocase
        $domain4 = "auth\.newtrendmicro\.com" ascii wide nocase
        $domain5 = "cdn-chrome\.com" ascii wide nocase
        $domain6 = "centralgoogle\.com" ascii wide nocase
        $domain7 = "cn\.mcafee-service\.us\.com" ascii wide nocase
        $domain8 = "collector\.centralgoogle\.com" ascii wide nocase
        $domain9 = "content\.centralgoogle\.com" ascii wide nocase
        $domain10 = "content\.newtrendmicro\.com" ascii wide nocase
        $domain11 = "contents\.newtrendmicro\.com" ascii wide nocase
        $domain12 = "derbox\.centralgoogle\.com" ascii wide nocase
        $domain13 = "docs\.microsoft-support\.net" ascii wide nocase
        $domain14 = "download\.softupdate-online\.top" ascii wide nocase
        $domain15 = "downloads\.softupdate-online\.top" ascii wide nocase
        $domain16 = "en\.mcafee-service\.us\.com" ascii wide nocase
        $domain17 = "funding-exchange\.org" ascii wide nocase
        $domain18 = "helpdisk\.ibmlotus\.net" ascii wide nocase
        $domain19 = "ibmlotus\.net" ascii wide nocase
        $domain20 = "internet\.softupdate-online\.top" ascii wide nocase
        $domain21 = "jumper\.funding-exchange\.org" ascii wide nocase
        $domain22 = "kaspernsky\.com" ascii wide nocase
        $domain23 = "login\.cdn-chrome\.com" ascii wide nocase
        $domain24 = "mail\.ibmlotus\.net" ascii wide nocase
        $domain25 = "mail\.tstartel\.org" ascii wide nocase
        $domain26 = "market\.newtrendmicro\.com" ascii wide nocase
        $domain27 = "mcafee-service\.us\.com" ascii wide nocase
        $domain28 = "mcafee-upgrade\.com" ascii wide nocase
        $domain29 = "microsofed\.com" ascii wide nocase
        $domain30 = "microsoft-support\.net" ascii wide nocase
        $domain31 = "newtrendmicro\.com" ascii wide nocase
        $domain32 = "ns1\.marocfamily\.com" ascii wide nocase
        $domain33 = "ns1\.marocfamilym\.com" ascii wide nocase
        $domain34 = "ns1\.marocfamilyx\.com" ascii wide nocase
        $domain35 = "ns1\.spezialsex\.com" ascii wide nocase
        $domain36 = "ns2\.marocfamily\.com" ascii wide nocase
        $domain37 = "ns2\.spezialsex\.com" ascii wide nocase
        $domain38 = "ns30\.mayashopping\.net" ascii wide nocase
        $domain39 = "ns31\.mayashopping\.net" ascii wide nocase
        $domain40 = "online\.softupdate-online\.top" ascii wide nocase
        $domain41 = "os\.microsoft-support\.net" ascii wide nocase
        $domain42 = "search\.ibmlotus\.net" ascii wide nocase
        $domain43 = "snn1\.mhysl\.org" ascii wide nocase
        $domain44 = "snn2\.mhysl\.org" ascii wide nocase
        $domain45 = "snn3\.mhysl\.org" ascii wide nocase
        $domain46 = "softupdate-online\.top" ascii wide nocase
        $domain47 = "ssl\.mcafee-upgrade\.com" ascii wide nocase
        $domain48 = "static\.mhysl\.org" ascii wide nocase
        $domain49 = "test\.mcafee-upgrade\.com" ascii wide nocase
        $ip50 = "115.144.122.8" ascii wide
        $ip51 = "45.91.24.73" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_CHARMINGKITTEN
{
    meta:
        description = "Detects IOCs associated with APT CHARMINGKITTEN"
        author = "APTtrail Automated Collection"
        apt_group = "CHARMINGKITTEN"
        aliases = "ajax security team, apt-c-51, apt35"
        reference = "http://researchcenter.paloaltonetworks.com/2017/02/unit42-magic-hound-campaign-attacks-saudi-targets/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "012mail-net-uwclogin\.ml" ascii wide nocase
        $domain1 = "0brandaeyes0\.xyz" ascii wide nocase
        $domain2 = "0standavalue0\.xyz" ascii wide nocase
        $domain3 = "0storageatools0\.xyz" ascii wide nocase
        $domain4 = "1drv\.casa" ascii wide nocase
        $domain5 = "1drv\.cyou" ascii wide nocase
        $domain6 = "1drv\.icu" ascii wide nocase
        $domain7 = "1drv\.live" ascii wide nocase
        $domain8 = "1drv\.online" ascii wide nocase
        $domain9 = "1drv\.surf" ascii wide nocase
        $domain10 = "1drv\.xyz" ascii wide nocase
        $domain11 = "1stemployer\.com" ascii wide nocase
        $domain12 = "3dauth\.live" ascii wide nocase
        $domain13 = "3dconfirrnation\.com" ascii wide nocase
        $domain14 = "8ghefkwdvbfdsg3asdf1\.com" ascii wide nocase
        $domain15 = "academy-update\.com" ascii wide nocase
        $domain16 = "accesscheckout\.online" ascii wide nocase
        $domain17 = "accessverification\.online" ascii wide nocase
        $domain18 = "acconut-signin\.com" ascii wide nocase
        $domain19 = "acconut-verify\.com" ascii wide nocase
        $domain20 = "account-customerservice\.com" ascii wide nocase
        $domain21 = "account-drive\.com" ascii wide nocase
        $domain22 = "account-dropbox\.net" ascii wide nocase
        $domain23 = "account-google\.co" ascii wide nocase
        $domain24 = "account-log-user-verify-mail\.com" ascii wide nocase
        $domain25 = "account-login\.net" ascii wide nocase
        $domain26 = "account-logins\.com" ascii wide nocase
        $domain27 = "account-permission-mail-user\.com" ascii wide nocase
        $domain28 = "account-profile-users\.info" ascii wide nocase
        $domain29 = "account-servicemanagement\.info" ascii wide nocase
        $domain30 = "account-servicerecovery\.com" ascii wide nocase
        $domain31 = "account-servieemanagement\.info" ascii wide nocase
        $domain32 = "account-signin-myaccount-users\.ga" ascii wide nocase
        $domain33 = "account-signin\.com" ascii wide nocase
        $domain34 = "account-siqnin\.com" ascii wide nocase
        $domain35 = "account-support-user\.com" ascii wide nocase
        $domain36 = "account-user-permission-account\.com" ascii wide nocase
        $domain37 = "account-user-verify-mail\.com" ascii wide nocase
        $domain38 = "account-user\.com" ascii wide nocase
        $domain39 = "account-users-mail\.com" ascii wide nocase
        $domain40 = "account-verifiy\.net" ascii wide nocase
        $domain41 = "accounts-apple\.com" ascii wide nocase
        $domain42 = "accounts-drive\.com" ascii wide nocase
        $domain43 = "accounts-googelmail\.com" ascii wide nocase
        $domain44 = "accounts-googelmails\.com" ascii wide nocase
        $domain45 = "accounts-logins\.net" ascii wide nocase
        $domain46 = "accounts-mails\.com" ascii wide nocase
        $domain47 = "accounts-manager\.info" ascii wide nocase
        $domain48 = "accounts-service\.support" ascii wide nocase
        $domain49 = "accounts-support\.services" ascii wide nocase
        $ip50 = "136.243.108.10" ascii wide
        $ip51 = "136.243.108.10" ascii wide
        $ip52 = "136.243.108.10" ascii wide
        $ip53 = "136.243.108.10" ascii wide
        $ip54 = "136.243.108.10" ascii wide
        $ip55 = "136.243.108.10" ascii wide
        $ip56 = "136.243.108.10" ascii wide
        $ip57 = "136.243.108.10" ascii wide
        $ip58 = "136.243.108.10" ascii wide
        $ip59 = "136.243.108.11" ascii wide
        $ip60 = "136.243.108.11" ascii wide
        $ip61 = "136.243.108.11" ascii wide
        $ip62 = "136.243.108.11" ascii wide
        $ip63 = "136.243.108.11" ascii wide
        $ip64 = "136.243.108.11" ascii wide
        $ip65 = "136.243.108.11" ascii wide
        $ip66 = "136.243.108.11" ascii wide
        $ip67 = "136.243.108.11" ascii wide
        $ip68 = "136.243.108.12" ascii wide
        $ip69 = "136.243.108.12" ascii wide
        $ip70 = "136.243.108.12" ascii wide
        $ip71 = "136.243.108.12" ascii wide
        $ip72 = "136.243.108.12" ascii wide
        $ip73 = "136.243.108.12" ascii wide
        $ip74 = "136.243.108.12" ascii wide
        $ip75 = "136.243.108.12" ascii wide
        $ip76 = "136.243.108.12" ascii wide
        $ip77 = "136.243.108.13" ascii wide
        $ip78 = "136.243.108.13" ascii wide
        $ip79 = "136.243.108.13" ascii wide
        $url80 = "/t/ruleset-update-summary-2024-05-06-v10590/1615" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_CLEAVER
{
    meta:
        description = "Detects IOCs associated with APT CLEAVER"
        author = "APTtrail Automated Collection"
        apt_group = "CLEAVER"
        reference = "http://www.cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "doosan-job\.com" ascii wide nocase
        $domain1 = "downloadsservers\.com" ascii wide nocase
        $domain2 = "drivercenterupdate\.com" ascii wide nocase
        $domain3 = "easyresumecreatorpro\.com" ascii wide nocase
        $domain4 = "googleproductupdate\.net" ascii wide nocase
        $domain5 = "microsoftmiddleast\.com" ascii wide nocase
        $domain6 = "microsoftserverupdate\.com" ascii wide nocase
        $domain7 = "microsoftwindowsresources\.com" ascii wide nocase
        $domain8 = "microsoftwindowsupdate\.net" ascii wide nocase
        $domain9 = "northropgrumman\.net" ascii wide nocase
        $domain10 = "teledyne-jobs\.com" ascii wide nocase
        $domain11 = "windowscentralupdate\.com" ascii wide nocase
        $domain12 = "windowssecurityupdate\.com" ascii wide nocase
        $domain13 = "windowsserverupdate\.com" ascii wide nocase
        $domain14 = "windowsupdateserver\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_CLOUDATLAS
{
    meta:
        description = "Detects IOCs associated with APT CLOUDATLAS"
        author = "APTtrail Automated Collection"
        apt_group = "CLOUDATLAS"
        aliases = "APT-LY-1007, CloudFall, CyrillicRAT"
        reference = "https://app.any.run/tasks/094820ce-042b-435f-9ce2-2d65c539dafd/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "2020-windows\.com" ascii wide nocase
        $domain1 = "advancestore\.workers\.dev" ascii wide nocase
        $domain2 = "agent-group\.org" ascii wide nocase
        $domain3 = "api-help\.com" ascii wide nocase
        $domain4 = "api\.office365online\.workers\.dev" ascii wide nocase
        $domain5 = "archive-downloader\.com" ascii wide nocase
        $domain6 = "asia\.office365-cloud\.workers\.dev" ascii wide nocase
        $domain7 = "avito-service\.net" ascii wide nocase
        $domain8 = "azureblog\.info" ascii wide nocase
        $domain9 = "becloud\.website" ascii wide nocase
        $domain10 = "blackberry-support\.herokuapp\.com" ascii wide nocase
        $domain11 = "brexitimpact\.com" ascii wide nocase
        $domain12 = "checklicensekey\.com" ascii wide nocase
        $domain13 = "cloud\.archive-downloader\.com" ascii wide nocase
        $domain14 = "cloud\.digitalstorage\.workers\.dev" ascii wide nocase
        $domain15 = "comparelicense\.com" ascii wide nocase
        $domain16 = "content-protect\.net" ascii wide nocase
        $domain17 = "control-issue\.net" ascii wide nocase
        $domain18 = "cortanaupdater\.info" ascii wide nocase
        $domain19 = "curly-waterfall-360d\.fetrikekke531\.workers\.dev" ascii wide nocase
        $domain20 = "dc-microsoft\.workers\.dev" ascii wide nocase
        $domain21 = "desktoppreview\.com" ascii wide nocase
        $domain22 = "digitalstorage\.workers\.dev" ascii wide nocase
        $domain23 = "doc-fid\.com" ascii wide nocase
        $domain24 = "documents\.publicserver\.workers\.dev" ascii wide nocase
        $domain25 = "driver-key\.com" ascii wide nocase
        $domain26 = "driver-updated\.com" ascii wide nocase
        $domain27 = "driversolution\.net" ascii wide nocase
        $domain28 = "e-aks\.uz" ascii wide nocase
        $domain29 = "e-government-pk\.com" ascii wide nocase
        $domain30 = "e-govoffice\.com" ascii wide nocase
        $domain31 = "ecolines\.es" ascii wide nocase
        $domain32 = "eu\.microsoft-365\.workers\.dev" ascii wide nocase
        $domain33 = "eurasia-research\.org" ascii wide nocase
        $domain34 = "exactsynchtime\.ru" ascii wide nocase
        $domain35 = "falling-haze-1812\.jerkufetra754\.workers\.dev" ascii wide nocase
        $domain36 = "falling-haze-1813\.jerkufetra754\.workers\.dev" ascii wide nocase
        $domain37 = "fatobara\.com" ascii wide nocase
        $domain38 = "fetrikekke531\.workers\.dev" ascii wide nocase
        $domain39 = "fmsru\.ru" ascii wide nocase
        $domain40 = "get-news-online\.com" ascii wide nocase
        $domain41 = "gettemplate\.org" ascii wide nocase
        $domain42 = "gimnazija\.org" ascii wide nocase
        $domain43 = "gmocloudhosting\.com" ascii wide nocase
        $domain44 = "gosportal\.net" ascii wide nocase
        $domain45 = "haarmannsi\.cz" ascii wide nocase
        $domain46 = "host-tools\.net" ascii wide nocase
        $domain47 = "http-updater\.hs\.vc" ascii wide nocase
        $domain48 = "infovesty\.ru" ascii wide nocase
        $domain49 = "interior-gov\.com" ascii wide nocase
        $ip50 = "168.100.11.142" ascii wide
        $ip51 = "185.252.147.12" ascii wide
        $ip52 = "185.252.147.12" ascii wide
        $ip53 = "185.252.147.12" ascii wide
        $ip54 = "5.252.179.45" ascii wide
        $url55 = "/appalcanedentrecentlyconvergenting\.png" ascii wide nocase
        $url56 = "/soarnegroidmeanalkydapresowntipslushing\.png" ascii wide nocase
        $url57 = "/appalcanedentrecentlyconvergenting\.png" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_CLOUDWIZARD
{
    meta:
        description = "Detects IOCs associated with APT CLOUDWIZARD"
        author = "APTtrail Automated Collection"
        apt_group = "CLOUDWIZARD"
        reference = "https://securelist.com/cloudwizard-apt/109722/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "curveroad\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_COBALTDICKENS
{
    meta:
        description = "Detects IOCs associated with APT COBALTDICKENS"
        author = "APTtrail Automated Collection"
        apt_group = "COBALTDICKENS"
        aliases = "cobalt dickens, mabna institute, silent librarian"
        reference = "https://blog.malwarebytes.com/malwarebytes-news/2020/10/silent-librarian-apt-phishing-attack/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "12st\.me" ascii wide nocase
        $domain1 = "12xb\.me" ascii wide nocase
        $domain2 = "1edu\.in" ascii wide nocase
        $domain3 = "1ezpro\.xyz" ascii wide nocase
        $domain4 = "1r3o\.me" ascii wide nocase
        $domain5 = "28ag\.me" ascii wide nocase
        $domain6 = "32ex\.me" ascii wide nocase
        $domain7 = "33qa\.me" ascii wide nocase
        $domain8 = "67vr\.me" ascii wide nocase
        $domain9 = "67yt\.me" ascii wide nocase
        $domain10 = "ac\.uk\.libte\.me" ascii wide nocase
        $domain11 = "aclib\.me" ascii wide nocase
        $domain12 = "acuk\.me" ascii wide nocase
        $domain13 = "adfs\.goucher\.adui\.me" ascii wide nocase
        $domain14 = "adfs\.goucher\.elru\.me" ascii wide nocase
        $domain15 = "adfs\.goucher\.pdlu\.me" ascii wide nocase
        $domain16 = "adfs\.goucher\.unde\.me" ascii wide nocase
        $domain17 = "adfs\.lincoln\.ac\.uk\.itlib\.me" ascii wide nocase
        $domain18 = "adui\.me" ascii wide nocase
        $domain19 = "aill\.cf" ascii wide nocase
        $domain20 = "aill\.nl" ascii wide nocase
        $domain21 = "allib\.me" ascii wide nocase
        $domain22 = "anvc\.me" ascii wide nocase
        $domain23 = "aroe\.me" ascii wide nocase
        $domain24 = "asoec\.me" ascii wide nocase
        $domain25 = "atll\.tk" ascii wide nocase
        $domain26 = "atna\.cf" ascii wide nocase
        $domain27 = "atti\.cf" ascii wide nocase
        $domain28 = "auth\.bath\.ac\.uk\.ctit\.cf" ascii wide nocase
        $domain29 = "auth\.bath\.ac\.uk\.ctit\.tk" ascii wide nocase
        $domain30 = "auth\.bath\.ac\.uk\.ncev\.me" ascii wide nocase
        $domain31 = "auth\.bath\.ac\.uk\.titt\.ml" ascii wide nocase
        $domain32 = "auth\.bath\.ac\.uk\.ukns\.me" ascii wide nocase
        $domain33 = "auth\.bath\.ac\.uk\.ztit\.cf" ascii wide nocase
        $domain34 = "auth\.miamioh\.eduo\.me" ascii wide nocase
        $domain35 = "avne\.me" ascii wide nocase
        $domain36 = "azll\.cf" ascii wide nocase
        $domain37 = "azll\.tk" ascii wide nocase
        $domain38 = "azlll\.cf" ascii wide nocase
        $domain39 = "aztt\.tk" ascii wide nocase
        $domain40 = "balamand\.edu\.lb\.ezlibin\.com" ascii wide nocase
        $domain41 = "bath\.ac\.uk\.ncev\.me" ascii wide nocase
        $domain42 = "bcfk\.me" ascii wide nocase
        $domain43 = "bdhw\.me" ascii wide nocase
        $domain44 = "bib\.mdh\.se\.ezlibin\.com" ascii wide nocase
        $domain45 = "bib\.mdh\.se\.libinpro\.xyz" ascii wide nocase
        $domain46 = "bidi\.uam\.mx\.logezpro\.xyz" ascii wide nocase
        $domain47 = "blackboard\.gcal\.crev\.me" ascii wide nocase
        $domain48 = "blackboard\.stonybrook\.ernn\.me" ascii wide nocase
        $domain49 = "blackboard\.stonybrook\.nrni\.me" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_CODOSO
{
    meta:
        description = "Detects IOCs associated with APT CODOSO"
        author = "APTtrail Automated Collection"
        apt_group = "CODOSO"
        aliases = "apt19, c0d0so0, codoso"
        reference = "https://attack.mitre.org/wiki/Group/G0009"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "EmpireB1ue\.com" ascii wide nocase
        $domain1 = "ameteksen\.com" ascii wide nocase
        $domain2 = "asconline\.we11point\.com" ascii wide nocase
        $domain3 = "assso\.net" ascii wide nocase
        $domain4 = "autodiscover\.2bunny\.com" ascii wide nocase
        $domain5 = "b\.gnisoft\.com" ascii wide nocase
        $domain6 = "capstoneturbine\.cechire\.com" ascii wide nocase
        $domain7 = "caref1rst\.com" ascii wide nocase
        $domain8 = "careflrst\.com" ascii wide nocase
        $domain9 = "client\.gnisoft\.com" ascii wide nocase
        $domain10 = "extcitrix\.we11point\.com" ascii wide nocase
        $domain11 = "facefuture\.us" ascii wide nocase
        $domain12 = "gifas\.blogsite\.org" ascii wide nocase
        $domain13 = "gifas\.cechire\.com" ascii wide nocase
        $domain14 = "giga\.gnisoft\.com" ascii wide nocase
        $domain15 = "gnisoft\.com" ascii wide nocase
        $domain16 = "google-dash\.com" ascii wide nocase
        $domain17 = "googlewebcache\.com" ascii wide nocase
        $domain18 = "healthslie\.com" ascii wide nocase
        $domain19 = "hrsolutions\.we11point\.com" ascii wide nocase
        $domain20 = "icbcqsz\.com" ascii wide nocase
        $domain21 = "images\.googlewebcache\.com" ascii wide nocase
        $domain22 = "jbossas\.org" ascii wide nocase
        $domain23 = "kaspersyk\.com" ascii wide nocase
        $domain24 = "lyncdiscover\.2bunny\.com" ascii wide nocase
        $domain25 = "me\.we11point\.com" ascii wide nocase
        $domain26 = "microsoft-cache\.com" ascii wide nocase
        $domain27 = "mycitrix\.we11point\.com" ascii wide nocase
        $domain28 = "myhr\.we11point\.com" ascii wide nocase
        $domain29 = "oa\.ameteksen\.com" ascii wide nocase
        $domain30 = "oa\.technical-requre\.com" ascii wide nocase
        $domain31 = "oa\.trustneser\.com" ascii wide nocase
        $domain32 = "outlookssl\.com" ascii wide nocase
        $domain33 = "polarroute\.com" ascii wide nocase
        $domain34 = "prennera\.com" ascii wide nocase
        $domain35 = "savmpet\.com" ascii wide nocase
        $domain36 = "sfo02s01-in-f2\.cloudsend\.net" ascii wide nocase
        $domain37 = "sharepoint-vaeit\.com" ascii wide nocase
        $domain38 = "sinmoung\.com" ascii wide nocase
        $domain39 = "smi1egate\.com" ascii wide nocase
        $domain40 = "smtp\.outlookssl\.com" ascii wide nocase
        $domain41 = "ssl-vaeit\.com" ascii wide nocase
        $domain42 = "ssl-vait\.com" ascii wide nocase
        $domain43 = "supermanbox\.org" ascii wide nocase
        $domain44 = "svn1\.smi1egate\.com" ascii wide nocase
        $domain45 = "tk-in-f156\.2bunny\.com" ascii wide nocase
        $domain46 = "topsec2014\.com" ascii wide nocase
        $domain47 = "vipreclod\.com" ascii wide nocase
        $domain48 = "vpn\.we11point\.com" ascii wide nocase
        $domain49 = "vpn2\.smi1egate\.com" ascii wide nocase
        $ip50 = "104.223.34.198" ascii wide
        $ip51 = "192.95.36.61" ascii wide
        $url52 = "/user/atv\.html" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_COLDRIVER
{
    meta:
        description = "Detects IOCs associated with APT COLDRIVER"
        author = "APTtrail Automated Collection"
        apt_group = "COLDRIVER"
        aliases = "baitswitch, calisto, lostkeys"
        reference = "https://app.validin.com/detail?find=82.221.139.160&type=ip4&ref_id=850ab70d5c4#tab=resolutions"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "access-confirmation\.com" ascii wide nocase
        $domain1 = "accounts-ukr\.com" ascii wide nocase
        $domain2 = "accounts\.hypertexttech\.com" ascii wide nocase
        $domain3 = "accounts\.kv-ukr\.net" ascii wide nocase
        $domain4 = "accounts\.ukr-mails\.net" ascii wide nocase
        $domain5 = "accounts\.ukr-reset\.email" ascii wide nocase
        $domain6 = "accsua\.com" ascii wide nocase
        $domain7 = "accsukr\.com" ascii wide nocase
        $domain8 = "alightcruellane\.net" ascii wide nocase
        $domain9 = "allow-access\.com" ascii wide nocase
        $domain10 = "ankaramuhaseben\.com" ascii wide nocase
        $domain11 = "antibots-service\.com" ascii wide nocase
        $domain12 = "apicomcloud\.com" ascii wide nocase
        $domain13 = "app-sharcpoint\.com" ascii wide nocase
        $domain14 = "app-sharcpointe\.com" ascii wide nocase
        $domain15 = "app-sharcpolnt\.com" ascii wide nocase
        $domain16 = "app-sharcpolnte\.com" ascii wide nocase
        $domain17 = "applicationformsubmit\.me" ascii wide nocase
        $domain18 = "appsharcpointe\.com" ascii wide nocase
        $domain19 = "appsharcpointes\.com" ascii wide nocase
        $domain20 = "appssharcpointe\.com" ascii wide nocase
        $domain21 = "as-mvd\.ru" ascii wide nocase
        $domain22 = "attach-docs\.com" ascii wide nocase
        $domain23 = "attach-update\.com" ascii wide nocase
        $domain24 = "bigdatabroadway\.com" ascii wide nocase
        $domain25 = "bittechllc\.net" ascii wide nocase
        $domain26 = "blintepeeste\.org" ascii wide nocase
        $domain27 = "blueskynetwork-drive\.com" ascii wide nocase
        $domain28 = "blueskynetwork-shared\.com" ascii wide nocase
        $domain29 = "botguard-checker\.com" ascii wide nocase
        $domain30 = "botguard-web\.com" ascii wide nocase
        $domain31 = "cache-dns-forwarding\.com" ascii wide nocase
        $domain32 = "cache-dns-preview\.com" ascii wide nocase
        $domain33 = "cache-dns\.com" ascii wide nocase
        $domain34 = "cache-docs\.com" ascii wide nocase
        $domain35 = "cache-pdf\.com" ascii wide nocase
        $domain36 = "cache-pdf\.online" ascii wide nocase
        $domain37 = "cache-services\.live" ascii wide nocase
        $domain38 = "captchanom\.top" ascii wide nocase
        $domain39 = "centeritdefcity\.com" ascii wide nocase
        $domain40 = "challenge-identifier\.com" ascii wide nocase
        $domain41 = "challenge-share\.com" ascii wide nocase
        $domain42 = "changepassword-ukr\.net" ascii wide nocase
        $domain43 = "checker-bot\.com" ascii wide nocase
        $domain44 = "checkscreenit\.com" ascii wide nocase
        $domain45 = "cija-docs\.com" ascii wide nocase
        $domain46 = "cija-drive\.com" ascii wide nocase
        $domain47 = "cityessentials\.net" ascii wide nocase
        $domain48 = "client-serviceauth0\.com" ascii wide nocase
        $domain49 = "cloud-docs\.com" ascii wide nocase
        $ip50 = "45.133.216.15" ascii wide
        $ip51 = "89.19.211.240" ascii wide
        $ip52 = "95.164.17.94" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_COLDWASTREL
{
    meta:
        description = "Detects IOCs associated with APT COLDWASTREL"
        author = "APTtrail Automated Collection"
        apt_group = "COLDWASTREL"
        reference = "https://app.validin.com/detail?find=38.180.18.59&type=ip4&ref_id=3160b1058e5#tab=resolutions"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "account-api\.cloudstorageservice\.online" ascii wide nocase
        $domain1 = "account-api\.onlinestorageroute\.space" ascii wide nocase
        $domain2 = "account-api\.protondrive\.online" ascii wide nocase
        $domain3 = "account\.email-pm\.me" ascii wide nocase
        $domain4 = "account\.onlinestorageroute\.space" ascii wide nocase
        $domain5 = "account\.open-button\.com" ascii wide nocase
        $domain6 = "account\.proton-drive\.me" ascii wide nocase
        $domain7 = "account\.proton-service\.services" ascii wide nocase
        $domain8 = "account\.proton-verify\.me" ascii wide nocase
        $domain9 = "account\.proton\.shared-urls\.me" ascii wide nocase
        $domain10 = "account\.protondrive\.cloud" ascii wide nocase
        $domain11 = "account\.protondrive\.online" ascii wide nocase
        $domain12 = "account\.protondrive\.onlinestorageroute\.space" ascii wide nocase
        $domain13 = "account\.protondrive\.services" ascii wide nocase
        $domain14 = "account\.secure-pm\.me" ascii wide nocase
        $domain15 = "account\.service-pm\.me" ascii wide nocase
        $domain16 = "account\.service-proton\.com" ascii wide nocase
        $domain17 = "account\.service-proton\.me" ascii wide nocase
        $domain18 = "account\.services-proton\.me" ascii wide nocase
        $domain19 = "accounts-proton\.me" ascii wide nocase
        $domain20 = "accounts\.support-ukr\.net" ascii wide nocase
        $domain21 = "center-facebook\.com" ascii wide nocase
        $domain22 = "civic-synergy\.online" ascii wide nocase
        $domain23 = "cloudstorageservice\.online" ascii wide nocase
        $domain24 = "decryptor\.me" ascii wide nocase
        $domain25 = "desktop-facebook\.com" ascii wide nocase
        $domain26 = "document-decryption\.me" ascii wide nocase
        $domain27 = "drive-proton\.com" ascii wide nocase
        $domain28 = "drive\.link-pm\.me" ascii wide nocase
        $domain29 = "drive\.proton-verify\.me" ascii wide nocase
        $domain30 = "drive\.proton\.decryptor\.me" ascii wide nocase
        $domain31 = "drive\.proton\.filestorage\.me" ascii wide nocase
        $domain32 = "drive\.proton\.shared-urls\.me" ascii wide nocase
        $domain33 = "drive\.secure-pm\.me" ascii wide nocase
        $domain34 = "drive\.service-pm\.me" ascii wide nocase
        $domain35 = "drive\.service-proton\.me" ascii wide nocase
        $domain36 = "driveproton\.me" ascii wide nocase
        $domain37 = "driveshare\.me" ascii wide nocase
        $domain38 = "edisk\.support-ukr\.net" ascii wide nocase
        $domain39 = "email-pm\.me" ascii wide nocase
        $domain40 = "email-ukr\.net" ascii wide nocase
        $domain41 = "email\.support-ukr\.net" ascii wide nocase
        $domain42 = "en-us\.center-facebook\.com" ascii wide nocase
        $domain43 = "en-us\.desktop-facebook\.com" ascii wide nocase
        $domain44 = "fb-me\.com" ascii wide nocase
        $domain45 = "fidh\.tech" ascii wide nocase
        $domain46 = "filestorage\.me" ascii wide nocase
        $domain47 = "fr-fr\.center-facebook\.com" ascii wide nocase
        $domain48 = "h\.maiils\.com" ascii wide nocase
        $domain49 = "link-pm\.me" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_COMMENTCREW
{
    meta:
        description = "Detects IOCs associated with APT COMMENTCREW"
        author = "APTtrail Automated Collection"
        apt_group = "COMMENTCREW"
        reference = "http://www.secureworks.com/cyber-threat-intelligence/threats/htran/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "08elec\.purpledaily\.com" ascii wide nocase
        $domain1 = "09back\.purpledaily\.com" ascii wide nocase
        $domain2 = "3ml\.infosupports\.com" ascii wide nocase
        $domain3 = "3pma\.firefoxupdata\.com" ascii wide nocase
        $domain4 = "4cback\.hugesoft\.org" ascii wide nocase
        $domain5 = "7cback\.hugesoft\.org" ascii wide nocase
        $domain6 = "911\.cnnnewsdaily\.com" ascii wide nocase
        $domain7 = "a-ad\.arrowservice\.net" ascii wide nocase
        $domain8 = "a-af\.arrowservice\.net" ascii wide nocase
        $domain9 = "a-bne\.arrowservice\.net" ascii wide nocase
        $domain10 = "a-co\.purpledaily\.com" ascii wide nocase
        $domain11 = "a-dl\.arrowservice\.net" ascii wide nocase
        $domain12 = "a-ec\.businessconsults\.net" ascii wide nocase
        $domain13 = "a-ep\.arrowservice\.net" ascii wide nocase
        $domain14 = "a-ex\.arrowservice\.net" ascii wide nocase
        $domain15 = "a-fj\.purpledaily\.com" ascii wide nocase
        $domain16 = "a-ga\.purpledaily\.com" ascii wide nocase
        $domain17 = "a-gon\.arrowservice\.net" ascii wide nocase
        $domain18 = "a-he\.arrowservice\.net" ascii wide nocase
        $domain19 = "a-he\.softsolutionbox\.net" ascii wide nocase
        $domain20 = "a-if\.arrowservice\.net" ascii wide nocase
        $domain21 = "a-iho\.arrowservice\.net" ascii wide nocase
        $domain22 = "a-ja\.purpledaily\.com" ascii wide nocase
        $domain23 = "a-jsm\.arrowservice\.net" ascii wide nocase
        $domain24 = "a-jsm\.infobusinessus\.org" ascii wide nocase
        $domain25 = "a-ol\.arrowservice\.net" ascii wide nocase
        $domain26 = "a-ov\.businessconsults\.net" ascii wide nocase
        $domain27 = "a-pep\.arrowservice\.net" ascii wide nocase
        $domain28 = "a-rdr\.arrowservice\.net" ascii wide nocase
        $domain29 = "a-ri\.comrepair\.net" ascii wide nocase
        $domain30 = "a-uac\.arrowservice\.net" ascii wide nocase
        $domain31 = "a-un\.purpledaily\.com" ascii wide nocase
        $domain32 = "a-za\.arrowservice\.net" ascii wide nocase
        $domain33 = "a-za\.businessconsults\.net" ascii wide nocase
        $domain34 = "a-zx\.purpledaily\.com" ascii wide nocase
        $domain35 = "aam\.businessconsults\.net" ascii wide nocase
        $domain36 = "aar\.bigdepression\.net" ascii wide nocase
        $domain37 = "aarco\.bigdepression\.net" ascii wide nocase
        $domain38 = "abs\.businessconsults\.net" ascii wide nocase
        $domain39 = "acer\.firefoxupdata\.com" ascii wide nocase
        $domain40 = "acli-mail\.businessconsults\.net" ascii wide nocase
        $domain41 = "acu\.businessconsults\.net" ascii wide nocase
        $domain42 = "adb\.businessconsults\.net" ascii wide nocase
        $domain43 = "add\.infosupports\.com" ascii wide nocase
        $domain44 = "addr\.infosupports\.com" ascii wide nocase
        $domain45 = "adi002\.hugesoft\.org" ascii wide nocase
        $domain46 = "admin\.arrowservice\.net" ascii wide nocase
        $domain47 = "admin\.datastorage01\.org" ascii wide nocase
        $domain48 = "admin\.firefoxupdata\.com" ascii wide nocase
        $domain49 = "admin\.softsolutionbox\.net" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_COPYKITTENS
{
    meta:
        description = "Detects IOCs associated with APT COPYKITTENS"
        author = "APTtrail Automated Collection"
        apt_group = "COPYKITTENS"
        reference = "https://s3-eu-west-1.amazonaws.com/minervaresearchpublic/CopyKittens/CopyKittens.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "alhadath\.mobi" ascii wide nocase
        $domain1 = "big-windowss\.com" ascii wide nocase
        $domain2 = "cacheupdate14\.com" ascii wide nocase
        $domain3 = "fbstatic-a\.space" ascii wide nocase
        $domain4 = "fbstatic-a\.xyz" ascii wide nocase
        $domain5 = "fbstatic-akamaihd\.com" ascii wide nocase
        $domain6 = "gmailtagmanager\.com" ascii wide nocase
        $domain7 = "haaretz-news\.com" ascii wide nocase
        $domain8 = "haaretz\.link" ascii wide nocase
        $domain9 = "heartax\.info" ascii wide nocase
        $domain10 = "kernel4windows\.in" ascii wide nocase
        $domain11 = "micro-windows\.in" ascii wide nocase
        $domain12 = "mswordupdate15\.com" ascii wide nocase
        $domain13 = "mswordupdate16\.com" ascii wide nocase
        $domain14 = "mswordupdate17\.com" ascii wide nocase
        $domain15 = "mywindows24\.in" ascii wide nocase
        $domain16 = "patch7-windows\.com" ascii wide nocase
        $domain17 = "patch8-windows\.com" ascii wide nocase
        $domain18 = "patchthiswindows\.com" ascii wide nocase
        $domain19 = "walla\.link" ascii wide nocase
        $domain20 = "wethearservice\.com" ascii wide nocase
        $domain21 = "wheatherserviceapi\.info" ascii wide nocase
        $domain22 = "windowkernel\.com" ascii wide nocase
        $domain23 = "windows-10patch\.in" ascii wide nocase
        $domain24 = "windows-drive20\.com" ascii wide nocase
        $domain25 = "windows-india\.in" ascii wide nocase
        $domain26 = "windows-kernel\.in" ascii wide nocase
        $domain27 = "windows-my50\.com" ascii wide nocase
        $domain28 = "windows24-kernel\.in" ascii wide nocase
        $domain29 = "windowskernel\.in" ascii wide nocase
        $domain30 = "windowskernel14\.com" ascii wide nocase
        $domain31 = "windowslayer\.in" ascii wide nocase
        $domain32 = "windowssup\.in" ascii wide nocase
        $domain33 = "windowsupup\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_COSMICDUKE
{
    meta:
        description = "Detects IOCs associated with APT COSMICDUKE"
        author = "APTtrail Automated Collection"
        apt_group = "COSMICDUKE"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "dukehole\.me" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_CRIMSONCOLLECTIVE
{
    meta:
        description = "Detects IOCs associated with APT CRIMSONCOLLECTIVE"
        author = "APTtrail Automated Collection"
        apt_group = "CRIMSONCOLLECTIVE"
        aliases = "crimson collective"
        reference = "https://www.rapid7.com/blog/post/tr-crimson-collective-a-new-threat-group-observed-operating-in-the-cloud/"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "195.201.175.210" ascii wide
        $ip1 = "3.215.23.185" ascii wide
        $ip2 = "3.215.23.185" ascii wide
        $ip3 = "45.148.10.141" ascii wide
        $ip4 = "45.148.10.141" ascii wide
        $ip5 = "5.9.108.250" ascii wide
        $ip6 = "5.9.108.250" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_CYBERAV3NGERS
{
    meta:
        description = "Detects IOCs associated with APT CYBERAV3NGERS"
        author = "APTtrail Automated Collection"
        apt_group = "CYBERAV3NGERS"
        aliases = "iocontrol"
        reference = "https://claroty.com/team82/research/inside-a-new-ot-iot-cyber-weapon-iocontrol"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "ocferda\.com" ascii wide nocase
        $domain1 = "tylarion867mino\.com" ascii wide nocase
        $domain2 = "uuokhhfsdlk\.tylarion867mino\.com" ascii wide nocase
        $ip3 = "159.100.6.69" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_CYBERBIT
{
    meta:
        description = "Detects IOCs associated with APT CYBERBIT"
        author = "APTtrail Automated Collection"
        apt_group = "CYBERBIT"
        reference = "https://citizenlab.ca/2017/12/champing-cyberbit-ethiopian-dissidents-targeted-commercial-spyware/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "cd-media4u\.com" ascii wide nocase
        $domain1 = "diretube\.co\.uk" ascii wide nocase
        $domain2 = "eastafro\.net" ascii wide nocase
        $domain3 = "flashpoint-ip\.com" ascii wide nocase
        $domain4 = "getadobeplayer\.com" ascii wide nocase
        $domain5 = "meskereme\.net" ascii wide nocase
        $domain6 = "nozonenet\.com" ascii wide nocase
        $domain7 = "pnv\.vipnetwork\.fr" ascii wide nocase
        $domain8 = "pupki\.co" ascii wide nocase
        $domain9 = "rdhotel\.uz" ascii wide nocase
        $domain10 = "signalschool\.net" ascii wide nocase
        $domain11 = "thewhistleblowers\.org" ascii wide nocase
        $domain12 = "time-local\.com" ascii wide nocase
        $domain13 = "time-local\.net" ascii wide nocase
        $domain14 = "villepinte2017\.dynu\.net" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_DALBIT
{
    meta:
        description = "Detects IOCs associated with APT DALBIT"
        author = "APTtrail Automated Collection"
        apt_group = "DALBIT"
        aliases = "m00nlight"
        reference = "https://1275.ru/ioc/1401/dalbit-m00nlight-apt-iocs/ (Russian)"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "aa\.zxcss\.com" ascii wide nocase
        $domain1 = "ff\.m00nlight\.top" ascii wide nocase
        $domain2 = "fk\.m00nlight\.top" ascii wide nocase
        $domain3 = "lt\.yxavkb\.xyz" ascii wide nocase
        $domain4 = "m00nlight\.top" ascii wide nocase
        $domain5 = "mod\.m00nlight\.top" ascii wide nocase
        $domain6 = "sk1\.m00nlight\.top" ascii wide nocase
        $domain7 = "yxavkb\.xyz" ascii wide nocase
        $domain8 = "zxcss\.com" ascii wide nocase
        $ip9 = "103.118.42.208" ascii wide
        $ip10 = "175.24.32.228" ascii wide
        $ip11 = "45.136.186.175" ascii wide
        $ip12 = "45.93.28.103" ascii wide
        $ip13 = "45.93.31.75" ascii wide
        $ip14 = "91.217.139.117" ascii wide
        $ip15 = "91.217.139.117" ascii wide
        $ip16 = "91.217.139.117" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_DARKCARACAL
{
    meta:
        description = "Detects IOCs associated with APT DARKCARACAL"
        author = "APTtrail Automated Collection"
        apt_group = "DARKCARACAL"
        reference = "https://info.lookout.com/rs/051-ESQ-475/images/Lookout_Dark-Caracal_srr_20180118_us_v.1.0.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "accountslogin\.services" ascii wide nocase
        $domain1 = "adobe-flashviewer\.accountslogin\.services" ascii wide nocase
        $domain2 = "adobeair\.net" ascii wide nocase
        $domain3 = "adobeinstall\.com" ascii wide nocase
        $domain4 = "ancmax\.com" ascii wide nocase
        $domain5 = "arablivenews\.com" ascii wide nocase
        $domain6 = "arabpublisherslb\.com" ascii wide nocase
        $domain7 = "axroot\.com" ascii wide nocase
        $domain8 = "dropboxonline\.com" ascii wide nocase
        $domain9 = "ecowatchasia\.com" ascii wide nocase
        $domain10 = "etn9\.com" ascii wide nocase
        $domain11 = "fbtweets\.net" ascii wide nocase
        $domain12 = "globalmic\.net" ascii wide nocase
        $domain13 = "gsec\.in" ascii wide nocase
        $domain14 = "iceteapeach\.com" ascii wide nocase
        $domain15 = "jaysonj\.no-ip\.biz" ascii wide nocase
        $domain16 = "kaliex\.net" ascii wide nocase
        $domain17 = "mangoco\.net" ascii wide nocase
        $domain18 = "mecodata\.com" ascii wide nocase
        $domain19 = "megadeb\.com" ascii wide nocase
        $domain20 = "nancyrazzouk\.com" ascii wide nocase
        $domain21 = "nvidiaupdate\.com" ascii wide nocase
        $domain22 = "opwalls\.com" ascii wide nocase
        $domain23 = "orange2015\.net" ascii wide nocase
        $domain24 = "paktest\.ddns\.net" ascii wide nocase
        $domain25 = "planethdx\.com" ascii wide nocase
        $domain26 = "playermea\.com" ascii wide nocase
        $domain27 = "roxsoft\.net" ascii wide nocase
        $domain28 = "sabisint\.com" ascii wide nocase
        $domain29 = "secureandroid\.info" ascii wide nocase
        $domain30 = "skypeservice\.no-ip\.org" ascii wide nocase
        $domain31 = "skypeupdate\.com" ascii wide nocase
        $domain32 = "tenoclock\.net" ascii wide nocase
        $domain33 = "tweetsfb\.com" ascii wide nocase
        $domain34 = "watermelon2017\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_DARKHOTEL
{
    meta:
        description = "Detects IOCs associated with APT DARKHOTEL"
        author = "APTtrail Automated Collection"
        apt_group = "DARKHOTEL"
        aliases = "apt-c-06, apt06, thinmon"
        reference = "http://blog.nsfocus.net/darkhotel-3-0908/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "100100011100\.com" ascii wide nocase
        $domain1 = "163pics\.net" ascii wide nocase
        $domain2 = "163services\.com" ascii wide nocase
        $domain3 = "42world\.net" ascii wide nocase
        $domain4 = "779999977\.com" ascii wide nocase
        $domain5 = "88dafa\.biz" ascii wide nocase
        $domain6 = "academyhouse\.us" ascii wide nocase
        $domain7 = "account163-mail\.com" ascii wide nocase
        $domain8 = "ackr\.myvnc\.com" ascii wide nocase
        $domain9 = "acrobatup\.com" ascii wide nocase
        $domain10 = "adobearm\.com" ascii wide nocase
        $domain11 = "adobeplugs\.net" ascii wide nocase
        $domain12 = "adoberegister\.flashserv\.net" ascii wide nocase
        $domain13 = "adobeupdates\.com" ascii wide nocase
        $domain14 = "albasrostga\.com" ascii wide nocase
        $domain15 = "alexa97\.com" ascii wide nocase
        $domain16 = "alphacranes\.com" ascii wide nocase
        $domain17 = "alphastros\.com" ascii wide nocase
        $domain18 = "amanity50\.biz" ascii wide nocase
        $domain19 = "anti-wars\.org" ascii wide nocase
        $domain20 = "appfreetools\.com" ascii wide nocase
        $domain21 = "apple-onlineservice\.com" ascii wide nocase
        $domain22 = "applyinfo\.org" ascii wide nocase
        $domain23 = "auto2115\.icr38\.net" ascii wide nocase
        $domain24 = "auto2116\.phpnet\.us" ascii wide nocase
        $domain25 = "auto24col\.info" ascii wide nocase
        $domain26 = "autobaba\.net84\.net" ascii wide nocase
        $domain27 = "autoban\.phpnet\.us" ascii wide nocase
        $domain28 = "autobicy\.yaahosting\.info" ascii wide nocase
        $domain29 = "autobicycle\.20x\.cc" ascii wide nocase
        $domain30 = "autobicycle\.freehostking\.com" ascii wide nocase
        $domain31 = "autobicyyyyyy\.50gigs\.net" ascii wide nocase
        $domain32 = "autoblank\.oni\.cc" ascii wide nocase
        $domain33 = "autobrown\.gofreeserve\.com" ascii wide nocase
        $domain34 = "autocargo\.100gbfreehost\.com" ascii wide nocase
        $domain35 = "autocash\.000php\.com" ascii wide nocase
        $domain36 = "autocashhh\.hostmefree\.org" ascii wide nocase
        $domain37 = "autocaze\.crabdance\.com" ascii wide nocase
        $domain38 = "autocheck\.000page\.com" ascii wide nocase
        $domain39 = "autochecker\.myftp\.biz" ascii wide nocase
        $domain40 = "autocracy\.phpnet\.us" ascii wide nocase
        $domain41 = "autocrat\.comuf\.com" ascii wide nocase
        $domain42 = "autodoor\.freebyte\.us" ascii wide nocase
        $domain43 = "autof888com\.20x\.cc" ascii wide nocase
        $domain44 = "autofseven\.freei\.me" ascii wide nocase
        $domain45 = "autogeremys\.com" ascii wide nocase
        $domain46 = "autoinsurance\.000space\.com" ascii wide nocase
        $domain47 = "autojob\.whostas\.com" ascii wide nocase
        $domain48 = "autoken\.scienceontheweb\.net" ascii wide nocase
        $domain49 = "autolace\.twilightparadox\.com" ascii wide nocase
        $ip50 = "193.29.187.178" ascii wide
        $ip51 = "193.29.187.178" ascii wide
        $ip52 = "91.235.116.147" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_DARKHYDRUS
{
    meta:
        description = "Detects IOCs associated with APT DARKHYDRUS"
        author = "APTtrail Automated Collection"
        apt_group = "DARKHYDRUS"
        reference = "https://docs.google.com/document/d/1oYX3uN6KxIX_StzTH0s0yFNNoHDnV8VgmVqU5WoeErc (DarkHydrus 2017 activity)"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "0ffice\.com" ascii wide nocase
        $domain1 = "0ffice365\.agency" ascii wide nocase
        $domain2 = "0ffice365\.life" ascii wide nocase
        $domain3 = "0ffice365\.services" ascii wide nocase
        $domain4 = "0ffiice\.com" ascii wide nocase
        $domain5 = "0nedrive\.agency" ascii wide nocase
        $domain6 = "0utl00k\.net" ascii wide nocase
        $domain7 = "0utlook\.accountant" ascii wide nocase
        $domain8 = "0utlook\.bid" ascii wide nocase
        $domain9 = "akadns\.services" ascii wide nocase
        $domain10 = "akamai\.agency" ascii wide nocase
        $domain11 = "akamaiedge\.live" ascii wide nocase
        $domain12 = "akamaiedge\.services" ascii wide nocase
        $domain13 = "akamaized\.live" ascii wide nocase
        $domain14 = "akdns\.live" ascii wide nocase
        $domain15 = "allexa\.net" ascii wide nocase
        $domain16 = "anyconnect\.stream" ascii wide nocase
        $domain17 = "asimov-win-microsoft\.services" ascii wide nocase
        $domain18 = "asisdns\.space" ascii wide nocase
        $domain19 = "asismdnu\.asisdns\.space" ascii wide nocase
        $domain20 = "azureedge\.today" ascii wide nocase
        $domain21 = "bigip\.stream" ascii wide nocase
        $domain22 = "brit\.ns\.cloudfronts\.services" ascii wide nocase
        $domain23 = "britns\.akadns\.live" ascii wide nocase
        $domain24 = "britns\.akadns\.services" ascii wide nocase
        $domain25 = "cisc0\.net" ascii wide nocase
        $domain26 = "citriix\.net" ascii wide nocase
        $domain27 = "cloudfronts\.services" ascii wide nocase
        $domain28 = "corewindows\.agency" ascii wide nocase
        $domain29 = "data-microsoft\.services" ascii wide nocase
        $domain30 = "dns\.cloudfronts\.services" ascii wide nocase
        $domain31 = "edgekey\.live" ascii wide nocase
        $domain32 = "fortiweb\.download" ascii wide nocase
        $domain33 = "gogle\.co" ascii wide nocase
        $domain34 = "iecvlist-microsoft\.live" ascii wide nocase
        $domain35 = "kaspersky\.host" ascii wide nocase
        $domain36 = "kaspersky\.science" ascii wide nocase
        $domain37 = "maccaffe\.com" ascii wide nocase
        $domain38 = "microsoftlab\.ir" ascii wide nocase
        $domain39 = "microsoftonline\.agency" ascii wide nocase
        $domain40 = "microsoftonline\.host" ascii wide nocase
        $domain41 = "microsoftonline\.services" ascii wide nocase
        $domain42 = "microtik\.stream" ascii wide nocase
        $domain43 = "micrrosoft\.net" ascii wide nocase
        $domain44 = "msdncss\.com" ascii wide nocase
        $domain45 = "msdnscripts\.com" ascii wide nocase
        $domain46 = "ns1\.microsoftlab\.ir" ascii wide nocase
        $domain47 = "ns102\.kaspersky\.host" ascii wide nocase
        $domain48 = "ns103\.kaspersky\.host" ascii wide nocase
        $domain49 = "ns2\.akadns\.live" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_DARKPINK
{
    meta:
        description = "Detects IOCs associated with APT DARKPINK"
        author = "APTtrail Automated Collection"
        apt_group = "DARKPINK"
        reference = "https://www.group-ib.com/blog/dark-pink-apt/"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "176.10.80.38" ascii wide

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_DARKRIVER
{
    meta:
        description = "Detects IOCs associated with APT DARKRIVER"
        author = "APTtrail Automated Collection"
        apt_group = "DARKRIVER"
        aliases = "matadoor"
        reference = "https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/dark-river-you-can-t-see-them-but-they-re-there/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "aliveyelp\.com" ascii wide nocase
        $domain1 = "bestandgood\.com" ascii wide nocase
        $domain2 = "bettertimator\.com" ascii wide nocase
        $domain3 = "biowitsg\.com" ascii wide nocase
        $domain4 = "cakeduer\.com" ascii wide nocase
        $domain5 = "cameoonion\.com" ascii wide nocase
        $domain6 = "capetipper\.com" ascii wide nocase
        $domain7 = "casgone\.com" ascii wide nocase
        $domain8 = "cravefool\.com" ascii wide nocase
        $domain9 = "diemonge\.com" ascii wide nocase
        $domain10 = "e5afaya\.com" ascii wide nocase
        $domain11 = "editngo\.com" ascii wide nocase
        $domain12 = "eimvivb\.com" ascii wide nocase
        $domain13 = "endlessutie\.com" ascii wide nocase
        $domain14 = "fetchbring\.com" ascii wide nocase
        $domain15 = "fledscuba\.com" ascii wide nocase
        $domain16 = "flowuboy\.com" ascii wide nocase
        $domain17 = "futureinv-gp\.com" ascii wide nocase
        $domain18 = "ganjabuscoa\.com" ascii wide nocase
        $domain19 = "getmyecoin\.com" ascii wide nocase
        $domain20 = "iemcvv\.com" ascii wide nocase
        $domain21 = "interactive-guides\.com" ascii wide nocase
        $domain22 = "investsportss\.com" ascii wide nocase
        $domain23 = "ipodlasso\.com" ascii wide nocase
        $domain24 = "ismysoulmate\.com" ascii wide nocase
        $domain25 = "justlikeahummer\.com" ascii wide nocase
        $domain26 = "kixthstage\.com" ascii wide nocase
        $domain27 = "merudlement\.com" ascii wide nocase
        $domain28 = "metaversalk\.com" ascii wide nocase
        $domain29 = "mlaycld\.com" ascii wide nocase
        $domain30 = "moveandtry\.com" ascii wide nocase
        $domain31 = "myballmecg\.com" ascii wide nocase
        $domain32 = "nuttyhumid\.com" ascii wide nocase
        $domain33 = "offernewer\.com" ascii wide nocase
        $domain34 = "otopitele\.com" ascii wide nocase
        $domain35 = "outsidenursery\.com" ascii wide nocase
        $domain36 = "primventure\.com" ascii wide nocase
        $domain37 = "pursestout\.com" ascii wide nocase
        $domain38 = "reasonsalt\.com" ascii wide nocase
        $domain39 = "searching4soulmate\.com" ascii wide nocase
        $domain40 = "speclaurp\.com" ascii wide nocase
        $domain41 = "sureyuare\.com" ascii wide nocase
        $domain42 = "tarzoose\.com" ascii wide nocase
        $domain43 = "trendparlye\.com" ascii wide nocase
        $domain44 = "wemobiledauk\.com" ascii wide nocase
        $domain45 = "wharfgold\.com" ascii wide nocase
        $domain46 = "ww12\.flowuboy\.com" ascii wide nocase
        $domain47 = "ww12\.merudlement\.com" ascii wide nocase
        $domain48 = "ww12\.offernewer\.com" ascii wide nocase
        $domain49 = "xdinzky\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_DEADLYKISS
{
    meta:
        description = "Detects IOCs associated with APT DEADLYKISS"
        author = "APTtrail Automated Collection"
        apt_group = "DEADLYKISS"
        reference = "https://blog.telsy.com/wp-content/uploads/2019/09/DeadlyKiss_TAAR.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "orionfile\.com" ascii wide nocase
        $domain1 = "tawaranmurah\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_DEATHSTALKER
{
    meta:
        description = "Detects IOCs associated with APT DEATHSTALKER"
        author = "APTtrail Automated Collection"
        apt_group = "DEATHSTALKER"
        reference = "https://archive.f-secure.com/weblog/archives/00002803.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "admex\.org" ascii wide nocase
        $domain1 = "adsoftpic\.com" ascii wide nocase
        $domain2 = "affijay\.com" ascii wide nocase
        $domain3 = "agagian\.com" ascii wide nocase
        $domain4 = "aidobe-update\.com" ascii wide nocase
        $domain5 = "allmedicalpro\.com" ascii wide nocase
        $domain6 = "allrivercenter\.com" ascii wide nocase
        $domain7 = "amazonappservice\.com" ascii wide nocase
        $domain8 = "amazoncld\.com" ascii wide nocase
        $domain9 = "amazoncontent\.org" ascii wide nocase
        $domain10 = "ammaze\.org" ascii wide nocase
        $domain11 = "amzbooks\.org" ascii wide nocase
        $domain12 = "amznapis\.com" ascii wide nocase
        $domain13 = "anyfoodappz\.com" ascii wide nocase
        $domain14 = "anypicsave\.com" ascii wide nocase
        $domain15 = "apidevops\.org" ascii wide nocase
        $domain16 = "apiygate\.com" ascii wide nocase
        $domain17 = "appcellor\.com" ascii wide nocase
        $domain18 = "apple-sdk\.com" ascii wide nocase
        $domain19 = "atomarket\.org" ascii wide nocase
        $domain20 = "audio-azure\.com" ascii wide nocase
        $domain21 = "azure-affiliate\.com" ascii wide nocase
        $domain22 = "azurecfd\.com" ascii wide nocase
        $domain23 = "azurecontents\.com" ascii wide nocase
        $domain24 = "azureservicesapi\.com" ascii wide nocase
        $domain25 = "bookfinder-ltd\.com" ascii wide nocase
        $domain26 = "borisjns\.com" ascii wide nocase
        $domain27 = "cargoargs\.com" ascii wide nocase
        $domain28 = "cashcores\.org" ascii wide nocase
        $domain29 = "check-avg\.co" ascii wide nocase
        $domain30 = "check-avg\.com" ascii wide nocase
        $domain31 = "cloud-appint\.com" ascii wide nocase
        $domain32 = "cloudappcer\.com" ascii wide nocase
        $domain33 = "cloudazureservices\.com" ascii wide nocase
        $domain34 = "cloudpdom\.com" ascii wide nocase
        $domain35 = "cloudreg-email\.com" ascii wide nocase
        $domain36 = "coreadvc\.com" ascii wide nocase
        $domain37 = "corstand\.com" ascii wide nocase
        $domain38 = "cosmoscld\.com" ascii wide nocase
        $domain39 = "covidaff\.org" ascii wide nocase
        $domain40 = "covidgov\.org" ascii wide nocase
        $domain41 = "covsafezone\.com" ascii wide nocase
        $domain42 = "dbcallog\.com" ascii wide nocase
        $domain43 = "dellscanhw\.com" ascii wide nocase
        $domain44 = "diamondncenter\.biz" ascii wide nocase
        $domain45 = "dnserviceapp\.com" ascii wide nocase
        $domain46 = "dnstotal\.org" ascii wide nocase
        $domain47 = "dogeofcoin\.com" ascii wide nocase
        $domain48 = "dustforms\.com" ascii wide nocase
        $domain49 = "earthviehuge\.com" ascii wide nocase
        $ip50 = "176.223.165.196" ascii wide
        $ip51 = "185.62.189.210" ascii wide
        $ip52 = "87.120.254.100" ascii wide
        $ip53 = "87.120.37.68" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_DESERTFALCON
{
    meta:
        description = "Detects IOCs associated with APT DESERTFALCON"
        author = "APTtrail Automated Collection"
        apt_group = "DESERTFALCON"
        reference = "http://www.trendmicro.com/cloud-content/us/pdfs/security-intelligence/white-papers/wp-operation-arid-viper.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "abuhmaid\.net" ascii wide nocase
        $domain1 = "advtravel\.info" ascii wide nocase
        $domain2 = "ahmedfaiez\.info" ascii wide nocase
        $domain3 = "androcity\.com" ascii wide nocase
        $domain4 = "blogging-host\.info" ascii wide nocase
        $domain5 = "facebook-emoticons\.bitblogoo\.com" ascii wide nocase
        $domain6 = "flushupate\.com" ascii wide nocase
        $domain7 = "flushupdate\.com" ascii wide nocase
        $domain8 = "fpupdate\.info" ascii wide nocase
        $domain9 = "ineltdriver\.com" ascii wide nocase
        $domain10 = "ineltdriver\.info" ascii wide nocase
        $domain11 = "iwork-sys\.com" ascii wide nocase
        $domain12 = "linkedim\.in" ascii wide nocase
        $domain13 = "linksis\.info" ascii wide nocase
        $domain14 = "liptona\.net" ascii wide nocase
        $domain15 = "mediahitech\.com" ascii wide nocase
        $domain16 = "mediahitech\.info" ascii wide nocase
        $domain17 = "mixedwork\.com" ascii wide nocase
        $domain18 = "nauss-lab\.com" ascii wide nocase
        $domain19 = "nice-mobiles\.com" ascii wide nocase
        $domain20 = "plmedgroup\.com" ascii wide nocase
        $domain21 = "pstcmedia\.com" ascii wide nocase
        $domain22 = "tvgate\.rocks" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_DNSPIONAGE
{
    meta:
        description = "Detects IOCs associated with APT DNSPIONAGE"
        author = "APTtrail Automated Collection"
        apt_group = "DNSPIONAGE"
        reference = "https://blog.talosintelligence.com/2018/11/dnspionage-campaign-targets-middle-east.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "0ffice36o\.com" ascii wide nocase
        $domain1 = "18-79-t\.net" ascii wide nocase
        $domain2 = "1qhd6v\.xyz" ascii wide nocase
        $domain3 = "4f-okdsvv\.com" ascii wide nocase
        $domain4 = "5-9idk-gug7-k7\.com" ascii wide nocase
        $domain5 = "52-ck29jr\.com" ascii wide nocase
        $domain6 = "5z-hyq-g\.net" ascii wide nocase
        $domain7 = "78p3-zgs-g-mc-u\.com" ascii wide nocase
        $domain8 = "8f-mxh6-hupgd-dy\.com" ascii wide nocase
        $domain9 = "8faf-rngtax\.com" ascii wide nocase
        $domain10 = "a87-sun0r1w\.com" ascii wide nocase
        $domain11 = "ac5e1f-fd2ph\.com" ascii wide nocase
        $domain12 = "acyjob\.tokyo" ascii wide nocase
        $domain13 = "adchum\.tokyo" ascii wide nocase
        $domain14 = "adzwrq\.tokyo" ascii wide nocase
        $domain15 = "akgxtu\.tokyo" ascii wide nocase
        $domain16 = "aletko\.tokyo" ascii wide nocase
        $domain17 = "am41-pm24ea\.com" ascii wide nocase
        $domain18 = "amb29l1v3re\.com" ascii wide nocase
        $domain19 = "ami10t-e37n\.com" ascii wide nocase
        $domain20 = "an87-24pen1d\.com" ascii wide nocase
        $domain21 = "and58-65kio\.com" ascii wide nocase
        $domain22 = "apply33547\.com" ascii wide nocase
        $domain23 = "ar5-chj-n-22d\.com" ascii wide nocase
        $domain24 = "as93-attack1\.com" ascii wide nocase
        $domain25 = "aso5fr-gre4\.com" ascii wide nocase
        $domain26 = "au\.imonju\.net" ascii wide nocase
        $domain27 = "b5mjjc8s\.com" ascii wide nocase
        $domain28 = "baebod\.tokyo" ascii wide nocase
        $domain29 = "ban09-4w1as\.com" ascii wide nocase
        $domain30 = "batdongsan\.dcsvnqvmn\.com" ascii wide nocase
        $domain31 = "baw2u-y6rsxf\.com" ascii wide nocase
        $domain32 = "bed52-town1\.com" ascii wide nocase
        $domain33 = "big429-7ten\.com" ascii wide nocase
        $domain34 = "bing0017-s4e\.com" ascii wide nocase
        $domain35 = "bing04-5ea1\.com" ascii wide nocase
        $domain36 = "bm-8qkc8w\.com" ascii wide nocase
        $domain37 = "bnv521-send4\.com" ascii wide nocase
        $domain38 = "boat-19830214yh\.com" ascii wide nocase
        $domain39 = "boceuz\.tokyo" ascii wide nocase
        $domain40 = "boundhereafter\.com" ascii wide nocase
        $domain41 = "bpugoc\.tokyo" ascii wide nocase
        $domain42 = "bqufsuqj\.com" ascii wide nocase
        $domain43 = "buffdrops\.com" ascii wide nocase
        $domain44 = "bvnc5418-4s\.com" ascii wide nocase
        $domain45 = "c02bf1r-kjre\.com" ascii wide nocase
        $domain46 = "c7ykg-0sd5w\.com" ascii wide nocase
        $domain47 = "cd-7rr-hgj\.net" ascii wide nocase
        $domain48 = "cg58-6dr4wa\.com" ascii wide nocase
        $domain49 = "chai58-mnew\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_DOCLESS
{
    meta:
        description = "Detects IOCs associated with APT DOCLESS"
        author = "APTtrail Automated Collection"
        apt_group = "DOCLESS"
        reference = "https://app.any.run/tasks/748eccd0-8a7c-4401-81ef-0902419819de/"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "144.202.54.86" ascii wide

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_DOMESTICKITTEN
{
    meta:
        description = "Detects IOCs associated with APT DOMESTICKITTEN"
        author = "APTtrail Automated Collection"
        apt_group = "DOMESTICKITTEN"
        aliases = "apt-c-50"
        reference = "https://github.com/ti-research-io/ti/blob/main/ioc_extender/ET_Lazarus.json"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "androidsystemswebview\.com" ascii wide nocase
        $domain1 = "appsoftupdate\.com" ascii wide nocase
        $domain2 = "arzdigitals\.com" ascii wide nocase
        $domain3 = "firmwaresystemupdate\.com" ascii wide nocase
        $domain4 = "georgethompson\.space" ascii wide nocase
        $domain5 = "googleassisstants\.com" ascii wide nocase
        $domain6 = "googleservicesforar\.com" ascii wide nocase
        $domain7 = "googlextabv\.com" ascii wide nocase
        $domain8 = "lohefeshordeh\.net" ascii wide nocase
        $domain9 = "newportschoolupdateserver\.com" ascii wide nocase
        $domain10 = "ns1\.googleassisstants\.com" ascii wide nocase
        $domain11 = "ns2\.googleassisstants\.com" ascii wide nocase
        $domain12 = "padre914\.com" ascii wide nocase
        $domain13 = "ronaldlubbers\.site" ascii wide nocase
        $domain14 = "sarayemaghale\.hami24\.net" ascii wide nocase
        $domain15 = "stevenwentz\.com" ascii wide nocase
        $domain16 = "systemdriverupdate\.com" ascii wide nocase
        $domain17 = "ychatonline\.net" ascii wide nocase
        $domain18 = "ydownyload\.net" ascii wide nocase
        $domain19 = "ynewnow\.net" ascii wide nocase
        $ip20 = "198.50.220.44" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_DONOT
{
    meta:
        description = "Detects IOCs associated with APT DONOT"
        author = "APTtrail Automated Collection"
        apt_group = "DONOT"
        aliases = "apt-c-35, donot, stealjob"
        reference = "http://blog.talosintelligence.com/2022/02/whats-with-shared-vba-code.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "162-33-178-135\.cprapid\.com" ascii wide nocase
        $domain1 = "abletalk\.info" ascii wide nocase
        $domain2 = "abodeupdater\.com" ascii wide nocase
        $domain3 = "account-sign-in-security\.ga" ascii wide nocase
        $domain4 = "account-update-com\.tk" ascii wide nocase
        $domain5 = "account-updates-team\.ga" ascii wide nocase
        $domain6 = "accounts\.googel\.email" ascii wide nocase
        $domain7 = "adjusteble\.info" ascii wide nocase
        $domain8 = "advancedmapsone\.com" ascii wide nocase
        $domain9 = "advancesearch\.xyz" ascii wide nocase
        $domain10 = "afd-gov-bd\.gq" ascii wide nocase
        $domain11 = "aioupdates\.buzz" ascii wide nocase
        $domain12 = "akamaifast\.club" ascii wide nocase
        $domain13 = "akamaihub\.stream" ascii wide nocase
        $domain14 = "alter\.drivethrough\.top" ascii wide nocase
        $domain15 = "altzserberin\.info" ascii wide nocase
        $domain16 = "amazon-books-gifts\.com" ascii wide nocase
        $domain17 = "aoc\.sessions4life\.pw" ascii wide nocase
        $domain18 = "apifile\.xyz" ascii wide nocase
        $domain19 = "apkfreeware\.xyz" ascii wide nocase
        $domain20 = "apkv6\.endurecif\.top" ascii wide nocase
        $domain21 = "aplcompin\.site" ascii wide nocase
        $domain22 = "aplinvest\.site" ascii wide nocase
        $domain23 = "aplusgroup\.online" ascii wide nocase
        $domain24 = "app-palace\.live" ascii wide nocase
        $domain25 = "app-view-support\.club" ascii wide nocase
        $domain26 = "appie\.host" ascii wide nocase
        $domain27 = "appnsure\.com" ascii wide nocase
        $domain28 = "apps\.privatechat\.life" ascii wide nocase
        $domain29 = "appservices\.info" ascii wide nocase
        $domain30 = "appshare\.buzz" ascii wide nocase
        $domain31 = "appshares\.buzz" ascii wide nocase
        $domain32 = "appsharing\.buzz" ascii wide nocase
        $domain33 = "appsharinggo\.buzz" ascii wide nocase
        $domain34 = "appshazing\.buzz" ascii wide nocase
        $domain35 = "appsservicess\.buzz" ascii wide nocase
        $domain36 = "appsservicess\.info" ascii wide nocase
        $domain37 = "appsshares\.buzz" ascii wide nocase
        $domain38 = "appstringfy\.xyz" ascii wide nocase
        $domain39 = "appsupports\.info" ascii wide nocase
        $domain40 = "appview\.buzz" ascii wide nocase
        $domain41 = "appzserv\.info" ascii wide nocase
        $domain42 = "azure\.mglassservice\.com" ascii wide nocase
        $domain43 = "backup\.latestsyn\.xyz" ascii wide nocase
        $domain44 = "backuplogs\.xyz" ascii wide nocase
        $domain45 = "baf-mil-bd\.tk" ascii wide nocase
        $domain46 = "bakedcakes\.online" ascii wide nocase
        $domain47 = "balancelogs\.buzz" ascii wide nocase
        $domain48 = "beachupdates\.live" ascii wide nocase
        $domain49 = "beetelson\.xyz" ascii wide nocase
        $ip50 = "131.153.22.218" ascii wide
        $ip51 = "135.181.198.146" ascii wide
        $ip52 = "139.180.135.59" ascii wide
        $ip53 = "142.93.12.211" ascii wide
        $ip54 = "151.236.11.222" ascii wide
        $ip55 = "162.33.177.183" ascii wide
        $ip56 = "162.33.178.242" ascii wide
        $ip57 = "162.33.178.3" ascii wide
        $ip58 = "162.33.178.85" ascii wide
        $ip59 = "162.33.179.171" ascii wide
        $ip60 = "162.33.179.198" ascii wide
        $ip61 = "162.33.179.238" ascii wide
        $ip62 = "162.33.179.32" ascii wide
        $ip63 = "164.68.108.22" ascii wide
        $ip64 = "164.68.108.22" ascii wide
        $ip65 = "167.99.130.191" ascii wide
        $ip66 = "167.99.190.44" ascii wide
        $ip67 = "178.63.172.2" ascii wide
        $ip68 = "178.63.172.6" ascii wide
        $ip69 = "185.224.83.16" ascii wide
        $ip70 = "193.149.176.226" ascii wide
        $ip71 = "193.149.176.226" ascii wide
        $ip72 = "193.149.176.237" ascii wide
        $ip73 = "193.149.176.65" ascii wide
        $ip74 = "193.149.176.65" ascii wide
        $ip75 = "195.85.115.143" ascii wide
        $ip76 = "206.188.197.34" ascii wide
        $ip77 = "206.188.197.34" ascii wide
        $ip78 = "206.188.197.53" ascii wide
        $ip79 = "206.188.197.82" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_DOWNEX
{
    meta:
        description = "Detects IOCs associated with APT DOWNEX"
        author = "APTtrail Automated Collection"
        apt_group = "DOWNEX"
        aliases = "BlackGuard, cherryspy, hatvibe"
        reference = "https://app.validin.com/detail?find=dd9aef0ce3d64a9dd4009357637617fc&type=hash&ref_id=1065472a0a3#tab=host_pairs"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "background-services\.net" ascii wide nocase
        $domain1 = "diagnostic-resolver\.com" ascii wide nocase
        $domain2 = "download-resourses\.info" ascii wide nocase
        $domain3 = "energieecoinnov\.info" ascii wide nocase
        $domain4 = "energieecotech\.info" ascii wide nocase
        $domain5 = "enrollmentdm\.com" ascii wide nocase
        $domain6 = "lookup\.ink" ascii wide nocase
        $domain7 = "ms-webdav-miniredir\.com" ascii wide nocase
        $domain8 = "net-certificate\.services" ascii wide nocase
        $domain9 = "trust-certificate\.net" ascii wide nocase
        $ip10 = "38.180.207.137" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_DRAGONOK
{
    meta:
        description = "Detects IOCs associated with APT DRAGONOK"
        author = "APTtrail Automated Collection"
        apt_group = "DRAGONOK"
        reference = "http://www.morphick.com/resources/news/deep-dive-dragonok-rambo-backdoor"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "bbs\.donkeyhaws\.info" ascii wide nocase
        $domain1 = "biosnews\.info" ascii wide nocase
        $domain2 = "busserh\.mancely\.com" ascii wide nocase
        $domain3 = "donkeyhaws\.info" ascii wide nocase
        $domain4 = "ghostale\.com" ascii wide nocase
        $domain5 = "http\.donkeyhaws\.info" ascii wide nocase
        $domain6 = "https\.osakaintec\.com" ascii wide nocase
        $domain7 = "jpaols\.com" ascii wide nocase
        $domain8 = "moafee\.com" ascii wide nocase
        $domain9 = "ndbssh\.com" ascii wide nocase
        $domain10 = "php\.marbletemps\.com" ascii wide nocase
        $domain11 = "pktmedia\.com" ascii wide nocase
        $domain12 = "skyppee\.com" ascii wide nocase
        $domain13 = "ycbackap\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_DRIFTINGCLOUD
{
    meta:
        description = "Detects IOCs associated with APT DRIFTINGCLOUD"
        author = "APTtrail Automated Collection"
        apt_group = "DRIFTINGCLOUD"
        reference = "https://github.com/volexity/threat-intel/blob/main/2022/2022-06-15%20DriftingCloud%20-%20Zero-Day%20Sophos%20Firewall%20Exploitation%20and%20an%20Insidious%20Breach/indicators/indicators.csv"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "akamprod\.com" ascii wide nocase
        $domain1 = "googleanalytics\.proxydns\.com" ascii wide nocase
        $domain2 = "servusers\.com" ascii wide nocase
        $domain3 = "u2d\.servusers\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_DUKE
{
    meta:
        description = "Detects IOCs associated with APT DUKE"
        author = "APTtrail Automated Collection"
        apt_group = "DUKE"
        aliases = "APT29, CloudDuke, CosmicDuke"
        reference = "https://app.validin.com/detail?find=151.236.16.138&type=ip4&ref_id=7e3792beeb8#tab=resolutions"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "1597ebba\.info\.gtjas\.site" ascii wide nocase
        $domain1 = "3bcc1bba\.info\.gtjas\.site" ascii wide nocase
        $domain2 = "4freerussia\.cloud" ascii wide nocase
        $domain3 = "74d6b7b2\.app\.giftbox4u\.com" ascii wide nocase
        $domain4 = "7c291bbe\.info\.gtjas\.site" ascii wide nocase
        $domain5 = "acciaio\.com\.br" ascii wide nocase
        $domain6 = "accounts-google\.online" ascii wide nocase
        $domain7 = "actualcombine\.com" ascii wide nocase
        $domain8 = "adm\.govua\.cloud" ascii wide nocase
        $domain9 = "admin-ch\.cloud" ascii wide nocase
        $domain10 = "aeinc\.solutions" ascii wide nocase
        $domain11 = "ahmed-ms\.online" ascii wide nocase
        $domain12 = "airtravelabroad\.com" ascii wide nocase
        $domain13 = "aka-ms\.cloud" ascii wide nocase
        $domain14 = "albrightstonebridge\.cloud" ascii wide nocase
        $domain15 = "amazonmeeting\.cloud" ascii wide nocase
        $domain16 = "amazonsolutions\.cloud" ascii wide nocase
        $domain17 = "americanprogress\.cloud" ascii wide nocase
        $domain18 = "ap-northeast-1-aws\.s3-ua\.cloud" ascii wide nocase
        $domain19 = "ap-northeast-1-aws\.ukrainesec\.cloud" ascii wide nocase
        $domain20 = "aspeninstitute\.cloud" ascii wide nocase
        $domain21 = "asucloud\.us" ascii wide nocase
        $domain22 = "avis-google\.online" ascii wide nocase
        $domain23 = "aws-app\.online" ascii wide nocase
        $domain24 = "aws-atshop\.online" ascii wide nocase
        $domain25 = "aws-cert\.online" ascii wide nocase
        $domain26 = "aws-cloud\.online" ascii wide nocase
        $domain27 = "aws-cloud\.tech" ascii wide nocase
        $domain28 = "aws-data\.cloud" ascii wide nocase
        $domain29 = "aws-devops\.site" ascii wide nocase
        $domain30 = "aws-exam\.online" ascii wide nocase
        $domain31 = "aws-il\.cloud" ascii wide nocase
        $domain32 = "aws-join\.cloud" ascii wide nocase
        $domain33 = "aws-meet\.cloud" ascii wide nocase
        $domain34 = "aws-meetings\.cloud" ascii wide nocase
        $domain35 = "aws-ms\.cloud" ascii wide nocase
        $domain36 = "aws-my\.online" ascii wide nocase
        $domain37 = "aws-online\.cloud" ascii wide nocase
        $domain38 = "aws-platform\.cloud" ascii wide nocase
        $domain39 = "aws-s3\.cloud" ascii wide nocase
        $domain40 = "aws-sagyo\.site" ascii wide nocase
        $domain41 = "aws-sample\.online" ascii wide nocase
        $domain42 = "aws-secure\.cloud" ascii wide nocase
        $domain43 = "aws-talib\.online" ascii wide nocase
        $domain44 = "aws-ukraine\.cloud" ascii wide nocase
        $domain45 = "aws-yamada\.site" ascii wide nocase
        $domain46 = "awsmeet\.cloud" ascii wide nocase
        $domain47 = "awsmeetings\.online" ascii wide nocase
        $domain48 = "awsplatform\.online" ascii wide nocase
        $domain49 = "awsprotect\.online" ascii wide nocase
        $ip50 = "103.216.221.18" ascii wide
        $ip51 = "103.253.41.102" ascii wide
        $ip52 = "103.76.128.34" ascii wide
        $ip53 = "111.90.150.140" ascii wide
        $ip54 = "141.98.212.55" ascii wide
        $ip55 = "141.98.212.55" ascii wide
        $ip56 = "185.243.99.17" ascii wide
        $ip57 = "209.58.186.196" ascii wide
        $ip58 = "45.91.93.89" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_DUNEQUIXOTE
{
    meta:
        description = "Detects IOCs associated with APT DUNEQUIXOTE"
        author = "APTtrail Automated Collection"
        apt_group = "DUNEQUIXOTE"
        aliases = "CR4T"
        reference = "https://securelist.com/dunequixote/112425/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "commonline\.space" ascii wide nocase
        $domain1 = "e1awq1lp\.commonline\.space" ascii wide nocase
        $domain2 = "g1sea23g\.commonline\.space" ascii wide nocase
        $domain3 = "mc\.commonline\.space" ascii wide nocase
        $domain4 = "service\.userfeedsync\.com" ascii wide nocase
        $domain5 = "telemetry\.commonline\.space" ascii wide nocase
        $domain6 = "telemetry\.userfeedsync\.com" ascii wide nocase
        $domain7 = "tg1sea23g\.commonline\.space" ascii wide nocase
        $domain8 = "userfeedsync\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_DUSTSQUAD
{
    meta:
        description = "Detects IOCs associated with APT DUSTSQUAD"
        author = "APTtrail Automated Collection"
        apt_group = "DUSTSQUAD"
        aliases = "Dustsquad, Nomadic Octopus, Octopus"
        reference = "https://securelist.com/octopus-infested-seas-of-central-asia/88200/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "blondehairman\.com" ascii wide nocase
        $domain1 = "certificatesshop\.com" ascii wide nocase
        $domain2 = "cookiesqueen\.com" ascii wide nocase
        $domain3 = "desperados20\.es" ascii wide nocase
        $domain4 = "footcoinball\.com" ascii wide nocase
        $domain5 = "giftfromspace\.com" ascii wide nocase
        $domain6 = "hovnanflovers\.com" ascii wide nocase
        $domain7 = "humorpics\.download" ascii wide nocase
        $domain8 = "islandsnake\.com" ascii wide nocase
        $domain9 = "latecafe\.in" ascii wide nocase
        $domain10 = "lovingearthy\.com" ascii wide nocase
        $domain11 = "mikohanzer\.website" ascii wide nocase
        $domain12 = "poisonfight\.com" ascii wide nocase
        $domain13 = "porenticofacts\.com" ascii wide nocase
        $domain14 = "prom3\.biz\.ua" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_EARTHBERBEROKA
{
    meta:
        description = "Detects IOCs associated with APT EARTHBERBEROKA"
        author = "APTtrail Automated Collection"
        apt_group = "EARTHBERBEROKA"
        reference = "https://documents.trendmicro.com/assets/txt/earth-berberoka-domains-2.txt"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "1\.googie\.ph" ascii wide nocase
        $domain1 = "12371829hkdanm\.fbi\.am" ascii wide nocase
        $domain2 = "1qw6etagydbn2peifj8hf\.fbi\.am" ascii wide nocase
        $domain3 = "2\.googie\.ph" ascii wide nocase
        $domain4 = "3\.googie\.ph" ascii wide nocase
        $domain5 = "adobe-flash\.wiki" ascii wide nocase
        $domain6 = "adobe\.name" ascii wide nocase
        $domain7 = "agph\.ivi66\.net" ascii wide nocase
        $domain8 = "bos\.github\.wiki" ascii wide nocase
        $domain9 = "caonimade\.11i\.me" ascii wide nocase
        $domain10 = "d\.github\.wiki" ascii wide nocase
        $domain11 = "darknet\.rootkit\.tools" ascii wide nocase
        $domain12 = "darwin\.github\.wiki" ascii wide nocase
        $domain13 = "download\.mircrosoftscoulds\.com" ascii wide nocase
        $domain14 = "dust\.github\.wiki" ascii wide nocase
        $domain15 = "exmail\.googie\.com\.ph" ascii wide nocase
        $domain16 = "fbi\.fuckbc\.com" ascii wide nocase
        $domain17 = "flash\.wy886066\.com" ascii wide nocase
        $domain18 = "fuckbc\.com" ascii wide nocase
        $domain19 = "fuckeryoumm\.nmb\.bet" ascii wide nocase
        $domain20 = "fuckyou\.fbi\.am" ascii wide nocase
        $domain21 = "gb\.googie\.ph" ascii wide nocase
        $domain22 = "github\.wiki" ascii wide nocase
        $domain23 = "googie\.com\.ph" ascii wide nocase
        $domain24 = "googie\.ph" ascii wide nocase
        $domain25 = "helloword\.11i\.me" ascii wide nocase
        $domain26 = "helloword\.daj8\.me" ascii wide nocase
        $domain27 = "hk\.whoamis\.info" ascii wide nocase
        $domain28 = "hkdust\.github\.wiki" ascii wide nocase
        $domain29 = "huaidan\.fbi\.am" ascii wide nocase
        $domain30 = "ivi66\.net" ascii wide nocase
        $domain31 = "linux\.daj8\.me" ascii wide nocase
        $domain32 = "linux\.daji8\.me" ascii wide nocase
        $domain33 = "linux\.shopingchina\.net" ascii wide nocase
        $domain34 = "linux\.wy01\.com" ascii wide nocase
        $domain35 = "linux\.wy01\.vip" ascii wide nocase
        $domain36 = "linux1\.shopingchina\.net" ascii wide nocase
        $domain37 = "linux2\.shopingchina\.net" ascii wide nocase
        $domain38 = "list\.whoamis\.info" ascii wide nocase
        $domain39 = "localhost\.11i\.me" ascii wide nocase
        $domain40 = "mircrosoftscoulds\.com" ascii wide nocase
        $domain41 = "mmimdown\.oss-cn-hongkong\.aliyuncs\.com" ascii wide nocase
        $domain42 = "rc\.dajuw\.com" ascii wide nocase
        $domain43 = "rootkit\.tools" ascii wide nocase
        $domain44 = "shopingchina\.net" ascii wide nocase
        $domain45 = "steam\.dajuw\.com" ascii wide nocase
        $domain46 = "test\.mircrosoftscoulds\.com" ascii wide nocase
        $domain47 = "tools\.daji8\.me" ascii wide nocase
        $domain48 = "update\.adobe\.wiki" ascii wide nocase
        $domain49 = "win\.googie\.ph" ascii wide nocase
        $ip50 = "103.43.18.71" ascii wide
        $ip51 = "167.179.95.191" ascii wide
        $ip52 = "45.76.199.119" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_EARTHESTRIES
{
    meta:
        description = "Detects IOCs associated with APT EARTHESTRIES"
        author = "APTtrail Automated Collection"
        apt_group = "EARTHESTRIES"
        aliases = "hemigate, trillclient, zingdoor"
        reference = "https://khonggianmang.vn/uploads/1_20241120_CV_APT_EARTHESTRIES_ce3a8ed572.PDF"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "access\.trhammer\.com" ascii wide nocase
        $domain1 = "anynucleus\.com" ascii wide nocase
        $domain2 = "api\.solveblemten\.com" ascii wide nocase
        $domain3 = "awsdns531\.com" ascii wide nocase
        $domain4 = "billing\.clothworls\.com" ascii wide nocase
        $domain5 = "c11r\.awsdns531\.com" ascii wide nocase
        $domain6 = "cas04\.awsdns531\.com" ascii wide nocase
        $domain7 = "cdn-6dd0035\.oxcdntech\.com" ascii wide nocase
        $domain8 = "cdn-7a3d\.vultr-dns\.com" ascii wide nocase
        $domain9 = "cdn181\.awsdns531\.com" ascii wide nocase
        $domain10 = "cdn728a66b0\.smartlinkcorp\.net" ascii wide nocase
        $domain11 = "cloudlibraries\.global\.ssl\.fastly\.net" ascii wide nocase
        $domain12 = "credits\.officesanalytics\.com" ascii wide nocase
        $domain13 = "dns2021\.net" ascii wide nocase
        $domain14 = "east\.smartpisang\.com" ascii wide nocase
        $domain15 = "esh\.hoovernamosong\.com" ascii wide nocase
        $domain16 = "globalnetzone\.bcdn\.net" ascii wide nocase
        $domain17 = "helpdesk\.stnekpro\.com" ascii wide nocase
        $domain18 = "imap\.dateupdata\.com" ascii wide nocase
        $domain19 = "infraredsen\.com" ascii wide nocase
        $domain20 = "jasmine\.lhousewares\.com" ascii wide nocase
        $domain21 = "jptomorrow\.com" ascii wide nocase
        $domain22 = "jttoday\.net" ascii wide nocase
        $domain23 = "keyplancorp\.com" ascii wide nocase
        $domain24 = "linkaircdn\.com" ascii wide nocase
        $domain25 = "llnw-dd\.awsdns531\.com" ascii wide nocase
        $domain26 = "lyncidc\.com" ascii wide nocase
        $domain27 = "materialplies\.com" ascii wide nocase
        $domain28 = "microware-help\.com" ascii wide nocase
        $domain29 = "mncdntech\.com" ascii wide nocase
        $domain30 = "ms101\.cloudshappen\.com" ascii wide nocase
        $domain31 = "news\.colourtinctem\.com" ascii wide nocase
        $domain32 = "nx2\.microware-help\.com" ascii wide nocase
        $domain33 = "officesanalytics\.com" ascii wide nocase
        $domain34 = "oxcdntech\.com" ascii wide nocase
        $domain35 = "private\.royalnas\.com" ascii wide nocase
        $domain36 = "publicdnsau\.com" ascii wide nocase
        $domain37 = "pulseathermakf\.com" ascii wide nocase
        $domain38 = "resource\.officesanalytics\.com" ascii wide nocase
        $domain39 = "rthtrade\.com" ascii wide nocase
        $domain40 = "rtsafetech\.com" ascii wide nocase
        $domain41 = "rtsoftcorp\.com" ascii wide nocase
        $domain42 = "rtwebmaster\.com" ascii wide nocase
        $domain43 = "services\.officesanalytics\.com" ascii wide nocase
        $domain44 = "shinas\.global\.ssl\.fastly\.net" ascii wide nocase
        $domain45 = "soffice\.officesanalytics\.com" ascii wide nocase
        $domain46 = "substantialeconomy\.com" ascii wide nocase
        $domain47 = "telcom\.grishamarkovgf8936\.workers\.dev" ascii wide nocase
        $domain48 = "trhammer\.com" ascii wide nocase
        $domain49 = "vpn114240349\.softether\.net" ascii wide nocase
        $ip50 = "103.159.133.205" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_EARTHHUNDUN
{
    meta:
        description = "Detects IOCs associated with APT EARTHHUNDUN"
        author = "APTtrail Automated Collection"
        apt_group = "EARTHHUNDUN"
        reference = "https://www.trendmicro.com/content/dam/trendmicro/global/en/research/24/d/cyberespionage-group-earth-hundun%27s-continuous-refinement-of-waterbear-and-deuterbear/ioc-earth-hundun.txt"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "cloudflaread\.quadrantbd\.com" ascii wide nocase
        $domain1 = "cloudsrm\.gelatosg\.com" ascii wide nocase
        $domain2 = "freeprous\.bakhell\.com" ascii wide nocase
        $domain3 = "rscvmogt\.taishanlaw\.com" ascii wide nocase
        $domain4 = "showgyella\.quadrantbd\.com" ascii wide nocase
        $domain5 = "smartclouds\.gelatosg\.com" ascii wide nocase
        $domain6 = "suitsvm003\.rchitecture\.org" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_EARTHKRAHANG
{
    meta:
        description = "Detects IOCs associated with APT EARTHKRAHANG"
        author = "APTtrail Automated Collection"
        apt_group = "EARTHKRAHANG"
        aliases = "dinodas, dinodasrat, linodas"
        reference = "https://github.com/eset/malware-ioc/tree/master/operation_jacana"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "115-126-98-204\.hkt\.cc" ascii wide nocase
        $domain1 = "118-99-6-202\.hkt\.cc" ascii wide nocase
        $domain2 = "centos-yum\.com" ascii wide nocase
        $domain3 = "microsoft-setting\.com" ascii wide nocase
        $domain4 = "microsoft-settings\.com" ascii wide nocase
        $domain5 = "security-microsoft\.net" ascii wide nocase
        $domain6 = "server-microsoft\.com" ascii wide nocase
        $domain7 = "update\.centos-yum\.com" ascii wide nocase
        $domain8 = "update\.microsoft-setting\.com" ascii wide nocase
        $domain9 = "update\.microsoft-settings\.com" ascii wide nocase
        $domain10 = "update\.windows\.server-microsoft\.com" ascii wide nocase
        $domain11 = "windows\.server-microsoft\.com" ascii wide nocase
        $ip12 = "115.126.98.204" ascii wide
        $ip13 = "118.107.221.43" ascii wide
        $ip14 = "118.107.221.43" ascii wide
        $ip15 = "118.107.221.43" ascii wide
        $ip16 = "118.99.6.202" ascii wide
        $ip17 = "199.231.211.19" ascii wide
        $ip18 = "199.231.211.19" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_EARTHKURMA
{
    meta:
        description = "Detects IOCs associated with APT EARTHKURMA"
        author = "APTtrail Automated Collection"
        apt_group = "EARTHKURMA"
        aliases = "dmloader, dunloader, frpc"
        reference = "https://documents.trendmicro.com/assets/txt/EarthKurma-IOCssVJ3RcK.txt"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "dfsg3gfsga\.space" ascii wide nocase
        $domain1 = "igtsadlb2ra\.pw" ascii wide nocase
        $domain2 = "ihyvcs5t\.pw" ascii wide nocase
        $domain3 = "vidsec\.cc" ascii wide nocase
        $ip4 = "103.238.214.88" ascii wide
        $ip5 = "149.28.147.63" ascii wide
        $ip6 = "166.88.194.53" ascii wide
        $ip7 = "185.239.225.106" ascii wide
        $ip8 = "38.147.191.103" ascii wide
        $ip9 = "38.60.199.225" ascii wide
        $ip10 = "45.77.250.21" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_EARTHWENDIGO
{
    meta:
        description = "Detects IOCs associated with APT EARTHWENDIGO"
        author = "APTtrail Automated Collection"
        apt_group = "EARTHWENDIGO"
        reference = "https://otx.alienvault.com/pulse/5ff4910b62daeb96d924cce8"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "anybodyopenfind\.com" ascii wide nocase
        $domain1 = "googletwtw\.com" ascii wide nocase
        $domain2 = "mail2000tw\.com" ascii wide nocase
        $domain3 = "travelsiteadvisor\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_EGOMANIAC
{
    meta:
        description = "Detects IOCs associated with APT EGOMANIAC"
        author = "APTtrail Automated Collection"
        apt_group = "EGOMANIAC"
        reference = "https://otx.alienvault.com/pulse/6138debb9bd98b0f5c3983a4"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "adobupdate\.serveftp\.com" ascii wide nocase
        $domain1 = "adobupdate\.servehttp\.com" ascii wide nocase
        $domain2 = "antivirus\.myftp\.org" ascii wide nocase
        $domain3 = "blogg\.serveblog\.net" ascii wide nocase
        $domain4 = "driver\.myftp\.org" ascii wide nocase
        $domain5 = "halkinsesitv\.com" ascii wide nocase
        $domain6 = "messenger\.serveirc\.com" ascii wide nocase
        $domain7 = "tigereyes2\.servepics\.com" ascii wide nocase
        $domain8 = "twiter\.serveblog\.net" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_ENERGETICBEAR
{
    meta:
        description = "Detects IOCs associated with APT ENERGETICBEAR"
        author = "APTtrail Automated Collection"
        apt_group = "ENERGETICBEAR"
        aliases = "crouching yeti, dragonfly, iron liberty"
        reference = "https://lab52.io/blog/the-geopolitical-and-potential-cyber-influence-of-russia-in-africa/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "ecco0\.b13x\.org" ascii wide nocase
        $domain1 = "kanri\.rbridal\.net" ascii wide nocase
        $domain2 = "lite\.ultralitedesigns\.com" ascii wide nocase
        $domain3 = "satanal\.info" ascii wide nocase
        $domain4 = "tureg\.info" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_EQUATIONGROUP
{
    meta:
        description = "Detects IOCs associated with APT EQUATIONGROUP"
        author = "APTtrail Automated Collection"
        apt_group = "EQUATIONGROUP"
        reference = "http://securelist.com/files/2015/02/Equation_group_questions_and_answers.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "247adbiz\.net" ascii wide nocase
        $domain1 = "ad-noise\.net" ascii wide nocase
        $domain2 = "ad-servicestats\.net" ascii wide nocase
        $domain3 = "ad-void\.com" ascii wide nocase
        $domain4 = "adsbizsimple\.com" ascii wide nocase
        $domain5 = "adservicestats\.com" ascii wide nocase
        $domain6 = "advancing-technology\.com" ascii wide nocase
        $domain7 = "afkarehroshan\.com" ascii wide nocase
        $domain8 = "amazinggreentechshop\.com" ascii wide nocase
        $domain9 = "arabtechmessenger\.net" ascii wide nocase
        $domain10 = "arm2pie\.com" ascii wide nocase
        $domain11 = "avidnewssource\.com" ascii wide nocase
        $domain12 = "aynachatsrv\.com" ascii wide nocase
        $domain13 = "bazandegan\.com" ascii wide nocase
        $domain14 = "brittlefilet\.com" ascii wide nocase
        $domain15 = "business-made-fun\.com" ascii wide nocase
        $domain16 = "businessdealsblog\.com" ascii wide nocase
        $domain17 = "businessdirectnessource\.com" ascii wide nocase
        $domain18 = "businessedgeadvance\.com" ascii wide nocase
        $domain19 = "charging-technology\.com" ascii wide nocase
        $domain20 = "charmedno1\.com" ascii wide nocase
        $domain21 = "cigape\.net" ascii wide nocase
        $domain22 = "coffeehausblog\.com" ascii wide nocase
        $domain23 = "computertechanalysis\.com" ascii wide nocase
        $domain24 = "config\.getmyip\.com" ascii wide nocase
        $domain25 = "cribdare2no\.com" ascii wide nocase
        $domain26 = "crisptic01\.net" ascii wide nocase
        $domain27 = "customerscreensavers\.com" ascii wide nocase
        $domain28 = "damavandkuh\.com" ascii wide nocase
        $domain29 = "darakht\.com" ascii wide nocase
        $domain30 = "dowelsobject\.com" ascii wide nocase
        $domain31 = "downloadmpplayer\.com" ascii wide nocase
        $domain32 = "dt1blog\.com" ascii wide nocase
        $domain33 = "easyadvertonline\.com" ascii wide nocase
        $domain34 = "fliteilex\.com" ascii wide nocase
        $domain35 = "fnlpic\.com" ascii wide nocase
        $domain36 = "following-technology\.com" ascii wide nocase
        $domain37 = "forboringbusinesses\.com" ascii wide nocase
        $domain38 = "forgotten-deals\.com" ascii wide nocase
        $domain39 = "foroushi\.net" ascii wide nocase
        $domain40 = "functional-business\.com" ascii wide nocase
        $domain41 = "gar-tech\.com" ascii wide nocase
        $domain42 = "ghalibaft\.com" ascii wide nocase
        $domain43 = "globalnetworkanalys\.com" ascii wide nocase
        $domain44 = "goldadpremium\.com" ascii wide nocase
        $domain45 = "goodbizez\.com" ascii wide nocase
        $domain46 = "havakhosh\.com" ascii wide nocase
        $domain47 = "honarkhabar\.com" ascii wide nocase
        $domain48 = "honarkhaneh\.net" ascii wide nocase
        $domain49 = "housedman\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_EVAPIKS
{
    meta:
        description = "Detects IOCs associated with APT EVAPIKS"
        author = "APTtrail Automated Collection"
        apt_group = "EVAPIKS"
        aliases = "evapiks, finteam"
        reference = "https://research.checkpoint.com/finteam-trojanized-teamviewer-against-government-targets/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "1c-ru\.net" ascii wide nocase
        $domain1 = "intersys32\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_EVASIVEPANDA
{
    meta:
        description = "Detects IOCs associated with APT EVASIVEPANDA"
        author = "APTtrail Automated Collection"
        apt_group = "EVASIVEPANDA"
        aliases = "Bronze Highland, Daggerfly"
        reference = "https://app.any.run/tasks/e5ad4dd0-32f7-45a6-8012-44711ed04f0e/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "flash\.governmentmm\.com" ascii wide nocase
        $domain1 = "governmentmm\.com" ascii wide nocase
        $domain2 = "update\.devicebug\.com" ascii wide nocase
        $ip3 = "103.96.128.44" ascii wide
        $ip4 = "103.96.128.44" ascii wide
        $ip5 = "103.96.131.150" ascii wide
        $ip6 = "103.96.131.150" ascii wide
        $ip7 = "122.10.89.170" ascii wide
        $ip8 = "122.10.89.172" ascii wide
        $ip9 = "223.165.4.175" ascii wide
        $ip10 = "45.125.64.200" ascii wide
        $ip11 = "45.125.64.200" ascii wide
        $ip12 = "45.125.64.200" ascii wide
        $ip13 = "45.77.140.81" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_EZQ
{
    meta:
        description = "Detects IOCs associated with APT EZQ"
        author = "APTtrail Automated Collection"
        apt_group = "EZQ"
        reference = "https://twitter.com/issuemakerslab/status/1035109539740172289"
        severity = "high"
        tlp = "white"

    strings:
        $url0 = "/data/member/style\.php" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_FAMILIARFEELING
{
    meta:
        description = "Detects IOCs associated with APT FAMILIARFEELING"
        author = "APTtrail Automated Collection"
        apt_group = "FAMILIARFEELING"
        reference = "https://citizenlab.ca/2018/01/spying-on-a-budget-inside-a-phishing-operation-with-targets-in-the-tibetan-community/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "comemail\.email" ascii wide nocase
        $domain1 = "comemails\.email" ascii wide nocase
        $domain2 = "commail\.co" ascii wide nocase
        $domain3 = "daynew\.today" ascii wide nocase
        $domain4 = "daynews\.today" ascii wide nocase
        $domain5 = "t1bet\.net" ascii wide nocase
        $domain6 = "tibet-office\.net" ascii wide nocase
        $domain7 = "tibetfreedom\.xyz" ascii wide nocase
        $domain8 = "tibetfrum\.info" ascii wide nocase
        $domain9 = "tibethouse\.info" ascii wide nocase
        $domain10 = "tibetnews\.info" ascii wide nocase
        $domain11 = "tibetnews\.today" ascii wide nocase
        $domain12 = "tibetyouthcongress\.com" ascii wide nocase
        $ip13 = "45.77.45.222" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_FEROCIOUSKITTEN
{
    meta:
        description = "Detects IOCs associated with APT FEROCIOUSKITTEN"
        author = "APTtrail Automated Collection"
        apt_group = "FEROCIOUSKITTEN"
        aliases = "MarkiRAT"
        reference = "https://securelist.com/ferocious-kitten-6-years-of-covert-surveillance-in-iran/102806/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "aparat\.com-view\.space" ascii wide nocase
        $domain1 = "com-view\.org" ascii wide nocase
        $domain2 = "com-view\.space" ascii wide nocase
        $domain3 = "comuk\.space" ascii wide nocase
        $domain4 = "khabarfarsi\.com-view\.org" ascii wide nocase
        $domain5 = "microcaft\.xyz" ascii wide nocase
        $domain6 = "microsoft\.com-view\.space" ascii wide nocase
        $domain7 = "microsoft\.comuk\.space" ascii wide nocase
        $domain8 = "microsoft\.microcaft\.xyz" ascii wide nocase
        $domain9 = "microsoft\.unupdate\.ml" ascii wide nocase
        $domain10 = "microsoft\.unupload\.xyz" ascii wide nocase
        $domain11 = "microsoft\.updatei\.com" ascii wide nocase
        $domain12 = "unupdate\.ml" ascii wide nocase
        $domain13 = "unupload\.xyz" ascii wide nocase
        $domain14 = "updatei\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_FINFISHER
{
    meta:
        description = "Detects IOCs associated with APT FINFISHER"
        author = "APTtrail Automated Collection"
        apt_group = "FINFISHER"
        reference = "http://securityaffairs.co/wordpress/8085/intelligence/finfisher-the-case-of-a-cyber-espionage-found-everywhere.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "browserupdate\.download" ascii wide nocase
        $domain1 = "ff-demo\.blogdns\.org" ascii wide nocase
        $domain2 = "google\.wwwhost\.biz" ascii wide nocase
        $domain3 = "info\.dynamic-dns\.net" ascii wide nocase
        $domain4 = "news-youm7\.com" ascii wide nocase
        $domain5 = "pal2me\.net" ascii wide nocase
        $domain6 = "pal4u\.net" ascii wide nocase
        $domain7 = "shop8d\.net" ascii wide nocase
        $domain8 = "tiger\.gamma-international\.de" ascii wide nocase
        $domain9 = "workingulf\.net" ascii wide nocase
        $domain10 = "wp\.piedslibres\.com" ascii wide nocase
        $ip11 = "108.61.190.183" ascii wide
        $ip12 = "109.235.67.175" ascii wide
        $ip13 = "184.82.101.234" ascii wide
        $ip14 = "184.82.101.234" ascii wide
        $ip15 = "185.141.24.204" ascii wide
        $ip16 = "185.25.51.104" ascii wide
        $ip17 = "213.252.247.105" ascii wide
        $ip18 = "45.86.136.138" ascii wide
        $ip19 = "45.86.163.138" ascii wide
        $ip20 = "79.143.87.216" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_FLAME
{
    meta:
        description = "Detects IOCs associated with APT FLAME"
        author = "APTtrail Automated Collection"
        apt_group = "FLAME"
        reference = "https://securelist.com/the-roof-is-on-fire-tackling-flames-cc-servers-6/33033/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "autosync\.info" ascii wide nocase
        $domain1 = "bannerspot\.in" ascii wide nocase
        $domain2 = "bannerspot\.info" ascii wide nocase
        $domain3 = "bannerzone\.in" ascii wide nocase
        $domain4 = "chchengine\.com" ascii wide nocase
        $domain5 = "chchengine\.net" ascii wide nocase
        $domain6 = "conf-net\.com" ascii wide nocase
        $domain7 = "dailynewsupdater\.com" ascii wide nocase
        $domain8 = "diznet\.biz" ascii wide nocase
        $domain9 = "dnslocation\.info" ascii wide nocase
        $domain10 = "dnsmask\.info" ascii wide nocase
        $domain11 = "dnsportal\.info" ascii wide nocase
        $domain12 = "dnsupdate\.info" ascii wide nocase
        $domain13 = "eventhosting\.com" ascii wide nocase
        $domain14 = "flashp\.webhop\.net" ascii wide nocase
        $domain15 = "flashupdates\.info" ascii wide nocase
        $domain16 = "flushdns\.info" ascii wide nocase
        $domain17 = "isyncautomation\.in" ascii wide nocase
        $domain18 = "isyncautoupdater\.in" ascii wide nocase
        $domain19 = "localgateway\.info" ascii wide nocase
        $domain20 = "micromedia\.in" ascii wide nocase
        $domain21 = "mysync\.info" ascii wide nocase
        $domain22 = "newstatisticfeeder\.com" ascii wide nocase
        $domain23 = "newsync\.info" ascii wide nocase
        $domain24 = "nvidiadrivers\.info" ascii wide nocase
        $domain25 = "nvidiasoft\.info" ascii wide nocase
        $domain26 = "nvidiastream\.info" ascii wide nocase
        $domain27 = "pingserver\.info" ascii wide nocase
        $domain28 = "quick-net\.info" ascii wide nocase
        $domain29 = "rendercodec\.info" ascii wide nocase
        $domain30 = "serveflash\.info" ascii wide nocase
        $domain31 = "serverss\.info" ascii wide nocase
        $domain32 = "smart-access\.net" ascii wide nocase
        $domain33 = "syncdomain\.info" ascii wide nocase
        $domain34 = "synclock\.info" ascii wide nocase
        $domain35 = "syncprovider\.info" ascii wide nocase
        $domain36 = "syncsource\.info" ascii wide nocase
        $domain37 = "syncstream\.info" ascii wide nocase
        $domain38 = "syncupdate\.info" ascii wide nocase
        $domain39 = "traffic-spot\.biz" ascii wide nocase
        $domain40 = "traffic-spot\.com" ascii wide nocase
        $domain41 = "ultrasoft\.in" ascii wide nocase
        $domain42 = "videosync\.info" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_FLAXTYPHOON
{
    meta:
        description = "Detects IOCs associated with APT FLAXTYPHOON"
        author = "APTtrail Automated Collection"
        apt_group = "FLAXTYPHOON"
        reference = "https://otx.alienvault.com/pulse/64e86c65ba511d1d4c4aa590"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "asljkdqhkhasdq\.softether\.net" ascii wide nocase
        $domain1 = "vpn437972693\.sednc\.cn" ascii wide nocase
        $domain2 = "vpn472462384\.softether\.net" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_FLIGHTNIGHT
{
    meta:
        description = "Detects IOCs associated with APT FLIGHTNIGHT"
        author = "APTtrail Automated Collection"
        apt_group = "FLIGHTNIGHT"
        reference = "https://blog.eclecticiq.com/operation-flightnight-indian-government-entities-and-energy-sector-targeted-by-cyber-espionage-campaign"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "alfarabischoolgroup\.slack\.com" ascii wide nocase
        $domain1 = "solucionesgeofisicas\.slack\.com" ascii wide nocase
        $domain2 = "swiftrecruiters\.slack\.com" ascii wide nocase
        $domain3 = "telcomprodicci\.slack\.com" ascii wide nocase
        $domain4 = "tucker-group\.slack\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_FLYINGYETI
{
    meta:
        description = "Detects IOCs associated with APT FLYINGYETI"
        author = "APTtrail Automated Collection"
        apt_group = "FLYINGYETI"
        aliases = "cookbox"
        reference = "https://blog.cloudflare.com/disrupting-flyingyeti-campaign-targeting-ukraine"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "array\.myftp\.biz" ascii wide nocase
        $domain1 = "bom02\.gotdns\.ch" ascii wide nocase
        $domain2 = "postdock\.serveftp\.com" ascii wide nocase
        $domain3 = "worker-polished-union-f396\.vqu89698\.workers\.dev" ascii wide nocase
        $domain4 = "worker-test-6f41\.idv64828\.workers\.dev" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_FORUMTROLL
{
    meta:
        description = "Detects IOCs associated with APT FORUMTROLL"
        author = "APTtrail Automated Collection"
        apt_group = "FORUMTROLL"
        aliases = "taxoff, team46"
        reference = "https://app.validin.com/detail?find=Future%20Bull&type=raw&ref_id=41bde129bf6#tab=host_pairs (# 2025-06-18)"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "2025primakovreadings\.info" ascii wide nocase
        $domain1 = "ads-stream-api-v2\.global\.ssl\.fastly\.net" ascii wide nocase
        $domain2 = "browser-time-stats\.global\.ssl\.fastly\.net" ascii wide nocase
        $domain3 = "clip-rdp-api\.global\.ssl\.fastly\.net" ascii wide nocase
        $domain4 = "common-rdp-front\.global\.ssl\.fastly\.net" ascii wide nocase
        $domain5 = "cybers46\.team" ascii wide nocase
        $domain6 = "cybers4646\.my\.id" ascii wide nocase
        $domain7 = "fast-telemetry-api\.global\.ssl\.fastly\.net" ascii wide nocase
        $domain8 = "front-static-api\.global\.ssl\.fastly\.net" ascii wide nocase
        $domain9 = "futurebull\.live" ascii wide nocase
        $domain10 = "futurebull\.net" ascii wide nocase
        $domain11 = "globaloneai\.com" ascii wide nocase
        $domain12 = "infosecteam\.info" ascii wide nocase
        $domain13 = "main-front-api\.global\.ssl\.fastly\.net" ascii wide nocase
        $domain14 = "mil-by\.info" ascii wide nocase
        $domain15 = "ms-appdata-fonts\.global\.ssl\.fastly\.net" ascii wide nocase
        $domain16 = "ms-appdata-main\.global\.ssl\.fastly\.net" ascii wide nocase
        $domain17 = "ms-appdata-query\.global\.ssl\.fastly\.net" ascii wide nocase
        $domain18 = "primakovreadings\.info" ascii wide nocase
        $domain19 = "primakovreadings2025\.info" ascii wide nocase
        $domain20 = "rabotnik\.today" ascii wide nocase
        $domain21 = "rdp-api-front\.global\.ssl\.fastly\.net" ascii wide nocase
        $domain22 = "rdp-query-api\.global\.ssl\.fastly\.net" ascii wide nocase
        $domain23 = "rdp-statistics-api\.global\.ssl\.fastly\.net" ascii wide nocase
        $domain24 = "srv480138\.hstgr\.cloud" ascii wide nocase
        $domain25 = "srv484118\.hstgr\.cloud" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_FRUITYARMOR
{
    meta:
        description = "Detects IOCs associated with APT FRUITYARMOR"
        author = "APTtrail Automated Collection"
        apt_group = "FRUITYARMOR"
        reference = "https://securelist.com/cve-2018-8453-used-in-targeted-attacks/88151/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "shelves-design\.com" ascii wide nocase
        $domain1 = "weekendstrips\.net" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_GAMAREDON
{
    meta:
        description = "Detects IOCs associated with APT GAMAREDON"
        author = "APTtrail Automated Collection"
        apt_group = "GAMAREDON"
        aliases = "actinium, apt-c-53, armageddon"
        reference = "http://lists.emergingthreats.net/pipermail/emerging-sigs/2021-November/030492.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "0\.elitoras\.ru" ascii wide nocase
        $domain1 = "0\.hustorla\.ru" ascii wide nocase
        $domain2 = "001912184\.retarus\.ru" ascii wide nocase
        $domain3 = "02\.belkort\.ru" ascii wide nocase
        $domain4 = "02\.bortogat\.ru" ascii wide nocase
        $domain5 = "02\.domasq\.ru" ascii wide nocase
        $domain6 = "02\.elitoras\.ru" ascii wide nocase
        $domain7 = "02\.timerto\.ru" ascii wide nocase
        $domain8 = "02\.vadilops\.ru" ascii wide nocase
        $domain9 = "02\.voranfi\.ru" ascii wide nocase
        $domain10 = "03\.bortogat\.ru" ascii wide nocase
        $domain11 = "03\.domasq\.ru" ascii wide nocase
        $domain12 = "03\.elitoras\.ru" ascii wide nocase
        $domain13 = "03\.protimas\.ru" ascii wide nocase
        $domain14 = "03\.vadilops\.ru" ascii wide nocase
        $domain15 = "03\.voranfi\.ru" ascii wide nocase
        $domain16 = "032xwkhts\.corolain\.ru" ascii wide nocase
        $domain17 = "043\.libellus\.ru" ascii wide nocase
        $domain18 = "04djgx9h1\.corolain\.ru" ascii wide nocase
        $domain19 = "06ez6x\.moolin\.ru" ascii wide nocase
        $domain20 = "0apkhude1h8biwnd\.spotifik\.ru" ascii wide nocase
        $domain21 = "0e42557e7ebf4251bad6d1e53a680dfb\.hopers\.ru" ascii wide nocase
        $domain22 = "0ejbfnz2mkneq14e46\.moolin\.ru" ascii wide nocase
        $domain23 = "0enhzs\.moolin\.ru" ascii wide nocase
        $domain24 = "0f6vi2h1w\.corolain\.ru" ascii wide nocase
        $domain25 = "0gcqbjhae4qj\.metanat\.ru" ascii wide nocase
        $domain26 = "0gg2nmb5vnea\.jolotras\.ru" ascii wide nocase
        $domain27 = "0hwo4ajnr\.corolain\.ru" ascii wide nocase
        $domain28 = "0ievltomh\.corolain\.ru" ascii wide nocase
        $domain29 = "0ivrlzyk\.moolin\.ru" ascii wide nocase
        $domain30 = "0jbnpsvrh\.corolain\.ru" ascii wide nocase
        $domain31 = "0jx4m1e8w7nojrwq2\.jolotras\.ru" ascii wide nocase
        $domain32 = "0lhrreh6l2\.moolin\.ru" ascii wide nocase
        $domain33 = "0ni4zdjeo\.corolain\.ru" ascii wide nocase
        $domain34 = "0nxfri\.moolin\.ru" ascii wide nocase
        $domain35 = "0ov\.libellus\.ru" ascii wide nocase
        $domain36 = "0rvbbrnjj\.corolain\.ru" ascii wide nocase
        $domain37 = "0rweqv9ui\.corolain\.ru" ascii wide nocase
        $domain38 = "0sn1nauyr\.corolain\.ru" ascii wide nocase
        $domain39 = "0tdkq2ss6yxnebgozvia\.jolotras\.ru" ascii wide nocase
        $domain40 = "0u3cn4ywt\.corolain\.ru" ascii wide nocase
        $domain41 = "0x2i7nbojeywnm64gfp5\.jolotras\.ru" ascii wide nocase
        $domain42 = "0zua3pmf6\.corolain\.ru" ascii wide nocase
        $domain43 = "1\.hustorla\.ru" ascii wide nocase
        $domain44 = "1\.timerto\.ru" ascii wide nocase
        $domain45 = "100\.potrakit\.ru" ascii wide nocase
        $domain46 = "100032482\.corolain\.ru" ascii wide nocase
        $domain47 = "1000576313\.corolain\.ru" ascii wide nocase
        $domain48 = "100066590\.corolain\.ru" ascii wide nocase
        $domain49 = "1000940450\.retarus\.ru" ascii wide nocase
        $ip50 = "124.15.125.1" ascii wide
        $ip51 = "159.65.63.215" ascii wide
        $ip52 = "159.65.63.215" ascii wide
        $ip53 = "162.33.178.129" ascii wide
        $ip54 = "176.57.220.210" ascii wide
        $ip55 = "185.45.193.31" ascii wide
        $ip56 = "188.225.25.132" ascii wide
        $ip57 = "188.225.44.138" ascii wide
        $ip58 = "188.225.78.105" ascii wide
        $ip59 = "194.58.100.230" ascii wide
        $ip60 = "194.58.56.169" ascii wide
        $ip61 = "194.58.56.34" ascii wide
        $ip62 = "194.67.105.190" ascii wide
        $ip63 = "194.67.109.164" ascii wide
        $ip64 = "195.62.52.93" ascii wide
        $ip65 = "195.62.53.63" ascii wide
        $ip66 = "195.88.208.51" ascii wide
        $ip67 = "2.59.37.5" ascii wide
        $ip68 = "31.31.204.59" ascii wide
        $ip69 = "45.10.246.103" ascii wide
        $ip70 = "45.61.138.226" ascii wide
        $ip71 = "5.101.88.18" ascii wide
        $ip72 = "5.252.176.52" ascii wide
        $ip73 = "5.252.178.184" ascii wide
        $ip74 = "84.32.188.31" ascii wide
        $ip75 = "84.32.188.31" ascii wide
        $ip76 = "89.223.123.121" ascii wide
        $ip77 = "92.53.119.52" ascii wide
        $url78 = "/infant\.php" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_GAMAREDON_1
{
    meta:
        description = "Detects IOCs associated with APT GAMAREDON-1"
        author = "APTtrail Automated Collection"
        apt_group = "GAMAREDON-1"
        aliases = "pteroeffigy, pterographin, pterolnk"
        reference = "https://app.validin.com/axon?find=31.129.22.48"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "0-index\.aytashpo\.ru" ascii wide nocase
        $domain1 = "0-tlcovid19-private\.veligo\.ru" ascii wide nocase
        $domain2 = "0\.agasibi\.ru" ascii wide nocase
        $domain3 = "0\.bahramt\.ru" ascii wide nocase
        $domain4 = "0\.bayramgo\.ru" ascii wide nocase
        $domain5 = "0\.payamt\.ru" ascii wide nocase
        $domain6 = "0031-sysfs\.aytashpo\.ru" ascii wide nocase
        $domain7 = "0069-bluetooth-fallback-to-sco-on-error-code-0x10-connect\.aytashpo\.ru" ascii wide nocase
        $domain8 = "007b9f33257f40a1ae9ad17e81497620\.hopers\.ru" ascii wide nocase
        $domain9 = "01\.arasht\.ru" ascii wide nocase
        $domain10 = "01\.bahramt\.ru" ascii wide nocase
        $domain11 = "01\.payamt\.ru" ascii wide nocase
        $domain12 = "02\.nightmit\.ru" ascii wide nocase
        $domain13 = "02\.payamt\.ru" ascii wide nocase
        $domain14 = "03\.arasht\.ru" ascii wide nocase
        $domain15 = "03\.bahramt\.ru" ascii wide nocase
        $domain16 = "03\.payamt\.ru" ascii wide nocase
        $domain17 = "03\.vilviton\.ru" ascii wide nocase
        $domain18 = "038422dd0aa7bc54f58f64956b4d8724\.hitorova\.ru" ascii wide nocase
        $domain19 = "09cb592b8982431fbdeba0d65dcedb47\.hopers\.ru" ascii wide nocase
        $domain20 = "0aaqhwf689wwecsz\.stradrol\.ru" ascii wide nocase
        $domain21 = "0b88948c8cc34efca2dfad9841aee4a5\.vasimgo\.ru" ascii wide nocase
        $domain22 = "0fd3a83fa12b4f21b96c61e0791b2826\.validgo\.ru" ascii wide nocase
        $domain23 = "0qh7kk5z-80\.euw\.devtunnels\.ms" ascii wide nocase
        $domain24 = "0wlxbqv4pfbm\.celticso\.ru" ascii wide nocase
        $domain25 = "0wsw44lbs6\.paramants\.ru" ascii wide nocase
        $domain26 = "0xgggj25-80\.euw\.devtunnels\.ms" ascii wide nocase
        $domain27 = "1\.arasht\.ru" ascii wide nocase
        $domain28 = "1\.bayramgo\.ru" ascii wide nocase
        $domain29 = "1\.payamt\.ru" ascii wide nocase
        $domain30 = "10\.bahramt\.ru" ascii wide nocase
        $domain31 = "10\.bayramgo\.ru" ascii wide nocase
        $domain32 = "10\.payamt\.ru" ascii wide nocase
        $domain33 = "1000000109\.pasamart\.ru" ascii wide nocase
        $domain34 = "1000061142\.ganara\.ru" ascii wide nocase
        $domain35 = "100064636\.polutar\.ru" ascii wide nocase
        $domain36 = "1001012353\.wicksl\.ru" ascii wide nocase
        $domain37 = "100103493\.makasd\.ru" ascii wide nocase
        $domain38 = "1001241254\.humahu\.ru" ascii wide nocase
        $domain39 = "100131717\.dfgqdsd\.ru" ascii wide nocase
        $domain40 = "1001583341\.wicksl\.ru" ascii wide nocase
        $domain41 = "1001774425\.makasd\.ru" ascii wide nocase
        $domain42 = "1001812139\.gokols\.ru" ascii wide nocase
        $domain43 = "1002139495\.ganara\.ru" ascii wide nocase
        $domain44 = "100215046\.gokols\.ru" ascii wide nocase
        $domain45 = "1002427615\.patrios\.ru" ascii wide nocase
        $domain46 = "1002763297\.patrios\.ru" ascii wide nocase
        $domain47 = "1002834610\.kurapat\.ru" ascii wide nocase
        $domain48 = "1002928871\.makasd\.ru" ascii wide nocase
        $domain49 = "1003576324\.kurapat\.ru" ascii wide nocase
        $ip50 = "141.8.192.151" ascii wide
        $ip51 = "141.8.197.42" ascii wide
        $ip52 = "159.89.205.135" ascii wide
        $ip53 = "185.186.26.98" ascii wide
        $ip54 = "206.189.188.38" ascii wide
        $ip55 = "5.252.178.181" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_GAZA
{
    meta:
        description = "Detects IOCs associated with APT GAZA"
        author = "APTtrail Automated Collection"
        apt_group = "GAZA"
        aliases = "ta402"
        reference = "https://app.any.run/tasks/3e9d412a-49c9-48db-8b1f-f6fe55414b17/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "0arfx4grailorhvlicbj\.servehumour\.com" ascii wide nocase
        $domain1 = "0n4tblbdfncaauxioxto\.ddns\.net" ascii wide nocase
        $domain2 = "3tshhm1nfphiqqrxbi8c\.servehumour\.com" ascii wide nocase
        $domain3 = "aaas\.mefound\.com" ascii wide nocase
        $domain4 = "acc\.buybit\.us" ascii wide nocase
        $domain5 = "accounts-helper\.ml" ascii wide nocase
        $domain6 = "adfdafsggdfgdfgsagaer\.blogsyte\.com" ascii wide nocase
        $domain7 = "adsmartweb9\.com" ascii wide nocase
        $domain8 = "ajaxo\.zapto\.org" ascii wide nocase
        $domain9 = "alasra-paper\.duckdns\.org" ascii wide nocase
        $domain10 = "aqs\.filezellasd\.co\.vu" ascii wide nocase
        $domain11 = "aracaravan\.com" ascii wide nocase
        $domain12 = "backjadwer\.bounceme\.net" ascii wide nocase
        $domain13 = "backop\.mooo\.com" ascii wide nocase
        $domain14 = "bandao\.publicvm\.com" ascii wide nocase
        $domain15 = "baz\.downloadcor\.xyz" ascii wide nocase
        $domain16 = "beatricewarner\.com" ascii wide nocase
        $domain17 = "bulk-smtp\.xyz" ascii wide nocase
        $domain18 = "bundanesia\.com" ascii wide nocase
        $domain19 = "buy\.israel-shipment\.xyz" ascii wide nocase
        $domain20 = "bypasstesting\.servehalflife\.com" ascii wide nocase
        $domain21 = "cbbnews\.tk" ascii wide nocase
        $domain22 = "cccam\.serveblog\.net" ascii wide nocase
        $domain23 = "checktest\.www1\.biz" ascii wide nocase
        $domain24 = "chromeupdt\.tk" ascii wide nocase
        $domain25 = "cl170915\.otzo\.com" ascii wide nocase
        $domain26 = "claire-conway\.com" ascii wide nocase
        $domain27 = "cloudserviceapi\.online" ascii wide nocase
        $domain28 = "cnaci8gyolttkgmguzog\.ignorelist\.com" ascii wide nocase
        $domain29 = "cyaxsnieccunozn0erih\.mefound\.com" ascii wide nocase
        $domain30 = "cyber-peace\.org" ascii wide nocase
        $domain31 = "cyber18\.no-ip\.net" ascii wide nocase
        $domain32 = "d\.nabzerd\.co\.vu" ascii wide nocase
        $domain33 = "dapoerwedding\.com" ascii wide nocase
        $domain34 = "data-server\.cloudns\.club" ascii wide nocase
        $domain35 = "deapka\.sytes\.net" ascii wide nocase
        $domain36 = "debka\.ga" ascii wide nocase
        $domain37 = "depka\.sytes\.net" ascii wide nocase
        $domain38 = "dfwsd\.co\.vu" ascii wide nocase
        $domain39 = "direct-marketing\.ml" ascii wide nocase
        $domain40 = "directl\.otzo\.com" ascii wide nocase
        $domain41 = "dji-msi\.2waky\.com" ascii wide nocase
        $domain42 = "dnsfor\.dnsfor\.me" ascii wide nocase
        $domain43 = "dontrplay\.tk" ascii wide nocase
        $domain44 = "dorcertg\.otzo\.com" ascii wide nocase
        $domain45 = "down\.downloadcor\.xyz" ascii wide nocase
        $domain46 = "down\.supportcom\.xyz" ascii wide nocase
        $domain47 = "download\.data-server\.cloudns\.club" ascii wide nocase
        $domain48 = "download\.likescandy\.com" ascii wide nocase
        $domain49 = "downloadlog\.linkpc\.net" ascii wide nocase
        $ip50 = "149.28.137.224" ascii wide
        $ip51 = "79.124.60.40" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_GHOSTEMPEROR
{
    meta:
        description = "Detects IOCs associated with APT GHOSTEMPEROR"
        author = "APTtrail Automated Collection"
        apt_group = "GHOSTEMPEROR"
        aliases = "entryshell, sparrowdoor, xiangoop"
        reference = "https://securelist.com/ghostemperor-from-proxylogon-to-kernel-mode/104407/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "aftercould\.com" ascii wide nocase
        $domain1 = "amelicen\.com" ascii wide nocase
        $domain2 = "datacentreonline\.com" ascii wide nocase
        $domain3 = "dateupdata\.com" ascii wide nocase
        $domain4 = "freedecrease\.com" ascii wide nocase
        $domain5 = "game\.newfreepre\.com" ascii wide nocase
        $domain6 = "imap\.dateupdata\.com" ascii wide nocase
        $domain7 = "imap\.newlylab\.com" ascii wide nocase
        $domain8 = "imap\.webdignusdata\.com" ascii wide nocase
        $domain9 = "mail\.reclubpress\.com" ascii wide nocase
        $domain10 = "newfreepre\.com" ascii wide nocase
        $domain11 = "newlylab\.com" ascii wide nocase
        $domain12 = "reclubpress\.com" ascii wide nocase
        $domain13 = "webdignusdata\.com" ascii wide nocase
        $ip14 = "103.85.25.166" ascii wide
        $ip15 = "107.148.165.158" ascii wide
        $ip16 = "107.148.165.158" ascii wide
        $ip17 = "154.223.135.214" ascii wide
        $ip18 = "154.223.135.214" ascii wide
        $ip19 = "27.102.113.240" ascii wide
        $ip20 = "27.102.113.240" ascii wide
        $ip21 = "27.102.113.57" ascii wide
        $ip22 = "27.102.113.57" ascii wide
        $ip23 = "27.102.114.55" ascii wide
        $ip24 = "27.102.114.55" ascii wide
        $ip25 = "27.102.115.51" ascii wide
        $ip26 = "27.102.115.51" ascii wide
        $ip27 = "27.102.129.120" ascii wide
        $ip28 = "27.102.129.120" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_GLASSES
{
    meta:
        description = "Detects IOCs associated with APT GLASSES"
        author = "APTtrail Automated Collection"
        apt_group = "GLASSES"
        reference = "https://citizenlab.ca/2013/02/apt1s-glasses-watching-a-human-rights-organization/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "ewplus\.com" ascii wide nocase
        $domain1 = "tcw\.homier\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_GOLDDRAGON
{
    meta:
        description = "Detects IOCs associated with APT GOLDDRAGON"
        author = "APTtrail Automated Collection"
        apt_group = "GOLDDRAGON"
        aliases = "brave prince, ghost419, gold dragon"
        reference = "https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/gold-dragon-widens-olympics-malware-attacks-gains-permanent-presence-on-victims-systems/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "0523qyfw\.cn" ascii wide nocase
        $domain1 = "0523qyfw\.com" ascii wide nocase
        $domain2 = "eodo1\.000webhostapp\.com" ascii wide nocase
        $domain3 = "followgho\.byethost7\.com" ascii wide nocase
        $domain4 = "ink\.inkboom\.co\.kr" ascii wide nocase
        $domain5 = "nid-help-pchange\.atwebpages\.com" ascii wide nocase
        $domain6 = "nyazz\.com" ascii wide nocase
        $domain7 = "one\.0523qyfw\.com" ascii wide nocase
        $domain8 = "redi\.nyazz\.com" ascii wide nocase
        $domain9 = "scrt1\.nyazz\.com" ascii wide nocase
        $domain10 = "ssh\.0523qyfw\.cn" ascii wide nocase
        $domain11 = "ssh\.0523qyfw\.com" ascii wide nocase
        $domain12 = "trydai\.000webhostapp\.com" ascii wide nocase
        $ip13 = "107.148.61.127" ascii wide
        $ip14 = "154.19.200.133" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_GOLDENJACKAL
{
    meta:
        description = "Detects IOCs associated with APT GOLDENJACKAL"
        author = "APTtrail Automated Collection"
        apt_group = "GOLDENJACKAL"
        reference = "https://securelist.com/goldenjackal-apt-group/109677/"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "83.24.9.124" ascii wide

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_GOLDENRAT
{
    meta:
        description = "Detects IOCs associated with APT GOLDENRAT"
        author = "APTtrail Automated Collection"
        apt_group = "GOLDENRAT"
        reference = "https://vxcube.com/recent-threats-ioc/5b56b22da39bb5094a3c9231/detail"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "bashalalassad1sea\.noip\.me" ascii wide nocase
        $domain1 = "bbbb4\.noip\.me" ascii wide nocase
        $domain2 = "chatsecurelite\.uk\.to" ascii wide nocase
        $domain3 = "chatsecurelite\.us\.to" ascii wide nocase
        $domain4 = "telegram\.strangled\.net" ascii wide nocase
        $domain5 = "telgram\.strangled\.net" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_GOLDMELODY
{
    meta:
        description = "Detects IOCs associated with APT GOLDMELODY"
        author = "APTtrail Automated Collection"
        apt_group = "GOLDMELODY"
        aliases = "AUDITUNNEL, IHS Back-Connect backdoor"
        reference = "https://otx.alienvault.com/pulse/6511e50028c3953453406132"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "149.28.193.216" ascii wide
        $ip1 = "149.28.200.140" ascii wide
        $ip2 = "149.28.207.120" ascii wide
        $ip3 = "195.123.240.183" ascii wide
        $ip4 = "40.76.20.11" ascii wide
        $ip5 = "64.190.113.185" ascii wide
        $ip6 = "67.205.135.147" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_GOLDMOUSE
{
    meta:
        description = "Detects IOCs associated with APT GOLDMOUSE"
        author = "APTtrail Automated Collection"
        apt_group = "GOLDMOUSE"
        aliases = "apt-c-27, goldmouse"
        reference = "https://ti.360.net/blog/articles/apt-c-27-(goldmouse):-suspected-target-attack-against-the-middle-east-with-winrar-exploit-en/"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "82.137.255.56" ascii wide
        $ip1 = "82.137.255.56" ascii wide
        $ip2 = "82.137.255.56" ascii wide
        $ip3 = "82.137.255.56" ascii wide
        $ip4 = "82.137.255.56" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_GORGON
{
    meta:
        description = "Detects IOCs associated with APT GORGON"
        author = "APTtrail Automated Collection"
        apt_group = "GORGON"
        reference = "https://app.any.run/tasks/bb1279af-7fff-4b37-8439-7b303f113082/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "0-day\.us" ascii wide nocase
        $domain1 = "1688jtn\.com" ascii wide nocase
        $domain2 = "41230077\.net" ascii wide nocase
        $domain3 = "6474sss\.com" ascii wide nocase
        $domain4 = "acorn-paper\.com" ascii wide nocase
        $domain5 = "asaigoldenrice\.com" ascii wide nocase
        $domain6 = "asdiamecwecw8cew\.blogspot\.com" ascii wide nocase
        $domain7 = "bjm9\.blogspot\.com" ascii wide nocase
        $domain8 = "brevini-france\.cf" ascii wide nocase
        $domain9 = "buydildoonline\.blogspot\.com" ascii wide nocase
        $domain10 = "bylgay\.hopto\.org" ascii wide nocase
        $domain11 = "diamondfoxpanel\.ml" ascii wide nocase
        $domain12 = "dixis\.bounceme\.net" ascii wide nocase
        $domain13 = "downloads\.blogsyte\.com" ascii wide nocase
        $domain14 = "emawattttson\.blogspot\.com" ascii wide nocase
        $domain15 = "fast-cargo\.com" ascii wide nocase
        $domain16 = "gritodopovo\.com\.br" ascii wide nocase
        $domain17 = "grupomsi\.com" ascii wide nocase
        $domain18 = "guelphupholstery\.com" ascii wide nocase
        $domain19 = "hongmenwenhua\.com" ascii wide nocase
        $domain20 = "ichoubyou\.net" ascii wide nocase
        $domain21 = "klapki\.online" ascii wide nocase
        $domain22 = "microsoftoutlook\.duckdns\.org" ascii wide nocase
        $domain23 = "miganshumarataa\.blogspot\.com" ascii wide nocase
        $domain24 = "ocha-gidi\.xyz" ascii wide nocase
        $domain25 = "onedrivenet\.xyz" ascii wide nocase
        $domain26 = "panelonetwothree\.ga" ascii wide nocase
        $domain27 = "panelonetwothree\.ml" ascii wide nocase
        $domain28 = "qp0o1j3-dmv4kwncw8e\.win" ascii wide nocase
        $domain29 = "securebotnetpanel\.tk" ascii wide nocase
        $domain30 = "stemtopx\.com" ascii wide nocase
        $domain31 = "stevemike-fireforce\.info" ascii wide nocase
        $domain32 = "stevemikeforce\.com" ascii wide nocase
        $domain33 = "sukfat\.com" ascii wide nocase
        $domain34 = "sxasxasxssaxxsasxasx\.blogspot\.com" ascii wide nocase
        $domain35 = "theaterloops\.com" ascii wide nocase
        $domain36 = "thedip\.zone" ascii wide nocase
        $domain37 = "tourismmanagement\.mba" ascii wide nocase
        $domain38 = "treffictesgn\.blogspot\.com" ascii wide nocase
        $domain39 = "x-ghost91\.ddns\.net" ascii wide nocase
        $domain40 = "xaasxasxasx\.blogspot\.com" ascii wide nocase
        $domain41 = "xyz-storez\.xyz" ascii wide nocase
        $domain42 = "ycsfuoabdicating\.review" ascii wide nocase
        $domain43 = "zupaservices\.info" ascii wide nocase
        $ip44 = "196.185.215.228" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_GOTHICPANDA
{
    meta:
        description = "Detects IOCs associated with APT GOTHICPANDA"
        author = "APTtrail Automated Collection"
        apt_group = "GOTHICPANDA"
        aliases = "apt-c-3, apt3, ups"
        reference = "https://www.fireeye.com/blog/threat-research/2014/11/operation_doubletap.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "bedircati\.com" ascii wide nocase
        $domain1 = "lamb-site\.com" ascii wide nocase
        $domain2 = "link\.angellroofing\.com" ascii wide nocase
        $domain3 = "playboysplus\.com" ascii wide nocase
        $domain4 = "psa\.perrydale\.com" ascii wide nocase
        $domain5 = "report\.perrydale\.com" ascii wide nocase
        $domain6 = "rpt\.perrydale\.com" ascii wide nocase
        $domain7 = "securitywap\.com" ascii wide nocase
        $domain8 = "vic\.perrydale\.com" ascii wide nocase
        $domain9 = "walterclean\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_GRAYLING
{
    meta:
        description = "Detects IOCs associated with APT GRAYLING"
        author = "APTtrail Automated Collection"
        apt_group = "GRAYLING"
        reference = "https://cybersecuritynews.com/apt-group-custom-malware/"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "45.148.120.23" ascii wide

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_GREENSPOT
{
    meta:
        description = "Detects IOCs associated with APT GREENSPOT"
        author = "APTtrail Automated Collection"
        apt_group = "GREENSPOT"
        aliases = "apt-c-01, poison ivy"
        reference = "https://hunt.io/blog/greenspot-apt-targets-163com-fake-downloads-spoofing"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "126mailserver\.serveftp\.com" ascii wide nocase
        $domain1 = "143-244-183-240\.cprapid\.com" ascii wide nocase
        $domain2 = "360urlscan\.com" ascii wide nocase
        $domain3 = "64-176-165-42\.cprapid\.com" ascii wide nocase
        $domain4 = "6c99b2c4cf5a\.expolebanon\.com" ascii wide nocase
        $domain5 = "access\.webplurk\.com" ascii wide nocase
        $domain6 = "accounts126\.com" ascii wide nocase
        $domain7 = "afte856422126\.com" ascii wide nocase
        $domain8 = "aliago\.dyndns\.dk" ascii wide nocase
        $domain9 = "annie165\.zyns\.com" ascii wide nocase
        $domain10 = "app\.newfacebk\.com" ascii wide nocase
        $domain11 = "as1688\.webhop\.org" ascii wide nocase
        $domain12 = "atrew56877\.com" ascii wide nocase
        $domain13 = "avdsart\.com" ascii wide nocase
        $domain14 = "babana\.wikaba\.com" ascii wide nocase
        $domain15 = "backaaa\.beijingdasihei\.com" ascii wide nocase
        $domain16 = "bearingonly\.rebatesrule\.net" ascii wide nocase
        $domain17 = "bribieislandhistory\.com" ascii wide nocase
        $domain18 = "bt0116\.servebbs\.net" ascii wide nocase
        $domain19 = "buendnis-fuer-kinder\.com" ascii wide nocase
        $domain20 = "caac-cn\.com" ascii wide nocase
        $domain21 = "caac-cn\.org" ascii wide nocase
        $domain22 = "canberk\.gecekodu\.com" ascii wide nocase
        $domain23 = "ceepitbj\.servepics\.com" ascii wide nocase
        $domain24 = "censor\.site" ascii wide nocase
        $domain25 = "center-gai\.com" ascii wide nocase
        $domain26 = "certifications\.services" ascii wide nocase
        $domain27 = "chamber\.icu" ascii wide nocase
        $domain28 = "check\.blogdns\.com" ascii wide nocase
        $domain29 = "china\.serveblog\.net" ascii wide nocase
        $domain30 = "chinamil\.lflink\.com" ascii wide nocase
        $domain31 = "chinmori\.com" ascii wide nocase
        $domain32 = "cloudattaches-126\.com" ascii wide nocase
        $domain33 = "clouddevice\.site" ascii wide nocase
        $domain34 = "clouddrive\.space" ascii wide nocase
        $domain35 = "cluster\.safe360\.dns05\.com" ascii wide nocase
        $domain36 = "cnsa163\.com" ascii wide nocase
        $domain37 = "cnwww\.m-music\.net" ascii wide nocase
        $domain38 = "co-journal163\.com" ascii wide nocase
        $domain39 = "co-journalyeah\.net" ascii wide nocase
        $domain40 = "comehigh\.mefound\.com" ascii wide nocase
        $domain41 = "contracter\.org" ascii wide nocase
        $domain42 = "daotongintelligence163\.com" ascii wide nocase
        $domain43 = "datamasterw\.com" ascii wide nocase
        $domain44 = "difusora890\.com" ascii wide nocase
        $domain45 = "dockerswarm2\.cic-webpro\.com" ascii wide nocase
        $domain46 = "download163ease\.com" ascii wide nocase
        $domain47 = "eadfg56877\.com" ascii wide nocase
        $domain48 = "eco163\.com" ascii wide nocase
        $domain49 = "eleusina\.com" ascii wide nocase
        $ip50 = "128.199.134.3" ascii wide
        $ip51 = "158.247.208.174" ascii wide
        $ip52 = "202.182.108.174" ascii wide
        $ip53 = "207.148.126.90" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_GREF
{
    meta:
        description = "Detects IOCs associated with APT GREF"
        author = "APTtrail Automated Collection"
        apt_group = "GREF"
        reference = "https://blog.lookout.com/multiyear-surveillance-campaigns-discovered-targeting-uyghurs"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "6006\.secpert\.com" ascii wide nocase
        $domain1 = "6006\.upupdate\.cn" ascii wide nocase
        $domain2 = "789aa654\.top" ascii wide nocase
        $domain3 = "adoptewer\.com" ascii wide nocase
        $domain4 = "allshell\.net" ascii wide nocase
        $domain5 = "allwhatsapp\.net" ascii wide nocase
        $domain6 = "amote-366\.vicp\.cc" ascii wide nocase
        $domain7 = "anar\.gleeze\.com" ascii wide nocase
        $domain8 = "android\.apps\.us\.to" ascii wide nocase
        $domain9 = "androidapps\.duia\.in" ascii wide nocase
        $domain10 = "androidapps\.fvk\.cc" ascii wide nocase
        $domain11 = "androidapps\.home\.hn\.org" ascii wide nocase
        $domain12 = "androidapps\.jetos\.com" ascii wide nocase
        $domain13 = "androidapps\.linkpc\.net" ascii wide nocase
        $domain14 = "androidapps\.myfirewall\.org" ascii wide nocase
        $domain15 = "androidapps\.nerdpol\.ovh" ascii wide nocase
        $domain16 = "androidapps\.npff\.co" ascii wide nocase
        $domain17 = "androidapps\.nsupdate\.info" ascii wide nocase
        $domain18 = "androidapps\.spdns\.eu" ascii wide nocase
        $domain19 = "androidapps\.spdns\.org" ascii wide nocase
        $domain20 = "androidapps\.tempors\.com" ascii wide nocase
        $domain21 = "androidsapps\.ml" ascii wide nocase
        $domain22 = "api--telegram\.ru" ascii wide nocase
        $domain23 = "api\.telegram5\.org" ascii wide nocase
        $domain24 = "api\.telegramrc\.com" ascii wide nocase
        $domain25 = "app\.telegramrc\.com" ascii wide nocase
        $domain26 = "attoo1s\.com" ascii wide nocase
        $domain27 = "babyedu-online\.com" ascii wide nocase
        $domain28 = "battle\.com\.tw" ascii wide nocase
        $domain29 = "bhvghg\.com" ascii wide nocase
        $domain30 = "cdngoogle\.com" ascii wide nocase
        $domain31 = "cisco-inc\.net" ascii wide nocase
        $domain32 = "coco\.wikaba\.com" ascii wide nocase
        $domain33 = "comeflxyr\.com" ascii wide nocase
        $domain34 = "cookedu-online\.com" ascii wide nocase
        $domain35 = "diablo-iii\.mobi" ascii wide nocase
        $domain36 = "down\.telegramxo\.com" ascii wide nocase
        $domain37 = "englishedu-online\.com" ascii wide nocase
        $domain38 = "everydayinfo\.top" ascii wide nocase
        $domain39 = "fgttgvh\.com" ascii wide nocase
        $domain40 = "flygram\.org" ascii wide nocase
        $domain41 = "flygram\.orgproxy1\.signalplus\.org" ascii wide nocase
        $domain42 = "fufijxgkg\.com" ascii wide nocase
        $domain43 = "gefacebook\.com" ascii wide nocase
        $domain44 = "ggl\.whoscaller\.net" ascii wide nocase
        $domain45 = "gheyret\.com" ascii wide nocase
        $domain46 = "gheyret\.net" ascii wide nocase
        $domain47 = "goldplusapp\.net" ascii wide nocase
        $domain48 = "googleanalyseservice\.net" ascii wide nocase
        $domain49 = "googlemapsoftware\.com" ascii wide nocase
        $ip50 = "103.27.186.156" ascii wide
        $ip51 = "103.27.186.195" ascii wide
        $ip52 = "142.132.131.28" ascii wide
        $ip53 = "142.132.131.28" ascii wide
        $ip54 = "142.132.131.28" ascii wide
        $ip55 = "142.132.131.28" ascii wide
        $ip56 = "148.251.87.245" ascii wide
        $ip57 = "148.251.87.247" ascii wide
        $ip58 = "148.251.87.247" ascii wide
        $ip59 = "148.251.87.247" ascii wide
        $ip60 = "148.251.87.247" ascii wide
        $ip61 = "154.202.59.169" ascii wide
        $ip62 = "154.212.147.129" ascii wide
        $ip63 = "185.239.227.14" ascii wide
        $ip64 = "195.154.60.3" ascii wide
        $ip65 = "195.154.60.3" ascii wide
        $ip66 = "195.154.60.3" ascii wide
        $ip67 = "195.154.60.3" ascii wide
        $ip68 = "217.163.29.84" ascii wide
        $ip69 = "23.88.28.222" ascii wide
        $ip70 = "45.133.238.92" ascii wide
        $ip71 = "45.154.12.132" ascii wide
        $ip72 = "45.154.12.151" ascii wide
        $ip73 = "45.154.12.202" ascii wide
        $ip74 = "45.63.89.238" ascii wide
        $ip75 = "62.210.28.116" ascii wide
        $ip76 = "62.210.30.158" ascii wide
        $ip77 = "62.210.30.158" ascii wide
        $ip78 = "62.210.30.158" ascii wide
        $ip79 = "62.210.30.158" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_GREYENERGY
{
    meta:
        description = "Detects IOCs associated with APT GREYENERGY"
        author = "APTtrail Automated Collection"
        apt_group = "GREYENERGY"
        reference = "https://github.com/eset/malware-ioc/tree/master/greyenergy"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "82.118.236.23" ascii wide
        $ip1 = "82.118.236.23" ascii wide
        $ip2 = "88.198.13.116" ascii wide
        $ip3 = "88.198.13.116" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_GROUNDBAIT
{
    meta:
        description = "Detects IOCs associated with APT GROUNDBAIT"
        author = "APTtrail Automated Collection"
        apt_group = "GROUNDBAIT"
        reference = "https://github.com/eset/malware-ioc/tree/master/groundbait"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "bolepaund\.com" ascii wide nocase
        $domain1 = "disk-fulldatabase\.rhcloud\.com" ascii wide nocase
        $domain2 = "gils\.ho\.ua" ascii wide nocase
        $domain3 = "lefting\.org" ascii wide nocase
        $domain4 = "literat\.ho\.ua" ascii wide nocase
        $domain5 = "wallejob\.in\.ua" ascii wide nocase
        $domain6 = "wallex\.ho\.ua" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_GROUP5
{
    meta:
        description = "Detects IOCs associated with APT GROUP5"
        author = "APTtrail Automated Collection"
        apt_group = "GROUP5"
        reference = "https://citizenlab.ca/2016/08/group5-syria/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "assadcrimes\.info" ascii wide nocase
        $domain1 = "crypter\.ir" ascii wide nocase
        $domain2 = "crypting\.org" ascii wide nocase
        $domain3 = "server22\.rayanegarco\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_HACKINGTEAM
{
    meta:
        description = "Detects IOCs associated with APT HACKINGTEAM"
        author = "APTtrail Automated Collection"
        apt_group = "HACKINGTEAM"
        reference = "http://reddittt.com/post/8pcl6a/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "androidgplay\.us\.to" ascii wide nocase
        $domain1 = "ar-24\.com" ascii wide nocase
        $domain2 = "bijiaexhibition\.com" ascii wide nocase
        $domain3 = "boardingpasstohome\.com" ascii wide nocase
        $domain4 = "cdc-asia\.org" ascii wide nocase
        $domain5 = "droidlatestnews\.com" ascii wide nocase
        $domain6 = "enjoyyourandroid\.com" ascii wide nocase
        $domain7 = "facebook-update\.info" ascii wide nocase
        $domain8 = "free\.dramakorea\.asia" ascii wide nocase
        $domain9 = "getnewandroid\.com" ascii wide nocase
        $domain10 = "hulahope\.mooo\.com" ascii wide nocase
        $domain11 = "link\.sexyhub\.co" ascii wide nocase
        $domain12 = "mytelkomsel\.co" ascii wide nocase
        $domain13 = "mywealthpop\.com" ascii wide nocase
        $domain14 = "nkpro\.lalanews\.net" ascii wide nocase
        $domain15 = "pantheon\.tobban\.com" ascii wide nocase
        $domain16 = "people\.dohabayt\.com" ascii wide nocase
        $domain17 = "play-mob\.org" ascii wide nocase
        $domain18 = "publiczone\.now\.im" ascii wide nocase
        $domain19 = "rcs-demo\.hackingteam\.it" ascii wide nocase
        $domain20 = "reflect\.dalnet\.ca" ascii wide nocase
        $domain21 = "samsung-update\.net" ascii wide nocase
        $domain22 = "secure\.anyurl\.org" ascii wide nocase
        $domain23 = "shrook\.mooo\.com" ascii wide nocase
        $domain24 = "telegram-apps\.org" ascii wide nocase
        $domain25 = "update\.indoorapps\.com" ascii wide nocase
        $domain26 = "video\.sexyhub\.co" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_HAFNIUM
{
    meta:
        description = "Detects IOCs associated with APT HAFNIUM"
        author = "APTtrail Automated Collection"
        apt_group = "HAFNIUM"
        aliases = "Hade ransomware, TimosaraHackerTerm"
        reference = "https://twitter.com/BushidoToken/status/1369273531867992064"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "back\.estonine\.com" ascii wide nocase
        $domain1 = "bingoshow\.xyz" ascii wide nocase
        $domain2 = "bk\.estonine\.com" ascii wide nocase
        $domain3 = "does-no-exist33\.estonine\.com" ascii wide nocase
        $domain4 = "e\.estonine\.com" ascii wide nocase
        $domain5 = "indicate\.estonine\.com" ascii wide nocase
        $domain6 = "inducate\.estonine\.com" ascii wide nocase
        $domain7 = "load\.estonine\.com" ascii wide nocase
        $domain8 = "log\.estonine\.com" ascii wide nocase
        $domain9 = "moon\.estonine\.com" ascii wide nocase
        $domain10 = "p\.estonine\.com" ascii wide nocase
        $domain11 = "pslog\.estonine\.com" ascii wide nocase
        $domain12 = "shelltools-1254394685\.cos\.ap-shanghai\.myqcloud\.com" ascii wide nocase
        $domain13 = "sk\.estonine\.com" ascii wide nocase
        $domain14 = "sploit\.estonine\.com" ascii wide nocase
        $domain15 = "task\.estonine\.com" ascii wide nocase
        $ip16 = "101.37.76.66" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_HANGOVER
{
    meta:
        description = "Detects IOCs associated with APT HANGOVER"
        author = "APTtrail Automated Collection"
        apt_group = "HANGOVER"
        aliases = "backconfig, monsoon, neon"
        reference = "https://otx.alienvault.com/pulse/5ebac662ee27db27e3174795"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "linkrequest\.live" ascii wide nocase
        $domain1 = "matissues\.com" ascii wide nocase
        $domain2 = "unique\.fontsupdate\.com" ascii wide nocase
        $ip3 = "212.114.52.20" ascii wide
        $ip4 = "45.153.241.33" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_HEADMARE
{
    meta:
        description = "Detects IOCs associated with APT HEADMARE"
        author = "APTtrail Automated Collection"
        apt_group = "HEADMARE"
        reference = "https://securelist.com/head-mare-hacktivists/113555/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "interoperaebility\.world" ascii wide nocase
        $domain1 = "jaudyoyh\.ru" ascii wide nocase
        $ip2 = "185.80.91.107" ascii wide
        $ip3 = "45.11.27.232" ascii wide
        $ip4 = "45.87.245.30" ascii wide
        $ip5 = "45.87.246.169" ascii wide
        $ip6 = "5.252.176.77" ascii wide
        $ip7 = "5.252.176.77" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_HELLHOUNDS
{
    meta:
        description = "Detects IOCs associated with APT HELLHOUNDS"
        author = "APTtrail Automated Collection"
        apt_group = "HELLHOUNDS"
        reference = "https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/hellhounds-operation-lahat-part-2/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "08m-srv\.daily-share\.ns3\.name" ascii wide nocase
        $domain1 = "2fm-srv\.daily-share\.ns3\.name" ascii wide nocase
        $domain2 = "6cm-srv\.daily-share\.ns3\.name" ascii wide nocase
        $domain3 = "78m-srv\.daily-share\.ns3\.name" ascii wide nocase
        $domain4 = "7fm-srv\.daily-share\.ns3\.name" ascii wide nocase
        $domain5 = "98m-srv\.daily-share\.ns3\.name" ascii wide nocase
        $domain6 = "acrm-11331\.com" ascii wide nocase
        $domain7 = "ads-tm-glb\.click" ascii wide nocase
        $domain8 = "allowlisted\.net" ascii wide nocase
        $domain9 = "atlas-upd\.com" ascii wide nocase
        $domain10 = "b1m-srv\.daily-share\.ns3\.name" ascii wide nocase
        $domain11 = "beacon\.net\.eu\.org" ascii wide nocase
        $domain12 = "c\.glb-ru\.info" ascii wide nocase
        $domain13 = "cbox4\.ignorelist\.com" ascii wide nocase
        $domain14 = "d5m-srv\.daily-share\.ns3\.name" ascii wide nocase
        $domain15 = "daily-share\.ns3\.name" ascii wide nocase
        $domain16 = "dw-filter\.com" ascii wide nocase
        $domain17 = "ertelecom\.org" ascii wide nocase
        $domain18 = "f-share\.duckdns\.org" ascii wide nocase
        $domain19 = "hsdps\.cc" ascii wide nocase
        $domain20 = "lez2yae2\.dynamic-dns\.net" ascii wide nocase
        $domain21 = "m-srv\.daily-share\.ns3\.name" ascii wide nocase
        $domain22 = "maxpatrol\.net" ascii wide nocase
        $domain23 = "mvs05\.zyns\.com" ascii wide nocase
        $domain24 = "net-sensors\.net" ascii wide nocase
        $domain25 = "ns1\.maxpatrol\.net" ascii wide nocase
        $domain26 = "ns1\.net-sensors\.net" ascii wide nocase
        $domain27 = "ns1\.webrtc\.foo" ascii wide nocase
        $domain28 = "ns2\.maxpatrol\.net" ascii wide nocase
        $domain29 = "ns2\.net-sensors\.net" ascii wide nocase
        $domain30 = "ns2\.webrtc\.foo" ascii wide nocase
        $domain31 = "ns3\.maxpatrol\.net" ascii wide nocase
        $domain32 = "ns4\.maxpatrol\.net" ascii wide nocase
        $domain33 = "vcs\.dns04\.com" ascii wide nocase
        $domain34 = "webrtc\.foo" ascii wide nocase
        $domain35 = "z-uid\.lez2yae2\.dynamic-dns\.net" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_HERMIT
{
    meta:
        description = "Detects IOCs associated with APT HERMIT"
        author = "APTtrail Automated Collection"
        apt_group = "HERMIT"
        reference = "https://s.tencent.com/research/report/613.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "071790\.000webhostapp\.com" ascii wide nocase
        $domain1 = "881\.000webhostapp\.com" ascii wide nocase
        $domain2 = "a7788\.1apps\.com" ascii wide nocase
        $domain3 = "alabamaok0515\.1apps\.com" ascii wide nocase
        $domain4 = "attach10132\.1apps\.com" ascii wide nocase
        $domain5 = "charley-online\.com" ascii wide nocase
        $domain6 = "clean\.1apps\.com" ascii wide nocase
        $domain7 = "fighiting1013\.org" ascii wide nocase
        $domain8 = "filer1\.1apps\.com" ascii wide nocase
        $domain9 = "filer2\.1apps\.com" ascii wide nocase
        $domain10 = "hanbosston\.000webhostapp\.com" ascii wide nocase
        $domain11 = "s8877\.1apps\.com" ascii wide nocase
        $domain12 = "tgbabcrfv\.1apps\.com" ascii wide nocase
        $ip13 = "103.249.31.159" ascii wide
        $ip14 = "5.252.198.93" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_HIGAISA
{
    meta:
        description = "Detects IOCs associated with APT HIGAISA"
        author = "APTtrail Automated Collection"
        apt_group = "HIGAISA"
        reference = "https://blog.malwarebytes.com/threat-analysis/2020/06/higaisa/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "api\.s2cloud-amazon\.com" ascii wide nocase
        $domain1 = "app-dimensiona\.s3\.sa-east-1\.amazonaws\.com" ascii wide nocase
        $domain2 = "bjj-files-production\.s3\.sa-east-1\.amazonaws\.com" ascii wide nocase
        $domain3 = "comcleanner\.info" ascii wide nocase
        $domain4 = "footracker-statics\.s3\.sa-east-1\.amazonaws\.com" ascii wide nocase
        $domain5 = "goodhk\.azurewebsites\.net" ascii wide nocase
        $domain6 = "p-game\.s3\.sa-east-1\.amazonaws\.com" ascii wide nocase
        $domain7 = "s2cloud-amazon\.com" ascii wide nocase
        $domain8 = "sixindent\.epizy\.com" ascii wide nocase
        $domain9 = "speedshare\.oss-cn-hongkong\.aliyuncs\.com" ascii wide nocase
        $domain10 = "xianggang000\.oss-cn-hongkong\.aliyuncs\.com" ascii wide nocase
        $domain11 = "yitoo\.oss-cn-hongkong\.aliyuncs\.com" ascii wide nocase
        $domain12 = "zeplin\.atwebpages\.com" ascii wide nocase
        $ip13 = "45.76.6.149" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_HOGFISH
{
    meta:
        description = "Detects IOCs associated with APT HOGFISH"
        author = "APTtrail Automated Collection"
        apt_group = "HOGFISH"
        reference = "https://www.accenture.com/t20180423T055005Z__w__/us-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "algorithm\.ddnsgeek\.com" ascii wide nocase
        $domain1 = "firefoxcomt\.arkouowi\.com" ascii wide nocase
        $domain2 = "friendlysupport\.giize\.com" ascii wide nocase
        $domain3 = "update\.arkouowi\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_ICEFOG
{
    meta:
        description = "Detects IOCs associated with APT ICEFOG"
        author = "APTtrail Automated Collection"
        apt_group = "ICEFOG"
        reference = "https://app.any.run/tasks/3a08945b-62c3-4a0e-893b-bcdbdc920650/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "01transport\.com" ascii wide nocase
        $domain1 = "applelenovo\.com" ascii wide nocase
        $domain2 = "appst0re\.net" ascii wide nocase
        $domain3 = "aries\.epac\.to" ascii wide nocase
        $domain4 = "baagii\.sportsnewsa\.net" ascii wide nocase
        $domain5 = "basaa\.sportsnewsa\.net" ascii wide nocase
        $domain6 = "benzerold\.com" ascii wide nocase
        $domain7 = "blue-vpn\.net" ascii wide nocase
        $domain8 = "bluesky\.zyns\.com" ascii wide nocase
        $domain9 = "bulgaa\.sportsnewsa\.net" ascii wide nocase
        $domain10 = "comesafe\.com" ascii wide nocase
        $domain11 = "cospation\.net" ascii wide nocase
        $domain12 = "date\.dellnewsup\.net" ascii wide nocase
        $domain13 = "dwm\.dnsedc\.com" ascii wide nocase
        $domain14 = "eagleoftajik\.dynamic-dns\.net" ascii wide nocase
        $domain15 = "eyellowarm\.com" ascii wide nocase
        $domain16 = "game\.sexidude\.com" ascii wide nocase
        $domain17 = "honoroftajik\.dynamic-dns\.net" ascii wide nocase
        $domain18 = "https\.ikwb\.com" ascii wide nocase
        $domain19 = "kaboolyn\.com" ascii wide nocase
        $domain20 = "kastygost\.compress\.to" ascii wide nocase
        $domain21 = "knightpal\.com" ascii wide nocase
        $domain22 = "kyssrcd\.pw" ascii wide nocase
        $domain23 = "laugh\.toh\.info" ascii wide nocase
        $domain24 = "mitian123\.com" ascii wide nocase
        $domain25 = "mn\.dellnewsup\.net" ascii wide nocase
        $domain26 = "mocus\.cospation\.net" ascii wide nocase
        $domain27 = "moonlight\.compress\.to" ascii wide nocase
        $domain28 = "news\.dellnewsup\.net" ascii wide nocase
        $domain29 = "nicodonald\.accesscam\.org" ascii wide nocase
        $domain30 = "niteast\.strangled\.net" ascii wide nocase
        $domain31 = "nitec\.ns1\.name" ascii wide nocase
        $domain32 = "numnote\.com" ascii wide nocase
        $domain33 = "poff\.wha\.la" ascii wide nocase
        $domain34 = "russion\.dnsedc\.com" ascii wide nocase
        $domain35 = "skylineqaz\.crabdance\.com" ascii wide nocase
        $domain36 = "suverycool\.com" ascii wide nocase
        $domain37 = "tajikmusic\.dynamic-dns\.net" ascii wide nocase
        $domain38 = "tajikstantravel\.dynamic-dns\.net" ascii wide nocase
        $domain39 = "tele\.zyns\.com" ascii wide nocase
        $domain40 = "trendiis\.sixth\.biz" ascii wide nocase
        $domain41 = "uzwatersource\.dynamic-dns\.net" ascii wide nocase
        $domain42 = "whitebirds\.mefound\.com" ascii wide nocase
        $domain43 = "win\.dellnewsup\.net" ascii wide nocase
        $domain44 = "xn--uareexcellent-or3qa\.kozow\.com" ascii wide nocase
        $domain45 = "ylineqaz-y25ja\.crabdance\.com" ascii wide nocase
        $domain46 = "youareexcellent\.kozow\.com" ascii wide nocase
        $domain47 = "zaluu\.dellnewsup\.net" ascii wide nocase
        $domain48 = "zorsoft\.ns1\.name" ascii wide nocase
        $ip49 = "95.179.131.29" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_ICEPEONY
{
    meta:
        description = "Detects IOCs associated with APT ICEPEONY"
        author = "APTtrail Automated Collection"
        apt_group = "ICEPEONY"
        reference = "https://nao-sec.org/2024/10/IcePeony-with-the-996-work-culture.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "88k8cc\.com" ascii wide nocase
        $domain1 = "d45qomwkl\.online" ascii wide nocase
        $domain2 = "googlesvn\.com" ascii wide nocase
        $domain3 = "k8ccyn\.com" ascii wide nocase
        $domain4 = "k9ccin\.com" ascii wide nocase
        $ip5 = "128.199.70.91" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_IMPERIALKITTEN
{
    meta:
        description = "Detects IOCs associated with APT IMPERIALKITTEN"
        author = "APTtrail Automated Collection"
        apt_group = "IMPERIALKITTEN"
        aliases = "IMAPLoader"
        reference = "https://otx.alienvault.com/pulse/65525ca657dbfce9173d57d2"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "analytics-service\.cloud" ascii wide nocase
        $domain1 = "analytics-service\.online" ascii wide nocase
        $domain2 = "blackcrocodile\.online" ascii wide nocase
        $domain3 = "cdn-analytics\.co" ascii wide nocase
        $domain4 = "cdn\.jguery\.org" ascii wide nocase
        $domain5 = "cdnpakage\.com" ascii wide nocase
        $domain6 = "fastanalizer\.live" ascii wide nocase
        $domain7 = "fastanalytics\.live" ascii wide nocase
        $domain8 = "jquery-cdn\.online" ascii wide nocase
        $domain9 = "jquery-code-download\.online" ascii wide nocase
        $domain10 = "jquery-stack\.online" ascii wide nocase
        $domain11 = "prostatistics\.live" ascii wide nocase
        $domain12 = "updatenewnet\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_INDIGOZEBRA
{
    meta:
        description = "Detects IOCs associated with APT INDIGOZEBRA"
        author = "APTtrail Automated Collection"
        apt_group = "INDIGOZEBRA"
        reference = "https://otx.alienvault.com/pulse/60ddbf90b3211a60e87da15f"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "2019mfa\.com" ascii wide nocase
        $domain1 = "6z98os\.id597\.link" ascii wide nocase
        $domain2 = "cdn\.muincxoil\.com" ascii wide nocase
        $domain3 = "google-upgrade\.com" ascii wide nocase
        $domain4 = "help\.2019mfa\.com" ascii wide nocase
        $domain5 = "hwyigd\.laccessal\.org" ascii wide nocase
        $domain6 = "ictdp\.com" ascii wide nocase
        $domain7 = "id597\.link" ascii wide nocase
        $domain8 = "index\.google-upgrade\.com" ascii wide nocase
        $domain9 = "infodocs\.kginfocom\.com" ascii wide nocase
        $domain10 = "kginfocom\.com" ascii wide nocase
        $domain11 = "laccessal\.org" ascii wide nocase
        $domain12 = "m\.usascd\.com" ascii wide nocase
        $domain13 = "mahallafond\.com" ascii wide nocase
        $domain14 = "mfa-uz\.com" ascii wide nocase
        $domain15 = "mofa\.ungov\.org" ascii wide nocase
        $domain16 = "muincxoil\.com" ascii wide nocase
        $domain17 = "ns01-mfa\.ungov\.org" ascii wide nocase
        $domain18 = "ousync\.kginfocom\.com" ascii wide nocase
        $domain19 = "post\.mfa-uz\.com" ascii wide nocase
        $domain20 = "tm\.2019mfa\.com" ascii wide nocase
        $domain21 = "ungov\.org" ascii wide nocase
        $domain22 = "update\.ictdp\.com" ascii wide nocase
        $domain23 = "usascd\.com" ascii wide nocase
        $domain24 = "uslugi\.mahallafond\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_INDRA
{
    meta:
        description = "Detects IOCs associated with APT INDRA"
        author = "APTtrail Automated Collection"
        apt_group = "INDRA"
        reference = "https://otx.alienvault.com/pulse/611a554ac771ff97c2273686"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "139.59.89.238" ascii wide
        $ip1 = "167.172.177.158" ascii wide
        $ip2 = "172.105.42.64" ascii wide
        $ip3 = "68.183.79.77" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_INFY
{
    meta:
        description = "Detects IOCs associated with APT INFY"
        author = "APTtrail Automated Collection"
        apt_group = "INFY"
        aliases = "foudre, infy"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.infy"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "017eab31\.space" ascii wide nocase
        $domain1 = "01ead12b\.space" ascii wide nocase
        $domain2 = "0ca0453a\.site" ascii wide nocase
        $domain3 = "149a673e\.dynu\.net" ascii wide nocase
        $domain4 = "149a673e\.net" ascii wide nocase
        $domain5 = "149a673e\.space" ascii wide nocase
        $domain6 = "149a673e\.top" ascii wide nocase
        $domain7 = "14c7e2dc\.space" ascii wide nocase
        $domain8 = "15bb747b\.site" ascii wide nocase
        $domain9 = "15ce27c5\.site" ascii wide nocase
        $domain10 = "16e53040\.space" ascii wide nocase
        $domain11 = "177a5c4a\.space" ascii wide nocase
        $domain12 = "17ecf559\.site" ascii wide nocase
        $domain13 = "1cb3c4c0\.space" ascii wide nocase
        $domain14 = "1d4ee030\.space" ascii wide nocase
        $domain15 = "1d8bfc20\.space" ascii wide nocase
        $domain16 = "1f0e7a56\.space" ascii wide nocase
        $domain17 = "23dafa1e\.space" ascii wide nocase
        $domain18 = "2daa46f1\.space" ascii wide nocase
        $domain19 = "32c39cf4\.dynu\.net" ascii wide nocase
        $domain20 = "32c39cf4\.net" ascii wide nocase
        $domain21 = "32c39cf4\.space" ascii wide nocase
        $domain22 = "32c39cf4\.top" ascii wide nocase
        $domain23 = "334edefd\.dynu\.net" ascii wide nocase
        $domain24 = "334edefd\.net" ascii wide nocase
        $domain25 = "334edefd\.space" ascii wide nocase
        $domain26 = "334edefd\.top" ascii wide nocase
        $domain27 = "341a436d\.space" ascii wide nocase
        $domain28 = "34231ae4\.dynu\.net" ascii wide nocase
        $domain29 = "34231ae4\.net" ascii wide nocase
        $domain30 = "34231ae4\.space" ascii wide nocase
        $domain31 = "34231ae4\.top" ascii wide nocase
        $domain32 = "3828b6ed\.site" ascii wide nocase
        $domain33 = "39451f31\.space" ascii wide nocase
        $domain34 = "3a6e08b4\.site" ascii wide nocase
        $domain35 = "3b75d0df\.dynu\.net" ascii wide nocase
        $domain36 = "3b75d0df\.net" ascii wide nocase
        $domain37 = "3b75d0df\.space" ascii wide nocase
        $domain38 = "3b75d0df\.top" ascii wide nocase
        $domain39 = "3c6e6571\.space" ascii wide nocase
        $domain40 = "3d9556cf\.dynu\.net" ascii wide nocase
        $domain41 = "3d9556cf\.net" ascii wide nocase
        $domain42 = "3d9556cf\.space" ascii wide nocase
        $domain43 = "3d9556cf\.top" ascii wide nocase
        $domain44 = "3e8718c3\.site" ascii wide nocase
        $domain45 = "3f4572f4\.site" ascii wide nocase
        $domain46 = "42a9687b\.dynu\.net" ascii wide nocase
        $domain47 = "42a9687b\.net" ascii wide nocase
        $domain48 = "42a9687b\.space" ascii wide nocase
        $domain49 = "42a9687b\.top" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_INNAPUT
{
    meta:
        description = "Detects IOCs associated with APT INNAPUT"
        author = "APTtrail Automated Collection"
        apt_group = "INNAPUT"
        reference = "https://asert.arbornetworks.com/innaput-actors-utilize-remote-access-trojan-since-2016-presumably-targeting-victim-files/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "alert-login-gmail\.com" ascii wide nocase
        $domain1 = "best-online-tv\.com" ascii wide nocase
        $domain2 = "blockhain\.name" ascii wide nocase
        $domain3 = "dockooment\.com" ascii wide nocase
        $domain4 = "docsautentification\.com" ascii wide nocase
        $domain5 = "g000glemail\.com" ascii wide nocase
        $domain6 = "googldraive\.com" ascii wide nocase
        $domain7 = "googledockumets\.com" ascii wide nocase
        $domain8 = "googledraive\.com" ascii wide nocase
        $domain9 = "googlesuport\.com" ascii wide nocase
        $domain10 = "googlmaile\.com" ascii wide nocase
        $domain11 = "googlsupport\.com" ascii wide nocase
        $domain12 = "govreportst\.com" ascii wide nocase
        $domain13 = "iceerd\.com" ascii wide nocase
        $domain14 = "login-googlemail\.com" ascii wide nocase
        $domain15 = "mail-redirect\.com\.kz" ascii wide nocase
        $domain16 = "mfa-events\.com" ascii wide nocase
        $domain17 = "msoficceupdate\.com" ascii wide nocase
        $domain18 = "officemicroupdate\.com" ascii wide nocase
        $domain19 = "officeonlaine\.com" ascii wide nocase
        $domain20 = "osc-e\.com" ascii wide nocase
        $domain21 = "pwdrecover\.com" ascii wide nocase
        $domain22 = "suporteng\.com" ascii wide nocase
        $domain23 = "un-booklet\.com" ascii wide nocase
        $domain24 = "update-app\.top" ascii wide nocase
        $domain25 = "us-embassy-report\.com" ascii wide nocase
        $domain26 = "usaid\.info" ascii wide nocase
        $domain27 = "worlwidesupport\.top" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_IRN2
{
    meta:
        description = "Detects IOCs associated with APT IRN2"
        author = "APTtrail Automated Collection"
        apt_group = "IRN2"
        reference = "https://www.area1security.com/resources/operation-doos/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "barsupport\.org" ascii wide nocase
        $domain1 = "coldflys\.com" ascii wide nocase
        $domain2 = "forskys\.com" ascii wide nocase
        $domain3 = "shoterup\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_IRONHUSKY
{
    meta:
        description = "Detects IOCs associated with APT IRONHUSKY"
        author = "APTtrail Automated Collection"
        apt_group = "IRONHUSKY"
        aliases = "mysterysnail"
        reference = "https://otx.alienvault.com/pulse/6166cbbeaa321dca2a453f97"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "ddspadus\.com" ascii wide nocase
        $domain1 = "http\.ddspadus\.com" ascii wide nocase
        $domain2 = "hxxp\.ddspadus\.com" ascii wide nocase
        $domain3 = "ipv6\.ddspadus\.com" ascii wide nocase
        $domain4 = "nhttp\.ddspadus\.com" ascii wide nocase
        $domain5 = "ttp\.ddspadus\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_IRONTIGER
{
    meta:
        description = "Detects IOCs associated with APT IRONTIGER"
        author = "APTtrail Automated Collection"
        apt_group = "IRONTIGER"
        reference = "http://www.secureworks.com/cyber-threat-intelligence/threats/threat-group-3390-targets-organizations-for-cyberespionage/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "american\.blackcmd\.com" ascii wide nocase
        $domain1 = "api\.apigmail\.com" ascii wide nocase
        $domain2 = "apigmail\.com" ascii wide nocase
        $domain3 = "backup\.darkhero\.org" ascii wide nocase
        $domain4 = "bel\.updatawindows\.com" ascii wide nocase
        $domain5 = "binary\.update-onlines\.org" ascii wide nocase
        $domain6 = "blackcmd\.com" ascii wide nocase
        $domain7 = "castle\.blackcmd\.com" ascii wide nocase
        $domain8 = "centuriosa\.info" ascii wide nocase
        $domain9 = "ctcb\.blackcmd\.com" ascii wide nocase
        $domain10 = "darkhero\.org" ascii wide nocase
        $domain11 = "dav\.local-test\.com" ascii wide nocase
        $domain12 = "dev\.local-test\.com" ascii wide nocase
        $domain13 = "dll\.pzchao\.com" ascii wide nocase
        $domain14 = "down\.pzchao\.com" ascii wide nocase
        $domain15 = "ftp\.google-ana1ytics\.com" ascii wide nocase
        $domain16 = "ga\.blackcmd\.com" ascii wide nocase
        $domain17 = "google-ana1ytics\.com" ascii wide nocase
        $domain18 = "helpdesk\.blackcmd\.com" ascii wide nocase
        $domain19 = "helpdesk\.csc-na\.com" ascii wide nocase
        $domain20 = "helpdesk\.hotmail-onlines\.com" ascii wide nocase
        $domain21 = "helpdesk\.lnip\.org" ascii wide nocase
        $domain22 = "hotmail-onlines\.com" ascii wide nocase
        $domain23 = "hotmailcontact\.net" ascii wide nocase
        $domain24 = "jobs\.hotmail-onlines\.com" ascii wide nocase
        $domain25 = "justufogame\.com" ascii wide nocase
        $domain26 = "laxness-lab\.com" ascii wide nocase
        $domain27 = "lnip\.org" ascii wide nocase
        $domain28 = "local-test\.com" ascii wide nocase
        $domain29 = "login\.hansoftupdate\.com" ascii wide nocase
        $domain30 = "long\.update-onlines\.org" ascii wide nocase
        $domain31 = "longlong\.update-onlines\.org" ascii wide nocase
        $domain32 = "longshadow\.dyndns\.org" ascii wide nocase
        $domain33 = "longshadow\.update-onlines\.org" ascii wide nocase
        $domain34 = "longykcai\.update-onlines\.org" ascii wide nocase
        $domain35 = "lostself\.update-onlines\.org" ascii wide nocase
        $domain36 = "mac\.navydocument\.com" ascii wide nocase
        $domain37 = "mail\.csc-na\.com" ascii wide nocase
        $domain38 = "mantech\.updatawindows\.com" ascii wide nocase
        $domain39 = "micr0soft\.org" ascii wide nocase
        $domain40 = "microsoft-outlook\.org" ascii wide nocase
        $domain41 = "mtc\.navydocument\.com" ascii wide nocase
        $domain42 = "mtc\.update-onlines\.org" ascii wide nocase
        $domain43 = "navydocument\.com" ascii wide nocase
        $domain44 = "news\.hotmail-onlines\.com" ascii wide nocase
        $domain45 = "oac\.3322\.org" ascii wide nocase
        $domain46 = "ocean\.apigmail\.com" ascii wide nocase
        $domain47 = "ocean\.local-test\.com" ascii wide nocase
        $domain48 = "pchomeserver\.com" ascii wide nocase
        $domain49 = "rat\.pzchao\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_ISOON
{
    meta:
        description = "Detects IOCs associated with APT ISOON"
        author = "APTtrail Automated Collection"
        apt_group = "ISOON"
        aliases = "i-soon"
        reference = "https://www.justice.gov/opa/media/1391896/dl"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "acc\.newyorker\.cloud" ascii wide nocase
        $domain1 = "account\.newyorker\.cloud" ascii wide nocase
        $domain2 = "asiaic\.org" ascii wide nocase
        $domain3 = "ecoatmosphere\.org" ascii wide nocase
        $domain4 = "grhost\.pro" ascii wide nocase
        $domain5 = "heidrickjobs\.com" ascii wide nocase
        $domain6 = "live\.newyorker\.cloud" ascii wide nocase
        $domain7 = "maddmail\.site" ascii wide nocase
        $domain8 = "mobprodetect\.live" ascii wide nocase
        $domain9 = "newvsrch\.pro" ascii wide nocase
        $domain10 = "newyorker\.cloud" ascii wide nocase
        $domain11 = "outlook\.newyorker\.cloud" ascii wide nocase
        $domain12 = "ssl\.newyorker\.cloud" ascii wide nocase
        $ip13 = "140.82.48.85" ascii wide
        $ip14 = "149.248.57.11" ascii wide
        $ip15 = "40.82.48.85" ascii wide
        $ip16 = "45.77.132.157" ascii wide
        $ip17 = "95.179.202.21" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_JUDGMENTPANDA
{
    meta:
        description = "Detects IOCs associated with APT JUDGMENTPANDA"
        author = "APTtrail Automated Collection"
        apt_group = "JUDGMENTPANDA"
        aliases = "apt-31, bronze vinewood, zirconium"
        reference = "https://otx.alienvault.com/pulse/610a40dee36aae4fcd35e9cf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "api\.flushcdn\.com" ascii wide nocase
        $domain1 = "api\.hostupoeui\.com" ascii wide nocase
        $domain2 = "api\.last-key\.com" ascii wide nocase
        $domain3 = "be-government\.com" ascii wide nocase
        $domain4 = "cdn\.microsoft-official\.com" ascii wide nocase
        $domain5 = "const\.be-government\.com" ascii wide nocase
        $domain6 = "drmtake\.tk" ascii wide nocase
        $domain7 = "edgecloudc\.com" ascii wide nocase
        $domain8 = "flushcdn\.com" ascii wide nocase
        $domain9 = "gitcloudcache\.com" ascii wide nocase
        $domain10 = "hostupoeui\.com" ascii wide nocase
        $domain11 = "inst\.rsnet-devel\.com" ascii wide nocase
        $domain12 = "intranet-rsnet\.com" ascii wide nocase
        $domain13 = "last-key\.com" ascii wide nocase
        $domain14 = "microsoft-products\.com" ascii wide nocase
        $domain15 = "office\.microsoft-products\.com" ascii wide nocase
        $domain16 = "offline-microsoft\.com" ascii wide nocase
        $domain17 = "p1\.offline-microsoft\.com" ascii wide nocase
        $domain18 = "portal\.intranet-rsnet\.com" ascii wide nocase
        $domain19 = "portal\.super-encrypt\.com" ascii wide nocase
        $domain20 = "rsnet-devel\.com" ascii wide nocase
        $domain21 = "super-encrypt\.com" ascii wide nocase
        $domain22 = "wshnews\.com" ascii wide nocase
        $domain23 = "yandexpro\.net" ascii wide nocase
        $ip24 = "20.11.11.67" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_KAPEKA
{
    meta:
        description = "Detects IOCs associated with APT KAPEKA"
        author = "APTtrail Automated Collection"
        apt_group = "KAPEKA"
        aliases = "KnuckleTouch, WrongSens"
        reference = "https://labs.withsecure.com/publications/kapeka"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "185.38.150.8" ascii wide
        $ip1 = "185.38.150.8" ascii wide
        $ip2 = "88.80.148.65" ascii wide
        $ip3 = "88.80.148.65" ascii wide
        $ip4 = "88.80.148.65" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_KARAKURT
{
    meta:
        description = "Detects IOCs associated with APT KARAKURT"
        author = "APTtrail Automated Collection"
        apt_group = "KARAKURT"
        aliases = "Karakurt Lair, Karakurt Team"
        reference = "https://gist.github.com/hrbrmstr/db75143d512faa983f7438b3f17e2f5a"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "3f7nxkjway3d223j27lyad7v5cgmyaifesycvmwq7i7cbs23lb6llryd\.onion" ascii wide nocase
        $domain1 = "blog\.karakurt\.tech" ascii wide nocase
        $domain2 = "internal\.karakurt\.tech" ascii wide nocase
        $domain3 = "karachat\.group" ascii wide nocase
        $domain4 = "karachat\.tech" ascii wide nocase
        $domain5 = "karakurt\.co" ascii wide nocase
        $domain6 = "karakurt\.group" ascii wide nocase
        $domain7 = "karakurt\.systems" ascii wide nocase
        $domain8 = "karakurt\.tech" ascii wide nocase
        $domain9 = "karaleaks\.com" ascii wide nocase
        $domain10 = "omx5iqrdbsoitf3q4xexrqw5r5tfw7vp3vl3li3lfo7saabxazshnead\.onion" ascii wide nocase
        $ip11 = "178.255.220.111" ascii wide
        $ip12 = "94.156.174.204" ascii wide
        $ip13 = "94.156.174.204" ascii wide
        $ip14 = "94.156.174.204" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_KASABLANKA
{
    meta:
        description = "Detects IOCs associated with APT KASABLANKA"
        author = "APTtrail Automated Collection"
        apt_group = "KASABLANKA"
        reference = "https://mp.weixin.qq.com/s?__biz=MzUyMjk4NzExMA==&mid=2247494512&idx=1&sn=151caeb7b46c3a6a58af714a576a8442&chksm=f9c1d879ceb6516fc6f52a837ad5d8084ab4cc643ea6bbb035e979ba80b5c76bd90ecfa9bb11&scene=178&cur_album_id=1955835290309230595#rd"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "karabakhtelekom\.com" ascii wide nocase
        $ip1 = "139.84.231.199" ascii wide
        $ip2 = "193.161.193.99" ascii wide

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_KE3CHANG
{
    meta:
        description = "Detects IOCs associated with APT KE3CHANG"
        author = "APTtrail Automated Collection"
        apt_group = "KE3CHANG"
        aliases = "Ke3chang, Mirage, Playful Dragon"
        reference = "https://app.any.run/tasks/8d777de7-d51d-4c97-8e91-d0e54461fc2b/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "adobeonline\.net" ascii wide nocase
        $domain1 = "andspurs\.com" ascii wide nocase
        $domain2 = "beltsymd\.org" ascii wide nocase
        $domain3 = "buy\.babytoy-online\.com" ascii wide nocase
        $domain4 = "buy\.healthcare-internet\.com" ascii wide nocase
        $domain5 = "cavanic9\.net" ascii wide nocase
        $domain6 = "center\.nmsvillage\.com" ascii wide nocase
        $domain7 = "centrozhlan\.com" ascii wide nocase
        $domain8 = "chart\.healthcare-internet\.com" ascii wide nocase
        $domain9 = "compatsec\.com" ascii wide nocase
        $domain10 = "control\.mimepanel\.org" ascii wide nocase
        $domain11 = "cv\.livehams\.com" ascii wide nocase
        $domain12 = "cyclophilit\.com" ascii wide nocase
        $domain13 = "cyprus-villas\.org" ascii wide nocase
        $domain14 = "daily\.huntereim\.com" ascii wide nocase
        $domain15 = "dnsapp\.info" ascii wide nocase
        $domain16 = "dream\.zepotac\.com" ascii wide nocase
        $domain17 = "dsmanfacture\.privatedns\.org" ascii wide nocase
        $domain18 = "dyname\.europemis\.com" ascii wide nocase
        $domain19 = "finance\.globaleducat\.com" ascii wide nocase
        $domain20 = "forcan\.hausblow\.com" ascii wide nocase
        $domain21 = "goback\.strangled\.net" ascii wide nocase
        $domain22 = "grek\.freetaxbar\.com" ascii wide nocase
        $domain23 = "halimatoudi\.com" ascii wide nocase
        $domain24 = "info\.audioexp\.com" ascii wide nocase
        $domain25 = "inicializacion\.com" ascii wide nocase
        $domain26 = "item\.amazonout\.com" ascii wide nocase
        $domain27 = "items\.babytoy-online\.com" ascii wide nocase
        $domain28 = "items\.burgermap\.org" ascii wide nocase
        $domain29 = "log\.autocount\.org" ascii wide nocase
        $domain30 = "login\.allionhealth\.com" ascii wide nocase
        $domain31 = "memozilla\.org" ascii wide nocase
        $domain32 = "menorustru\.com" ascii wide nocase
        $domain33 = "menu\.thehuguardian\.com" ascii wide nocase
        $domain34 = "micakiz\.wikaba\.org" ascii wide nocase
        $domain35 = "misiones\.soportesisco\.com" ascii wide nocase
        $domain36 = "newflow\.babytoy-online\.com" ascii wide nocase
        $domain37 = "news\.memozilla\.org" ascii wide nocase
        $domain38 = "perusmartcity\.com" ascii wide nocase
        $domain39 = "press\.premlist\.com" ascii wide nocase
        $domain40 = "promise\.miniaturizate\.org" ascii wide nocase
        $domain41 = "rain\.nmsvillage\.com" ascii wide nocase
        $domain42 = "ridingduck\.com" ascii wide nocase
        $domain43 = "run\.linodepower\.com" ascii wide nocase
        $domain44 = "singa\.linodepower\.com" ascii wide nocase
        $domain45 = "store\.ufmsecret\.org" ascii wide nocase
        $domain46 = "support\.slovakmaps\.com" ascii wide nocase
        $domain47 = "thehuguardian\.com" ascii wide nocase
        $domain48 = "tick\.ondemand-sport\.com" ascii wide nocase
        $domain49 = "translate\.europemis\.com" ascii wide nocase
        $ip50 = "106.75.99.101" ascii wide
        $ip51 = "123.60.31.114" ascii wide
        $ip52 = "172.104.143.75" ascii wide
        $ip53 = "172.104.143.75" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_KEYBOY
{
    meta:
        description = "Detects IOCs associated with APT KEYBOY"
        author = "APTtrail Automated Collection"
        apt_group = "KEYBOY"
        aliases = "famoussparrow, keyboy, pirate panda"
        reference = "https://citizenlab.ca/2016/11/parliament-keyboy/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "about\.jkub\.com" ascii wide nocase
        $domain1 = "adobehomework\.com" ascii wide nocase
        $domain2 = "ak\.buycheap\.cn" ascii wide nocase
        $domain3 = "amazoncdns\.com" ascii wide nocase
        $domain4 = "ap\.missmichiko\.com" ascii wide nocase
        $domain5 = "api\.cnicchina\.com" ascii wide nocase
        $domain6 = "athenatechlabs\.com" ascii wide nocase
        $domain7 = "auth\.boxlibraries\.com" ascii wide nocase
        $domain8 = "awsdns-531\.com" ascii wide nocase
        $domain9 = "backus\.myftp\.name" ascii wide nocase
        $domain10 = "blog\.techmersion\.com" ascii wide nocase
        $domain11 = "broadmediacloud\.com" ascii wide nocase
        $domain12 = "buycheap\.cn" ascii wide nocase
        $domain13 = "c11r\.awsdns-531\.com" ascii wide nocase
        $domain14 = "cache10\.newsfreecloud\.com" ascii wide nocase
        $domain15 = "cachecloud\.cloudflaresrv\.com" ascii wide nocase
        $domain16 = "cas04\.awsdns-531\.com" ascii wide nocase
        $domain17 = "cdglobalclouds\.com" ascii wide nocase
        $domain18 = "cdn\.kkxx888666\.com" ascii wide nocase
        $domain19 = "cdn101\.cloudflaresrv\.com" ascii wide nocase
        $domain20 = "cdn181\.awsdns-531\.com" ascii wide nocase
        $domain21 = "cloudflaresrv\.com" ascii wide nocase
        $domain22 = "cloudshappen\.com" ascii wide nocase
        $domain23 = "cloudsrv\.cloudfrontsrv\.com" ascii wide nocase
        $domain24 = "cnicchina\.com" ascii wide nocase
        $domain25 = "credits\.offices-analytics\.com" ascii wide nocase
        $domain26 = "dbacloudsupport\.com" ascii wide nocase
        $domain27 = "de\.huseinhbz\.click" ascii wide nocase
        $domain28 = "dpponline\.trickip\.org" ascii wide nocase
        $domain29 = "eleven\.mypop3\.org" ascii wide nocase
        $domain30 = "emv1\.cdglobalclouds\.com" ascii wide nocase
        $domain31 = "emv1\.techmersion\.com" ascii wide nocase
        $domain32 = "euphemismscase\.site" ascii wide nocase
        $domain33 = "flarecastdns\.com" ascii wide nocase
        $domain34 = "ftp\.techmersion\.com" ascii wide nocase
        $domain35 = "ge\.huseinhbz\.click" ascii wide nocase
        $domain36 = "global\.techmersion\.com" ascii wide nocase
        $domain37 = "globalnetzone\.b-cdn\.net" ascii wide nocase
        $domain38 = "helpdesk\.athenatechlabs\.com" ascii wide nocase
        $domain39 = "helpdesk\.cloudshappen\.com" ascii wide nocase
        $domain40 = "huseinhbz\.click" ascii wide nocase
        $domain41 = "images\.dbacloudsupport\.com" ascii wide nocase
        $domain42 = "johannesburghotel\.net" ascii wide nocase
        $domain43 = "jupiter\.qpoe\.com" ascii wide nocase
        $domain44 = "kidshomeworkabc\.global\.ssl\.fastly\.net" ascii wide nocase
        $domain45 = "kkxx888666\.com" ascii wide nocase
        $domain46 = "laishi\.ddns\.net" ascii wide nocase
        $domain47 = "llnw-dd\.awsdns-531\.com" ascii wide nocase
        $domain48 = "lync\.realtxholdem\.com" ascii wide nocase
        $domain49 = "mail\.euphemismscase\.site" ascii wide nocase
        $ip50 = "101.32.36.76" ascii wide
        $ip51 = "106.53.120.204" ascii wide
        $ip52 = "114.251.216.125" ascii wide
        $ip53 = "118.195.161.141" ascii wide
        $ip54 = "118.195.161.141" ascii wide
        $ip55 = "132.232.92.218" ascii wide
        $ip56 = "134.175.197.144" ascii wide
        $ip57 = "150.109.114.190" ascii wide
        $ip58 = "155.138.155.181" ascii wide
        $ip59 = "159.75.144.13" ascii wide
        $ip60 = "159.75.81.151" ascii wide
        $ip61 = "159.75.83.212" ascii wide
        $ip62 = "185.20.187.10" ascii wide
        $ip63 = "212.182.121.97" ascii wide
        $ip64 = "219.225.109.246" ascii wide
        $ip65 = "43.129.177.152" ascii wide
        $ip66 = "43.134.194.237" ascii wide
        $ip67 = "43.154.74.7" ascii wide
        $ip68 = "43.154.85.5" ascii wide
        $ip69 = "43.154.88.192" ascii wide
        $ip70 = "45.76.218.247" ascii wide
        $ip71 = "45.77.178.47" ascii wide
        $ip72 = "49.232.142.8" ascii wide
        $ip73 = "82.156.178.135" ascii wide
        $ip74 = "82.156.178.135" ascii wide
        $ip75 = "82.157.51.214" ascii wide
        $ip76 = "82.157.62.199" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_KIMSUKY
{
    meta:
        description = "Detects IOCs associated with APT KIMSUKY"
        author = "APTtrail Automated Collection"
        apt_group = "KIMSUKY"
        aliases = "APT-C-55, Black Banshee, Larva-25004"
        reference = "https://app.any.run/tasks/166bb71d-0998-46cf-844b-3cd263bef4bd"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "00701111\.000webhostapp\.com" ascii wide nocase
        $domain1 = "01nservercc\.cfd" ascii wide nocase
        $domain2 = "01onlinen\.cfd" ascii wide nocase
        $domain3 = "02nservercc\.cfd" ascii wide nocase
        $domain4 = "02onlinen\.cfd" ascii wide nocase
        $domain5 = "03nservercc\.cfd" ascii wide nocase
        $domain6 = "03onlinen\.cfd" ascii wide nocase
        $domain7 = "04nservercc\.cfd" ascii wide nocase
        $domain8 = "04onlinen\.cfd" ascii wide nocase
        $domain9 = "059879e5-b2e8-4f58-aa46-95f69d92aa34\.random\.onlinenhiscomservice\.store" ascii wide nocase
        $domain10 = "05nservercc\.cfd" ascii wide nocase
        $domain11 = "05onlinen\.cfd" ascii wide nocase
        $domain12 = "06nservercc\.cfd" ascii wide nocase
        $domain13 = "06onlinen\.cfd" ascii wide nocase
        $domain14 = "07nservercc\.cfd" ascii wide nocase
        $domain15 = "07onlinen\.cfd" ascii wide nocase
        $domain16 = "08nservercc\.cfd" ascii wide nocase
        $domain17 = "08onlinen\.cfd" ascii wide nocase
        $domain18 = "090\.apollo-page\.kro\.kr" ascii wide nocase
        $domain19 = "090\.gov5nikisa\.kro\.kr" ascii wide nocase
        $domain20 = "09nservercc\.cfd" ascii wide nocase
        $domain21 = "09onlinen\.cfd" ascii wide nocase
        $domain22 = "0knw2300\.mypressonline\.com" ascii wide nocase
        $domain23 = "0vym\.mailcorp\.eu" ascii wide nocase
        $domain24 = "1-z\.never\.com\.ru" ascii wide nocase
        $domain25 = "100000recipe\.com" ascii wide nocase
        $domain26 = "100nservercc\.cfd" ascii wide nocase
        $domain27 = "10nservercc\.cfd" ascii wide nocase
        $domain28 = "10onlinen\.cfd" ascii wide nocase
        $domain29 = "11nservercc\.cfd" ascii wide nocase
        $domain30 = "11onlinen\.cfd" ascii wide nocase
        $domain31 = "1213rt\.atwebpages\.com" ascii wide nocase
        $domain32 = "123\.apollo-page\.n-e\.kr" ascii wide nocase
        $domain33 = "12nservercc\.cfd" ascii wide nocase
        $domain34 = "12onlinen\.cfd" ascii wide nocase
        $domain35 = "13nservercc\.cfd" ascii wide nocase
        $domain36 = "13onlinen\.cfd" ascii wide nocase
        $domain37 = "14nservercc\.cfd" ascii wide nocase
        $domain38 = "14onlinen\.cfd" ascii wide nocase
        $domain39 = "15dhyfituhivoivjjgijrtjtgg\.cfd" ascii wide nocase
        $domain40 = "15fuerouhrgiurtituigjtug\.cfd" ascii wide nocase
        $domain41 = "15hjdgvfdjbvunghghod\.cfd" ascii wide nocase
        $domain42 = "15jhguerhguyogjopgoff\.cfd" ascii wide nocase
        $domain43 = "15nservercc\.cfd" ascii wide nocase
        $domain44 = "15onlinen\.cfd" ascii wide nocase
        $domain45 = "15ygfyerfgyufhsdgfyegf\.cfd" ascii wide nocase
        $domain46 = "15yufibeuiohuireiogjrgji\.cfd" ascii wide nocase
        $domain47 = "1636\.site" ascii wide nocase
        $domain48 = "1661-0241-call\.site" ascii wide nocase
        $domain49 = "1666-7797\.site" ascii wide nocase
        $ip50 = "103.20.235.113" ascii wide
        $ip51 = "103.76.228.204" ascii wide
        $ip52 = "104.168.145.83" ascii wide
        $ip53 = "104.194.152.22" ascii wide
        $ip54 = "104.194.152.251" ascii wide
        $ip55 = "104.194.152.251" ascii wide
        $ip56 = "104.36.229.179" ascii wide
        $ip57 = "104.36.229.179" ascii wide
        $ip58 = "107.148.71.88" ascii wide
        $ip59 = "107.189.16.65" ascii wide
        $ip60 = "109.248.151.179" ascii wide
        $ip61 = "121.183.134.113" ascii wide
        $ip62 = "121.183.134.113" ascii wide
        $ip63 = "121.183.134.113" ascii wide
        $ip64 = "121.66.72.110" ascii wide
        $ip65 = "125.136.67.99" ascii wide
        $ip66 = "141.164.41.17" ascii wide
        $ip67 = "152.89.247.57" ascii wide
        $ip68 = "156.224.22.247" ascii wide
        $ip69 = "158.247.238.155" ascii wide
        $ip70 = "159.100.6.137" ascii wide
        $ip71 = "162.216.114.133" ascii wide
        $ip72 = "172.93.201.248" ascii wide
        $ip73 = "172.93.201.248" ascii wide
        $ip74 = "183.105.66.48" ascii wide
        $ip75 = "185.224.137.164" ascii wide
        $ip76 = "185.235.128.114" ascii wide
        $ip77 = "192.186.142.74" ascii wide
        $ip78 = "192.236.154.125" ascii wide
        $ip79 = "203.245.0.121" ascii wide
        $url80 = "/test/v\.php" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_KUN3
{
    meta:
        description = "Detects IOCs associated with APT KUN3"
        author = "APTtrail Automated Collection"
        apt_group = "KUN3"
        aliases = "apt-k-un3"
        reference = "https://app.validin.com/detail?find=%E5%BF%AB%E8%BF%9EVPN_LetsVPN_%E5%BF%AB%E8%BF%9EVPN%E5%AE%98%E7%BD%91_%E4%B8%8B%E8%BD%BD%E5%BF%AB%E8%BF%9EVPN_%E6%B0%B8%E8%BF%9C%E8%83%BD%E8%BF%9E%E4%B8%8A%E7%9A%84VPN&type=raw&ref_id=334d03950fd#tab=host_pairs (# 2025-02-10)"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "28dg\.com" ascii wide nocase
        $domain1 = "8-210-67-136\.cprapid\.com" ascii wide nocase
        $domain2 = "api\.hami888\.com" ascii wide nocase
        $domain3 = "app\.zyxhlh\.com" ascii wide nocase
        $domain4 = "backlinkmate\.com" ascii wide nocase
        $domain5 = "beijingjiawenkeji\.com" ascii wide nocase
        $domain6 = "beijingzhongmingsheng\.com" ascii wide nocase
        $domain7 = "blackfale\.xyz" ascii wide nocase
        $domain8 = "bwsc668\.com" ascii wide nocase
        $domain9 = "cashotc\.com" ascii wide nocase
        $domain10 = "cz\.czsiss\.icu" ascii wide nocase
        $domain11 = "czsiss\.icu" ascii wide nocase
        $domain12 = "d1-myvip-mirrors\.avadev\.cn" ascii wide nocase
        $domain13 = "dingze\.com\.cn" ascii wide nocase
        $domain14 = "dkalca11\.asia" ascii wide nocase
        $domain15 = "down\.letsvpnc\.com" ascii wide nocase
        $domain16 = "fanshu8\.net" ascii wide nocase
        $domain17 = "fir\.zyxhlh\.com" ascii wide nocase
        $domain18 = "fx\.zyxhlh\.com" ascii wide nocase
        $domain19 = "google-pc\.cn" ascii wide nocase
        $domain20 = "gxbuliu\.cn" ascii wide nocase
        $domain21 = "gxxyclub\.com" ascii wide nocase
        $domain22 = "gzrzt\.cn" ascii wide nocase
        $domain23 = "hami888\.com" ascii wide nocase
        $domain24 = "hbklnb\.com" ascii wide nocase
        $domain25 = "heyukeji\.top" ascii wide nocase
        $domain26 = "huanfengkeji\.cn" ascii wide nocase
        $domain27 = "img\.hami888\.com" ascii wide nocase
        $domain28 = "interparklogistics\.com" ascii wide nocase
        $domain29 = "jitaikeji\.cn" ascii wide nocase
        $domain30 = "kleopatradayspa\.com" ascii wide nocase
        $domain31 = "kletscvpn\.com" ascii wide nocase
        $domain32 = "kletsxvpn\.com" ascii wide nocase
        $domain33 = "kletszvpn\.com" ascii wide nocase
        $domain34 = "kloewoman\.com" ascii wide nocase
        $domain35 = "kuai1lian\.com" ascii wide nocase
        $domain36 = "kuai2lian\.com" ascii wide nocase
        $domain37 = "kuai3lian\.com" ascii wide nocase
        $domain38 = "kuai5lian\.com" ascii wide nocase
        $domain39 = "kuailian002\.com" ascii wide nocase
        $domain40 = "kuailian003\.com" ascii wide nocase
        $domain41 = "kuailian005\.com" ascii wide nocase
        $domain42 = "kuailian006\.com" ascii wide nocase
        $domain43 = "kuailian12\.com" ascii wide nocase
        $domain44 = "kuailian13\.com" ascii wide nocase
        $domain45 = "kuailian15\.com" ascii wide nocase
        $domain46 = "kuailian55\.com" ascii wide nocase
        $domain47 = "kuailian555\.com" ascii wide nocase
        $domain48 = "kuailian66\.com" ascii wide nocase
        $domain49 = "kuailian777\.com" ascii wide nocase
        $ip50 = "156.251.17.147" ascii wide
        $ip51 = "45.204.207.244" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_LAZARUS
{
    meta:
        description = "Detects IOCs associated with APT LAZARUS"
        author = "APTtrail Automated Collection"
        apt_group = "LAZARUS"
        aliases = "akdoortea, alluring pisces, applejeus"
        reference = "http://report.threatbook.cn/LS.pdf (Chinese)"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "0927\.vercel\.app" ascii wide nocase
        $domain1 = "0xraiseup\.com" ascii wide nocase
        $domain2 = "118274-zoomid\.com" ascii wide nocase
        $domain3 = "11stnft\.click" ascii wide nocase
        $domain4 = "1215\.vercel\.app" ascii wide nocase
        $domain5 = "123fisd\.naveicoipg\.online" ascii wide nocase
        $domain6 = "15248636\.site" ascii wide nocase
        $domain7 = "1688dsj\.com" ascii wide nocase
        $domain8 = "172-86-114-141\.dal\.priv\.octovpn\.net" ascii wide nocase
        $domain9 = "172-86-114-170\.dal\.priv\.octovpn\.net" ascii wide nocase
        $domain10 = "1drvmicrosoft\.com" ascii wide nocase
        $domain11 = "247l\.net" ascii wide nocase
        $domain12 = "2ab9\.watashinonegai\.ru" ascii wide nocase
        $domain13 = "2daojnjnp666jla6\.dropfile\.online" ascii wide nocase
        $domain14 = "360scanner\.store" ascii wide nocase
        $domain15 = "360share\.pro" ascii wide nocase
        $domain16 = "4bjt2rceijktwedi\.onion" ascii wide nocase
        $domain17 = "4caddie\.com" ascii wide nocase
        $domain18 = "4w9h8ps9\.naveicoipa\.tech" ascii wide nocase
        $domain19 = "4w9h8ps9\.naveicoipc\.tech" ascii wide nocase
        $domain20 = "6la0cwds\.naveicoiph\.online" ascii wide nocase
        $domain21 = "7xvc\.meeting-central\.online" ascii wide nocase
        $domain22 = "7xvc\.meeting-zone\.online" ascii wide nocase
        $domain23 = "7xvc\.roomconnect\.online" ascii wide nocase
        $domain24 = "7xvc\.virtual-collab\.online" ascii wide nocase
        $domain25 = "8190ocvswfyd57v5\.docsend\.online" ascii wide nocase
        $domain26 = "8cap\.inashtech\.com" ascii wide nocase
        $domain27 = "9yxqida1b\.naveicoiph\.online" ascii wide nocase
        $domain28 = "a\.videotalks\.site" ascii wide nocase
        $domain29 = "aa2akhtech\.in" ascii wide nocase
        $domain30 = "aarnaitsolution\.in" ascii wide nocase
        $domain31 = "aat1pbil\.naveicoipg\.online" ascii wide nocase
        $domain32 = "abc\.meeting-central\.online" ascii wide nocase
        $domain33 = "abc\.meeting-zone\.online" ascii wide nocase
        $domain34 = "abc\.preconnection\.online" ascii wide nocase
        $domain35 = "abc\.roomconnect\.online" ascii wide nocase
        $domain36 = "abilityscan360\.com" ascii wide nocase
        $domain37 = "abiyz\.com" ascii wide nocase
        $domain38 = "abs\.twitter\.expublic\.linkpc\.net" ascii wide nocase
        $domain39 = "access\.support\.general-meet\.site" ascii wide nocase
        $domain40 = "accounts\.ceinbase\.com" ascii wide nocase
        $domain41 = "acom\.capital" ascii wide nocase
        $domain42 = "acoustickoala\.com" ascii wide nocase
        $domain43 = "acroadovw\.com" ascii wide nocase
        $domain44 = "activity-179384736\.site" ascii wide nocase
        $domain45 = "activity-permission\.online" ascii wide nocase
        $domain46 = "additional\.work\.gd" ascii wide nocase
        $domain47 = "additionalpublic\.work\.gd" ascii wide nocase
        $domain48 = "addrcheck\.corecheckmailsrv\.com" ascii wide nocase
        $domain49 = "ade\.dropfile\.online" ascii wide nocase
        $ip50 = "103.205.179.4" ascii wide
        $ip51 = "103.231.75.101" ascii wide
        $ip52 = "103.35.189.107" ascii wide
        $ip53 = "103.35.189.107" ascii wide
        $ip54 = "104.168.136.24" ascii wide
        $ip55 = "104.168.151.34" ascii wide
        $ip56 = "104.168.157.45" ascii wide
        $ip57 = "104.168.157.45" ascii wide
        $ip58 = "104.168.165.165" ascii wide
        $ip59 = "104.168.165.165" ascii wide
        $ip60 = "104.168.165.173" ascii wide
        $ip61 = "104.168.165.173" ascii wide
        $ip62 = "104.168.165.203" ascii wide
        $ip63 = "104.168.165.203" ascii wide
        $ip64 = "104.168.172.20" ascii wide
        $ip65 = "104.168.203.159" ascii wide
        $ip66 = "104.168.203.159" ascii wide
        $ip67 = "104.194.133.88" ascii wide
        $ip68 = "104.194.133.88" ascii wide
        $ip69 = "104.217.163.61" ascii wide
        $ip70 = "104.232.71.7" ascii wide
        $ip71 = "107.172.197.175" ascii wide
        $ip72 = "107.175.172.129" ascii wide
        $ip73 = "107.189.16.122" ascii wide
        $ip74 = "107.189.16.122" ascii wide
        $ip75 = "107.189.16.176" ascii wide
        $ip76 = "107.189.16.176" ascii wide
        $ip77 = "107.189.20.152" ascii wide
        $ip78 = "107.189.20.152" ascii wide
        $ip79 = "107.189.24.80" ascii wide
        $url80 = "/admin/verify\.php" ascii wide nocase
        $url81 = "/ServiceDeskPlus/products\.do" ascii wide nocase
        $url82 = "/ServiceDeskPlus/products\.do" ascii wide nocase
        $url83 = "/fileserver/temp/platform\.asp" ascii wide nocase
        $url84 = "/angkor\.ylw\.common\.fileserviceserver/web/document/netframework\.asp" ascii wide nocase
        $url85 = "/old/viewer\.php" ascii wide nocase
        $url86 = "/ServiceDeskPlus/products\.do" ascii wide nocase
        $url87 = "/theveniaux/webliotheque/public/css/main\.php" ascii wide nocase
        $url88 = "/admin/admin\.asp" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_LAZYSCRIPTER
{
    meta:
        description = "Detects IOCs associated with APT LAZYSCRIPTER"
        author = "APTtrail Automated Collection"
        apt_group = "LAZYSCRIPTER"
        reference = "https://lab52.io/blog/very-very-lazy-lazyscripters-scripts-double-compromise-in-a-single-obfuscation/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "bsjsiq3ytpt3efsn6wnu3pukxil6q6plty6m6dcz\.duckdns\.org" ascii wide nocase
        $domain1 = "gowaymevps\.xyz" ascii wide nocase
        $domain2 = "gowaymevpslink1\.xyz" ascii wide nocase
        $domain3 = "gowaymevpslink2\.xyz" ascii wide nocase
        $domain4 = "gowaymevpslink3\.xyz" ascii wide nocase
        $domain5 = "gowaymevpslink4\.xyz" ascii wide nocase
        $domain6 = "gowaymevpslink5\.xyz" ascii wide nocase
        $domain7 = "iatassl-telechargementsecurity\.duckdns\.org" ascii wide nocase
        $domain8 = "internetexploraldon\.sytes\.net" ascii wide nocase
        $domain9 = "jbizgsvhzj22evqon9ezz8bmbupp1s6cprmriam1\.duckdns\.org" ascii wide nocase
        $domain10 = "milla\.publicvm\.com" ascii wide nocase
        $domain11 = "saqicpcgflrlgxgoxxzkbfrjuisbkozeqrmthrzo\.duckdns\.org" ascii wide nocase
        $domain12 = "securessl\.fit" ascii wide nocase
        $domain13 = "smscs\.publicvm\.com" ascii wide nocase
        $domain14 = "stub\.ignorelist\.com" ascii wide nocase
        $domain15 = "u1153246fov\.ha004\.t\.justns\.ru" ascii wide nocase
        $domain16 = "varifsecuripass\.duckdns\.org" ascii wide nocase
        $domain17 = "vistacp-enhance\.duckdns\.org" ascii wide nocase
        $ip18 = "185.81.157.186" ascii wide
        $ip19 = "45.91.92.112" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_LEAFMINER
{
    meta:
        description = "Detects IOCs associated with APT LEAFMINER"
        author = "APTtrail Automated Collection"
        apt_group = "LEAFMINER"
        reference = "https://www.symantec.com/blogs/threat-intelligence/leafminer-espionage-middle-east"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "adobe-flash\.us" ascii wide nocase
        $domain1 = "adobe-plugin\.bid" ascii wide nocase
        $domain2 = "ilhost\.in" ascii wide nocase
        $domain3 = "iqhost\.us" ascii wide nocase
        $domain4 = "microsoft-office-free-templates-download\.btc-int\.in" ascii wide nocase
        $domain5 = "microsoft-office-free-templates\.in" ascii wide nocase
        $domain6 = "offiice365\.us" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_LIBRARIANGHOULS
{
    meta:
        description = "Detects IOCs associated with APT LIBRARIANGHOULS"
        author = "APTtrail Automated Collection"
        apt_group = "LIBRARIANGHOULS"
        reference = "https://app.validin.com/detail?find=89.110.65.154&type=ip4&ref_id=e41544d48ff#tab=resolutions"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "accouts-verification\.ru" ascii wide nocase
        $domain1 = "acountservices\.nl" ascii wide nocase
        $domain2 = "acountservices\.online" ascii wide nocase
        $domain3 = "anyhostings\.ru" ascii wide nocase
        $domain4 = "anyinfos\.ru" ascii wide nocase
        $domain5 = "bmapps\.org" ascii wide nocase
        $domain6 = "center-mail\.ru" ascii wide nocase
        $domain7 = "claud-mail\.ru" ascii wide nocase
        $domain8 = "deauthorization\.online" ascii wide nocase
        $domain9 = "detectis\.ru" ascii wide nocase
        $domain10 = "downdown\.ru" ascii wide nocase
        $domain11 = "dragonfires\.ru" ascii wide nocase
        $domain12 = "email-informer\.ru" ascii wide nocase
        $domain13 = "email-office\.ru" ascii wide nocase
        $domain14 = "hostingforme\.nl" ascii wide nocase
        $domain15 = "mail-cheker\.nl" ascii wide nocase
        $domain16 = "office-account\.ru" ascii wide nocase
        $domain17 = "office-email\.ru" ascii wide nocase
        $domain18 = "outinfo\.ru" ascii wide nocase
        $domain19 = "redaction-voenmeh\.info" ascii wide nocase
        $domain20 = "supersuit\.site" ascii wide nocase
        $domain21 = "unifikator\.ru" ascii wide nocase
        $domain22 = "users-mail\.ru" ascii wide nocase
        $domain23 = "verificationc\.nl" ascii wide nocase
        $domain24 = "verificationc\.online" ascii wide nocase
        $domain25 = "verifikations\.ru" ascii wide nocase
        $domain26 = "vniir\.nl" ascii wide nocase
        $domain27 = "vniir\.space" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_LONGHORN
{
    meta:
        description = "Detects IOCs associated with APT LONGHORN"
        author = "APTtrail Automated Collection"
        apt_group = "LONGHORN"
        aliases = "apt-c-39, coloredlamberts, lambert"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/actor/longhorn"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "cdn\.fmlstatic\.com" ascii wide nocase
        $domain1 = "financasdebrasil\.com" ascii wide nocase
        $domain2 = "fmlstatic\.com" ascii wide nocase
        $domain3 = "uaefinance\.org" ascii wide nocase
        $ip4 = "103.242.119.71" ascii wide
        $ip5 = "120.50.38.187" ascii wide
        $ip6 = "161.5.6.206" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_LOTUSBLOSSOM
{
    meta:
        description = "Detects IOCs associated with APT LOTUSBLOSSOM"
        author = "APTtrail Automated Collection"
        apt_group = "LOTUSBLOSSOM"
        reference = "https://www.accenture.com/t20180131T100734Z__w__/us-en/_acnmedia/PDF-46/Accenture-Security-Elise-Threat-Analysis.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "38qmk6\.0to9\.info" ascii wide nocase
        $domain1 = "3qyo4o7\.7r7i3\.info" ascii wide nocase
        $domain2 = "7g91xhp\.envuy3\.net" ascii wide nocase
        $domain3 = "aliancesky\.com" ascii wide nocase
        $domain4 = "asean-star\.com" ascii wide nocase
        $domain5 = "aseaneco\.org" ascii wide nocase
        $domain6 = "aseansec\.dynalias\.org" ascii wide nocase
        $domain7 = "babysoal\.com" ascii wide nocase
        $domain8 = "beckhammer\.xicp\.net" ascii wide nocase
        $domain9 = "boshman09\.com" ascii wide nocase
        $domain10 = "chris201\.net" ascii wide nocase
        $domain11 = "cpcl2006\.dyndns-free\.com" ascii wide nocase
        $domain12 = "cybertunnel\.dyndns\.info" ascii wide nocase
        $domain13 = "dtdf5vu\.nt7yq\.info" ascii wide nocase
        $domain14 = "harryleed\.dyndns\.org" ascii wide nocase
        $domain15 = "iascas\.net" ascii wide nocase
        $domain16 = "imonju\.com" ascii wide nocase
        $domain17 = "imonju\.net" ascii wide nocase
        $domain18 = "interhero\.net" ascii wide nocase
        $domain19 = "j\.4tc3ldw\.g9ml\.www0\.org" ascii wide nocase
        $domain20 = "jackyson\.dyndns\.info" ascii wide nocase
        $domain21 = "kid\.dyndns\.org" ascii wide nocase
        $domain22 = "kjd\.dyndns\.org" ascii wide nocase
        $domain23 = "l\.hovux\.eln9wj7\.7gpj\.org" ascii wide nocase
        $domain24 = "newinfo32\.eicp\.net" ascii wide nocase
        $domain25 = "newshappys\.dyndns-blog\.com" ascii wide nocase
        $domain26 = "petto\.mooo\.com" ascii wide nocase
        $domain27 = "phil-army\.gotdns\.org" ascii wide nocase
        $domain28 = "phil-gov\.gotdns\.org" ascii wide nocase
        $domain29 = "scristioned\.dyndns-web\.com" ascii wide nocase
        $domain30 = "seachers\.net" ascii wide nocase
        $domain31 = "serchers\.net" ascii wide nocase
        $domain32 = "shotacon\.dyndns\.info" ascii wide nocase
        $domain33 = "tgecc\.org" ascii wide nocase
        $domain34 = "tintuchoahau\.com" ascii wide nocase
        $domain35 = "ubkv1t\.ec0\.com" ascii wide nocase
        $domain36 = "usa-moon\.net" ascii wide nocase
        $domain37 = "verolalia\.dyndns\.org" ascii wide nocase
        $domain38 = "vienclp\.com" ascii wide nocase
        $domain39 = "w\.7sytdjc\.wroi\.cxy\.com" ascii wide nocase
        $domain40 = "wsi\.dyndns\.org" ascii wide nocase
        $domain41 = "www3\.bkav2010\.net" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_LUCKYCAT
{
    meta:
        description = "Detects IOCs associated with APT LUCKYCAT"
        author = "APTtrail Automated Collection"
        apt_group = "LUCKYCAT"
        aliases = "exilerat, luckycat, sepulcher"
        reference = "http://www.trendmicro.com/cloud-content/us/pdfs/security-intelligence/white-papers/wp_luckycat_redux.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "89757\.x\.gg" ascii wide nocase
        $domain1 = "airjaldi\.online" ascii wide nocase
        $domain2 = "applestatic\.com" ascii wide nocase
        $domain3 = "bailianlan\.c\.dwyu\.com" ascii wide nocase
        $domain4 = "cattree\.1x\.biz" ascii wide nocase
        $domain5 = "charlesbrain\.shop\.co" ascii wide nocase
        $domain6 = "clbest\.greenglassint\.net" ascii wide nocase
        $domain7 = "dalailamatrustindia\.ddns\.net" ascii wide nocase
        $domain8 = "duojee\.info" ascii wide nocase
        $domain9 = "fidk\.rkntils\.dnset\.com" ascii wide nocase
        $domain10 = "fireequipment\.website\.org" ascii wide nocase
        $domain11 = "flex-jobs\.in" ascii wide nocase
        $domain12 = "footballworldcup\.website\.org" ascii wide nocase
        $domain13 = "frankwhales\.shop\.co" ascii wide nocase
        $domain14 = "freetibet\.in" ascii wide nocase
        $domain15 = "gmailcom\.tw" ascii wide nocase
        $domain16 = "goodwell\.all\.co\.uk" ascii wide nocase
        $domain17 = "havefuns\.rkntils\.10dig\.net" ascii wide nocase
        $domain18 = "hi21222325\.x\.gg" ascii wide nocase
        $domain19 = "indiatrustdalailama\.com" ascii wide nocase
        $domain20 = "jeepvihecle\.shop\.co" ascii wide nocase
        $domain21 = "jobflex\.in" ascii wide nocase
        $domain22 = "johnnees\.rkntils\.10dig\.net" ascii wide nocase
        $domain23 = "killmannets\.0fees\.net" ascii wide nocase
        $domain24 = "kinkeechow\.shop\.co" ascii wide nocase
        $domain25 = "kittyshop\.kilu\.org" ascii wide nocase
        $domain26 = "lucysmith\.0fees\.net" ascii wide nocase
        $domain27 = "maritimemaster\.kilu\.org" ascii wide nocase
        $domain28 = "masterchoice\.shop\.co" ascii wide nocase
        $domain29 = "mondaynews\.tk" ascii wide nocase
        $domain30 = "nangsihistory\.vip" ascii wide nocase
        $domain31 = "newsindian\.xyz" ascii wide nocase
        $domain32 = "peopleoffreeworld\.tk" ascii wide nocase
        $domain33 = "perfect\.shop\.co" ascii wide nocase
        $domain34 = "pumasports\.website\.org" ascii wide nocase
        $domain35 = "rediffpapers\.com" ascii wide nocase
        $domain36 = "rkntils\.10dig\.net" ascii wide nocase
        $domain37 = "rkntils\.dnset\.com" ascii wide nocase
        $domain38 = "rukiyeangel\.dyndns\.pro" ascii wide nocase
        $domain39 = "sunshine\.shop\.co" ascii wide nocase
        $domain40 = "tb123\.xoomsite\.com" ascii wide nocase
        $domain41 = "tbda123\.gwchost\.com" ascii wide nocase
        $domain42 = "tennissport\.website\.org" ascii wide nocase
        $domain43 = "tibet-gov\.web\.app" ascii wide nocase
        $domain44 = "tibet\.bet" ascii wide nocase
        $domain45 = "tibetancongress\.com" ascii wide nocase
        $domain46 = "tibetanyouthcongress\.com" ascii wide nocase
        $domain47 = "toms\.0fees\.net" ascii wide nocase
        $domain48 = "tomsburs\.shop\.co" ascii wide nocase
        $domain49 = "tomygreen\.0fees\.net" ascii wide nocase
        $ip50 = "107.151.194.197" ascii wide
        $ip51 = "107.151.194.197" ascii wide
        $ip52 = "118.99.13.4" ascii wide
        $ip53 = "118.99.13.4" ascii wide
        $ip54 = "167.179.99.136" ascii wide
        $ip55 = "27.126.188.212" ascii wide
        $ip56 = "27.126.188.212" ascii wide
        $ip57 = "27.126.188.212" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_LUMINOUSMOTH
{
    meta:
        description = "Detects IOCs associated with APT LUMINOUSMOTH"
        author = "APTtrail Automated Collection"
        apt_group = "LUMINOUSMOTH"
        reference = "https://otx.alienvault.com/pulse/60efe4047c9b9b9564314643"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "7daydai1y\.com" ascii wide nocase
        $domain1 = "irrawddy\.com" ascii wide nocase
        $domain2 = "mmtimes\.net" ascii wide nocase
        $domain3 = "mmtimes\.org" ascii wide nocase
        $domain4 = "mopfi-ferd\.com" ascii wide nocase
        $domain5 = "updatecatalogs\.com" ascii wide nocase
        $domain6 = "webmail\.mmtimes\.net" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_LYCEUM
{
    meta:
        description = "Detects IOCs associated with APT LYCEUM"
        author = "APTtrail Automated Collection"
        apt_group = "LYCEUM"
        aliases = "danbot, hexane, lyceum"
        reference = "https://medium.com/@Manu_De_Lucia/exploding-the-danbot-code-to-hunt-for-hexanes-cyber-weapon-3d466775f480"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "akastatus\.com" ascii wide nocase
        $domain1 = "bsolutions-cloude\.com" ascii wide nocase
        $domain2 = "centosupdatecdn\.com" ascii wide nocase
        $domain3 = "cloudmsn\.net" ascii wide nocase
        $domain4 = "cyberclub\.one" ascii wide nocase
        $domain5 = "cybersecnet\.co\.za" ascii wide nocase
        $domain6 = "cybersecnet\.org" ascii wide nocase
        $domain7 = "defenderlive\.com" ascii wide nocase
        $domain8 = "defenderstatus\.com" ascii wide nocase
        $domain9 = "digitalmarketingnews\.net" ascii wide nocase
        $domain10 = "dmgagency\.net" ascii wide nocase
        $domain11 = "dnscachecloud\.com" ascii wide nocase
        $domain12 = "dnscatalog\.net" ascii wide nocase
        $domain13 = "dnscdn\.org" ascii wide nocase
        $domain14 = "dnscloudservice\.com" ascii wide nocase
        $domain15 = "dnsstatus\.org" ascii wide nocase
        $domain16 = "excsrvcdn\.com" ascii wide nocase
        $domain17 = "he-express-marketing\.com" ascii wide nocase
        $domain18 = "hpesystem\.com" ascii wide nocase
        $domain19 = "jobschippc\.com" ascii wide nocase
        $domain20 = "livecdn\.com" ascii wide nocase
        $domain21 = "main\.download" ascii wide nocase
        $domain22 = "mastertape\.org" ascii wide nocase
        $domain23 = "microsftonline\.net" ascii wide nocase
        $domain24 = "msnnews\.org" ascii wide nocase
        $domain25 = "news-reporter\.xyz" ascii wide nocase
        $domain26 = "news-spot\.live" ascii wide nocase
        $domain27 = "news-spot\.xyz" ascii wide nocase
        $domain28 = "online-analytic\.com" ascii wide nocase
        $domain29 = "onlineoutlook\.net" ascii wide nocase
        $domain30 = "opendnscloud\.com" ascii wide nocase
        $domain31 = "planet-informer\.me" ascii wide nocase
        $domain32 = "science-news\.live" ascii wide nocase
        $domain33 = "securednsservice\.net" ascii wide nocase
        $domain34 = "softwareagjobs\.com" ascii wide nocase
        $domain35 = "stgeorgebankers\.com" ascii wide nocase
        $domain36 = "sysadminnews\.info" ascii wide nocase
        $domain37 = "uctpostgraduate\.com" ascii wide nocase
        $domain38 = "updatecdn\.net" ascii wide nocase
        $domain39 = "web-statistics\.info" ascii wide nocase
        $domain40 = "web-traffic\.info" ascii wide nocase
        $domain41 = "webmaster-team\.com" ascii wide nocase
        $domain42 = "windowsupdatecdn\.com" ascii wide nocase
        $domain43 = "wsuslink\.com" ascii wide nocase
        $domain44 = "zonestatistic\.com" ascii wide nocase
        $ip45 = "104.249.26.60" ascii wide
        $ip46 = "185.243.112.136" ascii wide
        $ip47 = "185.243.112.136" ascii wide
        $ip48 = "85.206.175.199" ascii wide
        $ip49 = "89.39.149.18" ascii wide
        $ip50 = "89.39.149.18" ascii wide
        $ip51 = "89.39.149.18" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_MACHETE
{
    meta:
        description = "Detects IOCs associated with APT MACHETE"
        author = "APTtrail Automated Collection"
        apt_group = "MACHETE"
        aliases = "apt-c-43, apt43"
        reference = "https://app.validin.com/detail?find=212.224.107.244&type=ip4&ref_id=ee39f8a47e5#tab=resolutions"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "6e24a5fb\.ngrok\.io" ascii wide nocase
        $domain1 = "adtiomtardecessd\.zapto\.org" ascii wide nocase
        $domain2 = "agaliarept\.com" ascii wide nocase
        $domain3 = "artyomt\.com" ascii wide nocase
        $domain4 = "asymmetricfile\.blogspot\.com" ascii wide nocase
        $domain5 = "blogwhereyou\.com" ascii wide nocase
        $domain6 = "ceofanb18\.mipropia\.com" ascii wide nocase
        $domain7 = "correomindefensagobvemyspace\.com" ascii wide nocase
        $domain8 = "djcaps\.gotdns\.ch" ascii wide nocase
        $domain9 = "f9527d03\.ngrok\.io" ascii wide nocase
        $domain10 = "frejabe\.com" ascii wide nocase
        $domain11 = "funkytothemoon\.live" ascii wide nocase
        $domain12 = "grannegral\.com" ascii wide nocase
        $domain13 = "great-jepsen\.51-79-62-98\.plesk\.page" ascii wide nocase
        $domain14 = "intelligent-archimedes\.51-79-62-98\.plesk\.page" ascii wide nocase
        $domain15 = "java\.serveblog\.net" ascii wide nocase
        $domain16 = "koliast\.com" ascii wide nocase
        $domain17 = "lawyersofficial\.mipropia\.com" ascii wide nocase
        $domain18 = "mcsi\.gotdns\.ch" ascii wide nocase
        $domain19 = "op-icaro\.site" ascii wide nocase
        $domain20 = "plushbr\.com" ascii wide nocase
        $domain21 = "pompst\.store" ascii wide nocase
        $domain22 = "postinfomatico\.blogspot\.com" ascii wide nocase
        $domain23 = "pumapomp\.store" ascii wide nocase
        $domain24 = "sangeet1\.000webhostapp\.com" ascii wide nocase
        $domain25 = "skyscopeups\.cfd" ascii wide nocase
        $domain26 = "soldatenkovarten\.com" ascii wide nocase
        $domain27 = "solutionconect\.online" ascii wide nocase
        $domain28 = "surgutneftegazappstore\.com" ascii wide nocase
        $domain29 = "tobabean\.expert" ascii wide nocase
        $domain30 = "tokeiss\.ddns\.net" ascii wide nocase
        $domain31 = "u154611594\.hostingerapp\.com" ascii wide nocase
        $domain32 = "u929489355\.hostingerapp\.com" ascii wide nocase
        $domain33 = "xmailliwx\.com" ascii wide nocase
        $ip34 = "31.207.44.72" ascii wide
        $ip35 = "31.207.45.243" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_MALKAMAK
{
    meta:
        description = "Detects IOCs associated with APT MALKAMAK"
        author = "APTtrail Automated Collection"
        apt_group = "MALKAMAK"
        reference = "https://www.cybereason.com/blog/operation-ghostshell-novel-rat-targets-global-aerospace-and-telecoms-firms"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "azure\.ms-tech\.us" ascii wide nocase
        $domain1 = "ms-tech\.us" ascii wide nocase
        $domain2 = "whynooneistherefornoneofthem\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_MARBLEDDUST
{
    meta:
        description = "Detects IOCs associated with APT MARBLEDDUST"
        author = "APTtrail Automated Collection"
        apt_group = "MARBLEDDUST"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/05/12/marbled-dust-leverages-zero-day-in-output-messenger-for-regional-espionage/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "api\.wordinfos\.com" ascii wide nocase
        $domain1 = "wordinfos\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_MENUPASS
{
    meta:
        description = "Detects IOCs associated with APT MENUPASS"
        author = "APTtrail Automated Collection"
        apt_group = "MENUPASS"
        aliases = "apt10, earth kasha, gallium"
        reference = "http://blog.jpcert.or.jp/2017/02/chches-malware--93d6.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "002562066559681\.r3u8\.com" ascii wide nocase
        $domain1 = "031168053846049\.r3u8\.com" ascii wide nocase
        $domain2 = "0625\.have8000\.com" ascii wide nocase
        $domain3 = "1\.gadskysun\.com" ascii wide nocase
        $domain4 = "100fanwen\.com" ascii wide nocase
        $domain5 = "11\.usyahooapis\.com" ascii wide nocase
        $domain6 = "19518473326\.r3u8\.com" ascii wide nocase
        $domain7 = "1960445709311199\.r3u8\.com" ascii wide nocase
        $domain8 = "1j\.www1\.biz" ascii wide nocase
        $domain9 = "1z\.itsaol\.com" ascii wide nocase
        $domain10 = "2012yearleft\.com" ascii wide nocase
        $domain11 = "2014\.zzux\.com" ascii wide nocase
        $domain12 = "202017845\.r3u8\.com" ascii wide nocase
        $domain13 = "2139465544784\.r3u8\.com" ascii wide nocase
        $domain14 = "2789203959848958\.r3u8\.com" ascii wide nocase
        $domain15 = "5590428449750026\.r3u8\.com" ascii wide nocase
        $domain16 = "5q\.niushenghuo\.info" ascii wide nocase
        $domain17 = "6r\.suibian2010\.info" ascii wide nocase
        $domain18 = "9gowg\.tech" ascii wide nocase
        $domain19 = "Jepsen\.r3u8\.com" ascii wide nocase
        $domain20 = "a\.wubangtu\.info" ascii wide nocase
        $domain21 = "a1\.suibian2010\.info" ascii wide nocase
        $domain22 = "ab\.4pu\.com" ascii wide nocase
        $domain23 = "abc\.wikaba\.com" ascii wide nocase
        $domain24 = "abcd100621\.3322\.org" ascii wide nocase
        $domain25 = "abcd120719\.6600\.org" ascii wide nocase
        $domain26 = "abcd120807\.3322\.org" ascii wide nocase
        $domain27 = "acc\.emailfound\.info" ascii wide nocase
        $domain28 = "acc\.lehigtapp\.com" ascii wide nocase
        $domain29 = "acsocietyy\.com" ascii wide nocase
        $domain30 = "ad\.getfond\.info" ascii wide nocase
        $domain31 = "ad\.webbooting\.com" ascii wide nocase
        $domain32 = "additional\.sexidude\.com" ascii wide nocase
        $domain33 = "af\.zyns\.com" ascii wide nocase
        $domain34 = "afc\.https443\.org" ascii wide nocase
        $domain35 = "ako\.ddns\.us" ascii wide nocase
        $domain36 = "algorithm\.ddnsgeek\.com" ascii wide nocase
        $domain37 = "amsidgoo\.thedomais\.info" ascii wide nocase
        $domain38 = "androidmusicapp\.onmypc\.us" ascii wide nocase
        $domain39 = "announcements\.toythieves\.com" ascii wide nocase
        $domain40 = "anvprn\.com" ascii wide nocase
        $domain41 = "aotuo\.9966\.org" ascii wide nocase
        $domain42 = "apec\.qtsofta\.com" ascii wide nocase
        $domain43 = "app\.lehigtapp\.com" ascii wide nocase
        $domain44 = "apple\.cmdnetview\.com" ascii wide nocase
        $domain45 = "apple\.defensewar\.org" ascii wide nocase
        $domain46 = "apple\.ikwb\.com" ascii wide nocase
        $domain47 = "appledownload\.ourhobby\.com" ascii wide nocase
        $domain48 = "appleimages\.itemdb\.com" ascii wide nocase
        $domain49 = "appleimages\.longmusic\.com" ascii wide nocase
        $ip50 = "185.117.88.80" ascii wide
        $ip51 = "204.79.197.200" ascii wide
        $ip52 = "31.220.92.125" ascii wide
        $ip53 = "45.76.222.130" ascii wide
        $ip54 = "45.77.183.161" ascii wide
        $ip55 = "5.181.25.99" ascii wide
        $ip56 = "61.221.66.85" ascii wide
        $ip57 = "89.117.79.31" ascii wide
        $ip58 = "89.117.79.31" ascii wide
        $ip59 = "89.117.79.31" ascii wide
        $ip60 = "89.117.79.31" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_MERCENARYAMANDA
{
    meta:
        description = "Detects IOCs associated with APT MERCENARYAMANDA"
        author = "APTtrail Automated Collection"
        apt_group = "MERCENARYAMANDA"
        aliases = "Dark Basin"
        reference = "https://citizenlab.ca/2020/06/dark-basin-uncovering-a-massive-hack-for-hire-operation/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "2mblk\.com" ascii wide nocase
        $domain1 = "4mblk\.com" ascii wide nocase
        $domain2 = "ablyazovangels\.com" ascii wide nocase
        $domain3 = "ablyazovcog\.com" ascii wide nocase
        $domain4 = "ablyazovcrimestory\.com" ascii wide nocase
        $domain5 = "ablyazovcrimesyndicate\.com" ascii wide nocase
        $domain6 = "ablyazovcriminalgang\.com" ascii wide nocase
        $domain7 = "ablyazovcriminals\.com" ascii wide nocase
        $domain8 = "ablyazovgang\.com" ascii wide nocase
        $domain9 = "ablyazovmafia\.com" ascii wide nocase
        $domain10 = "ablyazovorganisedcrime\.com" ascii wide nocase
        $domain11 = "affiliatedomainservice\.com" ascii wide nocase
        $domain12 = "affliatedomainservice\.com" ascii wide nocase
        $domain13 = "allaboutiot\.website" ascii wide nocase
        $domain14 = "anitmationworldnews\.com" ascii wide nocase
        $domain15 = "anothershortnr\.com" ascii wide nocase
        $domain16 = "aplsrvrer\.com" ascii wide nocase
        $domain17 = "assuredreturnplan\.com" ascii wide nocase
        $domain18 = "auditionregistrationonline\.com" ascii wide nocase
        $domain19 = "backwaterreservoir\.com" ascii wide nocase
        $domain20 = "basemailservice\.com" ascii wide nocase
        $domain21 = "baseserveremailbg\.com" ascii wide nocase
        $domain22 = "basichostingrussia\.com" ascii wide nocase
        $domain23 = "basichostnetservice\.com" ascii wide nocase
        $domain24 = "basicmyoffshore\.com" ascii wide nocase
        $domain25 = "basicruoffshore\.com" ascii wide nocase
        $domain26 = "basicservicehk\.com" ascii wide nocase
        $domain27 = "basicservicelux\.com" ascii wide nocase
        $domain28 = "basicservicemy\.com" ascii wide nocase
        $domain29 = "basicservicerus\.com" ascii wide nocase
        $domain30 = "basicservicesg\.com" ascii wide nocase
        $domain31 = "basicsgoffshore\.com" ascii wide nocase
        $domain32 = "bellsouthnetwork\.com" ascii wide nocase
        $domain33 = "belowmargins\.com" ascii wide nocase
        $domain34 = "bitserverhk\.com" ascii wide nocase
        $domain35 = "bitserverlux\.com" ascii wide nocase
        $domain36 = "blogforpranks\.com" ascii wide nocase
        $domain37 = "blogserverlx\.com" ascii wide nocase
        $domain38 = "browserdirectservice\.com" ascii wide nocase
        $domain39 = "browserextensions\.info" ascii wide nocase
        $domain40 = "browserredirect\.com" ascii wide nocase
        $domain41 = "bsrvrer\.com" ascii wide nocase
        $domain42 = "budgtoffmy\.com" ascii wide nocase
        $domain43 = "budgtoffru\.com" ascii wide nocase
        $domain44 = "buzzoffbul\.com" ascii wide nocase
        $domain45 = "buzzoffhk\.com" ascii wide nocase
        $domain46 = "buzzoffmy\.com" ascii wide nocase
        $domain47 = "buzzoffru\.com" ascii wide nocase
        $domain48 = "buzzoffsg\.com" ascii wide nocase
        $domain49 = "capitalinvestmentsllp\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_MIDDLEEAST
{
    meta:
        description = "Detects IOCs associated with APT MIDDLEEAST"
        author = "APTtrail Automated Collection"
        apt_group = "MIDDLEEAST"
        reference = "https://blog.talosintelligence.com/2020/01/mideast-tensions-preparations.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "1e100\.tech" ascii wide nocase
        $domain1 = "1m100\.tech" ascii wide nocase
        $domain2 = "ads-youtube\.net" ascii wide nocase
        $domain3 = "ads-youtube\.online" ascii wide nocase
        $domain4 = "ads-youtube\.tech" ascii wide nocase
        $domain5 = "akamai\.press" ascii wide nocase
        $domain6 = "akamaitechnology\.com" ascii wide nocase
        $domain7 = "akamaitechnology\.tech" ascii wide nocase
        $domain8 = "alkamaihd\.com" ascii wide nocase
        $domain9 = "alkamaihd\.net" ascii wide nocase
        $domain10 = "azurewebsites\.tech" ascii wide nocase
        $domain11 = "big-windowss\.com" ascii wide nocase
        $domain12 = "britishnews\.press" ascii wide nocase
        $domain13 = "broadcast-microsoft\.tech" ascii wide nocase
        $domain14 = "cachevideo\.com" ascii wide nocase
        $domain15 = "cachevideo\.online" ascii wide nocase
        $domain16 = "cachevideo\.xyz" ascii wide nocase
        $domain17 = "chromeupdates\.online" ascii wide nocase
        $domain18 = "chromium\.online" ascii wide nocase
        $domain19 = "cissco\.net" ascii wide nocase
        $domain20 = "clalit\.press" ascii wide nocase
        $domain21 = "cloud-analyzer\.com" ascii wide nocase
        $domain22 = "cloudflare-analyse\.com" ascii wide nocase
        $domain23 = "cloudflare-analyse\.xyz" ascii wide nocase
        $domain24 = "cloudflare-statics\.com" ascii wide nocase
        $domain25 = "cloudflare\.news" ascii wide nocase
        $domain26 = "cloudflare\.site" ascii wide nocase
        $domain27 = "cloudmicrosoft\.net" ascii wide nocase
        $domain28 = "cortana-search\.com" ascii wide nocase
        $domain29 = "digicert\.online" ascii wide nocase
        $domain30 = "digicert\.space" ascii wide nocase
        $domain31 = "digicert\.xyz" ascii wide nocase
        $domain32 = "dnsserv\.host" ascii wide nocase
        $domain33 = "elasticbeanstalk\.tech" ascii wide nocase
        $domain34 = "f-tqn\.com" ascii wide nocase
        $domain35 = "fb-nameserver\.com" ascii wide nocase
        $domain36 = "fb-statics\.com" ascii wide nocase
        $domain37 = "fb-statics\.info" ascii wide nocase
        $domain38 = "fbcdn\.bid" ascii wide nocase
        $domain39 = "fbexternal-a\.press" ascii wide nocase
        $domain40 = "fbexternal-a\.pw" ascii wide nocase
        $domain41 = "fbstatic-a\.space" ascii wide nocase
        $domain42 = "fbstatic-a\.xyz" ascii wide nocase
        $domain43 = "fbstatic-akamaihd\.com" ascii wide nocase
        $domain44 = "fdgdsg\.xyz" ascii wide nocase
        $domain45 = "githubapp\.online" ascii wide nocase
        $domain46 = "githubapp\.tech" ascii wide nocase
        $domain47 = "githubusecontent\.tech" ascii wide nocase
        $domain48 = "gmailtagmanager\.com" ascii wide nocase
        $domain49 = "google-api-analyse\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_MIDDLEFLOOR
{
    meta:
        description = "Detects IOCs associated with APT MIDDLEFLOOR"
        author = "APTtrail Automated Collection"
        apt_group = "MIDDLEFLOOR"
        aliases = "apt-unk2"
        reference = "https://cert.pl/uploads/docs/Raport_CP_2023.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "cert-pl\.pl" ascii wide nocase
        $domain1 = "comunicacion-presidencia-gov\.es" ascii wide nocase
        $domain2 = "comunidad-madrid\.es" ascii wide nocase
        $domain3 = "energie-gov\.md" ascii wide nocase
        $domain4 = "eupm-moldova\.md" ascii wide nocase
        $domain5 = "europa-ec\.eu" ascii wide nocase
        $domain6 = "europa-eppo\.eu" ascii wide nocase
        $domain7 = "europa\.social" ascii wide nocase
        $domain8 = "europa\.study" ascii wide nocase
        $domain9 = "freepresunlimited\.org" ascii wide nocase
        $domain10 = "golebewski\.pl" ascii wide nocase
        $domain11 = "gov-md\.com" ascii wide nocase
        $domain12 = "interior-gov\.es" ascii wide nocase
        $domain13 = "isw-org\.pl" ascii wide nocase
        $domain14 = "ivention\.pl" ascii wide nocase
        $domain15 = "litexpo-portal\.lt" ascii wide nocase
        $domain16 = "mailgon\.online" ascii wide nocase
        $domain17 = "mailorun\.su" ascii wide nocase
        $domain18 = "mailos\.ru" ascii wide nocase
        $domain19 = "mc-md\.com" ascii wide nocase
        $domain20 = "mcgov\.md" ascii wide nocase
        $domain21 = "md-mec\.com" ascii wide nocase
        $domain22 = "mec-gov\.md" ascii wide nocase
        $domain23 = "moldova-energie\.md" ascii wide nocase
        $domain24 = "moldova-mediu\.md" ascii wide nocase
        $domain25 = "moldova-social\.md" ascii wide nocase
        $domain26 = "nask-pl\.com" ascii wide nocase
        $domain27 = "nnmnnm\.ru" ascii wide nocase
        $domain28 = "noname05716\.ru" ascii wide nocase
        $domain29 = "otllook\.com" ascii wide nocase
        $domain30 = "pass-check\.online" ascii wide nocase
        $domain31 = "sapsap\.site" ascii wide nocase
        $domain32 = "social-moldova\.md" ascii wide nocase
        $domain33 = "socialisti\.md" ascii wide nocase
        $domain34 = "socialistii\.com" ascii wide nocase
        $domain35 = "sso-log\.com" ascii wide nocase
        $domain36 = "te-storg\.com" ascii wide nocase
        $domain37 = "urm-lt\.com" ascii wide nocase
        $domain38 = "viilnius\.lt" ascii wide nocase
        $domain39 = "vilnius-summit\.lt" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_MINIDUKE
{
    meta:
        description = "Detects IOCs associated with APT MINIDUKE"
        author = "APTtrail Automated Collection"
        apt_group = "MINIDUKE"
        reference = "http://blog.crysys.hu/2013/02/miniduke/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "arabooks\.ch" ascii wide nocase
        $domain1 = "artas\.org" ascii wide nocase
        $domain2 = "eamtm\.com" ascii wide nocase
        $domain3 = "extremesportsevents\.net" ascii wide nocase
        $domain4 = "news\.grouptumbler\.com" ascii wide nocase
        $domain5 = "tsoftonline\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_MIRRORFACE
{
    meta:
        description = "Detects IOCs associated with APT MIRRORFACE"
        author = "APTtrail Automated Collection"
        apt_group = "MIRRORFACE"
        aliases = "lodeinfo, mirrorstealer"
        reference = "https://otx.alienvault.com/pulse/639b01a88df8698311dc2b43"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "aesorunwe\.com" ascii wide nocase
        $domain1 = "ninesmn\.com" ascii wide nocase
        $ip2 = "104.238.149.37" ascii wide
        $ip3 = "108.160.138.20" ascii wide
        $ip4 = "139.180.197.13" ascii wide
        $ip5 = "149.28.31.17" ascii wide
        $ip6 = "167.179.105.29" ascii wide
        $ip7 = "198.13.51.211" ascii wide
        $ip8 = "198.13.55.8" ascii wide
        $ip9 = "207.148.104.176" ascii wide
        $ip10 = "43.224.34.61" ascii wide
        $ip11 = "45.32.14.107" ascii wide
        $ip12 = "45.32.18.42" ascii wide
        $ip13 = "45.76.193.104" ascii wide
        $ip14 = "45.76.202.254" ascii wide
        $ip15 = "45.76.202.98" ascii wide
        $ip16 = "45.76.97.113" ascii wide
        $ip17 = "45.77.28.195" ascii wide
        $ip18 = "45.77.29.108" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_MODIFIEDELEPHANT
{
    meta:
        description = "Detects IOCs associated with APT MODIFIEDELEPHANT"
        author = "APTtrail Automated Collection"
        apt_group = "MODIFIEDELEPHANT"
        reference = "https://assets.sentinelone.com/sentinellabs-apt/modified-elephant-apt"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "atlaswebportal\.zapto\.org" ascii wide nocase
        $domain1 = "bzone\.no-ip\.biz" ascii wide nocase
        $domain2 = "chivalkarstone\.com" ascii wide nocase
        $domain3 = "duniaenewsportal\.ddns\.net" ascii wide nocase
        $domain4 = "gayakwaad\.com" ascii wide nocase
        $domain5 = "greenpeacesite\.com" ascii wide nocase
        $domain6 = "jasonhistoryarticles\.read-books\.org" ascii wide nocase
        $domain7 = "johnmarcus\.zapto\.org" ascii wide nocase
        $domain8 = "knudandersen\.zapto\.org" ascii wide nocase
        $domain9 = "nepal3\.msntv\.org" ascii wide nocase
        $domain10 = "new-agency\.us" ascii wide nocase
        $domain11 = "newmms\.ru" ascii wide nocase
        $domain12 = "pahiclisting\.ddns\.net" ascii wide nocase
        $domain13 = "ramesh212121\.zapto\.org" ascii wide nocase
        $domain14 = "researchplanet\.zapto\.org" ascii wide nocase
        $domain15 = "socialstatistics\.zapto\.org" ascii wide nocase
        $domain16 = "socialstudies\.zapto\.org" ascii wide nocase
        $domain17 = "testingnew\.no-ip\.org" ascii wide nocase
        $domain18 = "vinaychutiya\.no-ip\.biz" ascii wide nocase
        $ip19 = "146.148.42.217" ascii wide
        $ip20 = "222.212.28.30" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_MOUSTACHEDBOUNCER
{
    meta:
        description = "Detects IOCs associated with APT MOUSTACHEDBOUNCER"
        author = "APTtrail Automated Collection"
        apt_group = "MOUSTACHEDBOUNCER"
        reference = "https://www.welivesecurity.com/en/eset-research/moustachedbouncer-espionage-against-foreign-diplomats-in-belarus/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "centrocspupdate\.com" ascii wide nocase
        $domain1 = "dervasopssec\.com" ascii wide nocase
        $domain2 = "edgeupdate-security-windows\.com" ascii wide nocase
        $domain3 = "ocsp-atomsecure\.com" ascii wide nocase
        $domain4 = "securityocspdev\.com" ascii wide nocase
        $ip5 = "209.19.37.184" ascii wide
        $ip6 = "24.9.51.94" ascii wide
        $ip7 = "35.214.56.2" ascii wide
        $ip8 = "38.9.8.78" ascii wide
        $ip9 = "52.3.8.25" ascii wide
        $ip10 = "59.6.8.25" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_MUDCARP
{
    meta:
        description = "Detects IOCs associated with APT MUDCARP"
        author = "APTtrail Automated Collection"
        apt_group = "MUDCARP"
        aliases = "apt-c-40, apt40, leviathan"
        reference = "https://github.com/ti-research-io/ti/blob/main/ioc_extender/ET_Gh0st_Variant.json"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "accountsx\.bounceme\.net" ascii wide nocase
        $domain1 = "api\.dreamsbottle\.com" ascii wide nocase
        $domain2 = "appexistence\.com" ascii wide nocase
        $domain3 = "armybar\.hopto\.org" ascii wide nocase
        $domain4 = "australianmorningnews\.com" ascii wide nocase
        $domain5 = "bbranchs\.com" ascii wide nocase
        $domain6 = "byfleur\.myftp\.org" ascii wide nocase
        $domain7 = "cankerscarcass\.com" ascii wide nocase
        $domain8 = "capitana\.onthewifi\.com" ascii wide nocase
        $domain9 = "cdn\.aexhausts\.com" ascii wide nocase
        $domain10 = "chemscalere\.com" ascii wide nocase
        $domain11 = "cm\.musicandfile\.com" ascii wide nocase
        $domain12 = "cnnzapmeta\.com" ascii wide nocase
        $domain13 = "dexercisep\.com" ascii wide nocase
        $domain14 = "duutsxlydw\.com" ascii wide nocase
        $domain15 = "dynamics\.ddnsking\.com" ascii wide nocase
        $domain16 = "eujinonline\.sytes\.net" ascii wide nocase
        $domain17 = "goo2k88yyh2\.chickenkiller\.com" ascii wide nocase
        $domain18 = "guardggg\.com" ascii wide nocase
        $domain19 = "heraldsun\.me" ascii wide nocase
        $domain20 = "iherlvufjknw\.com" ascii wide nocase
        $domain21 = "image\.australianmorningnews\.com" ascii wide nocase
        $domain22 = "ja\.iherlvufjknw\.com" ascii wide nocase
        $domain23 = "katy197\.chickenkiller\.com" ascii wide nocase
        $domain24 = "kulkarni\.bounceme\.net" ascii wide nocase
        $domain25 = "laodailylive\.com" ascii wide nocase
        $domain26 = "laodata\.network" ascii wide nocase
        $domain27 = "laodiplomat\.com" ascii wide nocase
        $domain28 = "laotranslations\.com" ascii wide nocase
        $domain29 = "mail2\.ignorelist\.com" ascii wide nocase
        $domain30 = "manaloguek\.com" ascii wide nocase
        $domain31 = "microsql-update\.info" ascii wide nocase
        $domain32 = "mihybb\.com" ascii wide nocase
        $domain33 = "mlcdailynews\.com" ascii wide nocase
        $domain34 = "musicandfile\.com" ascii wide nocase
        $domain35 = "networkslaoupdate\.com" ascii wide nocase
        $domain36 = "news\.duutsxlydw\.com" ascii wide nocase
        $domain37 = "news\.networkslaoupdate\.com" ascii wide nocase
        $domain38 = "nmw4xhipveaca7hm\.onion\.link" ascii wide nocase
        $domain39 = "office\.duutsxlydw\.com" ascii wide nocase
        $domain40 = "porndec143\.chickenkiller\.com" ascii wide nocase
        $domain41 = "regionail\.xyz" ascii wide nocase
        $domain42 = "rninhsss\.com" ascii wide nocase
        $domain43 = "scsnewstoday\.com" ascii wide nocase
        $domain44 = "soure7788\.chickenkiller\.com" ascii wide nocase
        $domain45 = "teledynegroup\.com" ascii wide nocase
        $domain46 = "testdomain2019\.chickenkiller\.com" ascii wide nocase
        $domain47 = "theaustralian\.in" ascii wide nocase
        $domain48 = "thestar\.live" ascii wide nocase
        $domain49 = "thestar\.serveblog\.net" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_MUDDYWATER
{
    meta:
        description = "Detects IOCs associated with APT MUDDYWATER"
        author = "APTtrail Automated Collection"
        apt_group = "MUDDYWATER"
        aliases = "BoggySerpens, COBALT ULSTER (# https://malpedia.caad.fkie.fraunhofer.de/actor/muddywater), MERCURY"
        reference = "https://aksk.gov.al/wp-content/uploads/2024/04/Spear-Phishing_Malware-analysis-kurs-trajnimi.zip-ScreenConnectWindows.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "6nc051221a\.co" ascii wide nocase
        $domain1 = "6nc051221c\.co" ascii wide nocase
        $domain2 = "6nc110821hdb\.co" ascii wide nocase
        $domain3 = "6nc220721\.co" ascii wide nocase
        $domain4 = "accesemailaccount\.tk" ascii wide nocase
        $domain5 = "accounts-login\.ga" ascii wide nocase
        $domain6 = "accounts-login\.gq" ascii wide nocase
        $domain7 = "accountslogin\.ga" ascii wide nocase
        $domain8 = "admin\.syncroapi\.com" ascii wide nocase
        $domain9 = "administratie\.in" ascii wide nocase
        $domain10 = "airpaz\.egnyte\.com" ascii wide nocase
        $domain11 = "airpazflys\.egnyte\.com" ascii wide nocase
        $domain12 = "alibabacloud\.dynamic-dns\.net" ascii wide nocase
        $domain13 = "alibabacloud\.wikaba\.com" ascii wide nocase
        $domain14 = "alibabacloud\.zzux\.com" ascii wide nocase
        $domain15 = "alkan\.egnyte\.com" ascii wide nocase
        $domain16 = "amazo0n\.serveftp\.com" ascii wide nocase
        $domain17 = "ampacindustries\.com" ascii wide nocase
        $domain18 = "ankara24saatacikcicekci\.com" ascii wide nocase
        $domain19 = "apikeyallervice\.business" ascii wide nocase
        $domain20 = "apikeyallervice\.com" ascii wide nocase
        $domain21 = "appsharecloud\.com" ascii wide nocase
        $domain22 = "assignmenthelptoday\.com" ascii wide nocase
        $domain23 = "asure-onlinee\.com" ascii wide nocase
        $domain24 = "aurasync2\.com" ascii wide nocase
        $domain25 = "bevestig\.in" ascii wide nocase
        $domain26 = "binden\.in" ascii wide nocase
        $domain27 = "bing-google-soft\.com" ascii wide nocase
        $domain28 = "cairoairport\.egnyte\.com" ascii wide nocase
        $domain29 = "ciscoupdate2019\.gotdns\.ch" ascii wide nocase
        $domain30 = "cloud-233f9\.firebaseapp\.com" ascii wide nocase
        $domain31 = "cloud-233f9\.web\.app" ascii wide nocase
        $domain32 = "cloud-ed980\.web\.app" ascii wide nocase
        $domain33 = "cms\.qa" ascii wide nocase
        $domain34 = "cnsmportal\.egnyte\.com" ascii wide nocase
        $domain35 = "d25btwd9wax8gu\.cloudfront\.net" ascii wide nocase
        $domain36 = "domainsoftcloud\.com" ascii wide nocase
        $domain37 = "downloadfile\.egnyte\.com" ascii wide nocase
        $domain38 = "enreji\.gov\.tr" ascii wide nocase
        $domain39 = "fbcsoft\.egnyte\.com" ascii wide nocase
        $domain40 = "fileuploadcloud\.egnyte\.com" ascii wide nocase
        $domain41 = "gcare\.egnyte\.com" ascii wide nocase
        $domain42 = "getgooogle\.hopto\.org" ascii wide nocase
        $domain43 = "ghostrider\.serveirc\.com" ascii wide nocase
        $domain44 = "gladiyator\.tk" ascii wide nocase
        $domain45 = "googl-165a0\.web\.app" ascii wide nocase
        $domain46 = "googl-6c11f\.web\.app" ascii wide nocase
        $domain47 = "google-softnet\.com" ascii wide nocase
        $domain48 = "google-word\.com" ascii wide nocase
        $domain49 = "googleads\.hopto\.org" ascii wide nocase
        $ip50 = "103.27.108.14" ascii wide
        $ip51 = "103.27.108.14" ascii wide
        $ip52 = "103.27.109.206" ascii wide
        $ip53 = "103.27.109.206" ascii wide
        $ip54 = "103.27.109.52" ascii wide
        $ip55 = "103.27.109.52" ascii wide
        $ip56 = "103.43.16.65" ascii wide
        $ip57 = "103.43.16.65" ascii wide
        $ip58 = "104.168.44.16" ascii wide
        $ip59 = "104.194.222.219" ascii wide
        $ip60 = "104.237.233.38" ascii wide
        $ip61 = "104.237.233.38" ascii wide
        $ip62 = "104.237.233.38" ascii wide
        $ip63 = "104.237.233.40" ascii wide
        $ip64 = "104.237.233.40" ascii wide
        $ip65 = "104.237.255.212" ascii wide
        $ip66 = "107.175.196.104" ascii wide
        $ip67 = "134.19.215.3" ascii wide
        $ip68 = "136.243.87.112" ascii wide
        $ip69 = "137.220.251.44" ascii wide
        $ip70 = "137.220.251.44" ascii wide
        $ip71 = "137.74.131.16" ascii wide
        $ip72 = "141.95.22.153" ascii wide
        $ip73 = "146.19.143.14" ascii wide
        $ip74 = "146.70.106.89" ascii wide
        $ip75 = "146.70.124.102" ascii wide
        $ip76 = "146.70.149.61" ascii wide
        $ip77 = "149.202.242.80" ascii wide
        $ip78 = "149.202.242.80" ascii wide
        $ip79 = "149.202.242.84" ascii wide
        $url80 = "/tmp\.php" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_MURENSHARK
{
    meta:
        description = "Detects IOCs associated with APT MURENSHARK"
        author = "APTtrail Automated Collection"
        apt_group = "MURENSHARK"
        reference = "http://blog.nsfocus.net/murenshark/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "bookstore\.neu\.edu\.tr" ascii wide nocase
        $domain1 = "d0g3\.cachedns\.io" ascii wide nocase
        $domain2 = "jc\.neu\.edu\.tr" ascii wide nocase
        $domain3 = "oldies\.neu\.edu\.tr" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_MUSTANGPANDA
{
    meta:
        description = "Detects IOCs associated with APT MUSTANGPANDA"
        author = "APTtrail Automated Collection"
        apt_group = "MUSTANGPANDA"
        aliases = "BASIN, Earth Preta, HoneyMyte"
        reference = "http://cloud.google.com/blog/topics/threat-intelligence/prc-nexus-espionage-targets-diplomats/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "247up\.org" ascii wide nocase
        $domain1 = "aadcdn\.msauth\.document-invoiceviewer\.online" ascii wide nocase
        $domain2 = "aadcdn\.msauth\.document-viewer\.xyz" ascii wide nocase
        $domain3 = "aadcdn\.msauth\.documentpdfviewer\.xyz" ascii wide nocase
        $domain4 = "account\.live\.document-invoiceviewer\.online" ascii wide nocase
        $domain5 = "account\.live\.document-viewer\.xyz" ascii wide nocase
        $domain6 = "account\.live\.office-docs\.online" ascii wide nocase
        $domain7 = "accounts\.documentpdfviewer\.xyz" ascii wide nocase
        $domain8 = "accounts\.hmailevma5\.documentpdfviewer\.xyz" ascii wide nocase
        $domain9 = "adobephotostage\.com" ascii wide nocase
        $domain10 = "ai\.nerdnooks\.com" ascii wide nocase
        $domain11 = "aihkstore\.com" ascii wide nocase
        $domain12 = "airdndvn\.com" ascii wide nocase
        $domain13 = "aliyunconsole\.com" ascii wide nocase
        $domain14 = "api\.document-invoiceviewer\.online" ascii wide nocase
        $domain15 = "api\.document-viewer\.xyz" ascii wide nocase
        $domain16 = "api\.office-docs\.online" ascii wide nocase
        $domain17 = "apple-net\.com" ascii wide nocase
        $domain18 = "b\.document-viewer\.xyz" ascii wide nocase
        $domain19 = "b8pjmgd6\.com" ascii wide nocase
        $domain20 = "back\.vlvlvlvl\.site" ascii wide nocase
        $domain21 = "bcller\.com" ascii wide nocase
        $domain22 = "blogdirve\.com" ascii wide nocase
        $domain23 = "bonuscave\.com" ascii wide nocase
        $domain24 = "buyonebuy\.top" ascii wide nocase
        $domain25 = "cabsecnow\.com" ascii wide nocase
        $domain26 = "careerhuawei\.net" ascii wide nocase
        $domain27 = "cdn\.update\.huaweiyuncdn\.com" ascii wide nocase
        $domain28 = "cdn1\.update\.huaweiyuncdn\.com" ascii wide nocase
        $domain29 = "cdn7s65\.z13\.web\.core\.windows\.net" ascii wide nocase
        $domain30 = "conflictaslesson\.com" ascii wide nocase
        $domain31 = "coolboxpc\.com" ascii wide nocase
        $domain32 = "csp\.document-invoiceviewer\.online" ascii wide nocase
        $domain33 = "csp\.document-viewer\.xyz" ascii wide nocase
        $domain34 = "csp\.documentpdfviewer\.xyz" ascii wide nocase
        $domain35 = "csp\.office-docs\.online" ascii wide nocase
        $domain36 = "daydreamdew\.net" ascii wide nocase
        $domain37 = "deleted\.tripadviso\.online" ascii wide nocase
        $domain38 = "dest-working\.com" ascii wide nocase
        $domain39 = "destroy2013\.com" ascii wide nocase
        $domain40 = "dl6yfsl\.com" ascii wide nocase
        $domain41 = "dljmp2p\.com" ascii wide nocase
        $domain42 = "document-invoiceviewer\.online" ascii wide nocase
        $domain43 = "document-viewer\.xyz" ascii wide nocase
        $domain44 = "documentinvoice-viewer\.top" ascii wide nocase
        $domain45 = "documentpdfviewer\.xyz" ascii wide nocase
        $domain46 = "dodefoh\.com" ascii wide nocase
        $domain47 = "download\.flach\.cn" ascii wide nocase
        $domain48 = "download\.hilifimyanmar\.com" ascii wide nocase
        $domain49 = "electrictulsa\.com" ascii wide nocase
        $ip50 = "103.107.104.37" ascii wide
        $ip51 = "103.107.104.61" ascii wide
        $ip52 = "103.107.104.61" ascii wide
        $ip53 = "103.13.31.75" ascii wide
        $ip54 = "103.15.28.145" ascii wide
        $ip55 = "103.15.29.17" ascii wide
        $ip56 = "103.159.132.80" ascii wide
        $ip57 = "103.192.226.46" ascii wide
        $ip58 = "103.200.97.189" ascii wide
        $ip59 = "103.200.97.189" ascii wide
        $ip60 = "103.249.84.137" ascii wide
        $ip61 = "103.27.109.157" ascii wide
        $ip62 = "103.56.18.101" ascii wide
        $ip63 = "103.56.18.101" ascii wide
        $ip64 = "103.56.53.120" ascii wide
        $ip65 = "103.79.120.70" ascii wide
        $ip66 = "103.79.120.70" ascii wide
        $ip67 = "103.79.120.71" ascii wide
        $ip68 = "103.79.120.71" ascii wide
        $ip69 = "103.79.120.73" ascii wide
        $ip70 = "103.79.120.73" ascii wide
        $ip71 = "103.79.120.74" ascii wide
        $ip72 = "103.79.120.74" ascii wide
        $ip73 = "103.79.120.81" ascii wide
        $ip74 = "103.79.120.81" ascii wide
        $ip75 = "103.79.120.85" ascii wide
        $ip76 = "103.79.120.89" ascii wide
        $ip77 = "104.194.154.150" ascii wide
        $ip78 = "107.155.56.87" ascii wide
        $ip79 = "107.155.56.87" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_NAIKON
{
    meta:
        description = "Detects IOCs associated with APT NAIKON"
        author = "APTtrail Automated Collection"
        apt_group = "NAIKON"
        aliases = "deadringer"
        reference = "https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07205555/TheNaikonAPT-MsnMM1.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "a\.jrmfeeder\.org" ascii wide nocase
        $domain1 = "afhkl\.dseqoorg\.com" ascii wide nocase
        $domain2 = "ahzx\.eicp\.net" ascii wide nocase
        $domain3 = "ajtkgygth\.com" ascii wide nocase
        $domain4 = "aloha\.fekeigawy\.com" ascii wide nocase
        $domain5 = "articles\.whynotad\.com" ascii wide nocase
        $domain6 = "asp\.asphspes\.com" ascii wide nocase
        $domain7 = "asphspes\.com" ascii wide nocase
        $domain8 = "bbs\.forcejoyt\.com" ascii wide nocase
        $domain9 = "bkav\.imshop\.in" ascii wide nocase
        $domain10 = "blog\.toptogear\.com" ascii wide nocase
        $domain11 = "cat\.suttiphong\.com" ascii wide nocase
        $domain12 = "cent\.myanmarnewsrecent\.com" ascii wide nocase
        $domain13 = "cpc\.mashresearchb\.com" ascii wide nocase
        $domain14 = "dathktdga\.com" ascii wide nocase
        $domain15 = "dgwktifrn\.com" ascii wide nocase
        $domain16 = "dns\.jmrmfitym\.com" ascii wide nocase
        $domain17 = "dns\.seekvibega\.com" ascii wide nocase
        $domain18 = "dthjxc\.com" ascii wide nocase
        $domain19 = "familymart-pay\.cc" ascii wide nocase
        $domain20 = "fekeigawy\.com" ascii wide nocase
        $domain21 = "freebsd\.extrimtur\.com" ascii wide nocase
        $domain22 = "googlemm\.vicp\.net" ascii wide nocase
        $domain23 = "guaranteed9\.strangled\.net" ascii wide nocase
        $domain24 = "hosts\.mysaol\.com" ascii wide nocase
        $domain25 = "http\.jmrmfitym\.com" ascii wide nocase
        $domain26 = "imgs09\.homenet\.org" ascii wide nocase
        $domain27 = "java\.tripadvisorsapp\.com" ascii wide nocase
        $domain28 = "jdk\.gsvvfsso\.com" ascii wide nocase
        $domain29 = "jmrmfitym\.com" ascii wide nocase
        $domain30 = "kyawtun119\.com" ascii wide nocase
        $domain31 = "kyemtyjah\.com" ascii wide nocase
        $domain32 = "mail\.tripadvisorsapp\.com" ascii wide nocase
        $domain33 = "mncgn\.51vip\.biz" ascii wide nocase
        $domain34 = "mon-enews\.com" ascii wide nocase
        $domain35 = "my\.eiyfmrn\.com" ascii wide nocase
        $domain36 = "myanmarnewsrecent\.com" ascii wide nocase
        $domain37 = "myanmartech\.vicp\.net" ascii wide nocase
        $domain38 = "n91t78dxr3\.com" ascii wide nocase
        $domain39 = "news\.dgwktifrn\.com" ascii wide nocase
        $domain40 = "news\.nyhedmgtxck\.com" ascii wide nocase
        $domain41 = "nw\.eiyfmrn\.com" ascii wide nocase
        $domain42 = "osde\.twifwkeyh\.com" ascii wide nocase
        $domain43 = "php\.tripadvisorsapp\.com" ascii wide nocase
        $domain44 = "qisxnikm\.com" ascii wide nocase
        $domain45 = "rad\.geewkmy\.com" ascii wide nocase
        $domain46 = "realteks\.gjdredj\.com" ascii wide nocase
        $domain47 = "rrgwmmwgk\.com" ascii wide nocase
        $domain48 = "second\.photo-frame\.com" ascii wide nocase
        $domain49 = "seekvibega\.com" ascii wide nocase
        $ip50 = "124.156.241.24" ascii wide
        $ip51 = "150.109.178.252" ascii wide
        $ip52 = "150.109.178.252" ascii wide
        $ip53 = "150.109.178.252" ascii wide
        $ip54 = "150.109.178.252" ascii wide
        $ip55 = "150.109.178.252" ascii wide
        $ip56 = "150.109.178.252" ascii wide
        $ip57 = "150.109.178.252" ascii wide
        $ip58 = "150.109.178.252" ascii wide
        $ip59 = "150.109.178.252" ascii wide
        $ip60 = "150.109.178.252" ascii wide
        $ip61 = "150.109.184.127" ascii wide
        $ip62 = "150.109.184.127" ascii wide
        $ip63 = "150.109.184.127" ascii wide
        $ip64 = "150.109.184.127" ascii wide
        $ip65 = "150.109.184.127" ascii wide
        $ip66 = "150.109.184.127" ascii wide
        $ip67 = "150.109.184.127" ascii wide
        $ip68 = "150.109.184.127" ascii wide
        $ip69 = "150.109.184.127" ascii wide
        $ip70 = "47.241.127.190" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_NETTRAVELER
{
    meta:
        description = "Detects IOCs associated with APT NETTRAVELER"
        author = "APTtrail Automated Collection"
        apt_group = "NETTRAVELER"
        reference = "http://securelist.com/blog/research/35936/nettraveler-is-running-red-star-apt-attacks-compromise-high-profile-victims/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "allen\.w223\.west263\.cn" ascii wide nocase
        $domain1 = "andriodphone\.net" ascii wide nocase
        $domain2 = "bauer\.8866\.org" ascii wide nocase
        $domain3 = "buynewes\.com" ascii wide nocase
        $domain4 = "cultureacess\.com" ascii wide nocase
        $domain5 = "discoverypeace\.org" ascii wide nocase
        $domain6 = "drag2008\.com" ascii wide nocase
        $domain7 = "eaglesey\.com" ascii wide nocase
        $domain8 = "enterairment\.net" ascii wide nocase
        $domain9 = "gami1\.com" ascii wide nocase
        $domain10 = "globalmailru\.com" ascii wide nocase
        $domain11 = "hint09\.9966\.org" ascii wide nocase
        $domain12 = "imapupdate\.com" ascii wide nocase
        $domain13 = "info-spb\.com" ascii wide nocase
        $domain14 = "interfaxru\.com" ascii wide nocase
        $domain15 = "inwpvpn\.com" ascii wide nocase
        $domain16 = "keyboardhk\.com" ascii wide nocase
        $domain17 = "localgroupnet\.com" ascii wide nocase
        $domain18 = "mailyandexru\.com" ascii wide nocase
        $domain19 = "mogoogle\.com" ascii wide nocase
        $domain20 = "msnnewes\.com" ascii wide nocase
        $domain21 = "newesyahoo\.com" ascii wide nocase
        $domain22 = "newfax\.net" ascii wide nocase
        $domain23 = "pkspring\.net" ascii wide nocase
        $domain24 = "ra1nru\.com" ascii wide nocase
        $domain25 = "ramb1er\.com" ascii wide nocase
        $domain26 = "riaru\.net" ascii wide nocase
        $domain27 = "sghrhd\.190\.20081\.info" ascii wide nocase
        $domain28 = "southstock\.net" ascii wide nocase
        $domain29 = "spit113\.minidns\.net" ascii wide nocase
        $domain30 = "tassnews\.net" ascii wide nocase
        $domain31 = "tsgoogoo\.net" ascii wide nocase
        $domain32 = "vip222idc\.s169\.288idc\.com" ascii wide nocase
        $domain33 = "viplenta\.com" ascii wide nocase
        $domain34 = "vipmailru\.com" ascii wide nocase
        $domain35 = "viprainru\.com" ascii wide nocase
        $domain36 = "viprambler\.com" ascii wide nocase
        $domain37 = "vipyandex\.com" ascii wide nocase
        $domain38 = "voennovosti\.com" ascii wide nocase
        $domain39 = "vpnwork\.3322\.org" ascii wide nocase
        $domain40 = "wolf0\.3322\.org" ascii wide nocase
        $domain41 = "wolf001\.us109\.eoidc\.net" ascii wide nocase
        $domain42 = "yahooair\.com" ascii wide nocase
        $domain43 = "yangdex\.org" ascii wide nocase
        $domain44 = "zeroicelee\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_NEWSBEEF
{
    meta:
        description = "Detects IOCs associated with APT NEWSBEEF"
        author = "APTtrail Automated Collection"
        apt_group = "NEWSBEEF"
        reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "cloud\.services-mozilla\.com" ascii wide nocase
        $domain1 = "msservice\.site" ascii wide nocase
        $domain2 = "service\.chrome-up\.date" ascii wide nocase
        $domain3 = "service1\.chrome-up\.date" ascii wide nocase
        $domain4 = "webmaster\.serveirc\.com" ascii wide nocase
        $domain5 = "www\.chrome-up\.date" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_NEWSPENGUIN
{
    meta:
        description = "Detects IOCs associated with APT NEWSPENGUIN"
        author = "APTtrail Automated Collection"
        apt_group = "NEWSPENGUIN"
        reference = "https://blogs.blackberry.com/en/2023/02/newspenguin-a-previously-unknown-threat-actor-targets-pakistan-with-advanced-espionage-tool"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "updates\.win32\.live" ascii wide nocase
        $domain1 = "win32\.live" ascii wide nocase
        $domain2 = "windowsupdates\.shop" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_NIGHTEAGLE
{
    meta:
        description = "Detects IOCs associated with APT NIGHTEAGLE"
        author = "APTtrail Automated Collection"
        apt_group = "NIGHTEAGLE"
        aliases = "APT-Q-95"
        reference = "https://github.com/RedDrip7/Report/blob/master/APT/Exclusive%20disclosure%20of%20the%20attack%20activities%20of%20the%20USA%20APT%20group%20NightEagle.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "app\.flowgw\.com" ascii wide nocase
        $domain1 = "ccproxy\.org" ascii wide nocase
        $domain2 = "cloud\.synologyupdates\.com" ascii wide nocase
        $domain3 = "comfyupdate\.org" ascii wide nocase
        $domain4 = "coremailtech\.com" ascii wide nocase
        $domain5 = "daihou360\.com" ascii wide nocase
        $domain6 = "dashboard\.daihou360\.com" ascii wide nocase
        $domain7 = "doubleclicked\.com" ascii wide nocase
        $domain8 = "e-mailrelay\.com" ascii wide nocase
        $domain9 = "fastapi-cdn\.com" ascii wide nocase
        $domain10 = "flowgw\.com" ascii wide nocase
        $domain11 = "fortisys\.net" ascii wide nocase
        $domain12 = "haprxy\.org" ascii wide nocase
        $domain13 = "liveupdate\.wsupdatecloud\.net" ascii wide nocase
        $domain14 = "lvusdupdates\.org" ascii wide nocase
        $domain15 = "mirror1\.mirrors-openjdk\.org" ascii wide nocase
        $domain16 = "mirrors-openjdk\.org" ascii wide nocase
        $domain17 = "ms-nipre\.com" ascii wide nocase
        $domain18 = "ms\.wsupdatecloud\.net" ascii wide nocase
        $domain19 = "rhel\.lvusdupdates\.org" ascii wide nocase
        $domain20 = "sangsoft\.net" ascii wide nocase
        $domain21 = "saperpcloud\.com" ascii wide nocase
        $domain22 = "shangjuyike\.com" ascii wide nocase
        $domain23 = "synologyupdates\.com" ascii wide nocase
        $domain24 = "threatbookav\.com" ascii wide nocase
        $domain25 = "tracking\.doubleclicked\.com" ascii wide nocase
        $domain26 = "update\.haprxy\.org" ascii wide nocase
        $domain27 = "update\.saperpcloud\.com" ascii wide nocase
        $domain28 = "updates\.ccproxy\.org" ascii wide nocase
        $domain29 = "wechatutilities\.com" ascii wide nocase
        $domain30 = "wsupdatecloud\.net" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_NOISYBEAR
{
    meta:
        description = "Detects IOCs associated with APT NOISYBEAR"
        author = "APTtrail Automated Collection"
        apt_group = "NOISYBEAR"
        reference = "https://www.seqrite.com/blog/operation-barrelfire-noisybear-kazakhstan-oil-gas-sector/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "wellfitplan\.ru" ascii wide nocase
        $ip1 = "178.159.94.8" ascii wide
        $ip2 = "77.239.125.41" ascii wide
        $ip3 = "77.239.125.41" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_NONAME05716
{
    meta:
        description = "Detects IOCs associated with APT NONAME05716"
        author = "APTtrail Automated Collection"
        apt_group = "NONAME05716"
        aliases = "bobik, ddosia, killnet"
        reference = "https://decoded.avast.io/martinchlumecky/bobik/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "q7zemy6zc7ptaeks\.servehttp\.com" ascii wide nocase
        $domain1 = "tom56gaz6poh13f28\.myftp\.org" ascii wide nocase
        $domain2 = "v9agm8uwtjmz\.sytes\.net" ascii wide nocase
        $domain3 = "zig35m48zur14nel40\.myftp\.org" ascii wide nocase
        $ip4 = "109.107.181.130" ascii wide
        $ip5 = "109.107.181.130" ascii wide
        $ip6 = "109.107.184.11" ascii wide
        $ip7 = "161.35.199.2" ascii wide
        $ip8 = "161.35.199.2" ascii wide
        $ip9 = "185.173.37.220" ascii wide
        $ip10 = "185.173.37.220" ascii wide
        $ip11 = "31.13.195.87" ascii wide
        $ip12 = "77.91.66.85" ascii wide
        $ip13 = "77.91.66.85" ascii wide
        $ip14 = "87.121.52.9" ascii wide
        $ip15 = "87.121.52.9" ascii wide
        $ip16 = "91.142.79.201" ascii wide
        $ip17 = "91.142.79.201" ascii wide
        $ip18 = "94.140.114.239" ascii wide
        $ip19 = "94.140.114.239" ascii wide
        $ip20 = "94.140.115.129" ascii wide
        $ip21 = "94.140.115.129" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_NOVISPY
{
    meta:
        description = "Detects IOCs associated with APT NOVISPY"
        author = "APTtrail Automated Collection"
        apt_group = "NOVISPY"
        reference = "https://www.amnesty.org/en/latest/news/2024/12/serbia-authorities-using-spyware-and-cellebrite-forensic-extraction-tools-to-hack-journalists-and-activists/"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "185.86.148.174" ascii wide

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_OBSMOGWAI
{
    meta:
        description = "Detects IOCs associated with APT OBSMOGWAI"
        author = "APTtrail Automated Collection"
        apt_group = "OBSMOGWAI"
        aliases = "dimanorat, donnect, obstinate mogwai"
        reference = "https://rt-solar.ru/solar-4rays/blog/4753/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "cariolis\.com" ascii wide nocase
        $domain1 = "dns-stream\.com" ascii wide nocase
        $domain2 = "down\.soft-update\.com" ascii wide nocase
        $domain3 = "down\.softupdate\.com" ascii wide nocase
        $domain4 = "go\.thejra\.com" ascii wide nocase
        $domain5 = "help\.springnow\.net" ascii wide nocase
        $domain6 = "home\.thejra\.com" ascii wide nocase
        $domain7 = "hoteldinamo\.com" ascii wide nocase
        $domain8 = "hy\.indiatopsite\.com" ascii wide nocase
        $domain9 = "imail\.indiatopsite\.com" ascii wide nocase
        $domain10 = "indiatopsite\.com" ascii wide nocase
        $domain11 = "iss-tass\.com" ascii wide nocase
        $domain12 = "lion\.thejra\.com" ascii wide nocase
        $domain13 = "macbook\.thejra\.com" ascii wide nocase
        $domain14 = "my\.thejra\.com" ascii wide nocase
        $domain15 = "parking\.samogony\.com" ascii wide nocase
        $domain16 = "pitmanbed\.space" ascii wide nocase
        $domain17 = "puzirik\.com" ascii wide nocase
        $domain18 = "reformamebel\.com" ascii wide nocase
        $domain19 = "rhodesauto\.space" ascii wide nocase
        $domain20 = "rralphfood\.space" ascii wide nocase
        $domain21 = "seanpi\.thejra\.com" ascii wide nocase
        $domain22 = "secure\.thejra\.com" ascii wide nocase
        $domain23 = "skypi\.thejra\.com" ascii wide nocase
        $domain24 = "soft-update\.com" ascii wide nocase
        $domain25 = "softupdate\.com" ascii wide nocase
        $domain26 = "ssl\.hoteldinamo\.com" ascii wide nocase
        $domain27 = "tes\.indiatopsite\.com" ascii wide nocase
        $domain28 = "ttl\.huzfs\.com" ascii wide nocase
        $domain29 = "vorots\.ru" ascii wide nocase
        $domain30 = "yandexcloud\.samogony\.com" ascii wide nocase
        $ip31 = "108.160.136.200" ascii wide
        $ip32 = "116.251.217.104" ascii wide
        $ip33 = "122.192.11.114" ascii wide
        $ip34 = "122.96.34.142" ascii wide
        $ip35 = "139.162.111.143" ascii wide
        $ip36 = "139.84.139.176" ascii wide
        $ip37 = "149.28.189.102" ascii wide
        $ip38 = "158.247.203.87" ascii wide
        $ip39 = "181.215.229.119" ascii wide
        $ip40 = "185.132.125.154" ascii wide
        $ip41 = "185.167.116.30" ascii wide
        $ip42 = "185.4.66.116" ascii wide
        $ip43 = "188.116.22.90" ascii wide
        $ip44 = "188.130.160.144" ascii wide
        $ip45 = "192.121.171.190" ascii wide
        $ip46 = "192.121.47.214" ascii wide
        $ip47 = "192.248.153.215" ascii wide
        $ip48 = "193.47.34.229" ascii wide
        $ip49 = "194.68.26.142" ascii wide
        $ip50 = "194.68.26.164" ascii wide
        $ip51 = "213.135.67.198" ascii wide
        $ip52 = "213.183.54.200" ascii wide
        $ip53 = "213.183.56.238" ascii wide
        $ip54 = "213.183.57.73" ascii wide
        $ip55 = "27.102.115.153" ascii wide
        $ip56 = "31.192.234.35" ascii wide
        $ip57 = "31.214.157.5" ascii wide
        $ip58 = "38.180.29.3" ascii wide
        $ip59 = "38.54.16.120" ascii wide
        $ip60 = "45.12.67.18" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_OCEANLOTUS
{
    meta:
        description = "Detects IOCs associated with APT OCEANLOTUS"
        author = "APTtrail Automated Collection"
        apt_group = "OCEANLOTUS"
        aliases = "SectorF01, apt-c-00, apt-c-32"
        reference = "https://app.any.run/tasks/2a8d467c-65e4-417f-a747-b6e59bf037ba/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "163mailservice\.com" ascii wide nocase
        $domain1 = "24\.datatimes\.org" ascii wide nocase
        $domain2 = "360skylar\.host" ascii wide nocase
        $domain3 = "365\.urielcallum\.com" ascii wide nocase
        $domain4 = "accounts\.getmyip\.com" ascii wide nocase
        $domain5 = "ad\.ssageevrenue\.com" ascii wide nocase
        $domain6 = "adineohler\.com" ascii wide nocase
        $domain7 = "adobe\.riceaub\.com" ascii wide nocase
        $domain8 = "aisicoin\.com" ascii wide nocase
        $domain9 = "aki\.viperse\.com" ascii wide nocase
        $domain10 = "alicervois\.com" ascii wide nocase
        $domain11 = "aliexpresscn\.net" ascii wide nocase
        $domain12 = "alyerrac\.com" ascii wide nocase
        $domain13 = "anaehler\.com" ascii wide nocase
        $domain14 = "andreafaerber\.com" ascii wide nocase
        $domain15 = "andreagahuvrauvin\.com" ascii wide nocase
        $domain16 = "andreagbridge\.com" ascii wide nocase
        $domain17 = "anessallie\.com" ascii wide nocase
        $domain18 = "annamerrett\.com" ascii wide nocase
        $domain19 = "anofrio\.com" ascii wide nocase
        $domain20 = "antenham\.com" ascii wide nocase
        $domain21 = "aol\.straliaenollma\.xyz" ascii wide nocase
        $domain22 = "api\.anaehler\.com" ascii wide nocase
        $domain23 = "api\.blogdns\.com" ascii wide nocase
        $domain24 = "api\.ciscofreak\.com" ascii wide nocase
        $domain25 = "api\.myddns\.me" ascii wide nocase
        $domain26 = "apiservice\.webhop\.net" ascii wide nocase
        $domain27 = "arbenha\.com" ascii wide nocase
        $domain28 = "arinaurna\.com" ascii wide nocase
        $domain29 = "arkoimmerma\.com" ascii wide nocase
        $domain30 = "art\.guillermoespana\.com" ascii wide nocase
        $domain31 = "art\.yfieldrainasch\.com" ascii wide nocase
        $domain32 = "asia-kotoba\.net" ascii wide nocase
        $domain33 = "att\.illagedrivestralia\.xyz" ascii wide nocase
        $domain34 = "au\.charlineopkesston\.com" ascii wide nocase
        $domain35 = "audreybourgeois\.com" ascii wide nocase
        $domain36 = "aulolloy\.com" ascii wide nocase
        $domain37 = "auth\.lineage2ez\.com" ascii wide nocase
        $domain38 = "avidilleneu\.com" ascii wide nocase
        $domain39 = "avidsontre\.com" ascii wide nocase
        $domain40 = "aximilian\.com" ascii wide nocase
        $domain41 = "b\.cortanazone\.com" ascii wide nocase
        $domain42 = "background\.ristians\.com" ascii wide nocase
        $domain43 = "baidu-search\.net" ascii wide nocase
        $domain44 = "baodachieu\.com" ascii wide nocase
        $domain45 = "baomoivietnam\.com" ascii wide nocase
        $domain46 = "base\.msteamsapi\.com" ascii wide nocase
        $domain47 = "beaudrysang\.xyz" ascii wide nocase
        $domain48 = "beautifull-font\.salebusinesend\.com" ascii wide nocase
        $domain49 = "becreybour\.com" ascii wide nocase
        $ip50 = "103.91.67.74" ascii wide
        $ip51 = "109.107.171.113" ascii wide
        $ip52 = "109.107.171.113" ascii wide
        $ip53 = "109.107.171.113" ascii wide
        $ip54 = "139.59.30.109" ascii wide
        $ip55 = "144.202.46.221" ascii wide
        $ip56 = "154.93.37.106" ascii wide
        $ip57 = "160.86.38.21" ascii wide
        $ip58 = "178.255.220.115" ascii wide
        $ip59 = "185.198.57.184" ascii wide
        $ip60 = "185.225.19.100" ascii wide
        $ip61 = "185.43.220.188" ascii wide
        $ip62 = "185.82.126.4" ascii wide
        $ip63 = "190.211.254.203" ascii wide
        $ip64 = "193.138.195.192" ascii wide
        $ip65 = "195.12.50.172" ascii wide
        $ip66 = "202.59.10.170" ascii wide
        $ip67 = "221.219.213.178" ascii wide
        $ip68 = "43.254.132.117" ascii wide
        $ip69 = "43.254.132.212" ascii wide
        $ip70 = "45.41.204.15" ascii wide
        $ip71 = "45.41.204.18" ascii wide
        $ip72 = "45.61.139.211" ascii wide
        $ip73 = "45.63.123.237" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_OILALPHA
{
    meta:
        description = "Detects IOCs associated with APT OILALPHA"
        author = "APTtrail Automated Collection"
        apt_group = "OILALPHA"
        reference = "https://go.recordedfuture.com/hubfs/reports/cta-2023-0516.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "2020anekafkark2020\.ddns\.net" ascii wide nocase
        $domain1 = "712175206totot\.ddns\.net" ascii wide nocase
        $domain2 = "77112hilan\.ddns\.net" ascii wide nocase
        $domain3 = "87524uyre\.ddns\.net" ascii wide nocase
        $domain4 = "abas1\.ddns\.net" ascii wide nocase
        $domain5 = "akjdaks54678sdas\.ddns\.net" ascii wide nocase
        $domain6 = "antahomaar2022\.ddns\.net" ascii wide nocase
        $domain7 = "bobkkfoundationyemen2022\.ddns\.net" ascii wide nocase
        $domain8 = "bobm1jgjahsg81\.ddns\.net" ascii wide nocase
        $domain9 = "dhgrshghjrsg0092102\.ddns\.net" ascii wide nocase
        $domain10 = "djhgurjhwdskh72532\.ddns\.me" ascii wide nocase
        $domain11 = "goman239\.ddns\.net" ascii wide nocase
        $domain12 = "gomnd2873yemnenrc\.ddns\.net" ascii wide nocase
        $domain13 = "hilan77112\.ddns\.net" ascii wide nocase
        $domain14 = "hjsdg2368gskambv\.ddns\.net" ascii wide nocase
        $domain15 = "hm712175206zh\.ddns\.net" ascii wide nocase
        $domain16 = "hsdg763276jgkjx\.ddns\.net" ascii wide nocase
        $domain17 = "hsgdjh78632\.mypsx\.net" ascii wide nocase
        $domain18 = "magtimego\.servegame\.com" ascii wide nocase
        $domain19 = "manyouhomaar21\.ddns\.net" ascii wide nocase
        $domain20 = "moonname2022\.ddns\.net" ascii wide nocase
        $domain21 = "musicmatrix\.access\.ly" ascii wide nocase
        $domain22 = "ncbyemen2008\.ddns\.net" ascii wide nocase
        $domain23 = "ndf236fgh4367h\.ddns\.net" ascii wide nocase
        $domain24 = "saaoff33993homhl\.ddns\.net" ascii wide nocase
        $domain25 = "saudigazette2022yemen\.ddns\.net" ascii wide nocase
        $domain26 = "yemenofoneofline\.ddns\.net" ascii wide nocase
        $domain27 = "you7788mtnq\.ddns\.net" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_OILRIG
{
    meta:
        description = "Detects IOCs associated with APT OILRIG"
        author = "APTtrail Automated Collection"
        apt_group = "OILRIG"
        aliases = "apt34, greenbug, helixkitten"
        reference = "https://app.validin.com/detail?find=151.236.17.231&type=ip4&ref_id=29bbecc74a1#tab=resolutions"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "262t3my0gt\.cardioteacher\.com" ascii wide nocase
        $domain1 = "2fhj\.asiaworldremit\.com" ascii wide nocase
        $domain2 = "2u21hipg70\.uber-asia\.com" ascii wide nocase
        $domain3 = "2zcf\.uber-asia\.com" ascii wide nocase
        $domain4 = "3j3oyvsf8i\.joexpediagroup\.com" ascii wide nocase
        $domain5 = "5s5gp24f8x\.asiaworldremit\.com" ascii wide nocase
        $domain6 = "6google\.com" ascii wide nocase
        $domain7 = "7a7n4j60g4\.cardioteacher\.com" ascii wide nocase
        $domain8 = "7w7rbgt13f\.uber-asia\.com" ascii wide nocase
        $domain9 = "ababab\.biz" ascii wide nocase
        $domain10 = "acceptplan\.com" ascii wide nocase
        $domain11 = "acrlee\.com" ascii wide nocase
        $domain12 = "acrobatverify\.com" ascii wide nocase
        $domain13 = "admin\.mofaiq\.com" ascii wide nocase
        $domain14 = "akamai-global\.com" ascii wide nocase
        $domain15 = "akastatus\.com" ascii wide nocase
        $domain16 = "alcirineos\.com" ascii wide nocase
        $domain17 = "alforatsystem\.com" ascii wide nocase
        $domain18 = "allsecpackupdater\.com" ascii wide nocase
        $domain19 = "amazon-loveyou\.com" ascii wide nocase
        $domain20 = "anhuisiafu\.com" ascii wide nocase
        $domain21 = "antivirus-update\.top" ascii wide nocase
        $domain22 = "anyportals\.com" ascii wide nocase
        $domain23 = "applicationframehost\.in" ascii wide nocase
        $domain24 = "apps\.iqwebservice\.com" ascii wide nocase
        $domain25 = "asiacall\.net" ascii wide nocase
        $domain26 = "asiaworldremit\.com" ascii wide nocase
        $domain27 = "astrazencea\.com" ascii wide nocase
        $domain28 = "astrazeneeca\.com" ascii wide nocase
        $domain29 = "axoryvexity\.eu" ascii wide nocase
        $domain30 = "bargertextiles\.com" ascii wide nocase
        $domain31 = "base32\.iqwebservice\.com" ascii wide nocase
        $domain32 = "berqertextiles\.com" ascii wide nocase
        $domain33 = "bgre\.kozow\.com" ascii wide nocase
        $domain34 = "biam-iraq\.org" ascii wide nocase
        $domain35 = "boardexecutivemanagement\.com" ascii wide nocase
        $domain36 = "boardsexecutives\.com" ascii wide nocase
        $domain37 = "cam-research-ac\.com" ascii wide nocase
        $domain38 = "cardioteacher\.com" ascii wide nocase
        $domain39 = "careers-ntiva\.com" ascii wide nocase
        $domain40 = "cdn-edge-akamai\.com" ascii wide nocase
        $domain41 = "cererock\.com" ascii wide nocase
        $domain42 = "chinaconstructioncorp\.com" ascii wide nocase
        $domain43 = "chrome-dns\.com" ascii wide nocase
        $domain44 = "cisco0\.com" ascii wide nocase
        $domain45 = "clearinghouseinternational\.com" ascii wide nocase
        $domain46 = "cloudipnameserver\.com" ascii wide nocase
        $domain47 = "coinbasedeutschland\.com" ascii wide nocase
        $domain48 = "coldflys\.com" ascii wide nocase
        $domain49 = "confusedtown\.com" ascii wide nocase
        $ip50 = "151.236.17.231" ascii wide
        $ip51 = "151.236.17.231" ascii wide
        $ip52 = "151.236.17.231" ascii wide
        $ip53 = "185.198.59.121" ascii wide
        $ip54 = "185.198.59.121" ascii wide
        $ip55 = "185.198.59.121" ascii wide
        $ip56 = "185.32.178.176" ascii wide
        $ip57 = "185.76.78.177" ascii wide
        $ip58 = "185.76.78.177" ascii wide
        $ip59 = "185.76.78.177" ascii wide
        $ip60 = "185.76.78.177" ascii wide
        $ip61 = "192.71.166.24" ascii wide
        $ip62 = "193.36.132.224" ascii wide
        $ip63 = "194.68.32.114" ascii wide
        $ip64 = "198.44.140.29" ascii wide
        $ip65 = "198.44.140.29" ascii wide
        $ip66 = "206.206.123.176" ascii wide
        $ip67 = "206.206.123.176" ascii wide
        $ip68 = "37.1.213.152" ascii wide
        $ip69 = "37.1.213.152" ascii wide
        $ip70 = "38.180.140.30" ascii wide
        $ip71 = "38.180.18.189" ascii wide
        $ip72 = "38.180.31.225" ascii wide
        $ip73 = "38.180.31.225" ascii wide
        $ip74 = "89.46.233.239" ascii wide
        $ip75 = "89.46.233.239" ascii wide
        $ip76 = "91.132.95.117" ascii wide
        $ip77 = "91.132.95.117" ascii wide
        $ip78 = "91.132.95.117" ascii wide
        $ip79 = "91.132.95.117" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_ONYXSLEET
{
    meta:
        description = "Detects IOCs associated with APT ONYXSLEET"
        author = "APTtrail Automated Collection"
        apt_group = "ONYXSLEET"
        reference = "https://otx.alienvault.com/pulse/65534130052d1800f62e7ba2"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "147.78.149.201" ascii wide
        $ip1 = "162.19.71.175" ascii wide

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_OPERA1ER
{
    meta:
        description = "Detects IOCs associated with APT OPERA1ER"
        author = "APTtrail Automated Collection"
        apt_group = "OPERA1ER"
        aliases = "bluebottle, commonraven, desktop group"
        reference = "http://c-apt-ure.blogspot.com/2022/01/who-is-desktop-group.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "4x33\.ignorelist\.com" ascii wide nocase
        $domain1 = "actu\.afrikmedia\.info" ascii wide nocase
        $domain2 = "actu\.banquealtantique\.net" ascii wide nocase
        $domain3 = "afijoh\.net" ascii wide nocase
        $domain4 = "afrikmedia\.info" ascii wide nocase
        $domain5 = "bac\.eimaragon\.org" ascii wide nocase
        $domain6 = "bac\.senegalsante\.org" ascii wide nocase
        $domain7 = "boa\.eimaragon\.org" ascii wide nocase
        $domain8 = "cnam\.myvnc\.com" ascii wide nocase
        $domain9 = "cobalt\.warii\.club" ascii wide nocase
        $domain10 = "codir\.ocitnetad\.com" ascii wide nocase
        $domain11 = "contact\.senegalsante\.org" ascii wide nocase
        $domain12 = "coris-bank\.fr" ascii wide nocase
        $domain13 = "covid\.ocitnetad\.com" ascii wide nocase
        $domain14 = "crazy\.senegalsante\.org" ascii wide nocase
        $domain15 = "dc-4ade33bd8726\.bdm-sa\.fr" ascii wide nocase
        $domain16 = "direct8\.ddns\.net" ascii wide nocase
        $domain17 = "download\.nortonupdate\.com" ascii wide nocase
        $domain18 = "driver\.eimaragon\.org" ascii wide nocase
        $domain19 = "droid\.senegalsante\.org" ascii wide nocase
        $domain20 = "dynastie\.warzonedns\.com" ascii wide nocase
        $domain21 = "eimanet\.eimaragon\.org" ascii wide nocase
        $domain22 = "eimaragon\.org" ascii wide nocase
        $domain23 = "evamachine\.tk" ascii wide nocase
        $domain24 = "ftp\.eimaragon\.org" ascii wide nocase
        $domain25 = "gamevnc\.myvnc\.com" ascii wide nocase
        $domain26 = "helpdesk-security\.org" ascii wide nocase
        $domain27 = "hostmaster\.senegalsante\.org" ascii wide nocase
        $domain28 = "hunterx1-37009\.portmap\.io" ascii wide nocase
        $domain29 = "info\.senegalsante\.org" ascii wide nocase
        $domain30 = "info\.warii\.club" ascii wide nocase
        $domain31 = "kaspersky-lab\.org" ascii wide nocase
        $domain32 = "kpersky\.duckdns\.org" ascii wide nocase
        $domain33 = "mail\.mcafee-endpoint\.com" ascii wide nocase
        $domain34 = "mail\.warii\.club" ascii wide nocase
        $domain35 = "microsoft-af\.com" ascii wide nocase
        $domain36 = "news\.afrikmedia\.info" ascii wide nocase
        $domain37 = "news\.coris-bank\.fr" ascii wide nocase
        $domain38 = "noreply\.mcafee-endpoint\.com" ascii wide nocase
        $domain39 = "ns\.eimaragon\.org" ascii wide nocase
        $domain40 = "ns1\.eimaragon\.org" ascii wide nocase
        $domain41 = "ns1\.senegalsante\.org" ascii wide nocase
        $domain42 = "ns2\.senegalsante\.org" ascii wide nocase
        $domain43 = "ocitnetad\.com" ascii wide nocase
        $domain44 = "operan\.ddns\.net" ascii wide nocase
        $domain45 = "personnel\.bdm-sa\.fr" ascii wide nocase
        $domain46 = "queen2012\.ddns\.net" ascii wide nocase
        $domain47 = "reply2host\.duckdns\.org" ascii wide nocase
        $domain48 = "senegalsante\.org" ascii wide nocase
        $domain49 = "server\.senegalsante\.org" ascii wide nocase
        $ip50 = "178.73.192.15" ascii wide
        $ip51 = "46.246.12.12" ascii wide
        $ip52 = "46.246.14.17" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_PACKRAT
{
    meta:
        description = "Detects IOCs associated with APT PACKRAT"
        author = "APTtrail Automated Collection"
        apt_group = "PACKRAT"
        reference = "https://citizenlab.ca/2015/12/packrat-report/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "conhost\.servehttp\.com" ascii wide nocase
        $domain1 = "daynews\.sytes\.net" ascii wide nocase
        $domain2 = "deyrep24\.ddns\.net" ascii wide nocase
        $domain3 = "dllhost\.servehttp\.com" ascii wide nocase
        $domain4 = "lolinha\.no-ip\.org" ascii wide nocase
        $domain5 = "ruley\.no-ip\.org" ascii wide nocase
        $domain6 = "taskmgr\.redirectme\.com" ascii wide nocase
        $domain7 = "taskmgr\.serveftp\.com" ascii wide nocase
        $domain8 = "taskmgr\.servehttp\.com" ascii wide nocase
        $domain9 = "wjwj\.no-ip\.org" ascii wide nocase
        $domain10 = "wjwjwj\.no-ip\.org" ascii wide nocase
        $domain11 = "wjwjwjwj\.no-ip\.org" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_PARAGON
{
    meta:
        description = "Detects IOCs associated with APT PARAGON"
        author = "APTtrail Automated Collection"
        apt_group = "PARAGON"
        aliases = "bigpretzel, graphite spyware"
        reference = "https://app.validin.com/detail?find=%2FO%3Dnetwork39managment%2FCN%3Dgreenad&type=raw&ref_id=92a69af4516#tab=host_pairs (# 2025-06-13)"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "ancient-thing\.it" ascii wide nocase
        $domain1 = "external-astra\.com" ascii wide nocase
        $domain2 = "external-cag\.com" ascii wide nocase
        $domain3 = "external-cap\.com" ascii wide nocase
        $domain4 = "external-drt\.com" ascii wide nocase
        $domain5 = "external-muki\.com" ascii wide nocase
        $domain6 = "external-shotgun3\.com" ascii wide nocase
        $domain7 = "external-sht-prd-4\.com" ascii wide nocase
        $domain8 = "external-sht\.com" ascii wide nocase
        $domain9 = "forti\.external-muki\.com" ascii wide nocase
        $domain10 = "forti\.external-shotgun3\.com" ascii wide nocase
        $domain11 = "forti\.external-sht-prd-4\.com" ascii wide nocase
        $domain12 = "forti\.external-sht\.com" ascii wide nocase
        $domain13 = "forti\.internal-stg\.com" ascii wide nocase
        $domain14 = "forti\.paraccess\.com" ascii wide nocase
        $domain15 = "internal-abba\.com" ascii wide nocase
        $domain16 = "internal-stg\.com" ascii wide nocase
        $domain17 = "modern-money\.org" ascii wide nocase
        $ip18 = "178.237.39.204" ascii wide
        $ip19 = "178.237.39.204" ascii wide
        $ip20 = "178.237.39.204" ascii wide
        $ip21 = "178.237.39.204" ascii wide
        $ip22 = "194.71.130.218" ascii wide
        $ip23 = "46.183.184.91" ascii wide
        $ip24 = "84.110.122.27" ascii wide
        $ip25 = "84.110.47.82" ascii wide
        $ip26 = "84.110.47.83" ascii wide
        $ip27 = "84.110.47.84" ascii wide
        $ip28 = "84.110.47.84" ascii wide
        $ip29 = "84.110.47.84" ascii wide
        $ip30 = "84.110.47.85" ascii wide
        $ip31 = "84.110.47.85" ascii wide
        $ip32 = "84.110.47.86" ascii wide
        $ip33 = "84.110.47.86" ascii wide
        $ip34 = "84.110.47.86" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_PATCHWORK
{
    meta:
        description = "Detects IOCs associated with APT PATCHWORK"
        author = "APTtrail Automated Collection"
        apt_group = "PATCHWORK"
        aliases = "apachestealer, apt-c-09, chinastrats"
        reference = "https://0xthreatintel.medium.com/internals-of-ave-maria-malware-cb0f63bcce8d"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "130dozen\.com" ascii wide nocase
        $domain1 = "15731\.org" ascii wide nocase
        $domain2 = "163-cn\.org" ascii wide nocase
        $domain3 = "81-cn\.net" ascii wide nocase
        $domain4 = "a\.gyyun\.xyz" ascii wide nocase
        $domain5 = "aaskmee\.com" ascii wide nocase
        $domain6 = "abcvip\.us\.org" ascii wide nocase
        $domain7 = "accounts\.opensecurity-legacy\.com" ascii wide nocase
        $domain8 = "adaptation-funds\.org" ascii wide nocase
        $domain9 = "adhath-learning\.com" ascii wide nocase
        $domain10 = "adobefileshare\.com" ascii wide nocase
        $domain11 = "ados\.fyicompsol\.xyz" ascii wide nocase
        $domain12 = "alfred\.ignorelist\.com" ascii wide nocase
        $domain13 = "alieanmote\.live" ascii wide nocase
        $domain14 = "altered\.twilightparadox\.com" ascii wide nocase
        $domain15 = "amelaits\.info" ascii wide nocase
        $domain16 = "anabel\.rootranger\.info" ascii wide nocase
        $domain17 = "anchorsoft\.org" ascii wide nocase
        $domain18 = "android-helper\.info" ascii wide nocase
        $domain19 = "anglerrscovey\.com" ascii wide nocase
        $domain20 = "annchenn\.com" ascii wide nocase
        $domain21 = "aonepiece\.org" ascii wide nocase
        $domain22 = "apcas\.bhutanembassynepal\.com" ascii wide nocase
        $domain23 = "api\.inboundhealthcare\.us" ascii wide nocase
        $domain24 = "api\.opensecurity-legacy\.com" ascii wide nocase
        $domain25 = "applepicker\.info" ascii wide nocase
        $domain26 = "appplace\.life" ascii wide nocase
        $domain27 = "apps-house\.com" ascii wide nocase
        $domain28 = "aquilei\.live" ascii wide nocase
        $domain29 = "aquileia\.live" ascii wide nocase
        $domain30 = "arabcomputersupportgroup\.com" ascii wide nocase
        $domain31 = "arkiverat\.info" ascii wide nocase
        $domain32 = "arpawebdom\.org" ascii wide nocase
        $domain33 = "asftbngh\.top" ascii wide nocase
        $domain34 = "asiandefnetwork\.com" ascii wide nocase
        $domain35 = "atus\.toproid\.xyz" ascii wide nocase
        $domain36 = "aurorafoss\.xyz" ascii wide nocase
        $domain37 = "auth\.fyicompsol\.xyz" ascii wide nocase
        $domain38 = "avangrid\.info" ascii wide nocase
        $domain39 = "avtofrom\.us" ascii wide nocase
        $domain40 = "b3autybab3s\.com" ascii wide nocase
        $domain41 = "baidunetdisk\.info" ascii wide nocase
        $domain42 = "bayanat\.co\.nf" ascii wide nocase
        $domain43 = "beautifullimages\.co\.nf" ascii wide nocase
        $domain44 = "beijingtv\.org" ascii wide nocase
        $domain45 = "bhutanembassynepal\.com" ascii wide nocase
        $domain46 = "biaonton\.insightglobel\.info" ascii wide nocase
        $domain47 = "bilibil\.info" ascii wide nocase
        $domain48 = "bin\.opensecurity-legacy\.com" ascii wide nocase
        $domain49 = "bingoplant\.live" ascii wide nocase
        $ip50 = "103.106.2.35" ascii wide
        $ip51 = "104.27.172.22" ascii wide
        $ip52 = "104.27.173.22" ascii wide
        $ip53 = "106.215.68.174" ascii wide
        $ip54 = "108.62.12.210" ascii wide
        $ip55 = "142.202.191.234" ascii wide
        $ip56 = "142.234.157.195" ascii wide
        $ip57 = "142.234.157.195" ascii wide
        $ip58 = "146.70.79.15" ascii wide
        $ip59 = "162.216.240.173" ascii wide
        $ip60 = "172.67.180.160" ascii wide
        $ip61 = "172.81.62.199" ascii wide
        $ip62 = "172.81.62.199" ascii wide
        $ip63 = "172.81.62.199" ascii wide
        $ip64 = "172.94.99.215" ascii wide
        $ip65 = "176.56.237.126" ascii wide
        $ip66 = "185.157.78.135" ascii wide
        $ip67 = "185.193.38.24" ascii wide
        $ip68 = "185.29.10.117" ascii wide
        $ip69 = "185.61.148.223" ascii wide
        $ip70 = "185.74.222.165" ascii wide
        $ip71 = "185.74.222.169" ascii wide
        $ip72 = "185.74.222.233" ascii wide
        $ip73 = "185.74.222.34" ascii wide
        $ip74 = "185.82.216.57" ascii wide
        $ip75 = "188.241.58.60" ascii wide
        $ip76 = "188.241.58.61" ascii wide
        $ip77 = "192.250.236.76" ascii wide
        $ip78 = "194.156.98.121" ascii wide
        $ip79 = "194.156.98.141" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_PEEPINGTITLE
{
    meta:
        description = "Detects IOCs associated with APT PEEPINGTITLE"
        author = "APTtrail Automated Collection"
        apt_group = "PEEPINGTITLE"
        aliases = "magalenha"
        reference = "https://www.sentinelone.com/labs/operation-magalenha-long-running-campaign-pursues-portuguese-credentials-and-pii/"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "81.200.152.38" ascii wide

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_PEGASUS
{
    meta:
        description = "Detects IOCs associated with APT PEGASUS"
        author = "APTtrail Automated Collection"
        apt_group = "PEGASUS"
        reference = "http://citizenlab.org/2016/08/million-dollar-dissident-iphone-zero-day-nso-group-uae/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "123tramites\.com" ascii wide nocase
        $domain1 = "14-tracking\.com" ascii wide nocase
        $domain2 = "1minto-start\.com" ascii wide nocase
        $domain3 = "1place-togo\.com" ascii wide nocase
        $domain4 = "24-7clinic\.com" ascii wide nocase
        $domain5 = "301-redirecting\.com" ascii wide nocase
        $domain6 = "365redirect\.co" ascii wide nocase
        $domain7 = "3driving\.com" ascii wide nocase
        $domain8 = "456h612i458g\.com" ascii wide nocase
        $domain9 = "7style\.org" ascii wide nocase
        $domain10 = "800health\.net" ascii wide nocase
        $domain11 = "911hig11carcay959454\.com" ascii wide nocase
        $domain12 = "9jp1dx8odjw1kbkt\.f15fwd322\.regularhours\.net" ascii wide nocase
        $domain13 = "a-redirect\.com" ascii wide nocase
        $domain14 = "a-resolver\.com" ascii wide nocase
        $domain15 = "aalaan\.tv" ascii wide nocase
        $domain16 = "accomodation-tastes\.net" ascii wide nocase
        $domain17 = "accountant-audio\.com" ascii wide nocase
        $domain18 = "accountcanceled\.com" ascii wide nocase
        $domain19 = "accountnotify\.com" ascii wide nocase
        $domain20 = "accounts-unread\.com" ascii wide nocase
        $domain21 = "accounts\.mx" ascii wide nocase
        $domain22 = "accountsections\.com" ascii wide nocase
        $domain23 = "accountsecurities\.org" ascii wide nocase
        $domain24 = "activate-discount\.com" ascii wide nocase
        $domain25 = "active-folders\.com" ascii wide nocase
        $domain26 = "actorsshop\.net" ascii wide nocase
        $domain27 = "actu24\.online" ascii wide nocase
        $domain28 = "ad-generator\.net" ascii wide nocase
        $domain29 = "ad-switcher\.com" ascii wide nocase
        $domain30 = "add-client\.com" ascii wide nocase
        $domain31 = "additional-costs\.com" ascii wide nocase
        $domain32 = "addmyid\.net" ascii wide nocase
        $domain33 = "addresstimeframe\.com" ascii wide nocase
        $domain34 = "adeal4u\.co" ascii wide nocase
        $domain35 = "adjust-local-settings\.co" ascii wide nocase
        $domain36 = "adjust-local-settings\.com" ascii wide nocase
        $domain37 = "adjustlocalsettings\.net" ascii wide nocase
        $domain38 = "adscreator\.net" ascii wide nocase
        $domain39 = "adsload\.co" ascii wide nocase
        $domain40 = "adsmetrics\.co" ascii wide nocase
        $domain41 = "advert-time\.com" ascii wide nocase
        $domain42 = "advert-track\.com" ascii wide nocase
        $domain43 = "afriquenouvelle\.com" ascii wide nocase
        $domain44 = "afternicweb\.net" ascii wide nocase
        $domain45 = "agilityprocessing\.net" ascii wide nocase
        $domain46 = "aircraftsxhibition\.com" ascii wide nocase
        $domain47 = "ajelnews\.net" ascii wide nocase
        $domain48 = "akhbar-aliqtisad\.com" ascii wide nocase
        $domain49 = "akhbar-almasdar\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_PITTYTIGER
{
    meta:
        description = "Detects IOCs associated with APT PITTYTIGER"
        author = "APTtrail Automated Collection"
        apt_group = "PITTYTIGER"
        aliases = "apt-5, apt5, pittypanda"
        reference = "https://apt.thaicert.or.th/cgi-bin/showcard.cgi?g=PittyTiger%2C%20Pitty%20Panda"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "acers\.com\.tw" ascii wide nocase
        $domain1 = "avstore\.com\.tw" ascii wide nocase
        $domain2 = "dopodo\.com\.tw" ascii wide nocase
        $domain3 = "foxcom\.com\.tw" ascii wide nocase
        $domain4 = "helosaf\.com\.tw" ascii wide nocase
        $domain5 = "killerhost\.skypetm\.com\.tw" ascii wide nocase
        $domain6 = "kimoo\.com\.tw" ascii wide nocase
        $domain7 = "lightening\.com\.tw" ascii wide nocase
        $domain8 = "newb02\.skypetm\.com\.tw" ascii wide nocase
        $domain9 = "paccfic\.com" ascii wide nocase
        $domain10 = "seed01\.com\.tw" ascii wide nocase
        $domain11 = "skypetm\.com\.tw" ascii wide nocase
        $domain12 = "stareastnet\.com\.tw" ascii wide nocase
        $domain13 = "symantecs\.com\.tw" ascii wide nocase
        $domain14 = "trendmicro\.org\.tw" ascii wide nocase
        $domain15 = "trendmicroup\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_PKPLUG
{
    meta:
        description = "Detects IOCs associated with APT PKPLUG"
        author = "APTtrail Automated Collection"
        apt_group = "PKPLUG"
        reference = "https://community.emergingthreats.net/t/ruleset-update-summary-2023-09-22-v10423/980"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "3w\.tcpdo\.net" ascii wide nocase
        $domain1 = "admin\.nslookupdns\.com" ascii wide nocase
        $domain2 = "adminloader\.com" ascii wide nocase
        $domain3 = "adminsysteminfo\.com" ascii wide nocase
        $domain4 = "andphocen\.com" ascii wide nocase
        $domain5 = "app\.newfacebk\.com" ascii wide nocase
        $domain6 = "appupdatemoremagic\.com" ascii wide nocase
        $domain7 = "cdncool\.com" ascii wide nocase
        $domain8 = "csip6\.biz" ascii wide nocase
        $domain9 = "dns\.cdncool\.com" ascii wide nocase
        $domain10 = "feed-5613\.coderformylife\.info" ascii wide nocase
        $domain11 = "gooledriveservice\.com" ascii wide nocase
        $domain12 = "honor2020\.ga" ascii wide nocase
        $domain13 = "hwmt10\.w3\.ezua\.com" ascii wide nocase
        $domain14 = "imw100pass\.imwork\.net" ascii wide nocase
        $domain15 = "info\.adminsysteminfo\.com" ascii wide nocase
        $domain16 = "jackhex\.md5c\.com" ascii wide nocase
        $domain17 = "jackhex\.md5c\.net" ascii wide nocase
        $domain18 = "lala513\.gicp\.net" ascii wide nocase
        $domain19 = "linkdatax\.com" ascii wide nocase
        $domain20 = "logitechwkgame\.com" ascii wide nocase
        $domain21 = "lzsps\.ml" ascii wide nocase
        $domain22 = "mail\.queryurl\.com" ascii wide nocase
        $domain23 = "md\.sony36\.com" ascii wide nocase
        $domain24 = "md5c\.net" ascii wide nocase
        $domain25 = "microsoftdefence\.com" ascii wide nocase
        $domain26 = "microsoftserve\.com" ascii wide nocase
        $domain27 = "mxdnsv6\.com" ascii wide nocase
        $domain28 = "netvovo\.windowsnetwork\.org" ascii wide nocase
        $domain29 = "newfacebk\.com" ascii wide nocase
        $domain30 = "news\.tibetgroupworks\.com" ascii wide nocase
        $domain31 = "nslookupdns\.com" ascii wide nocase
        $domain32 = "outhmail\.com" ascii wide nocase
        $domain33 = "ppt\.bodologetee\.com" ascii wide nocase
        $domain34 = "queryurl\.com" ascii wide nocase
        $domain35 = "re\.queryurl\.com" ascii wide nocase
        $domain36 = "sm\.umtt\.com" ascii wide nocase
        $domain37 = "sony36\.com" ascii wide nocase
        $domain38 = "tcpdo\.net" ascii wide nocase
        $domain39 = "tibetgroupworks\.com" ascii wide nocase
        $domain40 = "up\.outhmail\.com" ascii wide nocase
        $domain41 = "update\.newfacebk\.com" ascii wide nocase
        $domain42 = "update\.queryurl\.com" ascii wide nocase
        $domain43 = "update\.tcpdo\.net" ascii wide nocase
        $domain44 = "uvfr43p\.com" ascii wide nocase
        $domain45 = "uvfr4ep\.com" ascii wide nocase
        $domain46 = "uyghurapps\.net" ascii wide nocase
        $domain47 = "w3\.changeip\.org" ascii wide nocase
        $domain48 = "w3\.ezua\.com" ascii wide nocase
        $domain49 = "web\.microsoftdefence\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_PLATINUM
{
    meta:
        description = "Detects IOCs associated with APT PLATINUM"
        author = "APTtrail Automated Collection"
        apt_group = "PLATINUM"
        reference = "https://otx.alienvault.com/pulse/5cf7ccd8e9e95f3f24518a6a"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "happiness\.freevar\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_POISONNEEDLES
{
    meta:
        description = "Detects IOCs associated with APT POISONNEEDLES"
        author = "APTtrail Automated Collection"
        apt_group = "POISONNEEDLES"
        reference = "https://blogs.360.net/post/PoisonNeedles_CVE-2018-15982_EN.html"
        severity = "high"
        tlp = "white"

    strings:

    condition:
        any of them
}

rule APT_POKINGTHEBEAR
{
    meta:
        description = "Detects IOCs associated with APT POKINGTHEBEAR"
        author = "APTtrail Automated Collection"
        apt_group = "POKINGTHEBEAR"
        aliases = "RedControle, StickyKeys"
        reference = "https://threatvector.cylance.com/en_us/home/poking-the-bear-three-year-campaign-targets-russian-critical-infrastructure.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "10-sendmail\.ru" ascii wide nocase
        $domain1 = "3-sendmail\.ru" ascii wide nocase
        $domain2 = "a-nhk\.ru" ascii wide nocase
        $domain3 = "agrarnik-ooo\.ru" ascii wide nocase
        $domain4 = "agrocentrer-eurohem\.ru" ascii wide nocase
        $domain5 = "agroudo\.ru" ascii wide nocase
        $domain6 = "amonni\.ru" ascii wide nocase
        $domain7 = "audemar-piguet\.ru" ascii wide nocase
        $domain8 = "autch-mail\.ru" ascii wide nocase
        $domain9 = "azot-n\.ru" ascii wide nocase
        $domain10 = "azot-sds\.ru" ascii wide nocase
        $domain11 = "azotsds\.ru" ascii wide nocase
        $domain12 = "azs-gazpromneft\.ru" ascii wide nocase
        $domain13 = "balecsm\.ru" ascii wide nocase
        $domain14 = "barsintez\.ru" ascii wide nocase
        $domain15 = "bashneft-centralasia\.ru" ascii wide nocase
        $domain16 = "bashneft\.su" ascii wide nocase
        $domain17 = "berkovetc\.ru" ascii wide nocase
        $domain18 = "bitmain\.org\.ru" ascii wide nocase
        $domain19 = "bitum-gazpromneft\.ru" ascii wide nocase
        $domain20 = "bitum-rosneft\.ru" ascii wide nocase
        $domain21 = "bitum-samara\.ru" ascii wide nocase
        $domain22 = "bitumnpk\.ru" ascii wide nocase
        $domain23 = "bor-silicat\.ru" ascii wide nocase
        $domain24 = "box5\.photosfromcessna\.com" ascii wide nocase
        $domain25 = "bulgarsyntezi\.ru" ascii wide nocase
        $domain26 = "bunker-rosneft\.ru" ascii wide nocase
        $domain27 = "card-rn\.ru" ascii wide nocase
        $domain28 = "center-nic\.ru" ascii wide nocase
        $domain29 = "chem-torg\.ru" ascii wide nocase
        $domain30 = "chemcourier\.ru" ascii wide nocase
        $domain31 = "chickenpaws\.ru" ascii wide nocase
        $domain32 = "china-technika\.ru" ascii wide nocase
        $domain33 = "combisapsan\.ru" ascii wide nocase
        $domain34 = "contacts\.rosneft-opt\.su" ascii wide nocase
        $domain35 = "cryptoman\.org\.ru" ascii wide nocase
        $domain36 = "dc-02ec0b5f-mail\.mail-autch\.ru" ascii wide nocase
        $domain37 = "dc-0649e3d7-mail\.mp-star\.ru" ascii wide nocase
        $domain38 = "dc-45e81045-mail\.cibur\.ru" ascii wide nocase
        $domain39 = "dc-99de0f72f24b\.3-sendmail\.ru" ascii wide nocase
        $domain40 = "dv-china\.ru" ascii wide nocase
        $domain41 = "electronrg\.ru" ascii wide nocase
        $domain42 = "euro-bitum\.ru" ascii wide nocase
        $domain43 = "euro-chimgroup\.ru" ascii wide nocase
        $domain44 = "eurochem-nevinnomissk\.ru" ascii wide nocase
        $domain45 = "eurochem-novomoskovsk\.ru" ascii wide nocase
        $domain46 = "eurochem-orel\.ru" ascii wide nocase
        $domain47 = "eurochem-trading\.com" ascii wide nocase
        $domain48 = "eurochem-trading\.ru" ascii wide nocase
        $domain49 = "eurochemnovomoskovsk\.ru" ascii wide nocase
        $ip50 = "83.166.242.15" ascii wide
        $ip51 = "91.211.245.246" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_POLONIUM
{
    meta:
        description = "Detects IOCs associated with APT POLONIUM"
        author = "APTtrail Automated Collection"
        apt_group = "POLONIUM"
        reference = "https://github.com/eset/malware-ioc/tree/master/polonium"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "146.70.86.6" ascii wide
        $ip1 = "185.203.119.99" ascii wide
        $ip2 = "185.244.129.216" ascii wide
        $ip3 = "185.244.129.216" ascii wide
        $ip4 = "185.244.129.79" ascii wide
        $ip5 = "195.166.100.23" ascii wide
        $ip6 = "45.137.148.7" ascii wide
        $ip7 = "45.80.148.119" ascii wide
        $ip8 = "45.80.148.167" ascii wide
        $ip9 = "45.80.148.167" ascii wide
        $ip10 = "45.80.148.186" ascii wide
        $ip11 = "45.80.149.108" ascii wide
        $ip12 = "45.80.149.154" ascii wide
        $ip13 = "45.80.149.154" ascii wide
        $ip14 = "45.80.149.22" ascii wide
        $ip15 = "45.80.149.68" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_POTAO
{
    meta:
        description = "Detects IOCs associated with APT POTAO"
        author = "APTtrail Automated Collection"
        apt_group = "POTAO"
        reference = "https://github.com/eset/malware-ioc/tree/master/potao"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "camprainbowgold\.ru" ascii wide nocase
        $domain1 = "mntexpress\.com" ascii wide nocase
        $domain2 = "poolwaterslide2011\.ru" ascii wide nocase
        $domain3 = "truecryptrussia\.ru" ascii wide nocase
        $domain4 = "worldairpost\.com" ascii wide nocase
        $domain5 = "worldairpost\.net" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_PREDATOR
{
    meta:
        description = "Detects IOCs associated with APT PREDATOR"
        author = "APTtrail Automated Collection"
        apt_group = "PREDATOR"
        aliases = "CVE-2023-41991, CVE-2023-41992, CVE-2023-41993"
        reference = "https://blog.sekoia.io/the-predator-spyware-ecosystem-is-not-dead/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "1domainregistry\.com" ascii wide nocase
        $domain1 = "almal-news\.com" ascii wide nocase
        $domain2 = "asistentcomercialonline\.com" ascii wide nocase
        $domain3 = "barbequebros\.com" ascii wide nocase
        $domain4 = "beinfo\.net" ascii wide nocase
        $domain5 = "bestshowineu\.com" ascii wide nocase
        $domain6 = "betly\.me" ascii wide nocase
        $domain7 = "blocoinformativo\.com" ascii wide nocase
        $domain8 = "bni-madagascar\.com" ascii wide nocase
        $domain9 = "boundbreeze\.com" ascii wide nocase
        $domain10 = "branchbreeze\.com" ascii wide nocase
        $domain11 = "buysalesblog\.com" ascii wide nocase
        $domain12 = "c\.betly\.me" ascii wide nocase
        $domain13 = "c1tvapp\.com" ascii wide nocase
        $domain14 = "c3p0solutions\.com" ascii wide nocase
        $domain15 = "cabinet-salyk\.kz" ascii wide nocase
        $domain16 = "caddylane\.com" ascii wide nocase
        $domain17 = "canylane\.com" ascii wide nocase
        $domain18 = "chat-support\.support" ascii wide nocase
        $domain19 = "cheesyarcade\.com" ascii wide nocase
        $domain20 = "cibeg\.online" ascii wide nocase
        $domain21 = "clockpatcher\.com" ascii wide nocase
        $domain22 = "colabfile\.com" ascii wide nocase
        $domain23 = "craftilly\.com" ascii wide nocase
        $domain24 = "despachosnegocios\.com" ascii wide nocase
        $domain25 = "dollgoodies\.com" ascii wide nocase
        $domain26 = "drivemountain\.com" ascii wide nocase
        $domain27 = "e-kgd\.kz" ascii wide nocase
        $domain28 = "eclipsemonitor\.com" ascii wide nocase
        $domain29 = "eppointment\.io" ascii wide nocase
        $domain30 = "eroticsmoments\.com" ascii wide nocase
        $domain31 = "espeednet\.com" ascii wide nocase
        $domain32 = "flickerxxx\.com" ascii wide nocase
        $domain33 = "fr-monde\.com" ascii wide nocase
        $domain34 = "fruitynew\.com" ascii wide nocase
        $domain35 = "g\.sec-flare\.com" ascii wide nocase
        $domain36 = "gameformovies\.com" ascii wide nocase
        $domain37 = "gamestuts\.com" ascii wide nocase
        $domain38 = "gardalul\.com" ascii wide nocase
        $domain39 = "gettravelright\.com" ascii wide nocase
        $domain40 = "gilfonts\.com" ascii wide nocase
        $domain41 = "gobbledgums\.com" ascii wide nocase
        $domain42 = "happytotstoys\.com" ascii wide nocase
        $domain43 = "healthyhub\.io" ascii wide nocase
        $domain44 = "holidaypriceguide\.com" ascii wide nocase
        $domain45 = "humansprinter\.com" ascii wide nocase
        $domain46 = "infoaomomento\.com" ascii wide nocase
        $domain47 = "infoshoutout\.com" ascii wide nocase
        $domain48 = "jumia-egy\.com" ascii wide nocase
        $domain49 = "keep-badinigroups\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_PURPLEHAZE
{
    meta:
        description = "Detects IOCs associated with APT PURPLEHAZE"
        author = "APTtrail Automated Collection"
        apt_group = "PURPLEHAZE"
        aliases = "goreshell"
        reference = "https://www.sentinelone.com/labs/follow-the-smoke-china-nexus-threat-actors-hammer-at-the-doors-of-top-tier-targets/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "ccna\.organiccrap\.com" ascii wide nocase
        $domain1 = "cloud\.trendav\.co" ascii wide nocase
        $domain2 = "downloads\.trendav\.vip" ascii wide nocase
        $domain3 = "epp\.navy\.ddns\.info" ascii wide nocase
        $domain4 = "mail\.ccna\.organiccrap\.com" ascii wide nocase
        $domain5 = "mail\.secmailbox\.us" ascii wide nocase
        $domain6 = "navy\.ddns\.info" ascii wide nocase
        $domain7 = "secmailbox\.us" ascii wide nocase
        $domain8 = "sentinelxdr\.us" ascii wide nocase
        $domain9 = "tatacom\.duckdns\.org" ascii wide nocase
        $domain10 = "trendav\.vip" ascii wide nocase
        $ip11 = "45.13.199.209" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_PUTTERPANDA
{
    meta:
        description = "Detects IOCs associated with APT PUTTERPANDA"
        author = "APTtrail Automated Collection"
        apt_group = "PUTTERPANDA"
        aliases = "msupdater"
        reference = "https://samples.vx-underground.org/APTs/2010/2010.09.06/Paper/MSUpdater%20Trojan.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "great\.vssigma\.com" ascii wide nocase
        $domain1 = "red\.vssigma\.com" ascii wide nocase
        $domain2 = "resell\.siseau\.com" ascii wide nocase
        $domain3 = "siseau\.com" ascii wide nocase
        $domain4 = "vssigma\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_Q015
{
    meta:
        description = "Detects IOCs associated with APT Q015"
        author = "APTtrail Automated Collection"
        apt_group = "Q015"
        aliases = "operation run, utg-q-015"
        reference = "https://app.validin.com/detail?type=dom&find=updategoogls.cc#tab=host_pairs (# 2025-05-28)"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "beta\.naipump\.xyz" ascii wide nocase
        $domain1 = "biodao\.finance" ascii wide nocase
        $domain2 = "chormeupdatetool\.xyz" ascii wide nocase
        $domain3 = "molecular-mazda-forests-shop\.trycloudflare\.com" ascii wide nocase
        $domain4 = "naipump\.xyz" ascii wide nocase
        $domain5 = "safe-controls\.oss-cn-hongkong\.aliyuncs\.com" ascii wide nocase
        $domain6 = "updategoogls\.cc" ascii wide nocase
        $ip7 = "194.34.254.219" ascii wide
        $ip8 = "194.34.254.219" ascii wide
        $ip9 = "209.250.254.130" ascii wide
        $ip10 = "209.250.254.130" ascii wide
        $ip11 = "209.250.254.130" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_Q12
{
    meta:
        description = "Detects IOCs associated with APT Q12"
        author = "APTtrail Automated Collection"
        apt_group = "Q12"
        reference = "https://twitter.com/malwrhunterteam/status/1541784815728459779"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "aufreighttransport\.com" ascii wide nocase
        $domain1 = "controlmytraffic\.com" ascii wide nocase
        $domain2 = "coredashcloud\.com" ascii wide nocase
        $domain3 = "guesttrafficinformation\.com" ascii wide nocase
        $domain4 = "hoaquincloud\.com" ascii wide nocase
        $domain5 = "msvsseccloud\.com" ascii wide nocase
        $domain6 = "nyculturecloud\.com" ascii wide nocase
        $domain7 = "org-nk\.com" ascii wide nocase
        $domain8 = "tomatozcloud\.com" ascii wide nocase
        $domain9 = "trafficcheckdaily\.com" ascii wide nocase
        $ip10 = "185.181.229.110" ascii wide
        $ip11 = "185.231.222.86" ascii wide
        $ip12 = "192.236.209.139" ascii wide
        $ip13 = "51.77.72.146" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_Q27
{
    meta:
        description = "Detects IOCs associated with APT Q27"
        author = "APTtrail Automated Collection"
        apt_group = "Q27"
        aliases = "apt-q-27, dragon breath, golden eye dog"
        reference = "https://github.com/sophoslabs/IoCs/blob/master/double-dragon-breath-iocs.csv"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "123\.nsjdhmdjs\.com" ascii wide nocase
        $domain1 = "2\.nsjdhmdjs\.com" ascii wide nocase
        $domain2 = "2\.potatouu\.com" ascii wide nocase
        $domain3 = "a\.pic447\.com" ascii wide nocase
        $domain4 = "ac2\.nsjdhmdjs\.com" ascii wide nocase
        $domain5 = "d\.pic447\.com" ascii wide nocase
        $domain6 = "l\.pic447\.com" ascii wide nocase
        $domain7 = "l2\.pic447\.com" ascii wide nocase
        $domain8 = "nsjdhmdjs\.com" ascii wide nocase
        $domain9 = "potatouu\.com" ascii wide nocase
        $domain10 = "t\.pic447\.com" ascii wide nocase
        $domain11 = "v\.pic447\.com" ascii wide nocase
        $domain12 = "v2\.pic447\.com" ascii wide nocase
        $domain13 = "w\.pic447\.com" ascii wide nocase
        $ip14 = "206.233.128.103" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_QUARIAN
{
    meta:
        description = "Detects IOCs associated with APT QUARIAN"
        author = "APTtrail Automated Collection"
        apt_group = "QUARIAN"
        aliases = "BackdoorDiplomacy, Quarian, Turian"
        reference = "https://github.com/advanced-threat-research/IOCs/blob/master/2013/2013-10-07-quarian-group-targets-victims-with-spearphishing-attacks/quarian-group-targets-victims-with-spearphishing-attacks.csv"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "250f7cloud\.crmdev\.org" ascii wide nocase
        $domain1 = "29c04uc\.ejalase\.org" ascii wide nocase
        $domain2 = "62ffauc\.ejalase\.org" ascii wide nocase
        $domain3 = "7f4d9fcanet\.microsoftshop\.org" ascii wide nocase
        $domain4 = "adboeonline\.net" ascii wide nocase
        $domain5 = "alberto2011\.com" ascii wide nocase
        $domain6 = "andyothers\.acmetoy\.com" ascii wide nocase
        $domain7 = "bill\.microsoftbuys\.com" ascii wide nocase
        $domain8 = "buffetfactory\.oicp\.io" ascii wide nocase
        $domain9 = "cloud\.fastpaymentser-vice\.com" ascii wide nocase
        $domain10 = "cloud\.microsoftshop\.org" ascii wide nocase
        $domain11 = "cloud\.skypecloud\.net" ascii wide nocase
        $domain12 = "crmdev\.org" ascii wide nocase
        $domain13 = "delldrivers\.in" ascii wide nocase
        $domain14 = "dnsupdate\.dns1\.us" ascii wide nocase
        $domain15 = "dnsupdate\.dns2\.us" ascii wide nocase
        $domain16 = "dynsystem\.imbbs\.in" ascii wide nocase
        $domain17 = "efanshion\.com" ascii wide nocase
        $domain18 = "ejalase\.org" ascii wide nocase
        $domain19 = "fastpaymentser-vice\.com" ascii wide nocase
        $domain20 = "fazlol-lah\.net" ascii wide nocase
        $domain21 = "fazlollah\.net" ascii wide nocase
        $domain22 = "freedns02\.dns2\.us" ascii wide nocase
        $domain23 = "icta\.worldmessg\.com" ascii wide nocase
        $domain24 = "info\.fazlol-lah\.net" ascii wide nocase
        $domain25 = "info\.fazlollah\.net" ascii wide nocase
        $domain26 = "info\.payamra-dio\.com" ascii wide nocase
        $domain27 = "info\.payamradio\.com" ascii wide nocase
        $domain28 = "intelupdate\.dns1\.us" ascii wide nocase
        $domain29 = "irir\.org" ascii wide nocase
        $domain30 = "keep\.ns3\.name" ascii wide nocase
        $domain31 = "mail\.irir\.org" ascii wide nocase
        $domain32 = "mci\.ejalase\.org" ascii wide nocase
        $domain33 = "mfaantivirus\.xyz" ascii wide nocase
        $domain34 = "microsoftbuys\.com" ascii wide nocase
        $domain35 = "microsoftshop\.org" ascii wide nocase
        $domain36 = "news\.alberto2011\.com" ascii wide nocase
        $domain37 = "officenews365\.com" ascii wide nocase
        $domain38 = "officeupdate\.ns01\.us" ascii wide nocase
        $domain39 = "officeupdates\.cleansite\.us" ascii wide nocase
        $domain40 = "oracleapps\.org" ascii wide nocase
        $domain41 = "payamra-dio\.com" ascii wide nocase
        $domain42 = "payamradio\.com" ascii wide nocase
        $domain43 = "pfs1010\.com" ascii wide nocase
        $domain44 = "pfs1010\.xyz" ascii wide nocase
        $domain45 = "picture\.efanshion\.com" ascii wide nocase
        $domain46 = "plastic\.delldrivers\.in" ascii wide nocase
        $domain47 = "pmdskm\.top" ascii wide nocase
        $domain48 = "proxy\.oracleapps\.org" ascii wide nocase
        $domain49 = "scm\.oracleapps\.org" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_QUASAR
{
    meta:
        description = "Detects IOCs associated with APT QUASAR"
        author = "APTtrail Automated Collection"
        apt_group = "QUASAR"
        reference = "http://researchcenter.paloaltonetworks.com/2017/01/unit42-downeks-and-quasar-rat-used-in-recent-targeted-attacks-against-governments/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "bandtester\.com" ascii wide nocase
        $domain1 = "datasamsung\.com" ascii wide nocase
        $domain2 = "down\.downloadoneyoutube\.co\.vu" ascii wide nocase
        $domain3 = "downloadlog\.linkpc\.net" ascii wide nocase
        $domain4 = "downloadmyhost\.zapto\.org" ascii wide nocase
        $domain5 = "downloadtesting\.com" ascii wide nocase
        $domain6 = "dynamicipaddress\.linkpc\.net" ascii wide nocase
        $domain7 = "exportball\.servegame\.org" ascii wide nocase
        $domain8 = "ftpserverit\.otzo\.com" ascii wide nocase
        $domain9 = "galaxy-s\.com" ascii wide nocase
        $domain10 = "galaxysupdates\.com" ascii wide nocase
        $domain11 = "gameoolines\.com" ascii wide nocase
        $domain12 = "gamestoplay\.bid" ascii wide nocase
        $domain13 = "havan\.qhigh\.com" ascii wide nocase
        $domain14 = "help2014\.linkpc\.net" ascii wide nocase
        $domain15 = "helpyoume\.linkpc\.net" ascii wide nocase
        $domain16 = "hostgatero\.ddns\.net" ascii wide nocase
        $domain17 = "kolabdown\.sytes\.net" ascii wide nocase
        $domain18 = "microsoftnewupdate\.com" ascii wide nocase
        $domain19 = "netstreamag\.publicvm\.com" ascii wide nocase
        $domain20 = "newphoneapp\.com" ascii wide nocase
        $domain21 = "noredirecto\.redirectme\.net" ascii wide nocase
        $domain22 = "onlinesoft\.space" ascii wide nocase
        $domain23 = "progsupdate\.com" ascii wide nocase
        $domain24 = "rotter2\.publicvm\.com" ascii wide nocase
        $domain25 = "safara\.sytes\.net" ascii wide nocase
        $domain26 = "smartsftp\.pw" ascii wide nocase
        $domain27 = "speedbind\.com" ascii wide nocase
        $domain28 = "subsidiaryohio\.linkpc\.net" ascii wide nocase
        $domain29 = "topgamse\.com" ascii wide nocase
        $domain30 = "ukgames\.tech" ascii wide nocase
        $domain31 = "viewnet\.better-than\.tv" ascii wide nocase
        $domain32 = "wallanews\.publicvm\.com" ascii wide nocase
        $domain33 = "wallanews\.sytes\.net" ascii wide nocase
        $domain34 = "webfile\.myq-see\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_RAMPANTKITTEN
{
    meta:
        description = "Detects IOCs associated with APT RAMPANTKITTEN"
        author = "APTtrail Automated Collection"
        apt_group = "RAMPANTKITTEN"
        reference = "https://otx.alienvault.com/pulse/5f64d3ca157b5eecc4646710"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "afalr-onedrive\.com" ascii wide nocase
        $domain1 = "afalr-sharepoint\.com" ascii wide nocase
        $domain2 = "alarabiye\.net" ascii wide nocase
        $domain3 = "cpuconfig\.com" ascii wide nocase
        $domain4 = "developerchrome\.com" ascii wide nocase
        $domain5 = "endupload\.com" ascii wide nocase
        $domain6 = "firefox-addons\.com" ascii wide nocase
        $domain7 = "gradleservice\.info" ascii wide nocase
        $domain8 = "mailgoogle\.info" ascii wide nocase
        $domain9 = "picfile\.net" ascii wide nocase
        $domain10 = "telegrambackups\.com" ascii wide nocase
        $domain11 = "telegrambots\.me" ascii wide nocase
        $domain12 = "telegramco\.org" ascii wide nocase
        $domain13 = "telegramdesktop\.com" ascii wide nocase
        $domain14 = "telegramreport\.me" ascii wide nocase
        $domain15 = "telegramup\.com" ascii wide nocase
        $domain16 = "update-help\.com" ascii wide nocase
        $domain17 = "vareangold\.de" ascii wide nocase
        $domain18 = "winchecking\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_RANCOR
{
    meta:
        description = "Detects IOCs associated with APT RANCOR"
        author = "APTtrail Automated Collection"
        apt_group = "RANCOR"
        reference = "https://meltx0r.github.io/tech/2019/09/11/rancor-apt.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "754d56-8523\.sexidude\.com" ascii wide nocase
        $domain1 = "bafunpda\.xyz" ascii wide nocase
        $domain2 = "charleseedwards\.dynamic-dns\.net" ascii wide nocase
        $domain3 = "dsdfdscxcv\.justdied\.com" ascii wide nocase
        $domain4 = "dsgsdgergrfv\.toythieves\.com" ascii wide nocase
        $domain5 = "facebook-apps\.com" ascii wide nocase
        $domain6 = "ftp\.chinhphu\.ddns\.ms" ascii wide nocase
        $domain7 = "goole\.authorizeddns\.us" ascii wide nocase
        $domain8 = "jdanief\.xyz" ascii wide nocase
        $domain9 = "kfesv\.xyz" ascii wide nocase
        $domain10 = "kibistation\.onmypc\.net" ascii wide nocase
        $domain11 = "microsoft\.authorizeddns\.us" ascii wide nocase
        $domain12 = "microsoft\.https443\.org" ascii wide nocase
        $domain13 = "msdns\.otzo\.com" ascii wide nocase
        $domain14 = "nicetiss54\.lflink\.com" ascii wide nocase
        $domain15 = "oui6473rf\.xxuz\.com" ascii wide nocase
        $domain16 = "sfstnksfcv\.jungleheart\.com" ascii wide nocase
        $domain17 = "vvcxvsdvx\.dynamic-dns\.net" ascii wide nocase
        $ip18 = "139.162.14.25" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_REAPER
{
    meta:
        description = "Detects IOCs associated with APT REAPER"
        author = "APTtrail Automated Collection"
        apt_group = "REAPER"
        reference = "https://blog.talosintelligence.com/2018/04/fake-av-investigation-unearths-kevdroid.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "account\.drive-google-com\.tk" ascii wide nocase
        $domain1 = "account\.gommask\.online" ascii wide nocase
        $domain2 = "accounts-youtube\.drive-google-com\.tk" ascii wide nocase
        $domain3 = "anyportals\.com" ascii wide nocase
        $domain4 = "cgalim\.com" ascii wide nocase
        $domain5 = "dns-update\.club" ascii wide nocase
        $domain6 = "drive-google-com\.tk" ascii wide nocase
        $domain7 = "gmail\.drive-google-com\.tk" ascii wide nocase
        $domain8 = "gommask\.online" ascii wide nocase
        $domain9 = "hakproperty\.com" ascii wide nocase
        $domain10 = "hpserver\.online" ascii wide nocase
        $domain11 = "iblcor\.cafe24\.com" ascii wide nocase
        $domain12 = "imagedownloadsupport\.com" ascii wide nocase
        $domain13 = "login\.drive-google-com\.tk" ascii wide nocase
        $domain14 = "mailattachmentimageurlxyz\.site" ascii wide nocase
        $domain15 = "mumbai-m\.site" ascii wide nocase
        $domain16 = "pmoae\.com" ascii wide nocase
        $domain17 = "proxycheker\.pro" ascii wide nocase
        $domain18 = "ssl-gstatic\.drive-google-com\.tk" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_REDFOXTROT
{
    meta:
        description = "Detects IOCs associated with APT REDFOXTROT"
        author = "APTtrail Automated Collection"
        apt_group = "REDFOXTROT"
        reference = "https://github.com/Insikt-Group/Research/blob/master/RedFoxtrot%20June%202021"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "adobesupport\.net" ascii wide nocase
        $domain1 = "adtl\.mywire\.org" ascii wide nocase
        $domain2 = "anywheres\.run\.place" ascii wide nocase
        $domain3 = "appinfo\.camdvr\.org" ascii wide nocase
        $domain4 = "appsupport\.my-router\.de" ascii wide nocase
        $domain5 = "appupdate\.firewall-gateway\.de" ascii wide nocase
        $domain6 = "appupdate\.my-router\.de" ascii wide nocase
        $domain7 = "aries\.epac\.to" ascii wide nocase
        $domain8 = "bbsaili\.camdvr\.org" ascii wide nocase
        $domain9 = "billing\.epac\.to" ascii wide nocase
        $domain10 = "capture\.kozow\.com" ascii wide nocase
        $domain11 = "cheapnews\.online" ascii wide nocase
        $domain12 = "chock\.mywire\.org" ascii wide nocase
        $domain13 = "ciscoteam\.ignorelist\.com" ascii wide nocase
        $domain14 = "coreldraw\.kozow\.com" ascii wide nocase
        $domain15 = "czconnections\.ddns\.info" ascii wide nocase
        $domain16 = "darkpapa\.chickenkiller\.com" ascii wide nocase
        $domain17 = "dhsg123\.jkub\.com" ascii wide nocase
        $domain18 = "drdo\.dumb1\.com" ascii wide nocase
        $domain19 = "drdo\.mypop3\.net" ascii wide nocase
        $domain20 = "dsgf\.chickenkiller\.com" ascii wide nocase
        $domain21 = "elienceso\.kozow\.com" ascii wide nocase
        $domain22 = "exat\.dnset\.com" ascii wide nocase
        $domain23 = "exat\.zyns\.com" ascii wide nocase
        $domain24 = "execserver\.giize\.com" ascii wide nocase
        $domain25 = "exujjat\.xxuz\.com" ascii wide nocase
        $domain26 = "fashget\.theworkpc\.com" ascii wide nocase
        $domain27 = "fivenum\.mooo\.com" ascii wide nocase
        $domain28 = "foreverlove\.zzux\.com" ascii wide nocase
        $domain29 = "forum\.camdvr\.org" ascii wide nocase
        $domain30 = "ftp\.isronrsc\.giize\.com" ascii wide nocase
        $domain31 = "fukebutt\.zzux\.com" ascii wide nocase
        $domain32 = "googiao\.top" ascii wide nocase
        $domain33 = "googleupdate\.myz\.info" ascii wide nocase
        $domain34 = "gov4us\.online" ascii wide nocase
        $domain35 = "gulistan\.wikaba\.com" ascii wide nocase
        $domain36 = "hcl\.sexidude\.com" ascii wide nocase
        $domain37 = "holyshit\.dynamic-dns\.net" ascii wide nocase
        $domain38 = "honoroftajik\.dynamic-dns\.net" ascii wide nocase
        $domain39 = "hostmail1\.com" ascii wide nocase
        $domain40 = "https\.dnset\.com" ascii wide nocase
        $domain41 = "https\.ikwb\.com" ascii wide nocase
        $domain42 = "https\.otzo\.com" ascii wide nocase
        $domain43 = "https\.vizvaz\.com" ascii wide nocase
        $domain44 = "inbsnl\.ddns\.info" ascii wide nocase
        $domain45 = "inbsnl\.ddns\.ms" ascii wide nocase
        $domain46 = "indiabs\.nl" ascii wide nocase
        $domain47 = "indiabsnl\.com" ascii wide nocase
        $domain48 = "indiabsnl\.in" ascii wide nocase
        $domain49 = "indiabsnl\.net" ascii wide nocase
        $ip50 = "135.181.243.34" ascii wide
        $ip51 = "164.132.27.225" ascii wide
        $ip52 = "192.51.188.47" ascii wide
        $ip53 = "194.126.202.217" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_REDJULIETT
{
    meta:
        description = "Detects IOCs associated with APT REDJULIETT"
        author = "APTtrail Automated Collection"
        apt_group = "REDJULIETT"
        reference = "https://www.recordedfuture.com/research/redjuliett-intensifies-taiwanese-cyber-espionage-via-network-perimeter"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "cktime\.ooguy\.com" ascii wide nocase
        $domain1 = "cond0r\.com" ascii wide nocase
        $domain2 = "dns361\.tk" ascii wide nocase
        $domain3 = "godblack\.cf" ascii wide nocase
        $domain4 = "javacheck\.ooguy\.com" ascii wide nocase
        $domain5 = "javaupdate\.giize\.com" ascii wide nocase
        $domain6 = "purple76\.com" ascii wide nocase
        $domain7 = "sofeter\.ml" ascii wide nocase
        $domain8 = "solana\.onl" ascii wide nocase
        $domain9 = "togey\.online" ascii wide nocase
        $domain10 = "yeeyeey\.top" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_REDOCTOBER
{
    meta:
        description = "Detects IOCs associated with APT REDOCTOBER"
        author = "APTtrail Automated Collection"
        apt_group = "REDOCTOBER"
        reference = "https://www.alienvault.com/blog-content/2013/01/RedOctober-Indicatorsofcompromise-2.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "bb-apps-world\.com" ascii wide nocase
        $domain1 = "blackberry-apps-world\.com" ascii wide nocase
        $domain2 = "blackberry-update\.com" ascii wide nocase
        $domain3 = "csrss-check-new\.com" ascii wide nocase
        $domain4 = "csrss-update-new\.com" ascii wide nocase
        $domain5 = "csrss-upgrade-new\.com" ascii wide nocase
        $domain6 = "dailyinfonews\.net" ascii wide nocase
        $domain7 = "dll-host-check\.com" ascii wide nocase
        $domain8 = "dll-host-udate\.com" ascii wide nocase
        $domain9 = "dll-host-update\.com" ascii wide nocase
        $domain10 = "dll-host\.com" ascii wide nocase
        $domain11 = "dllupdate\.info" ascii wide nocase
        $domain12 = "drivers-check\.com" ascii wide nocase
        $domain13 = "drivers-get\.com" ascii wide nocase
        $domain14 = "drivers-update-online\.com" ascii wide nocase
        $domain15 = "genuine-check\.com" ascii wide nocase
        $domain16 = "genuineservicecheck\.com" ascii wide nocase
        $domain17 = "genuineupdate\.com" ascii wide nocase
        $domain18 = "hotinfonews\.com" ascii wide nocase
        $domain19 = "microsoft-msdn\.com" ascii wide nocase
        $domain20 = "microsoftcheck\.com" ascii wide nocase
        $domain21 = "microsoftosupdate\.com" ascii wide nocase
        $domain22 = "mobile-update\.com" ascii wide nocase
        $domain23 = "mobileimho\.com" ascii wide nocase
        $domain24 = "mobileimho\.ru" ascii wide nocase
        $domain25 = "ms-software-check\.com" ascii wide nocase
        $domain26 = "ms-software-genuine\.com" ascii wide nocase
        $domain27 = "ms-software-update\.com" ascii wide nocase
        $domain28 = "msgenuine\.net" ascii wide nocase
        $domain29 = "msinfoonline\.org" ascii wide nocase
        $domain30 = "msonlinecheck\.com" ascii wide nocase
        $domain31 = "msonlineget\.com" ascii wide nocase
        $domain32 = "msonlineupdate\.com" ascii wide nocase
        $domain33 = "new-driver-upgrade\.com" ascii wide nocase
        $domain34 = "nt-windows-check\.com" ascii wide nocase
        $domain35 = "nt-windows-online\.com" ascii wide nocase
        $domain36 = "nt-windows-update\.com" ascii wide nocase
        $domain37 = "os-microsoft-check\.com" ascii wide nocase
        $domain38 = "os-microsoft-update\.com" ascii wide nocase
        $domain39 = "osgenuine\.com" ascii wide nocase
        $domain40 = "security-mobile\.com" ascii wide nocase
        $domain41 = "shellupdate\.com" ascii wide nocase
        $domain42 = "svchost-check\.com" ascii wide nocase
        $domain43 = "svchost-online\.com" ascii wide nocase
        $domain44 = "svchost-update\.com" ascii wide nocase
        $domain45 = "update-genuine\.com" ascii wide nocase
        $domain46 = "win-check-update\.com" ascii wide nocase
        $domain47 = "win-driver-upgrade\.com" ascii wide nocase
        $domain48 = "windows-genuine\.com" ascii wide nocase
        $domain49 = "windowscheckupdate\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_REDWOLF
{
    meta:
        description = "Detects IOCs associated with APT REDWOLF"
        author = "APTtrail Automated Collection"
        apt_group = "REDWOLF"
        aliases = "earthkapre, goldblade, redcurl"
        reference = "https://bi-zone.medium.com/hunting-the-hunter-bi-zone-traces-the-footsteps-of-red-wolf-3677783e164d"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "alphastoned\.pro" ascii wide nocase
        $domain1 = "amscloudhost\.com" ascii wide nocase
        $domain2 = "app-ins-001\.amscloudhost\.com" ascii wide nocase
        $domain3 = "app-ins-002\.amscloudhost\.com" ascii wide nocase
        $domain4 = "app-l01\.msftcloud\.click" ascii wide nocase
        $domain5 = "app-l03\.msftcloud\.click" ascii wide nocase
        $domain6 = "app-l03\.servicehost\.click" ascii wide nocase
        $domain7 = "app-l07\.servicehost\.click" ascii wide nocase
        $domain8 = "automatinghrservices\.workers\.dev" ascii wide nocase
        $domain9 = "bora\.teracloud\.jp" ascii wide nocase
        $domain10 = "buyhighroad\.scienceontheweb\.net" ascii wide nocase
        $domain11 = "cdn\.wgroadcdn\.workers\.dev" ascii wide nocase
        $domain12 = "clever\.forcloudnetworks\.online" ascii wide nocase
        $domain13 = "cloud-01\.servicehost\.click" ascii wide nocase
        $domain14 = "community\.rmobileappdevelopment\.workers\.dev" ascii wide nocase
        $domain15 = "ctrl1\.sm\.advhost\.co\.uk" ascii wide nocase
        $domain16 = "cvsend\.resumeexpert\.cloud" ascii wide nocase
        $domain17 = "datascience\.iotconnectivity\.workers\.dev" ascii wide nocase
        $domain18 = "dav\.automatinghrservices\.workers\.dev" ascii wide nocase
        $domain19 = "dav\.cloud-01\.servicehost\.click" ascii wide nocase
        $domain20 = "dav\.linkedin-cloud-manager\.servicehost\.click" ascii wide nocase
        $domain21 = "eap\.byethost10\.com" ascii wide nocase
        $domain22 = "earthmart\.c1\.biz" ascii wide nocase
        $domain23 = "fiona\.forcloudnetworks\.online" ascii wide nocase
        $domain24 = "forcloudnetworks\.online" ascii wide nocase
        $domain25 = "hfn-c-001\.cc\.msftcloud\.click" ascii wide nocase
        $domain26 = "hwsrv-1048332\.hostwindsdns\.com" ascii wide nocase
        $domain27 = "ksg-c-001\.cc\.msftcloud\.click" ascii wide nocase
        $domain28 = "ksg-c-002\.cc\.msftcloud\.click" ascii wide nocase
        $domain29 = "ktr-cn-001\.amscloudhost\.com" ascii wide nocase
        $domain30 = "ktr-cn-002\.amscloudhost\.com" ascii wide nocase
        $domain31 = "l-dn-01\.msftcloud\.click" ascii wide nocase
        $domain32 = "l-dn-02\.msftcloud\.click" ascii wide nocase
        $domain33 = "l3-dn-01\.servicehost\.click" ascii wide nocase
        $domain34 = "l4-dn-01\.servicehost\.click" ascii wide nocase
        $domain35 = "l7-dn-01\.servicehost\.click" ascii wide nocase
        $domain36 = "linkedin-cloud-manager\.servicehost\.click" ascii wide nocase
        $domain37 = "live\.airemoteplant\.workers\.dev" ascii wide nocase
        $domain38 = "live\.itsmartuniverse\.workers\.dev" ascii wide nocase
        $domain39 = "m-dn-001\.amscloudhost\.com" ascii wide nocase
        $domain40 = "m-dn-002\.amscloudhost\.com" ascii wide nocase
        $domain41 = "mainsts-01\.cn\.alphastoned\.pro" ascii wide nocase
        $domain42 = "mia\.nl\.tab\.digital" ascii wide nocase
        $domain43 = "msftcloud\.click" ascii wide nocase
        $domain44 = "mtk-cn-001\.amscloudhost\.com" ascii wide nocase
        $domain45 = "mtk-cn-002\.amscloudhost\.com" ascii wide nocase
        $domain46 = "quiet\.msftlivecloudsrv\.workers\.dev" ascii wide nocase
        $domain47 = "rl-cn-s-001\.amscloudhost\.com" ascii wide nocase
        $domain48 = "servicehost\.click" ascii wide nocase
        $domain49 = "sm\.vbigdatasolutions\.workers\.dev" ascii wide nocase
        $ip50 = "188.130.207.253" ascii wide
        $ip51 = "193.176.158.30" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_RNEXUS
{
    meta:
        description = "Detects IOCs associated with APT RNEXUS"
        author = "APTtrail Automated Collection"
        apt_group = "RNEXUS"
        reference = "https://citizenlab.ca/2017/05/tainted-leaks-disinformation-phish/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "com-securitysettingpage\.tk" ascii wide nocase
        $domain1 = "id4242\.ga" ascii wide nocase
        $domain2 = "id833\.ga" ascii wide nocase
        $domain3 = "id834\.ga" ascii wide nocase
        $domain4 = "id9954\.gq" ascii wide nocase
        $domain5 = "mail-google-login\.blogspot\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_RUSTICWEB
{
    meta:
        description = "Detects IOCs associated with APT RUSTICWEB"
        author = "APTtrail Automated Collection"
        apt_group = "RUSTICWEB"
        reference = "https://twitter.com/Cuser07/status/1742437262078660874"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "apsdighi\.estttsec\.in" ascii wide nocase
        $domain1 = "awesscholarship\.in" ascii wide nocase
        $domain2 = "epar\.in" ascii wide nocase
        $domain3 = "estttsec\.in" ascii wide nocase
        $domain4 = "nicdsa\.estttsec\.in" ascii wide nocase
        $domain5 = "parichay\.epar\.in" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SAGUARO
{
    meta:
        description = "Detects IOCs associated with APT SAGUARO"
        author = "APTtrail Automated Collection"
        apt_group = "SAGUARO"
        reference = "https://apt.securelist.com/apt/saguaro"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "eduarditopallares\.mooo\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_SANDMAN
{
    meta:
        description = "Detects IOCs associated with APT SANDMAN"
        author = "APTtrail Automated Collection"
        apt_group = "SANDMAN"
        reference = "https://www.sentinelone.com/labs/sandman-apt-a-mystery-group-targeting-telcos-with-a-luajit-toolkit/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "encagil\.com" ascii wide nocase
        $domain1 = "explorecell\.com" ascii wide nocase
        $domain2 = "mode\.encagil\.com" ascii wide nocase
        $domain3 = "ssl\.explorecell\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SANDWORM
{
    meta:
        description = "Detects IOCs associated with APT SANDWORM"
        author = "APTtrail Automated Collection"
        apt_group = "SANDWORM"
        aliases = "KALAMBUR backdoor, apt44, blackenergy"
        reference = "https://app.validin.com/detail?find=a78dda24e41edb22c214a4d5db1caf2671b5dff7&type=hash&ref_id=4c558f1ca34#tab=host_pairs (# 2025-02-12)"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "2zilmiystfbjib2k4hvhpnv2uhni4ax5ce4xlpb7swkjimfnszxbkaid\.onion" ascii wide nocase
        $domain1 = "abaronaweb\.net" ascii wide nocase
        $domain2 = "account-check\.hostapp\.link" ascii wide nocase
        $domain3 = "account-googlmail\.ml" ascii wide nocase
        $domain4 = "account-loginserv\.com" ascii wide nocase
        $domain5 = "account\.adfs\.kyivstar\.online" ascii wide nocase
        $domain6 = "accounts\.google-account-settings\.spdup\.art" ascii wide nocase
        $domain7 = "activationsmicrosoft\.com" ascii wide nocase
        $domain8 = "adfs\.kyivstar\.online" ascii wide nocase
        $domain9 = "adobeprotectcheck\.com" ascii wide nocase
        $domain10 = "ads\.ew\.com\.cn" ascii wide nocase
        $domain11 = "all-invite\.org" ascii wide nocase
        $domain12 = "annualgieconferenceinmunich2024\.com" ascii wide nocase
        $domain13 = "antimailspam\.com" ascii wide nocase
        $domain14 = "aplusdesktop\.workers\.dev" ascii wide nocase
        $domain15 = "aplusmodgovua\.workers\.dev" ascii wide nocase
        $domain16 = "armylpus\.workers\.dev" ascii wide nocase
        $domain17 = "armyplus-desktop\.workers\.dev" ascii wide nocase
        $domain18 = "aut0mat\.info" ascii wide nocase
        $domain19 = "beta-0-110\.armyplus-desktop\.workers\.dev" ascii wide nocase
        $domain20 = "beta-0-2237\.desktopapluscom\.workers\.dev" ascii wide nocase
        $domain21 = "bka\.im" ascii wide nocase
        $domain22 = "cazino-game\.com" ascii wide nocase
        $domain23 = "cdnauthsoft\.com" ascii wide nocase
        $domain24 = "claud\.in" ascii wide nocase
        $domain25 = "cloud-sync\.org" ascii wide nocase
        $domain26 = "cloue\.link" ascii wide nocase
        $domain27 = "cxim\.asia" ascii wide nocase
        $domain28 = "darkett\.ddns\.net" ascii wide nocase
        $domain29 = "darksea\.ddns\.net" ascii wide nocase
        $domain30 = "ddumasz\.info" ascii wide nocase
        $domain31 = "desktopaplus\.workers\.dev" ascii wide nocase
        $domain32 = "desktopapluscom\.workers\.dev" ascii wide nocase
        $domain33 = "documentreader\.net" ascii wide nocase
        $domain34 = "documents-reader\.com" ascii wide nocase
        $domain35 = "drive\.google\.com\.filepreview\.auth\.userarea\.click" ascii wide nocase
        $domain36 = "dvjbn4sg4p1ck\.cloudfront\.net" ascii wide nocase
        $domain37 = "esetpremium\.com" ascii wide nocase
        $domain38 = "ett\.ddns\.net" ascii wide nocase
        $domain39 = "ett\.hopto\.org" ascii wide nocase
        $domain40 = "fbapp\.info" ascii wide nocase
        $domain41 = "fbapp\.link" ascii wide nocase
        $domain42 = "fbapp\.top" ascii wide nocase
        $domain43 = "filepreview\.auth\.userarea\.click" ascii wide nocase
        $domain44 = "gieannualconferenceinmunich\.com" ascii wide nocase
        $domain45 = "globdomain\.ru" ascii wide nocase
        $domain46 = "google-account-settings\.spdup\.art" ascii wide nocase
        $domain47 = "hackzona\.tk" ascii wide nocase
        $domain48 = "hostapp\.be" ascii wide nocase
        $domain49 = "hwupdates\.com" ascii wide nocase
        $ip50 = "1.9.85.247" ascii wide
        $ip51 = "1.9.85.247" ascii wide
        $ip52 = "1.9.85.247" ascii wide
        $ip53 = "1.9.85.247" ascii wide
        $ip54 = "1.9.85.247" ascii wide
        $ip55 = "1.9.85.247" ascii wide
        $ip56 = "1.9.85.247" ascii wide
        $ip57 = "1.9.85.248" ascii wide
        $ip58 = "1.9.85.248" ascii wide
        $ip59 = "1.9.85.248" ascii wide
        $ip60 = "1.9.85.248" ascii wide
        $ip61 = "1.9.85.248" ascii wide
        $ip62 = "1.9.85.248" ascii wide
        $ip63 = "1.9.85.248" ascii wide
        $ip64 = "1.9.85.249" ascii wide
        $ip65 = "1.9.85.249" ascii wide
        $ip66 = "1.9.85.249" ascii wide
        $ip67 = "1.9.85.249" ascii wide
        $ip68 = "1.9.85.249" ascii wide
        $ip69 = "1.9.85.249" ascii wide
        $ip70 = "1.9.85.249" ascii wide
        $ip71 = "1.9.85.252" ascii wide
        $ip72 = "1.9.85.252" ascii wide
        $ip73 = "1.9.85.252" ascii wide
        $ip74 = "1.9.85.252" ascii wide
        $ip75 = "1.9.85.252" ascii wide
        $ip76 = "1.9.85.252" ascii wide
        $ip77 = "1.9.85.252" ascii wide
        $ip78 = "1.9.85.253" ascii wide
        $ip79 = "1.9.85.253" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SAURON
{
    meta:
        description = "Detects IOCs associated with APT SAURON"
        author = "APTtrail Automated Collection"
        apt_group = "SAURON"
        reference = "https://securelist.com/files/2016/07/The-ProjectSauron-APT_IOCs_KL.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "bikessport\.com" ascii wide nocase
        $domain1 = "flowershop22\.110mb\.com" ascii wide nocase
        $domain2 = "myhomemusic\.com" ascii wide nocase
        $domain3 = "rapidcomments\.com" ascii wide nocase
        $domain4 = "wildhorses\.awardspace\.info" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SCANBOX
{
    meta:
        description = "Detects IOCs associated with APT SCANBOX"
        author = "APTtrail Automated Collection"
        apt_group = "SCANBOX"
        reference = "http://pwc.blogs.com/files/cto-tib-20150223-01a.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "bak\.mailaunch\.com" ascii wide nocase
        $domain1 = "file\.googlecaches\.com" ascii wide nocase
        $domain2 = "gtm\.googlecaches\.com" ascii wide nocase
        $domain3 = "js\.googlewebcache\.com" ascii wide nocase
        $domain4 = "owa\.outlookssl\.com" ascii wide nocase
        $domain5 = "us-mg6\.mail\.yahoo\.mailaunch\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SCARLETMIMIC
{
    meta:
        description = "Detects IOCs associated with APT SCARLETMIMIC"
        author = "APTtrail Automated Collection"
        apt_group = "SCARLETMIMIC"
        aliases = "fakem, fakemrat"
        reference = "http://researchcenter.paloaltonetworks.com/2016/01/scarlet-mimic-years-long-espionage-targets-minority-activists/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "aaa123\.spdns\.de" ascii wide nocase
        $domain1 = "account\.websurprisemail\.com" ascii wide nocase
        $domain2 = "accounts\.yourturbe\.org" ascii wide nocase
        $domain3 = "addi\.apple\.cloudns\.org" ascii wide nocase
        $domain4 = "addnow\.zapto\.org" ascii wide nocase
        $domain5 = "admin\.spdns\.org" ascii wide nocase
        $domain6 = "alma\.apple\.cloudns\.org" ascii wide nocase
        $domain7 = "angleegg\.ddns\.us" ascii wide nocase
        $domain8 = "angleegg\.xxxy\.info" ascii wide nocase
        $domain9 = "apple\.lenovositegroup\.com" ascii wide nocase
        $domain10 = "apple12\.co\.cc" ascii wide nocase
        $domain11 = "apple12\.crabdance\.com" ascii wide nocase
        $domain12 = "avira\.suroot\.com" ascii wide nocase
        $domain13 = "bailee\.alanna\.cloudns\.biz" ascii wide nocase
        $domain14 = "bee\.aoto\.cloudns\.org" ascii wide nocase
        $domain15 = "bits\.githubs\.net" ascii wide nocase
        $domain16 = "book\.websurprisemail\.com" ascii wide nocase
        $domain17 = "clean\.popqueen\.cloudns\.org" ascii wide nocase
        $domain18 = "desk\.websurprisemail\.com" ascii wide nocase
        $domain19 = "detail43\.myfirewall\.org" ascii wide nocase
        $domain20 = "dolat\.diyarpakzimin\.com" ascii wide nocase
        $domain21 = "dolat\.websurprisemail\.com" ascii wide nocase
        $domain22 = "dolet\.websurprisemail\.com" ascii wide nocase
        $domain23 = "economy\.spdns\.de" ascii wide nocase
        $domain24 = "economy\.spdns\.eu" ascii wide nocase
        $domain25 = "eemete\.freetcp\.com" ascii wide nocase
        $domain26 = "email\.googmail\.org" ascii wide nocase
        $domain27 = "endless\.zapto\.org" ascii wide nocase
        $domain28 = "firefox\.spdns\.de" ascii wide nocase
        $domain29 = "firewallupdate\.firewall-gateway\.net" ascii wide nocase
        $domain30 = "fish\.seafood\.cloudns\.org" ascii wide nocase
        $domain31 = "freeavg\.sites\.net" ascii wide nocase
        $domain32 = "freeavg\.sytes\.net" ascii wide nocase
        $domain33 = "freeonline\.3d-game\.com" ascii wide nocase
        $domain34 = "ftp112\.lenta\.cloudns\.pw" ascii wide nocase
        $domain35 = "github\.ignorelist\.com" ascii wide nocase
        $domain36 = "googmail\.com" ascii wide nocase
        $domain37 = "googmail\.org" ascii wide nocase
        $domain38 = "gorlan\.cloudns\.pro" ascii wide nocase
        $domain39 = "ibmcorp\.slyip\.com" ascii wide nocase
        $domain40 = "intersecurity\.firewall-gateway\.com" ascii wide nocase
        $domain41 = "islam\.youtubesitegroup\.com" ascii wide nocase
        $domain42 = "kaspersky\.firewall-gateway\.net" ascii wide nocase
        $domain43 = "kasperskysecurity\.firewall-gateway\.com" ascii wide nocase
        $domain44 = "kissecurity\.firewall-gateway\.net" ascii wide nocase
        $domain45 = "lemondtree\.freetcp\.com" ascii wide nocase
        $domain46 = "liumingzhen\.myftp\.org" ascii wide nocase
        $domain47 = "liumingzhen\.zapto\.org" ascii wide nocase
        $domain48 = "mail\.firewall-gateway\.com" ascii wide nocase
        $domain49 = "mareva\.catherine\.cloudns\.us" ascii wide nocase
        $ip50 = "153.148.120.217" ascii wide
        $ip51 = "207.204.225.117" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SCIERON
{
    meta:
        description = "Detects IOCs associated with APT SCIERON"
        author = "APTtrail Automated Collection"
        apt_group = "SCIERON"
        aliases = "HeaderTip, cosmicbeetle, scarab"
        reference = "http://www.symantec.com/content/en/us/enterprise/media/security_response/docs/Scarab_IOCs_January_2015.txt"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "Markshell\.etowns\.net" ascii wide nocase
        $domain1 = "akamaicdnup\.com" ascii wide nocase
        $domain2 = "apple\.dynamic-dns\.net" ascii wide nocase
        $domain3 = "autocar\.ServeUser\.com" ascii wide nocase
        $domain4 = "autocar\.suroot\.com" ascii wide nocase
        $domain5 = "b\.688\.org" ascii wide nocase
        $domain6 = "blackblog\.chatnook\.com" ascii wide nocase
        $domain7 = "bulldog\.toh\.info" ascii wide nocase
        $domain8 = "cdnupdate\.net" ascii wide nocase
        $domain9 = "cew58e\.xxxy\.info" ascii wide nocase
        $domain10 = "coastnews\.darktech\.org" ascii wide nocase
        $domain11 = "d\.piii\.net" ascii wide nocase
        $domain12 = "d1lhk2kflvant7\.cloudfront\.net" ascii wide nocase
        $domain13 = "demon\.4irc\.com" ascii wide nocase
        $domain14 = "dynamic\.ddns\.mobi" ascii wide nocase
        $domain15 = "ebook\.port25\.biz" ascii wide nocase
        $domain16 = "expert\.4irc\.com" ascii wide nocase
        $domain17 = "football\.mrbasic\.com" ascii wide nocase
        $domain18 = "gjjb\.flnet\.org" ascii wide nocase
        $domain19 = "imirnov\.ddns\.info" ascii wide nocase
        $domain20 = "jingnan88\.chatnook\.com" ascii wide nocase
        $domain21 = "lehnjb\.epac\.to" ascii wide nocase
        $domain22 = "lockbitblog\.info" ascii wide nocase
        $domain23 = "logoff\.25u\.com" ascii wide nocase
        $domain24 = "logoff\.ddns\.info" ascii wide nocase
        $domain25 = "ls910329\.my03\.com" ascii wide nocase
        $domain26 = "mailru\.25u\.com" ascii wide nocase
        $domain27 = "mert\.my03\.com" ascii wide nocase
        $domain28 = "mydear\.ddns\.info" ascii wide nocase
        $domain29 = "nazgul\.zyns\.com" ascii wide nocase
        $domain30 = "ndcinformation\.acmetoy\.com" ascii wide nocase
        $domain31 = "newdyndns\.scieron\.com" ascii wide nocase
        $domain32 = "newoutlook\.darktech\.org" ascii wide nocase
        $domain33 = "photocard\.4irc\.com" ascii wide nocase
        $domain34 = "pricetag\.deaftone\.com" ascii wide nocase
        $domain35 = "product2020\.mrbasic\.com" ascii wide nocase
        $domain36 = "rubberduck\.gotgeeks\.com" ascii wide nocase
        $domain37 = "service\.authorizeddns\.net" ascii wide nocase
        $domain38 = "shutdown\.25u\.com" ascii wide nocase
        $domain39 = "sorry\.ns2\.name" ascii wide nocase
        $domain40 = "ss\.688\.org" ascii wide nocase
        $domain41 = "sskill\.b0ne\.com" ascii wide nocase
        $domain42 = "sys\.688\.org" ascii wide nocase
        $domain43 = "text-First\.flnet\.org" ascii wide nocase
        $domain44 = "text-first\.trickip\.org" ascii wide nocase
        $domain45 = "u\.cbu\.net" ascii wide nocase
        $domain46 = "u\.piii\.net" ascii wide nocase
        $domain47 = "up\.awiki\.org" ascii wide nocase
        $domain48 = "up\.vctel\.com" ascii wide nocase
        $domain49 = "update\.cbu\.net" ascii wide nocase
        $ip50 = "104.155.198.25" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SEAFLOWER
{
    meta:
        description = "Detects IOCs associated with APT SEAFLOWER"
        author = "APTtrail Automated Collection"
        apt_group = "SEAFLOWER"
        reference = "https://blog.confiant.com/how-seaflower-%E8%97%8F%E6%B5%B7%E8%8A%B1-installs-backdoors-in-ios-android-web3-wallets-to-steal-your-seed-phrase-d25f0ccdffce"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "74871011\.huliqianbao\.com" ascii wide nocase
        $domain1 = "app\.imztoken\.xyz" ascii wide nocase
        $domain2 = "bnb\.lnfura\.org" ascii wide nocase
        $domain3 = "bsc\.lnfura\.org" ascii wide nocase
        $domain4 = "btc\.lnfura\.org" ascii wide nocase
        $domain5 = "colnbase\.homes" ascii wide nocase
        $domain6 = "copy\.lnfura\.org" ascii wide nocase
        $domain7 = "eth\.lnfura\.org" ascii wide nocase
        $domain8 = "facai\.im" ascii wide nocase
        $domain9 = "imztoken\.xyz" ascii wide nocase
        $domain10 = "lnfura\.io" ascii wide nocase
        $domain11 = "lnfura\.org" ascii wide nocase
        $domain12 = "mainnet\.lnfura\.io" ascii wide nocase
        $domain13 = "mainnet\.lnfura\.org" ascii wide nocase
        $domain14 = "manage\.lnfura\.io" ascii wide nocase
        $domain15 = "metanask\.cc" ascii wide nocase
        $domain16 = "som-coinbase\.com" ascii wide nocase
        $domain17 = "test\.lnfura\.org" ascii wide nocase
        $domain18 = "token18\.app" ascii wide nocase
        $domain19 = "trx\.lnfura\.org" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SECTORA05
{
    meta:
        description = "Detects IOCs associated with APT SECTORA05"
        author = "APTtrail Automated Collection"
        apt_group = "SECTORA05"
        reference = "http://download.ahnlab.com/kr/site/library/%5BAnalysis_Report%5DOperation_Kabar_Cobra.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "acount-qooqle\.pe\.hu" ascii wide nocase
        $domain1 = "ago2\.co\.kr" ascii wide nocase
        $domain2 = "ahnniab\.esy\.es" ascii wide nocase
        $domain3 = "aiyac-updaite\.hol\.es" ascii wide nocase
        $domain4 = "daum-safety-team\.esy\.es" ascii wide nocase
        $domain5 = "daum-settting\.hol\.es" ascii wide nocase
        $domain6 = "gyjmc\.com" ascii wide nocase
        $domain7 = "jejuseongahn\.org" ascii wide nocase
        $domain8 = "jundosase\.cafe24\.com" ascii wide nocase
        $domain9 = "kuku675\.site11\.com" ascii wide nocase
        $domain10 = "kuku79\.herobo\.com" ascii wide nocase
        $domain11 = "mail-service\.pe\.hu" ascii wide nocase
        $domain12 = "mail-support\.esy\.es" ascii wide nocase
        $domain13 = "ms-performance\.hol\.es" ascii wide nocase
        $domain14 = "msperformance\.hol\.es" ascii wide nocase
        $domain15 = "my-homework\.890m\.com" ascii wide nocase
        $domain16 = "myacccounts-goggle\.hol\.es" ascii wide nocase
        $domain17 = "myaccounnts-goggle\.esy\.es" ascii wide nocase
        $domain18 = "myprofileacc\.pe\.hu" ascii wide nocase
        $domain19 = "nav-mail\.hol\.es" ascii wide nocase
        $domain20 = "navem-rnail\.hol\.es" ascii wide nocase
        $domain21 = "need-nver\.hol\.es" ascii wide nocase
        $domain22 = "nid-mail\.esy\.es" ascii wide nocase
        $domain23 = "nid-mail\.hol\.es" ascii wide nocase
        $domain24 = "nid-mail\.pe\.hu" ascii wide nocase
        $domain25 = "nid-naver\.hol\.es" ascii wide nocase
        $domain26 = "nid-never\.pe\.hu" ascii wide nocase
        $domain27 = "qqoqle-centering\.esy\.es" ascii wide nocase
        $domain28 = "rnyacount-jpadmin\.hol\.es" ascii wide nocase
        $domain29 = "safe-naver-mail\.pe\.hu" ascii wide nocase
        $domain30 = "suppcrt-seourity\.esy\.es" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SHAMOON
{
    meta:
        description = "Detects IOCs associated with APT SHAMOON"
        author = "APTtrail Automated Collection"
        apt_group = "SHAMOON"
        reference = "https://github.com/advanced-threat-research/IOCs/blob/master/2017/2017-01-27-spotlight-on-shamoon/spotlight-on-shamoon.csv"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "analytics-google\.org" ascii wide nocase
        $domain1 = "go-microstf\.com" ascii wide nocase
        $domain2 = "key8854321\.pub" ascii wide nocase
        $domain3 = "maps-modon\.club" ascii wide nocase
        $domain4 = "mol\.com-ho\.me" ascii wide nocase
        $domain5 = "mynetwork\.ddns\.net" ascii wide nocase
        $domain6 = "ntg-sa\.com" ascii wide nocase
        $domain7 = "possibletarget\.ddns\.com" ascii wide nocase
        $domain8 = "winappupdater\.com" ascii wide nocase
        $domain9 = "winupdater\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SHARPPANDA
{
    meta:
        description = "Detects IOCs associated with APT SHARPPANDA"
        author = "APTtrail Automated Collection"
        apt_group = "SHARPPANDA"
        reference = "https://blog.vincss.net/2021/05/re022-phan-1-phan-tich-nhanh-mau-ma-doc-gia-mao-cong-van-cua-uy-ban-kiem-tra-tw-VietNam.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "office\.oiqezet\.com" ascii wide nocase
        $domain1 = "oiqezet\.com" ascii wide nocase
        $domain2 = "openxmlformats\.shop" ascii wide nocase
        $domain3 = "schemas\.openxmlformats\.shop" ascii wide nocase
        $domain4 = "template-content\.azurecloudapp\.workers\.dev" ascii wide nocase
        $ip5 = "107.148.165.151" ascii wide
        $ip6 = "13.236.189.80" ascii wide
        $ip7 = "45.121.146.88" ascii wide
        $ip8 = "45.76.190.210" ascii wide
        $ip9 = "45.91.225.139" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SHIQIANG
{
    meta:
        description = "Detects IOCs associated with APT SHIQIANG"
        author = "APTtrail Automated Collection"
        apt_group = "SHIQIANG"
        reference = "https://github.com/advanced-threat-research/IOCs/blob/master/2014/2014-05-03-stolen-certificates-shiqiang-gang/stolen-certificates-shiqiang-gang.csv"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "newyorkonlin\.com" ascii wide nocase
        $domain1 = "tibetcongress\.oicp\.net" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_SIDEWINDER
{
    meta:
        description = "Detects IOCs associated with APT SIDEWINDER"
        author = "APTtrail Automated Collection"
        apt_group = "SIDEWINDER"
        aliases = "GroupA21, apt-04, apt-c-24"
        reference = "http://blog.talosintelligence.com/2022/02/whats-with-shared-vba-code.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "0ultook\.live" ascii wide nocase
        $domain1 = "1\.modp-pk\.org" ascii wide nocase
        $domain2 = "101c4a583c3acdd2a06ca2fb183cf995fgd55fghf67dhf7dhf7dhnfks7\.pages\.dev" ascii wide nocase
        $domain3 = "101c4a583c3acdd2afd06ca2fb183cf995sdfsdh54jkdfgh54893489h5\.pages\.dev" ascii wide nocase
        $domain4 = "101c4a583c3acdd2dfgn54990fgmkl5i90ghml569ig06ca2fb183cf995\.pages\.dev" ascii wide nocase
        $domain5 = "101c4a5fdjfjkf8fg90fksd9dfslsd0fk83c3acdd2a06ca2fb183cf995\.pages\.dev" ascii wide nocase
        $domain6 = "126-com\.live" ascii wide nocase
        $domain7 = "163inc\.org" ascii wide nocase
        $domain8 = "168-gov\.info" ascii wide nocase
        $domain9 = "1c1157fa\.caa\.update\.customs-lk\.org" ascii wide nocase
        $domain10 = "1d06bfb2\.check\.update\.fia-gov\.org" ascii wide nocase
        $domain11 = "1d06bfb2\.local\.update\.fia-gov\.org" ascii wide nocase
        $domain12 = "1d06bfb2\.scan\.update\.fia-gov\.org" ascii wide nocase
        $domain13 = "203-124351878443\.hopto\.org" ascii wide nocase
        $domain14 = "24170-40494\.bacloud\.info" ascii wide nocase
        $domain15 = "2aeb306b-4c5f-4cc6-a7a2-6fcd96612b9d\.us-east-1\.cloud\.genez\.io" ascii wide nocase
        $domain16 = "2let\.org" ascii wide nocase
        $domain17 = "38273409\.mail-defence-lk-loging-horde\.pages\.dev" ascii wide nocase
        $domain18 = "5673696e-bcf9-4a34-848d-2e6875b0561e\.us-east-1\.cloud\.genez\.io" ascii wide nocase
        $domain19 = "63inc\.com" ascii wide nocase
        $domain20 = "64115cb6\.check\.update\.fia-gov\.org" ascii wide nocase
        $domain21 = "6441056b613c32a9\.dwnlld\.info" ascii wide nocase
        $domain22 = "753fa5b2\.check\.update\.fia-gov\.org" ascii wide nocase
        $domain23 = "7b1271c3-0158-4f94-b54e-d51a4be1cfc4\.us-east-1\.cloud\.genez\.io" ascii wide nocase
        $domain24 = "7ef1996f-c463-4540-936a-70d0fd477f98\.live-co\.org" ascii wide nocase
        $domain25 = "81-cn\.ddns\.net" ascii wide nocase
        $domain26 = "81-cn\.info" ascii wide nocase
        $domain27 = "85476ee3-a4b9-4815-bd1d-68653205e378\.us-east-1\.cloud\.genez\.io" ascii wide nocase
        $domain28 = "8ad94e36\.cdn-caa-sco\.pages\.dev" ascii wide nocase
        $domain29 = "a\.bc\.1d06bfb2\.check\.update\.fia-gov\.org" ascii wide nocase
        $domain30 = "a\.bc\.1d06bfb2\.local\.update\.fia-gov\.org" ascii wide nocase
        $domain31 = "a\.bc\.1d06bfb2\.scan\.update\.fia-gov\.org" ascii wide nocase
        $domain32 = "a\.bc\.64115cb6\.check\.update\.fia-gov\.org" ascii wide nocase
        $domain33 = "a5936441-e402-41e3-b02b-75af112074b5\.org-co\.net" ascii wide nocase
        $domain34 = "a6dff163-e0b9-49c9-87e4-357f761f3c3b\.us-east-1\.cloud\.genez\.io" ascii wide nocase
        $domain35 = "aa173\.bank-ok\.com" ascii wide nocase
        $domain36 = "abc\.bol-north\.com" ascii wide nocase
        $domain37 = "academy\.lesporc\.live" ascii wide nocase
        $domain38 = "acc\.pk-govt\.net" ascii wide nocase
        $domain39 = "acenent\.site" ascii wide nocase
        $domain40 = "acfinang\.shop" ascii wide nocase
        $domain41 = "acrobat\.paknavy-pk\.org" ascii wide nocase
        $domain42 = "active\.roteh\.site" ascii wide nocase
        $domain43 = "adobe\.pdf-downlod\.com" ascii wide nocase
        $domain44 = "adobeglobal\.com" ascii wide nocase
        $domain45 = "advancedhealth\.medicallab\.site" ascii wide nocase
        $domain46 = "advisary\.army-govbd\.info" ascii wide nocase
        $domain47 = "advisories-sgcustoms\.d0cumentview\.info" ascii wide nocase
        $domain48 = "advisory-cabinetgpk\.servehttp\.com" ascii wide nocase
        $domain49 = "advisory\.army-govbd\.info" ascii wide nocase
        $ip50 = "110.10.176.193" ascii wide
        $ip51 = "141.136.0.91" ascii wide
        $ip52 = "144.91.72.17" ascii wide
        $ip53 = "149.102.131.122" ascii wide
        $ip54 = "151.236.11.147" ascii wide
        $ip55 = "164.68.108.153" ascii wide
        $ip56 = "164.68.108.153" ascii wide
        $ip57 = "164.68.108.153" ascii wide
        $ip58 = "167.86.94.42" ascii wide
        $ip59 = "173.212.242.43" ascii wide
        $ip60 = "185.159.128.117" ascii wide
        $ip61 = "185.225.17.239" ascii wide
        $ip62 = "185.225.19.46" ascii wide
        $ip63 = "185.225.19.46" ascii wide
        $ip64 = "193.200.16.230" ascii wide
        $ip65 = "202.58.104.100" ascii wide
        $ip66 = "213.227.154.175" ascii wide
        $ip67 = "31.15.17.230" ascii wide
        $ip68 = "31.58.137.246" ascii wide
        $ip69 = "46.8.226.5" ascii wide
        $ip70 = "47.236.177.123" ascii wide
        $ip71 = "47.76.135.130" ascii wide
        $ip72 = "47.84.196.148" ascii wide
        $ip73 = "5.230.40.141" ascii wide
        $ip74 = "5.230.42.202" ascii wide
        $ip75 = "5.230.43.203" ascii wide
        $ip76 = "5.230.52.133" ascii wide
        $ip77 = "5.230.54.162" ascii wide
        $ip78 = "5.230.54.63" ascii wide
        $ip79 = "5.230.55.29" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SILENCE
{
    meta:
        description = "Detects IOCs associated with APT SILENCE"
        author = "APTtrail Automated Collection"
        apt_group = "SILENCE"
        reference = "https://otx.alienvault.com/pulse/5d5d6e09e5809a8cb83bcea1"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "1bmank\.ru" ascii wide nocase
        $domain1 = "1m-lombard\.ru" ascii wide nocase
        $domain2 = "1m6ank\.ru" ascii wide nocase
        $domain3 = "1mbabk\.ru" ascii wide nocase
        $domain4 = "1mbakn\.ru" ascii wide nocase
        $domain5 = "1mbamk\.ru" ascii wide nocase
        $domain6 = "1mbanc\.ru" ascii wide nocase
        $domain7 = "1mbanck\.ru" ascii wide nocase
        $domain8 = "1mbang\.ru" ascii wide nocase
        $domain9 = "1mbanj\.ru" ascii wide nocase
        $domain10 = "1mbank\.biz" ascii wide nocase
        $domain11 = "1mbank\.info" ascii wide nocase
        $domain12 = "1mbank\.me" ascii wide nocase
        $domain13 = "1mbank\.net" ascii wide nocase
        $domain14 = "1mbank\.online" ascii wide nocase
        $domain15 = "1mbank\.su" ascii wide nocase
        $domain16 = "1mbankru\.ru" ascii wide nocase
        $domain17 = "1mbanl\.ru" ascii wide nocase
        $domain18 = "1mbnak\.ru" ascii wide nocase
        $domain19 = "1mbonk\.ru" ascii wide nocase
        $domain20 = "1mbsnk\.ru" ascii wide nocase
        $domain21 = "1mbunk\.ru" ascii wide nocase
        $domain22 = "1mcredit\.ru" ascii wide nocase
        $domain23 = "1mliked\.ru" ascii wide nocase
        $domain24 = "1mnank\.ru" ascii wide nocase
        $domain25 = "1mvank\.ru" ascii wide nocase
        $domain26 = "1mvklad\.ru" ascii wide nocase
        $domain27 = "1nnbank\.ru" ascii wide nocase
        $domain28 = "abp\.ru" ascii wide nocase
        $domain29 = "bankrebres\.ru" ascii wide nocase
        $domain30 = "basch\.eu" ascii wide nocase
        $domain31 = "cardisprom\.ru" ascii wide nocase
        $domain32 = "counterstat\.club" ascii wide nocase
        $domain33 = "counterstat\.pw" ascii wide nocase
        $domain34 = "fpbank\.ru" ascii wide nocase
        $domain35 = "itablex\.com" ascii wide nocase
        $domain36 = "maybank\.ru" ascii wide nocase
        $domain37 = "mobilecommerzbank\.com" ascii wide nocase
        $domain38 = "morefin\.ru" ascii wide nocase
        $domain39 = "odinmbank\.ru" ascii wide nocase
        $domain40 = "onembank\.ru" ascii wide nocase
        $domain41 = "pharmk\.group" ascii wide nocase
        $domain42 = "xn--1---7cdbdjx3ajbffshlvpuz\.xn--p1ai" ascii wide nocase
        $domain43 = "xn--1--8kcadhu0aibfergltoty\.xn--p1ai" ascii wide nocase
        $domain44 = "xn--1-8sbc1bhi\.xn--p1ai" ascii wide nocase
        $domain45 = "xn--1-8sbydbel6b\.xn--p1ai" ascii wide nocase
        $domain46 = "xn--80absjpcg\.com" ascii wide nocase
        $domain47 = "zaometallniva\.ru" ascii wide nocase
        $ip48 = "185.20.187.89" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SILENCERLION
{
    meta:
        description = "Detects IOCs associated with APT SILENCERLION"
        author = "APTtrail Automated Collection"
        apt_group = "SILENCERLION"
        reference = "https://mp.weixin.qq.com/s/UlTX4M8SzwhjI74tFKg_YA"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "cdn\.dosya\.web\.tr" ascii wide nocase
        $domain1 = "ludo\.ezyro\.com" ascii wide nocase
        $domain2 = "samsung\.apps\.linkpc\.net" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_SILENTLYNX
{
    meta:
        description = "Detects IOCs associated with APT SILENTLYNX"
        author = "APTtrail Automated Collection"
        apt_group = "SILENTLYNX"
        aliases = "shadowsilk"
        reference = "https://app.validin.com/detail?find=64.7.198.66&type=ip4&ref_id=55f2c681bec#tab=resolutions"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "accessibleneats\.com" ascii wide nocase
        $domain1 = "accttechllc\.com" ascii wide nocase
        $domain2 = "adm-govuz\.com" ascii wide nocase
        $domain3 = "admin\.inboxsession\.info" ascii wide nocase
        $domain4 = "akcloud\.top" ascii wide nocase
        $domain5 = "akersolutoins\.com" ascii wide nocase
        $domain6 = "alandyh\.com" ascii wide nocase
        $domain7 = "albertinamachinery\.com" ascii wide nocase
        $domain8 = "alfhjdumnsulhuehs\.com" ascii wide nocase
        $domain9 = "allcloudindex\.com" ascii wide nocase
        $domain10 = "allocco-ar\.com" ascii wide nocase
        $domain11 = "alpine-hosokawa\.net" ascii wide nocase
        $domain12 = "altendorf-de\.com" ascii wide nocase
        $domain13 = "annons\.info" ascii wide nocase
        $domain14 = "arableaguenews\.com" ascii wide nocase
        $domain15 = "arpimportnl\.com" ascii wide nocase
        $domain16 = "asdnwakalet\.net" ascii wide nocase
        $domain17 = "asmtld\.com" ascii wide nocase
        $domain18 = "atomicenergylab\.com" ascii wide nocase
        $domain19 = "auth\.allcloudindex\.com" ascii wide nocase
        $domain20 = "authmailinbox\.com" ascii wide nocase
        $domain21 = "ax47tui83\.com" ascii wide nocase
        $domain22 = "aydemirtek\.com" ascii wide nocase
        $domain23 = "babblnipresses\.com" ascii wide nocase
        $domain24 = "bencoconstructionsllc\.com" ascii wide nocase
        $domain25 = "bestdomblog\.com" ascii wide nocase
        $domain26 = "bestmartsolutions\.com" ascii wide nocase
        $domain27 = "bestunif\.com" ascii wide nocase
        $domain28 = "bluemoono\.com" ascii wide nocase
        $domain29 = "brainytask\.tech" ascii wide nocase
        $domain30 = "brandxoffice\.com" ascii wide nocase
        $domain31 = "breuing-irco\.com" ascii wide nocase
        $domain32 = "brindley-medical\.com" ascii wide nocase
        $domain33 = "cae-gruope\.com" ascii wide nocase
        $domain34 = "cairo-day-trips\.com" ascii wide nocase
        $domain35 = "caprnatic\.com" ascii wide nocase
        $domain36 = "catchthestorms\.net" ascii wide nocase
        $domain37 = "check-connection\.org" ascii wide nocase
        $domain38 = "checkingsite\.org" ascii wide nocase
        $domain39 = "citylinefood\.com" ascii wide nocase
        $domain40 = "cm-elevatori\.com" ascii wide nocase
        $domain41 = "cmcrushermachine\.com" ascii wide nocase
        $domain42 = "colombaogrobg\.com" ascii wide nocase
        $domain43 = "consultafacildoc\.com" ascii wide nocase
        $domain44 = "consultasfacildoc\.com" ascii wide nocase
        $domain45 = "converting-system\.com" ascii wide nocase
        $domain46 = "csiwoffshore\.com" ascii wide nocase
        $domain47 = "datosdecuit\.com" ascii wide nocase
        $domain48 = "dl-keepass\.info" ascii wide nocase
        $domain49 = "dmgrnori\.com" ascii wide nocase
        $ip50 = "141.98.82.198" ascii wide
        $ip51 = "185.122.171.22" ascii wide
        $ip52 = "193.124.203.226" ascii wide
        $ip53 = "81.19.136.241" ascii wide
        $ip54 = "85.209.128.171" ascii wide
        $ip55 = "85.209.128.171" ascii wide
        $ip56 = "85.209.128.171" ascii wide
        $ip57 = "85.209.128.171" ascii wide
        $ip58 = "88.214.26.37" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SIMBAA
{
    meta:
        description = "Detects IOCs associated with APT SIMBAA"
        author = "APTtrail Automated Collection"
        apt_group = "SIMBAA"
        reference = "https://www.malcrawler.com/team-simbaa-targets-indian-government-using-united-nations-military-observers-themed-malware-nicked-named-keeoil/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "firebasebox\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_SNOWMAN
{
    meta:
        description = "Detects IOCs associated with APT SNOWMAN"
        author = "APTtrail Automated Collection"
        apt_group = "SNOWMAN"
        reference = "https://www.fireeye.com/blog/threat-research/2014/02/operation-snowman-deputydog-actor-compromises-us-veterans-of-foreign-wars-website.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "ali\.blankchair\.com" ascii wide nocase
        $domain1 = "book\.flnet\.org" ascii wide nocase
        $domain2 = "cht\.blankchair\.com" ascii wide nocase
        $domain3 = "dll\.freshdns\.org" ascii wide nocase
        $domain4 = "icybin\.flnet\.org" ascii wide nocase
        $domain5 = "info\.flnet\.org" ascii wide nocase
        $domain6 = "me\.scieron\.com" ascii wide nocase
        $domain7 = "rt\.blankchair\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SOBAKEN
{
    meta:
        description = "Detects IOCs associated with APT SOBAKEN"
        author = "APTtrail Automated Collection"
        apt_group = "SOBAKEN"
        aliases = "SPECTR, Vermin, firmachagent"
        reference = "https://cert.gov.ua/article/37815 (Ukrainian)"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "aeroua\.online" ascii wide nocase
        $domain1 = "akamaicdn\.ru" ascii wide nocase
        $domain2 = "akamainet021\.info" ascii wide nocase
        $domain3 = "akamainet022\.info" ascii wide nocase
        $domain4 = "akamainet023\.info" ascii wide nocase
        $domain5 = "akamainet024\.info" ascii wide nocase
        $domain6 = "akamainet066\.info" ascii wide nocase
        $domain7 = "akamainet067\.info" ascii wide nocase
        $domain8 = "aviasys\.somee\.com" ascii wide nocase
        $domain9 = "cdnakamai\.ru" ascii wide nocase
        $domain10 = "code\.ukraero\.space" ascii wide nocase
        $domain11 = "firma\.ukraero\.space" ascii wide nocase
        $domain12 = "getmod\.host" ascii wide nocase
        $domain13 = "gw\.telegrarn\.fun" ascii wide nocase
        $domain14 = "mail\.ukraero\.space" ascii wide nocase
        $domain15 = "mailukr\.net" ascii wide nocase
        $domain16 = "meteolink\.host" ascii wide nocase
        $domain17 = "netbin\.host" ascii wide nocase
        $domain18 = "notifymail\.ru" ascii wide nocase
        $domain19 = "prozorro\.online" ascii wide nocase
        $domain20 = "stormpredictor\.host" ascii wide nocase
        $domain21 = "syncapp\.host" ascii wide nocase
        $domain22 = "tech-adobe\.dyndns\.biz" ascii wide nocase
        $domain23 = "telegrarn\.fun" ascii wide nocase
        $domain24 = "ukr\.somee\.com" ascii wide nocase
        $domain25 = "ukraero\.space" ascii wide nocase
        $domain26 = "windowsupdate\.kiev\.ua" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SOFACY
{
    meta:
        description = "Detects IOCs associated with APT SOFACY"
        author = "APTtrail Automated Collection"
        apt_group = "SOFACY"
        aliases = "KTA007, SNAKEMACKEREL, STRONTIUM"
        reference = "http://permalink.gmane.org/gmane.comp.security.ids.snort.emerging-sigs/22170"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "000000027\.xyz" ascii wide nocase
        $domain1 = "0x4fc271\.tk" ascii wide nocase
        $domain2 = "0xf4a5\.tk" ascii wide nocase
        $domain3 = "0xf4a54cf56\.tk" ascii wide nocase
        $domain4 = "1000018\.xyz" ascii wide nocase
        $domain5 = "1000020\.xyz" ascii wide nocase
        $domain6 = "100plusapps\.com" ascii wide nocase
        $domain7 = "1221\.site" ascii wide nocase
        $domain8 = "15052021\.space" ascii wide nocase
        $domain9 = "150520212\.space" ascii wide nocase
        $domain10 = "150520213\.space" ascii wide nocase
        $domain11 = "1681683130\.website" ascii wide nocase
        $domain12 = "16868138130\.space" ascii wide nocase
        $domain13 = "1833\.site" ascii wide nocase
        $domain14 = "1oo7\.net" ascii wide nocase
        $domain15 = "200200\.duckdns\.org" ascii wide nocase
        $domain16 = "2055\.site" ascii wide nocase
        $domain17 = "2215\.site" ascii wide nocase
        $domain18 = "29572459487545-4543543-543534255-454-35432524-5243523-234543\.xyz" ascii wide nocase
        $domain19 = "2f9348243249382479234343284324023432748892349702394023\.xyz" ascii wide nocase
        $domain20 = "32689657\.xyz" ascii wide nocase
        $domain21 = "32689658\.xyz" ascii wide nocase
        $domain22 = "32689659\.xyz" ascii wide nocase
        $domain23 = "33655990\.cyou" ascii wide nocase
        $domain24 = "34564414564\.com" ascii wide nocase
        $domain25 = "357\.duckdns\.org" ascii wide nocase
        $domain26 = "365msoffice\.com" ascii wide nocase
        $domain27 = "47e811dbe2ed0ea8d506af94c1bb7d4c\.serveo\.net" ascii wide nocase
        $domain28 = "4895458025-4545445-222435-9635794543-3242314342-234123423728\.space" ascii wide nocase
        $domain29 = "512521525-5245451515-985978774-2341235146436\.xyz" ascii wide nocase
        $domain30 = "546874\.tk" ascii wide nocase
        $domain31 = "5thelementq8\.com" ascii wide nocase
        $domain32 = "645547657668787\.com" ascii wide nocase
        $domain33 = "6c7aa72bd5f1d30203b80596f926b2b7\.serveo\.net" ascii wide nocase
        $domain34 = "73ce1aae8a9ba738b91040232524f51a\.serveo\.net" ascii wide nocase
        $domain35 = "78cc700b31dcd7c7f25fd7b0372259e3\.serveo\.net" ascii wide nocase
        $domain36 = "7daysinabudhabi\.org" ascii wide nocase
        $domain37 = "90update\.com" ascii wide nocase
        $domain38 = "92ace7e653e9c32d2af9700592cc96ea\.serveo\.net" ascii wide nocase
        $domain39 = "9348243249382479234343284324023432748892349702394023\.xyz" ascii wide nocase
        $domain40 = "9832473219412342343423243242364-34939246823743287468793247237\.site" ascii wide nocase
        $domain41 = "99996665550\.fun" ascii wide nocase
        $domain42 = "99kg\.site" ascii wide nocase
        $domain43 = "9b5uja\.am\.files\.1drv\.com" ascii wide nocase
        $domain44 = "aa\.69\.mu" ascii wide nocase
        $domain45 = "aadexpo2014\.co\.za" ascii wide nocase
        $domain46 = "abbott-export\.com" ascii wide nocase
        $domain47 = "academl\.com" ascii wide nocase
        $domain48 = "acccountverify\.com" ascii wide nocase
        $domain49 = "accesd-de-desjardins\.com" ascii wide nocase
        $ip50 = "101.255.119.42" ascii wide
        $ip51 = "109.169.15.73" ascii wide
        $ip52 = "113.160.234.229" ascii wide
        $ip53 = "128.199.199.187" ascii wide
        $ip54 = "144.126.202.227" ascii wide
        $ip55 = "145.249.106.198" ascii wide
        $ip56 = "148.252.42.42" ascii wide
        $ip57 = "163.172.67.233" ascii wide
        $ip58 = "167.114.153.55" ascii wide
        $ip59 = "168.205.200.55" ascii wide
        $ip60 = "172.114.170.18" ascii wide
        $ip61 = "172.114.170.18" ascii wide
        $ip62 = "174.53.242.108" ascii wide
        $ip63 = "178.32.251.98" ascii wide
        $ip64 = "18.157.68.73" ascii wide
        $ip65 = "18.192.93.86" ascii wide
        $ip66 = "18.197.239.109" ascii wide
        $ip67 = "181.209.99.204" ascii wide
        $ip68 = "184.95.51.172" ascii wide
        $ip69 = "185.132.17.160" ascii wide
        $ip70 = "185.141.63.103" ascii wide
        $ip71 = "185.236.203.53" ascii wide
        $ip72 = "193.70.80.214" ascii wide
        $ip73 = "194.126.178.8" ascii wide
        $ip74 = "194.126.178.8" ascii wide
        $ip75 = "202.55.80.225" ascii wide
        $ip76 = "203.161.50.145" ascii wide
        $ip77 = "203.161.50.145" ascii wide
        $ip78 = "203.161.50.145" ascii wide
        $ip79 = "213.32.252.221" ascii wide
        $url80 = "/software-protection/app\.php" ascii wide nocase
        $url81 = "/ControllerReset/view/register/comid/sid\.php" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_SPACEPIRATES
{
    meta:
        description = "Detects IOCs associated with APT SPACEPIRATES"
        author = "APTtrail Automated Collection"
        apt_group = "SPACEPIRATES"
        reference = "https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/space-pirates-tools-and-connections/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "0077\.x24hr\.com" ascii wide nocase
        $domain1 = "alex\.dnset\.com" ascii wide nocase
        $domain2 = "amazon-corp\.wikaba\.com" ascii wide nocase
        $domain3 = "api\.microft\.dynssl\.com" ascii wide nocase
        $domain4 = "app\.hostareas\.com" ascii wide nocase
        $domain5 = "apple-corp\.changeip\.org" ascii wide nocase
        $domain6 = "as\.amazon-corp\.wikaba\.com" ascii wide nocase
        $domain7 = "asd\.powergame\.0077\.x24hr\.com" ascii wide nocase
        $domain8 = "bamo\.ocry\.com" ascii wide nocase
        $domain9 = "cdnsvc\.microft\.dynssl\.com" ascii wide nocase
        $domain10 = "chdsjjkrazomg\.dhcp\.biz" ascii wide nocase
        $domain11 = "comein\.journal\.itsaol\.com" ascii wide nocase
        $domain12 = "community\.reportsearch\.dynamic-dns\.net" ascii wide nocase
        $domain13 = "dnsinfo\.microft\.dynssl\.com" ascii wide nocase
        $domain14 = "docs\.microft\.dynssl\.com" ascii wide nocase
        $domain15 = "edge\.microft\.dynssl\.com" ascii wide nocase
        $domain16 = "elienceso\.kozow\.com" ascii wide nocase
        $domain17 = "erdcserver\.microft\.dynssl\.com" ascii wide nocase
        $domain18 = "eset\.zzux\.com" ascii wide nocase
        $domain19 = "exowa\.microft\.dynssl\.com" ascii wide nocase
        $domain20 = "fgjhkergvlimdfg2\.wikaba\.com" ascii wide nocase
        $domain21 = "fileserverrt\.reportsearch\.dynamic-dns\.net" ascii wide nocase
        $domain22 = "flashplayeractivex\.info" ascii wide nocase
        $domain23 = "freewula\.strangled\.net" ascii wide nocase
        $domain24 = "fssprus\.dns04\.com" ascii wide nocase
        $domain25 = "ftp\.microft\.dynssl\.com" ascii wide nocase
        $domain26 = "gamepoer7\.com" ascii wide nocase
        $domain27 = "gigabitdate\.com" ascii wide nocase
        $domain28 = "goon\.oldvideo\.longmusic\.com" ascii wide nocase
        $domain29 = "journal\.itsaol\.com" ascii wide nocase
        $domain30 = "js\.journal\.itsaol\.com" ascii wide nocase
        $domain31 = "lck\.gigabitdate\.com" ascii wide nocase
        $domain32 = "lib\.hostareas\.com" ascii wide nocase
        $domain33 = "loge\.otzo\.com" ascii wide nocase
        $domain34 = "mail\.playdr2\.com" ascii wide nocase
        $domain35 = "mcafee-update\.com" ascii wide nocase
        $domain36 = "miche\.justdied\.com" ascii wide nocase
        $domain37 = "micro\.dns04\.com" ascii wide nocase
        $domain38 = "microft\.dynssl\.com" ascii wide nocase
        $domain39 = "mktoon\.ftp1\.biz" ascii wide nocase
        $domain40 = "news\.flashplayeractivex\.info" ascii wide nocase
        $domain41 = "noon\.dns04\.com" ascii wide nocase
        $domain42 = "ns2\.gamepoer7\.com" ascii wide nocase
        $domain43 = "ns9\.mcafee-update\.com" ascii wide nocase
        $domain44 = "oldvideo\.longmusic\.com" ascii wide nocase
        $domain45 = "omgod\.org" ascii wide nocase
        $domain46 = "playdr2\.com" ascii wide nocase
        $domain47 = "pop\.playdr2\.com" ascii wide nocase
        $domain48 = "powergame\.0077\.x24hr\.com" ascii wide nocase
        $domain49 = "q34ewrd\.youdontcare\.com" ascii wide nocase
        $ip50 = "101.37.16.125" ascii wide
        $ip51 = "103.101.178.152" ascii wide
        $ip52 = "120.78.127.189" ascii wide
        $ip53 = "121.89.210.144" ascii wide
        $ip54 = "154.211.161.161" ascii wide
        $ip55 = "154.85.48.108" ascii wide
        $ip56 = "170.178.190.213" ascii wide
        $ip57 = "192.225.226.123" ascii wide
        $ip58 = "192.225.226.217" ascii wide
        $ip59 = "192.225.226.218" ascii wide
        $ip60 = "207.148.121.88" ascii wide
        $ip61 = "45.77.16.91" ascii wide
        $ip62 = "47.108.89.169" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_STEALTHFALCON
{
    meta:
        description = "Detects IOCs associated with APT STEALTHFALCON"
        author = "APTtrail Automated Collection"
        apt_group = "STEALTHFALCON"
        reference = "https://citizenlab.ca/2016/05/stealth-falcon/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "adhostingcache\.com" ascii wide nocase
        $domain1 = "adlinkmetric\.com" ascii wide nocase
        $domain2 = "adlinkmetrics\.com" ascii wide nocase
        $domain3 = "adobereaderupdater\.com" ascii wide nocase
        $domain4 = "airlineadverts\.com" ascii wide nocase
        $domain5 = "akamai-host-network\.com" ascii wide nocase
        $domain6 = "akamai-hosting-network\.com" ascii wide nocase
        $domain7 = "akamaicachecdn\.com" ascii wide nocase
        $domain8 = "akamaicloud\.net" ascii wide nocase
        $domain9 = "akamaicss\.com" ascii wide nocase
        $domain10 = "akamaihostcdn\.net" ascii wide nocase
        $domain11 = "akamaiwebcache\.com" ascii wide nocase
        $domain12 = "appleimagecache\.com" ascii wide nocase
        $domain13 = "bestairlinepricetags\.com" ascii wide nocase
        $domain14 = "burst-media\.com" ascii wide nocase
        $domain15 = "cachecontent\.com" ascii wide nocase
        $domain16 = "cdn-logichosting\.com" ascii wide nocase
        $domain17 = "cdnimagescache\.com" ascii wide nocase
        $domain18 = "chromeupdater\.com" ascii wide nocase
        $domain19 = "clickstatistic\.com" ascii wide nocase
        $domain20 = "cloudburstcdn\.net" ascii wide nocase
        $domain21 = "cloudburstercdn\.net" ascii wide nocase
        $domain22 = "cloudimagecdn\.com" ascii wide nocase
        $domain23 = "cloudimagehosters\.com" ascii wide nocase
        $domain24 = "contenthosts\.com" ascii wide nocase
        $domain25 = "contenthosts\.net" ascii wide nocase
        $domain26 = "cyclingonlineshop\.com" ascii wide nocase
        $domain27 = "dnsclienthelper\.com" ascii wide nocase
        $domain28 = "dnsclientresolver\.com" ascii wide nocase
        $domain29 = "domainimagehost\.com" ascii wide nocase
        $domain30 = "dotnetupdatechecker\.com" ascii wide nocase
        $domain31 = "dotnetupdates\.com" ascii wide nocase
        $domain32 = "downloadessays\.net" ascii wide nocase
        $domain33 = "dropboxsyncservice\.com" ascii wide nocase
        $domain34 = "edgecacheimagehosting\.com" ascii wide nocase
        $domain35 = "electricalweb\.org" ascii wide nocase
        $domain36 = "fastfilebackup\.com" ascii wide nocase
        $domain37 = "fasttravelclearance\.com" ascii wide nocase
        $domain38 = "flashplayersupdates\.com" ascii wide nocase
        $domain39 = "flashplayerupdater\.com" ascii wide nocase
        $domain40 = "footballtimes\.info" ascii wide nocase
        $domain41 = "healthherofit\.com" ascii wide nocase
        $domain42 = "iesafebrowsingcache\.com" ascii wide nocase
        $domain43 = "iesaferbrowsingcache\.com" ascii wide nocase
        $domain44 = "incapsulawebcache\.com" ascii wide nocase
        $domain45 = "javaupdatecache\.com" ascii wide nocase
        $domain46 = "javaupdatersvc\.com" ascii wide nocase
        $domain47 = "javaupdatescache\.com" ascii wide nocase
        $domain48 = "javaupdatesvc\.com" ascii wide nocase
        $domain49 = "limelightimagecache\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_STOLENPENCIL
{
    meta:
        description = "Detects IOCs associated with APT STOLENPENCIL"
        author = "APTtrail Automated Collection"
        apt_group = "STOLENPENCIL"
        aliases = "babyshark, kimjongrat"
        reference = "https://asert.arbornetworks.com/stolen-pencil-campaign-targets-academia/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "bizsonet\.ayar\.biz" ascii wide nocase
        $domain1 = "bizsonet\.com" ascii wide nocase
        $domain2 = "client-message\.com" ascii wide nocase
        $domain3 = "client-screenfonts\.com" ascii wide nocase
        $domain4 = "docsdriver\.com" ascii wide nocase
        $domain5 = "grsvps\.com" ascii wide nocase
        $domain6 = "itservicedesk\.org" ascii wide nocase
        $domain7 = "pqexport\.com" ascii wide nocase
        $domain8 = "scaurri\.com" ascii wide nocase
        $domain9 = "secozco\.com" ascii wide nocase
        $domain10 = "sharedriver\.pw" ascii wide nocase
        $domain11 = "sharedriver\.us" ascii wide nocase
        $domain12 = "tempdomain8899\.com" ascii wide nocase
        $domain13 = "world-paper\.net" ascii wide nocase
        $domain14 = "zwfaxi\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_STONEDRILL
{
    meta:
        description = "Detects IOCs associated with APT STONEDRILL"
        author = "APTtrail Automated Collection"
        apt_group = "STONEDRILL"
        reference = "https://www.symantec.com/security_response/writeup.jsp?docid=2017-030708-4403-99&tabid=2"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "eservice\.com" ascii wide nocase
        $domain1 = "securityupdated\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_STONEFLY
{
    meta:
        description = "Detects IOCs associated with APT STONEFLY"
        author = "APTtrail Automated Collection"
        apt_group = "STONEFLY"
        aliases = "apt-45, apt45, onyx sleet"
        reference = "https://otx.alienvault.com/pulse/626bba5ec3f783b80d69a882"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "bluedragon\.com" ascii wide nocase
        $domain1 = "cyancow\.com" ascii wide nocase
        $domain2 = "phpick\.com" ascii wide nocase
        $domain3 = "semiconductboard\.com" ascii wide nocase
        $domain4 = "tecnojournals\.com" ascii wide nocase
        $domain5 = "trollbydefault\.com" ascii wide nocase
        $ip6 = "216.120.201.112" ascii wide
        $ip7 = "51.81.168.157" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_STRONGPITY
{
    meta:
        description = "Detects IOCs associated with APT STRONGPITY"
        author = "APTtrail Automated Collection"
        apt_group = "STRONGPITY"
        aliases = "apt-c-41, promethium, strongpity"
        reference = "http://www.tgsoft.it/english/news_archivio_eng.asp?id=781"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "apn-state-upd2\.com" ascii wide nocase
        $domain1 = "app-mx3-delivery\.com" ascii wide nocase
        $domain2 = "applicationrepo\.com" ascii wide nocase
        $domain3 = "apt5-secure3-state\.com" ascii wide nocase
        $domain4 = "cdn12-web-security\.com" ascii wide nocase
        $domain5 = "cdn2-state-upd\.com" ascii wide nocase
        $domain6 = "cdn2-svr-state\.com" ascii wide nocase
        $domain7 = "cdn4-rxe3-map\.com" ascii wide nocase
        $domain8 = "cerulearc\.com" ascii wide nocase
        $domain9 = "dutchvideochatting\.com" ascii wide nocase
        $domain10 = "edicupd002\.com" ascii wide nocase
        $domain11 = "fairgowingo\.com" ascii wide nocase
        $domain12 = "fileaccesscontrol\.com" ascii wide nocase
        $domain13 = "filedocumentmanager\.com" ascii wide nocase
        $domain14 = "findingpcdrivers\.com" ascii wide nocase
        $domain15 = "ftp\.mynetenergy\.com" ascii wide nocase
        $domain16 = "hardwareoption\.com" ascii wide nocase
        $domain17 = "hierarchicalfiles\.com" ascii wide nocase
        $domain18 = "hostoperationsystems\.com" ascii wide nocase
        $domain19 = "hotpatches\.net" ascii wide nocase
        $domain20 = "hybirdcloudreportingsoftware\.com" ascii wide nocase
        $domain21 = "informationserviceslab\.com" ascii wide nocase
        $domain22 = "inodeapplicationserver\.com" ascii wide nocase
        $domain23 = "intagrefedcircuitchip\.com" ascii wide nocase
        $domain24 = "javaplugin-update\.com" ascii wide nocase
        $domain25 = "lurkingnet\.com" ascii wide nocase
        $domain26 = "mailtransfersagents\.com" ascii wide nocase
        $domain27 = "mentiononecommon\.com" ascii wide nocase
        $domain28 = "ms-cdn-88\.com" ascii wide nocase
        $domain29 = "ms-health-monitor\.com" ascii wide nocase
        $domain30 = "ms-sys-security\.com" ascii wide nocase
        $domain31 = "ms21-app3-upload\.com" ascii wide nocase
        $domain32 = "ms6-upload-serv3\.com" ascii wide nocase
        $domain33 = "mx-upd2-cdn-state\.com" ascii wide nocase
        $domain34 = "myrappid\.com" ascii wide nocase
        $domain35 = "mytoshba\.com" ascii wide nocase
        $domain36 = "networkmanagemersolutions\.com" ascii wide nocase
        $domain37 = "networksoftwaresegment\.com" ascii wide nocase
        $domain38 = "node1-cdn-network\.com" ascii wide nocase
        $domain39 = "oem-sec4-mx32\.com" ascii wide nocase
        $domain40 = "pinkturtle\.me" ascii wide nocase
        $domain41 = "protectapplication\.com" ascii wide nocase
        $domain42 = "pulmonyarea\.com" ascii wide nocase
        $domain43 = "ralrab\.com" ascii wide nocase
        $domain44 = "record-fords\.cerulearc\.com" ascii wide nocase
        $domain45 = "remoteaaddressconnect\.com" ascii wide nocase
        $domain46 = "repositoryupdating\.com" ascii wide nocase
        $domain47 = "requiredvision\.com" ascii wide nocase
        $domain48 = "resolutionplatform\.com" ascii wide nocase
        $domain49 = "selectednewfile\.com" ascii wide nocase
        $ip50 = "193.235.207.60" ascii wide
        $url51 = "/gui/ip-address/139\.59\.250\.183/relations" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_STUXNET
{
    meta:
        description = "Detects IOCs associated with APT STUXNET"
        author = "APTtrail Automated Collection"
        apt_group = "STUXNET"
        reference = "http://www.wired.com/images_blogs/threatlevel/2010/10/w32_stuxnet_dossier.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "mypremierfutbol\.com" ascii wide nocase
        $domain1 = "todaysfutbol\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_TA2101
{
    meta:
        description = "Detects IOCs associated with APT TA2101"
        author = "APTtrail Automated Collection"
        apt_group = "TA2101"
        reference = "https://www.proofpoint.com/us/threat-insight/post/ta2101-plays-government-imposter-distribute-malware-german-italian-and-us"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "conbase\.top" ascii wide nocase
        $domain1 = "uspsdelivery-service\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_TA240524
{
    meta:
        description = "Detects IOCs associated with APT TA240524"
        author = "APTtrail Automated Collection"
        apt_group = "TA240524"
        aliases = "ABCloader, ABCsync, Actor240524"
        reference = "https://nsfocusglobal.com/new-apt-group-actor240524-a-closer-look-at-its-cyber-tactics-against-azerbaijan-and-israel/"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "185.23.253.143" ascii wide

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_TA410
{
    meta:
        description = "Detects IOCs associated with APT TA410"
        author = "APTtrail Automated Collection"
        apt_group = "TA410"
        aliases = "FlowCloud, LookBack, LookingFrog"
        reference = "https://github.com/eset/malware-ioc/tree/master/ta410"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "a\.bigbluedc\.com" ascii wide nocase
        $domain1 = "asce\.email" ascii wide nocase
        $domain2 = "bigbluedc\.com" ascii wide nocase
        $domain3 = "cahe\.microsofts\.com" ascii wide nocase
        $domain4 = "daveengineer\.com" ascii wide nocase
        $domain5 = "dlaxpcmghd\.com" ascii wide nocase
        $domain6 = "energysemi\.com" ascii wide nocase
        $domain7 = "eset-sync\.com" ascii wide nocase
        $domain8 = "ffca\.caibi379\.com" ascii wide nocase
        $domain9 = "nsfwgo\.com" ascii wide nocase
        $domain10 = "powersafetraining\.net" ascii wide nocase
        $domain11 = "powersafetrainings\.org" ascii wide nocase
        $domain12 = "s\.eset-sync\.com" ascii wide nocase
        $domain13 = "smtp\.nsfwgo\.com" ascii wide nocase
        $domain14 = "translateupdate\.com" ascii wide nocase
        $domain15 = "update\.translateupdate\.com" ascii wide nocase
        $ip16 = "103.139.2.93" ascii wide
        $ip17 = "188.131.233.27" ascii wide
        $ip18 = "188.131.233.27" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TA416
{
    meta:
        description = "Detects IOCs associated with APT TA416"
        author = "APTtrail Automated Collection"
        apt_group = "TA416"
        reference = "https://otx.alienvault.com/pulse/5fbc0c5ec4bfeaa7f7956ff4"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "upespr\.com" ascii wide nocase
        $domain1 = "zyber-i\.com" ascii wide nocase
        $ip2 = "103.107.104.19" ascii wide
        $ip3 = "103.107.104.19" ascii wide
        $ip4 = "103.107.104.19" ascii wide
        $ip5 = "107.167.64.4" ascii wide
        $ip6 = "45.154.14.235" ascii wide
        $ip7 = "45.248.87.162" ascii wide
        $ip8 = "69.90.184.125" ascii wide
        $ip9 = "92.118.188.78" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TA428
{
    meta:
        description = "Detects IOCs associated with APT TA428"
        author = "APTtrail Automated Collection"
        apt_group = "TA428"
        aliases = "DNSep, ironhusky, nccTrojan"
        reference = "https://app.any.run/tasks/8937295d-ea36-4398-96bd-20e7f3b193cb/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "aircraft\.tsagagaar\.com" ascii wide nocase
        $domain1 = "aiwqi\.aurobindos\.com" ascii wide nocase
        $domain2 = "atlas\.golianbooks\.com" ascii wide nocase
        $domain3 = "atob\.kommesantor\.com" ascii wide nocase
        $domain4 = "aurobindos\.com" ascii wide nocase
        $domain5 = "beijingspring\.niccenter\.net" ascii wide nocase
        $domain6 = "bloomberg\.mefound\.com" ascii wide nocase
        $domain7 = "bloomberg\.ns02\.biz" ascii wide nocase
        $domain8 = "cniitiic\.com" ascii wide nocase
        $domain9 = "coms\.documentmeda\.com" ascii wide nocase
        $domain10 = "custom\.songuulcomiss\.com" ascii wide nocase
        $domain11 = "darknightcloud\.com" ascii wide nocase
        $domain12 = "defensysminck\.net" ascii wide nocase
        $domain13 = "dm\.golianbooks\.com" ascii wide nocase
        $domain14 = "doc\.redstrpela\.net" ascii wide nocase
        $domain15 = "documentmeda\.com" ascii wide nocase
        $domain16 = "dog\.darknightcloud\.com" ascii wide nocase
        $domain17 = "dotomater\.club" ascii wide nocase
        $domain18 = "ecustoms-mn\.com" ascii wide nocase
        $domain19 = "eye\.darknightcloud\.com" ascii wide nocase
        $domain20 = "f1news\.vzglagtime\.net" ascii wide nocase
        $domain21 = "fax\.internnetionfax\.com" ascii wide nocase
        $domain22 = "foudation\.sdelanasnou\.com" ascii wide nocase
        $domain23 = "freenow\.chickenkiller\.com" ascii wide nocase
        $domain24 = "fuji1\.aurobindos\.com" ascii wide nocase
        $domain25 = "gazar\.ecustoms-mn\.com" ascii wide nocase
        $domain26 = "go\.vegispaceshop\.org" ascii wide nocase
        $domain27 = "gogonews\.organiccrap\.com" ascii wide nocase
        $domain28 = "golianbooks\.com" ascii wide nocase
        $domain29 = "govi-altai\.ecustoms-mn\.com" ascii wide nocase
        $domain30 = "home\.sysclearprom\.space" ascii wide nocase
        $domain31 = "idfnv\.net" ascii wide nocase
        $domain32 = "info\.ntcprotek\.com" ascii wide nocase
        $domain33 = "internnetionfax\.com" ascii wide nocase
        $domain34 = "kino\.redstrpela\.net" ascii wide nocase
        $domain35 = "kommesantor\.com" ascii wide nocase
        $domain36 = "krseoul93\.idfnv\.net" ascii wide nocase
        $domain37 = "morgoclass\.com" ascii wide nocase
        $domain38 = "mtanews\.vzglagtime\.net" ascii wide nocase
        $domain39 = "news-click\.net" ascii wide nocase
        $domain40 = "news\.niiriip\.com" ascii wide nocase
        $domain41 = "news\.vzglagtime\.net" ascii wide nocase
        $domain42 = "nicblainfo\.net" ascii wide nocase
        $domain43 = "niigem\.olloo-news\.com" ascii wide nocase
        $domain44 = "niiriip\.com" ascii wide nocase
        $domain45 = "nmcustoms\.https443\.org" ascii wide nocase
        $domain46 = "nppnavigator\.net" ascii wide nocase
        $domain47 = "ns02\.ns02\.us" ascii wide nocase
        $domain48 = "ns28\.ntcprotek\.com" ascii wide nocase
        $domain49 = "ntcprotek\.com" ascii wide nocase
        $ip50 = "103.249.87.72" ascii wide
        $ip51 = "104.234.15.90" ascii wide
        $ip52 = "185.82.218.40" ascii wide
        $ip53 = "185.82.218.40" ascii wide
        $ip54 = "185.82.219.182" ascii wide
        $ip55 = "185.82.219.182" ascii wide
        $ip56 = "217.69.8.255" ascii wide
        $ip57 = "45.154.12.93" ascii wide
        $ip58 = "45.63.27.162" ascii wide
        $ip59 = "45.76.210.68" ascii wide
        $ip60 = "45.76.210.68" ascii wide
        $ip61 = "45.77.129.213" ascii wide
        $ip62 = "95.179.131.29" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TA555
{
    meta:
        description = "Detects IOCs associated with APT TA555"
        author = "APTtrail Automated Collection"
        apt_group = "TA555"
        reference = "http://www.hexed.in/2020/02/ta555-campaign-feb-2020.html"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "194.36.188.132" ascii wide

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_TA5918
{
    meta:
        description = "Detects IOCs associated with APT TA5918"
        author = "APTtrail Automated Collection"
        apt_group = "TA5918"
        aliases = "uat-5918, uat-7237"
        reference = "https://blog.talosintelligence.com/uat-5918-targets-critical-infra-in-taiwan/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "cvbbonwxtgvc3isfqfc52cwzja0kvuqd\.lambda-url\.ap-northeast-1\.on\.aws" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_TAG22
{
    meta:
        description = "Detects IOCs associated with APT TAG22"
        author = "APTtrail Automated Collection"
        apt_group = "TAG22"
        aliases = "tag-22"
        reference = "https://github.com/Insikt-Group/Research/blob/master/Chinese%20APT%20TAG-22%20Targets%20Asian%20Countries"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "microsoftd\.tk" ascii wide nocase
        $domain1 = "wikimedia\.vip" ascii wide nocase
        $domain2 = "windowshostnamehost\.club" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_TAG28
{
    meta:
        description = "Detects IOCs associated with APT TAG28"
        author = "APTtrail Automated Collection"
        apt_group = "TAG28"
        aliases = "UIDAI"
        reference = "https://otx.alienvault.com/pulse/614af64c63989af23d536083"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "admin\.samuelblog\.xyz" ascii wide nocase
        $domain1 = "date\.samuelblog\.info" ascii wide nocase
        $domain2 = "db1\.samuelblog\.me" ascii wide nocase
        $domain3 = "db1\.samuelblog\.site" ascii wide nocase
        $domain4 = "samuelblog\.info" ascii wide nocase
        $domain5 = "samuelblog\.me" ascii wide nocase
        $domain6 = "samuelblog\.site" ascii wide nocase
        $domain7 = "samuelblog\.website" ascii wide nocase
        $domain8 = "samuelblog\.xyz" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TAJMAHAL
{
    meta:
        description = "Detects IOCs associated with APT TAJMAHAL"
        author = "APTtrail Automated Collection"
        apt_group = "TAJMAHAL"
        reference = "https://otx.alienvault.com/pulse/5cad645554fab2031f8d0109"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "rahasn\.akamake\.net" ascii wide nocase
        $domain1 = "rahasn\.homewealth\.biz" ascii wide nocase
        $domain2 = "rahasn\.webhop\.org" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_TEALKURMA
{
    meta:
        description = "Detects IOCs associated with APT TEALKURMA"
        author = "APTtrail Automated Collection"
        apt_group = "TEALKURMA"
        aliases = "snappytcp"
        reference = "https://blog.strikeready.com/blog/pivoting-through-a-sea-of-indicators-to-spot-turtles/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "23be\.xtechsupport\.org" ascii wide nocase
        $domain1 = "ai-connector\.goldchekin\.com" ascii wide nocase
        $domain2 = "ai-connector\.splendor\.org" ascii wide nocase
        $domain3 = "ai-connector\.splendos\.org" ascii wide nocase
        $domain4 = "al-marsad\.co" ascii wide nocase
        $domain5 = "alarabiyaa\.online" ascii wide nocase
        $domain6 = "alhurra\.online" ascii wide nocase
        $domain7 = "anfturkce\.news" ascii wide nocase
        $domain8 = "aws\.systemctl\.network" ascii wide nocase
        $domain9 = "boord\.info" ascii wide nocase
        $domain10 = "caglayandergisi\.net" ascii wide nocase
        $domain11 = "cn\.sslname\.com" ascii wide nocase
        $domain12 = "dhcp\.systemctl\.network" ascii wide nocase
        $domain13 = "eth0\.secrsys\.net" ascii wide nocase
        $domain14 = "exp-al-marsad\.co" ascii wide nocase
        $domain15 = "forward\.boord\.info" ascii wide nocase
        $domain16 = "infohaber\.net" ascii wide nocase
        $domain17 = "lo0\.systemctl\.network" ascii wide nocase
        $domain18 = "loading-website\.net" ascii wide nocase
        $domain19 = "netssh\.net" ascii wide nocase
        $domain20 = "nmcbcd\.live" ascii wide nocase
        $domain21 = "nuceciwan\.news" ascii wide nocase
        $domain22 = "querryfiles\.com" ascii wide nocase
        $domain23 = "secrsys\.net" ascii wide nocase
        $domain24 = "serverssl\.net" ascii wide nocase
        $domain25 = "solhaber\.info" ascii wide nocase
        $domain26 = "solhaber\.news" ascii wide nocase
        $domain27 = "systemctl\.network" ascii wide nocase
        $domain28 = "ud\.ybcd\.tech" ascii wide nocase
        $domain29 = "update\.qnetau\.net" ascii wide nocase
        $domain30 = "upt\.mcsoft\.org" ascii wide nocase
        $domain31 = "xtechsupport\.org" ascii wide nocase
        $domain32 = "ybcd\.tech" ascii wide nocase
        $ip33 = "62.115.255.163" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TELEBOTS
{
    meta:
        description = "Detects IOCs associated with APT TELEBOTS"
        author = "APTtrail Automated Collection"
        apt_group = "TELEBOTS"
        reference = "https://www.welivesecurity.com/2018/10/11/new-telebots-backdoor-linking-industroyer-notpetya/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "esetsmart\.org" ascii wide nocase
        $domain1 = "um10eset\.net" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_TEMPPERISCOPE
{
    meta:
        description = "Detects IOCs associated with APT TEMPPERISCOPE"
        author = "APTtrail Automated Collection"
        apt_group = "TEMPPERISCOPE"
        reference = "https://www.fireeye.com/blog/threat-research/2018/07/chinese-espionage-group-targets-cambodia-ahead-of-elections.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "chemscalere\.com" ascii wide nocase
        $domain1 = "mlcdailynews\.com" ascii wide nocase
        $domain2 = "partyforumseasia\.com" ascii wide nocase
        $domain3 = "scsnewstoday\.com" ascii wide nocase
        $domain4 = "thyssenkrupp-marinesystems\.org" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TEMPTINGCEDAR
{
    meta:
        description = "Detects IOCs associated with APT TEMPTINGCEDAR"
        author = "APTtrail Automated Collection"
        apt_group = "TEMPTINGCEDAR"
        reference = "https://blog.avast.com/avast-tracks-down-tempting-cedar-spyware"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "arab-chat\.site" ascii wide nocase
        $domain1 = "arab-download\.com" ascii wide nocase
        $domain2 = "chat-messenger\.site" ascii wide nocase
        $domain3 = "chat-world\.site" ascii wide nocase
        $domain4 = "free-apps\.us" ascii wide nocase
        $domain5 = "gserv\.mobi" ascii wide nocase
        $domain6 = "kikstore\.net" ascii wide nocase
        $domain7 = "network-lab\.info" ascii wide nocase
        $domain8 = "onlineclub\.info" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TENGYUNSNAKE
{
    meta:
        description = "Detects IOCs associated with APT TENGYUNSNAKE"
        author = "APTtrail Automated Collection"
        apt_group = "TENGYUNSNAKE"
        aliases = "apt-c-61, apt-q-122"
        reference = "https://mp.weixin.qq.com/s/Jpw7TqyPzOy57RAZDQdlWA (Chinese)"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "a0w\.herokuapp\.com" ascii wide nocase
        $domain1 = "a0x\.herokuapp\.com" ascii wide nocase
        $domain2 = "en-db\.herokuapp\.com" ascii wide nocase
        $domain3 = "en-docs\.herokuapp\.com" ascii wide nocase
        $domain4 = "en-localhost\.herokuapp\.com" ascii wide nocase
        $domain5 = "en-office365updatescente\.herokuapp\.com" ascii wide nocase
        $domain6 = "fcdn\.pythonanywhere\.com" ascii wide nocase
        $domain7 = "il1\.000webhostapp\.com" ascii wide nocase
        $domain8 = "jl3\.000webhostapp\.com" ascii wide nocase
        $domain9 = "media\.randreports\.org" ascii wide nocase
        $domain10 = "o-s\.herokuapp\.com" ascii wide nocase
        $domain11 = "os\.herokuapp\.com" ascii wide nocase
        $domain12 = "p-v\.herokuapp\.com" ascii wide nocase
        $domain13 = "p92\.herokuapp\.com" ascii wide nocase
        $domain14 = "pn0\.herokuapp\.com" ascii wide nocase
        $domain15 = "ps9\.000webhostapp\.com" ascii wide nocase
        $domain16 = "sysupdate\.pythonanywhere\.com" ascii wide nocase
        $domain17 = "w0m\.herokuapp\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TIBET
{
    meta:
        description = "Detects IOCs associated with APT TIBET"
        author = "APTtrail Automated Collection"
        apt_group = "TIBET"
        reference = "https://citizenlab.ca/2019/09/poison-carp-tibetan-groups-targeted-with-1-click-mobile-exploits/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "1\.test\.3322\.org\.cn" ascii wide nocase
        $domain1 = "123ewqasdcxz\.xicp\.net" ascii wide nocase
        $domain2 = "2\.test\.3322\.org\.cn" ascii wide nocase
        $domain3 = "3\.test\.3322\.org\.cn" ascii wide nocase
        $domain4 = "4\.test\.3322\.org\.cn" ascii wide nocase
        $domain5 = "airjaldinet\.ml" ascii wide nocase
        $domain6 = "antmoving\.online" ascii wide nocase
        $domain7 = "beemail\.online" ascii wide nocase
        $domain8 = "bf\.mk" ascii wide nocase
        $domain9 = "browserservice\.zzux\.com" ascii wide nocase
        $domain10 = "client-user-id\.com" ascii wide nocase
        $domain11 = "cta-tibet\.com" ascii wide nocase
        $domain12 = "ctmail\.dns-dns\.com" ascii wide nocase
        $domain13 = "dalailama\.online" ascii wide nocase
        $domain14 = "designer\.dynamic-dns\.net" ascii wide nocase
        $domain15 = "energy-mail\.org" ascii wide nocase
        $domain16 = "getadobeflashdownloader\.proxydns\.com" ascii wide nocase
        $domain17 = "gmail\.isooncloud\.com" ascii wide nocase
        $domain18 = "gmailapp\.me" ascii wide nocase
        $domain19 = "hoop-america\.oicp\.net" ascii wide nocase
        $domain20 = "hotmal1\.com" ascii wide nocase
        $domain21 = "hy\.micrsofts\.com" ascii wide nocase
        $domain22 = "in-tibet\.net" ascii wide nocase
        $domain23 = "install\.ddns\.info" ascii wide nocase
        $domain24 = "ip\.micrsofts\.com" ascii wide nocase
        $domain25 = "izelense\.com" ascii wide nocase
        $domain26 = "loginwebmailnic\.dynssl\.com" ascii wide nocase
        $domain27 = "ly\.micorsofts\.net" ascii wide nocase
        $domain28 = "mail-tibet\.net" ascii wide nocase
        $domain29 = "mailanalysis\.services" ascii wide nocase
        $domain30 = "mailcontactanalysis\.online" ascii wide nocase
        $domain31 = "mailnotes\.online" ascii wide nocase
        $domain32 = "micorsofts\.net" ascii wide nocase
        $domain33 = "micrsofts\.com" ascii wide nocase
        $domain34 = "mon7am\.000webhostapp\.com" ascii wide nocase
        $domain35 = "mon7am\.tk" ascii wide nocase
        $domain36 = "msap\.services" ascii wide nocase
        $domain37 = "news\.cmitcsubs\.tk" ascii wide nocase
        $domain38 = "polarismail\.services" ascii wide nocase
        $domain39 = "rf\.mk" ascii wide nocase
        $domain40 = "root20system20macosxdriver\.serveusers\.com" ascii wide nocase
        $domain41 = "roots\.dynamic-dns\.net" ascii wide nocase
        $domain42 = "tibet-office\.com" ascii wide nocase
        $domain43 = "tibetoffice\.in" ascii wide nocase
        $domain44 = "ubntrooters\.serveuser\.com" ascii wide nocase
        $domain45 = "walkingnote\.online" ascii wide nocase
        $domain46 = "windows-report\.com" ascii wide nocase
        $domain47 = "xdx\.hotmal1\.com" ascii wide nocase
        $ip48 = "43.251.16.87" ascii wide
        $ip49 = "45.76.149.154" ascii wide
        $ip50 = "66.42.58.59" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TICK
{
    meta:
        description = "Detects IOCs associated with APT TICK"
        author = "APTtrail Automated Collection"
        apt_group = "TICK"
        reference = "https://blogs.jpcert.or.jp/ja/2019/02/tick-activity.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "amamihanahana\.com" ascii wide nocase
        $domain1 = "englandprevail\.com" ascii wide nocase
        $domain2 = "han-game\.com" ascii wide nocase
        $domain3 = "kot\.gogoblog\.net" ascii wide nocase
        $domain4 = "memsbay\.com" ascii wide nocase
        $domain5 = "menu\.han-game\.com" ascii wide nocase
        $domain6 = "menu\.rakutenline\.com" ascii wide nocase
        $domain7 = "menu\.sa-guard\.com" ascii wide nocase
        $domain8 = "mssql\.waterglue\.org" ascii wide nocase
        $domain9 = "oracle\.eneygylakes\.com" ascii wide nocase
        $domain10 = "poi\.cydisk\.net" ascii wide nocase
        $domain11 = "pre\.englandprevail\.com" ascii wide nocase
        $domain12 = "rakutenline\.com" ascii wide nocase
        $domain13 = "rbb\.gol-unkai4\.com" ascii wide nocase
        $domain14 = "rp\.thumbbay\.com" ascii wide nocase
        $domain15 = "sa-guard\.com" ascii wide nocase
        $domain16 = "slientship\.com" ascii wide nocase
        $domain17 = "travelasist\.com" ascii wide nocase
        $domain18 = "update\.saranmall\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TIDRONE
{
    meta:
        description = "Detects IOCs associated with APT TIDRONE"
        author = "APTtrail Automated Collection"
        apt_group = "TIDRONE"
        aliases = "clntend, cxclnt, tidrone"
        reference = "https://www.trendmicro.com/en_us/research/24/i/tidrone-targets-military-and-satellite-industries-in-taiwan.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "auto-update\.microsoftsvc\.com" ascii wide nocase
        $domain1 = "bestadll\.fghytr\.com" ascii wide nocase
        $domain2 = "client\.wns\.windowswns\.com" ascii wide nocase
        $domain3 = "eupractic\.s3\.ap-east-1\.amazonaws\.com" ascii wide nocase
        $domain4 = "fghytr\.com" ascii wide nocase
        $domain5 = "hp\.kt168\.org" ascii wide nocase
        $domain6 = "microsoftsvc\.com" ascii wide nocase
        $domain7 = "onmondayr\.s3\.ap-east-1\.amazonaws\.com" ascii wide nocase
        $domain8 = "server\.microsoftsvc\.com" ascii wide nocase
        $domain9 = "service\.symantecsecuritycloud\.com" ascii wide nocase
        $domain10 = "symantecsecuritycloud\.com" ascii wide nocase
        $domain11 = "time\.vmwaresync\.com" ascii wide nocase
        $domain12 = "totting\.s3\.ap-east-1\.amazonaws\.com" ascii wide nocase
        $domain13 = "tpckcapital\.top" ascii wide nocase
        $domain14 = "update\.microsoftsvc\.com" ascii wide nocase
        $domain15 = "upgrade\.microsoftsvc\.com" ascii wide nocase
        $domain16 = "uppaycn\.com" ascii wide nocase
        $domain17 = "vmwaresync\.com" ascii wide nocase
        $domain18 = "windowswns\.com" ascii wide nocase
        $domain19 = "wns\.windowswns\.com" ascii wide nocase
        $domain20 = "wot\.tpckcapital\.top" ascii wide nocase
        $ip21 = "154.23.184.30" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TINYSCOUTS
{
    meta:
        description = "Detects IOCs associated with APT TINYSCOUTS"
        author = "APTtrail Automated Collection"
        apt_group = "TINYSCOUTS"
        aliases = "oldgremlin, tinyfluff"
        reference = "https://app.any.run/tasks/f21e3a4f-b734-4285-96b4-d2f274e19413/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "a3c65c\.org" ascii wide nocase
        $domain1 = "broken-poetry-de86\.nscimupf\.workers\.dev" ascii wide nocase
        $domain2 = "calm-night-6067\.bhrcaoqf\.workers\.dev" ascii wide nocase
        $domain3 = "ccdn\.microsoftdocs\.workers\.dev" ascii wide nocase
        $domain4 = "curly-sound-d93e\.ygrhxogxiogc\.workers\.dev" ascii wide nocase
        $domain5 = "eccbc8\.com" ascii wide nocase
        $domain6 = "hello\.tyvbxdobr0\.workers\.dev" ascii wide nocase
        $domain7 = "ksdkpwpfrtyvbxdobr1\.tiyvbxdobr1\.workers\.dev" ascii wide nocase
        $domain8 = "ksdkpwprtyvbxdobr0\.tyvbxdobr0\.workers\.dev" ascii wide nocase
        $domain9 = "late-salad-2839\.yriqwzjskbbg\.workers\.dev" ascii wide nocase
        $domain10 = "mirfinance\.org" ascii wide nocase
        $domain11 = "noisy-cell-7d07\.poecdjusb\.workers\.dev" ascii wide nocase
        $domain12 = "ns1\.a3c65c\.org" ascii wide nocase
        $domain13 = "ns1\.eccbc8\.com" ascii wide nocase
        $domain14 = "ns2\.a3c65c\.org" ascii wide nocase
        $domain15 = "ns2\.eccbc8\.com" ascii wide nocase
        $domain16 = "ns3\.a3c65c\.org" ascii wide nocase
        $domain17 = "ns3\.eccbc8\.com" ascii wide nocase
        $domain18 = "ns4\.a3c65c\.org" ascii wide nocase
        $domain19 = "ns4\.eccbc8\.com" ascii wide nocase
        $domain20 = "odd-thunder-c853\.tkbizulvc\.workers\.dev" ascii wide nocase
        $domain21 = "old-mud-23cb\.tkbizulvc\.workers\.dev" ascii wide nocase
        $domain22 = "rbcholding\.press" ascii wide nocase
        $domain23 = "rough-grass-45e9\.poecdjusb\.workers\.dev" ascii wide nocase
        $domain24 = "wispy-fire-1da3\.nscimupf\.workers\.dev" ascii wide nocase
        $domain25 = "wispy-surf-fabd\.bhrcaoqf\.workers\.dev" ascii wide nocase
        $ip26 = "161.35.41.9" ascii wide
        $ip27 = "46.101.113.161" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TODDYCAT
{
    meta:
        description = "Detects IOCs associated with APT TODDYCAT"
        author = "APTtrail Automated Collection"
        apt_group = "TODDYCAT"
        reference = "https://research.checkpoint.com/2023/stayin-alive-targeted-attacks-against-telecoms-and-government-ministries-in-asia/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "ad\.fopingu\.com" ascii wide nocase
        $domain1 = "admit\.pkigoscorp\.com" ascii wide nocase
        $domain2 = "backend\.rtmcsync\.com" ascii wide nocase
        $domain3 = "cdn\.pkigoscorp\.com" ascii wide nocase
        $domain4 = "cert\.qform3d\.in" ascii wide nocase
        $domain5 = "certexvpn\.com" ascii wide nocase
        $domain6 = "cyberguard\.certexvpn\.com" ascii wide nocase
        $domain7 = "eaq\.machineaccountquota\.com" ascii wide nocase
        $domain8 = "eohsdnsaaojrhnqo\.windowshost\.us" ascii wide nocase
        $domain9 = "fopingu\.com" ascii wide nocase
        $domain10 = "gist\.gitbusercontent\.com" ascii wide nocase
        $domain11 = "git\.gitbusercontent\.com" ascii wide nocase
        $domain12 = "gitbusercontent\.com" ascii wide nocase
        $domain13 = "githubdd\.workers\.dev" ascii wide nocase
        $domain14 = "idp\.pkigoscorp\.com" ascii wide nocase
        $domain15 = "imap\.774b884034c450b\.com" ascii wide nocase
        $domain16 = "machineaccountquota\.com" ascii wide nocase
        $domain17 = "mfeagents\.workers\.dev" ascii wide nocase
        $domain18 = "ns01\.nayatel\.orinafz\.com" ascii wide nocase
        $domain19 = "pic\.rtmcsync\.com" ascii wide nocase
        $domain20 = "pkigoscorp\.com" ascii wide nocase
        $domain21 = "proxy\.rtmcsync\.com" ascii wide nocase
        $domain22 = "qaq2\.machineaccountquota\.com" ascii wide nocase
        $domain23 = "qform3d\.in" ascii wide nocase
        $domain24 = "raw\.gitbusercontent\.com" ascii wide nocase
        $domain25 = "rtmcsync\.com" ascii wide nocase
        $domain26 = "solitary-dawn-61af\.mfeagents\.workers\.dev" ascii wide nocase
        $domain27 = "sslvpn\.pkigoscorp\.com" ascii wide nocase
        $domain28 = "update\.certexvpn\.com" ascii wide nocase
        $ip29 = "139.180.145.121" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TORTOISESHELL
{
    meta:
        description = "Detects IOCs associated with APT TORTOISESHELL"
        author = "APTtrail Automated Collection"
        apt_group = "TORTOISESHELL"
        aliases = "crimson sandstorm, imperial kitten, ta456"
        reference = "https://blog.talosintelligence.com/2019/09/tortoiseshell-fake-veterans.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "1st-smtp2go\.email" ascii wide nocase
        $domain1 = "2nd-smtp2go\.email" ascii wide nocase
        $domain2 = "3rd-smtp2go\.email" ascii wide nocase
        $domain3 = "4th-smtp2go\.email" ascii wide nocase
        $domain4 = "accounts\.cam" ascii wide nocase
        $domain5 = "activesessions\.me" ascii wide nocase
        $domain6 = "adobes\.software" ascii wide nocase
        $domain7 = "alhds\.net" ascii wide nocase
        $domain8 = "apppure\.cf" ascii wide nocase
        $domain9 = "bahri\.site" ascii wide nocase
        $domain10 = "bbcnews\.email" ascii wide nocase
        $domain11 = "bitly\.cam" ascii wide nocase
        $domain12 = "biturl\.cx" ascii wide nocase
        $domain13 = "brdcst\.email" ascii wide nocase
        $domain14 = "careeronestop\.site" ascii wide nocase
        $domain15 = "cc-security-inc\.email" ascii wide nocase
        $domain16 = "ccsecurity-mail-inc\.email" ascii wide nocase
        $domain17 = "ccsecurity-mail-inc\.services" ascii wide nocase
        $domain18 = "citymyworkday\.com" ascii wide nocase
        $domain19 = "cityofberkeley\.support" ascii wide nocase
        $domain20 = "cnbcnews\.email" ascii wide nocase
        $domain21 = "cnnnews\.global" ascii wide nocase
        $domain22 = "codejquery-ui\.com" ascii wide nocase
        $domain23 = "com-account-challenge\.email" ascii wide nocase
        $domain24 = "com-signin-v2\.email" ascii wide nocase
        $domain25 = "comlogin\.online" ascii wide nocase
        $domain26 = "comlogin\.services" ascii wide nocase
        $domain27 = "copyleft\.today" ascii wide nocase
        $domain28 = "crisiswatchsupport\.shop" ascii wide nocase
        $domain29 = "datacatch\.xyz" ascii wide nocase
        $domain30 = "dayzim\.org" ascii wide nocase
        $domain31 = "dh135\.world" ascii wide nocase
        $domain32 = "dollrealdoll\.com" ascii wide nocase
        $domain33 = "dollrealdoll\.online" ascii wide nocase
        $domain34 = "entrust\.work" ascii wide nocase
        $domain35 = "erictrumpfundation\.com" ascii wide nocase
        $domain36 = "facebookservices\.gq" ascii wide nocase
        $domain37 = "fblogin\.me" ascii wide nocase
        $domain38 = "fileblade\.ga" ascii wide nocase
        $domain39 = "findcareersatusbofa\.com" ascii wide nocase
        $domain40 = "fiservcareers\.com" ascii wide nocase
        $domain41 = "goodreads\.rest" ascii wide nocase
        $domain42 = "googl\.club" ascii wide nocase
        $domain43 = "gropinggo\.com" ascii wide nocase
        $domain44 = "hex6mak5z98nubb9vpd6t36cydkncfci9im872qx6hjci2egx8irq3qyt9pj\.online" ascii wide nocase
        $domain45 = "hike\.studio" ascii wide nocase
        $domain46 = "hiremilitaryheroes\.com" ascii wide nocase
        $domain47 = "hosted-microsoft\.com" ascii wide nocase
        $domain48 = "iemail\.today" ascii wide nocase
        $domain49 = "incognito\.today" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TRANSPARENTTRIBE
{
    meta:
        description = "Detects IOCs associated with APT TRANSPARENTTRIBE"
        author = "APTtrail Automated Collection"
        apt_group = "TRANSPARENTTRIBE"
        aliases = "G0134, actionrat, apt36"
        reference = "http://blog.talosintelligence.com/2022/07/transparent-tribe-targets-education.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "01411\.club" ascii wide nocase
        $domain1 = "130t\.xyz" ascii wide nocase
        $domain2 = "1s1\.accesscam\.org" ascii wide nocase
        $domain3 = "2ndline\.cfd" ascii wide nocase
        $domain4 = "34667\.fun" ascii wide nocase
        $domain5 = "37-221-64-252\.cprapid\.com" ascii wide nocase
        $domain6 = "376zbaqsnigt\.com" ascii wide nocase
        $domain7 = "3a4p8gq8bojwn\.xyz" ascii wide nocase
        $domain8 = "414\.camdvr\.org" ascii wide nocase
        $domain9 = "415\.mywire\.org" ascii wide nocase
        $domain10 = "419\.theworkpc\.com" ascii wide nocase
        $domain11 = "43-228-125-28\.cprapid\.com" ascii wide nocase
        $domain12 = "5-135-125-106\.cinfuserver\.com" ascii wide nocase
        $domain13 = "56184\.fun" ascii wide nocase
        $domain14 = "5zbm0\.cfd" ascii wide nocase
        $domain15 = "66xq2\.top" ascii wide nocase
        $domain16 = "6jxbmkpe\.torontobotdns\.com" ascii wide nocase
        $domain17 = "76767\.icu" ascii wide nocase
        $domain18 = "78990\.fun" ascii wide nocase
        $domain19 = "7thcpcupdates\.info" ascii wide nocase
        $domain20 = "873013\.xyz" ascii wide nocase
        $domain21 = "88c\.34667\.fun" ascii wide nocase
        $domain22 = "89204\.fun" ascii wide nocase
        $domain23 = "8ln62\.cfd" ascii wide nocase
        $domain24 = "8thpaycomission\.cloud" ascii wide nocase
        $domain25 = "8tqxpf27\.torontobotdns\.com" ascii wide nocase
        $domain26 = "903\.78990\.fun" ascii wide nocase
        $domain27 = "9123\.89204\.fun" ascii wide nocase
        $domain28 = "9882aa1216\.autos" ascii wide nocase
        $domain29 = "999game\.website" ascii wide nocase
        $domain30 = "9gi02\.cfd" ascii wide nocase
        $domain31 = "9ydygorig3l7z\.xyz" ascii wide nocase
        $domain32 = "aa\.76767\.icu" ascii wide nocase
        $domain33 = "aadharpor\.xyz" ascii wide nocase
        $domain34 = "aaloochaat\.com" ascii wide nocase
        $domain35 = "aboutcase\.nl" ascii wide nocase
        $domain36 = "ac\.76767\.icu" ascii wide nocase
        $domain37 = "accinfo\.live" ascii wide nocase
        $domain38 = "account-recovery\.com" ascii wide nocase
        $domain39 = "account\.migration\.jkpolice\.gov\.in\.mgovcloud\.de" ascii wide nocase
        $domain40 = "accounts-migration\.mgovcloud\.de" ascii wide nocase
        $domain41 = "accounts\.mgovcloud\.de" ascii wide nocase
        $domain42 = "accounts\.mgovcloud\.in\.cloudshare\.digital" ascii wide nocase
        $domain43 = "accounts\.mgovcloud\.in\.indiagov\.support" ascii wide nocase
        $domain44 = "accounts\.mgovcloud\.in\.storagecloud\.download" ascii wide nocase
        $domain45 = "accounts\.mgovcloud\.in\.virtualeoffice\.cloud" ascii wide nocase
        $domain46 = "accountsinfo\.site" ascii wide nocase
        $domain47 = "acmarketsapp\.com" ascii wide nocase
        $domain48 = "ad\.caselist\.in" ascii wide nocase
        $domain49 = "ad2\.admart\.tv" ascii wide nocase
        $ip50 = "101.99.92.182" ascii wide
        $ip51 = "101.99.92.182" ascii wide
        $ip52 = "101.99.92.182" ascii wide
        $ip53 = "103.2.232.82" ascii wide
        $ip54 = "103.231.254.55" ascii wide
        $ip55 = "104.129.27.14" ascii wide
        $ip56 = "104.129.27.14" ascii wide
        $ip57 = "104.129.27.14" ascii wide
        $ip58 = "104.129.27.14" ascii wide
        $ip59 = "104.129.27.14" ascii wide
        $ip60 = "104.129.42.102" ascii wide
        $ip61 = "104.129.42.102" ascii wide
        $ip62 = "104.129.42.102" ascii wide
        $ip63 = "104.129.42.102" ascii wide
        $ip64 = "104.129.42.102" ascii wide
        $ip65 = "104.144.198.105" ascii wide
        $ip66 = "104.144.198.105" ascii wide
        $ip67 = "104.144.198.105" ascii wide
        $ip68 = "104.144.198.105" ascii wide
        $ip69 = "104.144.198.105" ascii wide
        $ip70 = "104.168.48.210" ascii wide
        $ip71 = "104.168.48.210" ascii wide
        $ip72 = "104.168.48.210" ascii wide
        $ip73 = "104.168.48.210" ascii wide
        $ip74 = "104.168.48.210" ascii wide
        $ip75 = "104.223.106.8" ascii wide
        $ip76 = "104.227.97.53" ascii wide
        $ip77 = "107.150.18.166" ascii wide
        $ip78 = "107.172.76.170" ascii wide
        $ip79 = "107.173.204.38" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TRIANGULATION
{
    meta:
        description = "Detects IOCs associated with APT TRIANGULATION"
        author = "APTtrail Automated Collection"
        apt_group = "TRIANGULATION"
        reference = "https://securelist.com/operation-triangulation/109842/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "addatamarket\.net" ascii wide nocase
        $domain1 = "ans7tv\.net" ascii wide nocase
        $domain2 = "anstv\.net" ascii wide nocase
        $domain3 = "backuprabbit\.com" ascii wide nocase
        $domain4 = "businessvideonews\.com" ascii wide nocase
        $domain5 = "cloudsponcer\.com" ascii wide nocase
        $domain6 = "datamarketplace\.net" ascii wide nocase
        $domain7 = "growthtransport\.com" ascii wide nocase
        $domain8 = "mobilegamerstats\.com" ascii wide nocase
        $domain9 = "snoweeanalytics\.com" ascii wide nocase
        $domain10 = "tagclick-cdn\.com" ascii wide nocase
        $domain11 = "topographyupdates\.com" ascii wide nocase
        $domain12 = "unlimitedteacup\.com" ascii wide nocase
        $domain13 = "virtuallaughing\.com" ascii wide nocase
        $domain14 = "web-trackers\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TURLA
{
    meta:
        description = "Detects IOCs associated with APT TURLA"
        author = "APTtrail Automated Collection"
        apt_group = "TURLA"
        aliases = "apolloshadow, atg26, blue python"
        reference = "http://artemonsecurity.com/snake_whitepaper.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "61paris\.fr" ascii wide nocase
        $domain1 = "academyawards\.effers\.com" ascii wide nocase
        $domain2 = "accessdest\.strangled\.net" ascii wide nocase
        $domain3 = "adgf\.am" ascii wide nocase
        $domain4 = "adstore\.twilightparadox\.com" ascii wide nocase
        $domain5 = "agony\.compress\.to" ascii wide nocase
        $domain6 = "archive-articles\.linkpc\.net" ascii wide nocase
        $domain7 = "arctic-zone\.bbsindex\.com" ascii wide nocase
        $domain8 = "arinas\.tk" ascii wide nocase
        $domain9 = "auberdine\.etowns\.net" ascii wide nocase
        $domain10 = "av\.master\.dns-cloud\.net" ascii wide nocase
        $domain11 = "avmaster\.dns-cloud\.net" ascii wide nocase
        $domain12 = "badget\.ignorelist\.com" ascii wide nocase
        $domain13 = "baltdefcol\.webredirect\.org" ascii wide nocase
        $domain14 = "bedrost\.com" ascii wide nocase
        $domain15 = "bestfunc\.slyip\.net" ascii wide nocase
        $domain16 = "bigpen\.ga" ascii wide nocase
        $domain17 = "blackerror\.ignorelist\.com" ascii wide nocase
        $domain18 = "booking\.etowns\.org" ascii wide nocase
        $domain19 = "booking\.strangled\.net" ascii wide nocase
        $domain20 = "bookstore\.strangled\.net" ascii wide nocase
        $domain21 = "branter\.tk" ascii wide nocase
        $domain22 = "bronerg\.tk" ascii wide nocase
        $domain23 = "bug\.ignorelist\.com" ascii wide nocase
        $domain24 = "buy-new-car\.com" ascii wide nocase
        $domain25 = "caduff-sa\.chjeepcarlease\.com" ascii wide nocase
        $domain26 = "carleasingguru\.com" ascii wide nocase
        $domain27 = "cars-online\.zapto\.org" ascii wide nocase
        $domain28 = "celestyna\.tk" ascii wide nocase
        $domain29 = "ceremon\.2waky\.com" ascii wide nocase
        $domain30 = "cheapflights\.etowns\.net" ascii wide nocase
        $domain31 = "chinafood\.chickenkiller\.com" ascii wide nocase
        $domain32 = "chjeepcarlease\.com" ascii wide nocase
        $domain33 = "climbent\.mooo\.com" ascii wide nocase
        $domain34 = "codewizard\.ml" ascii wide nocase
        $domain35 = "coldriver\.strangled\.net" ascii wide nocase
        $domain36 = "communityeu\.xp3\.biz" ascii wide nocase
        $domain37 = "connectotels\.net" ascii wide nocase
        $domain38 = "crusider\.tk" ascii wide nocase
        $domain39 = "cyberazov\.com" ascii wide nocase
        $domain40 = "cyberazov\.tk" ascii wide nocase
        $domain41 = "d3hdbjtb1686tn\.cloudfront\.net" ascii wide nocase
        $domain42 = "da\.anythinktech\.com" ascii wide nocase
        $domain43 = "davilta\.tk" ascii wide nocase
        $domain44 = "dellservice\.publicvm\.com" ascii wide nocase
        $domain45 = "deme\.ml" ascii wide nocase
        $domain46 = "developarea\.mooo\.com" ascii wide nocase
        $domain47 = "dixito\.ml" ascii wide nocase
        $domain48 = "downtown\.crabdance\.com" ascii wide nocase
        $domain49 = "dropbox12\.com" ascii wide nocase
        $ip50 = "134.209.222.206" ascii wide
        $ip51 = "154.53.42.194" ascii wide
        $ip52 = "85.222.235.156" ascii wide
        $url53 = "/rss_0\.php" ascii wide nocase
        $url54 = "/config\.php" ascii wide nocase
        $url55 = "/rss_0\.php" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TVRMS
{
    meta:
        description = "Detects IOCs associated with APT TVRMS"
        author = "APTtrail Automated Collection"
        apt_group = "TVRMS"
        reference = "https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/08/01075510/TV_RMS_IoC_eng.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "barinoh9\.beget\.tech" ascii wide nocase
        $domain1 = "barinovbb\.had\.su" ascii wide nocase
        $domain2 = "buhuchetooo\.ru" ascii wide nocase
        $domain3 = "document-buh\.com" ascii wide nocase
        $domain4 = "micorsoft\.info" ascii wide nocase
        $domain5 = "mts2015stm\.myjino\.ru" ascii wide nocase
        $domain6 = "papaninili\.temp\.swtest\.ru" ascii wide nocase
        $domain7 = "rosatomgov\.ru" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_TWISTEDPANDA
{
    meta:
        description = "Detects IOCs associated with APT TWISTEDPANDA"
        author = "APTtrail Automated Collection"
        apt_group = "TWISTEDPANDA"
        reference = "https://otx.alienvault.com/pulse/628755c56b3dff4b4459107b"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "elliotterusties\.com" ascii wide nocase
        $domain1 = "img\.elliotterusties\.com" ascii wide nocase
        $domain2 = "microtreely\.com" ascii wide nocase
        $domain3 = "miniboxmail\.com" ascii wide nocase
        $domain4 = "minzdravros\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC1151
{
    meta:
        description = "Detects IOCs associated with APT UNC1151"
        author = "APTtrail Automated Collection"
        apt_group = "UNC1151"
        aliases = "Ghostwriter, HALFSHELL, Influence Activity"
        reference = "https://app.any.run/tasks/4d96f03e-317e-498d-a9d7-e2d719a70b5b/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "account-inbox\.online" ascii wide nocase
        $domain1 = "account-login\.top" ascii wide nocase
        $domain2 = "account-noreply\.space" ascii wide nocase
        $domain3 = "account-passports\.top" ascii wide nocase
        $domain4 = "account\.no-replay-notification\.ga" ascii wide nocase
        $domain5 = "accounts-facebook\.com-pastas\.top" ascii wide nocase
        $domain6 = "accounts-gmail\.com-check\.online" ascii wide nocase
        $domain7 = "accounts-gmail\.com-login\.space" ascii wide nocase
        $domain8 = "accounts-gmail\.com-pastas\.top" ascii wide nocase
        $domain9 = "accounts-group\.com-pastas\.top" ascii wide nocase
        $domain10 = "accounts-inbox\.ml" ascii wide nocase
        $domain11 = "accounts-login\.top" ascii wide nocase
        $domain12 = "accounts-mail\.site" ascii wide nocase
        $domain13 = "accounts-passport\.top" ascii wide nocase
        $domain14 = "accounts-secure\.com-firewall\.online" ascii wide nocase
        $domain15 = "accounts-support\.com-account\.website" ascii wide nocase
        $domain16 = "accounts-support\.net-account\.space" ascii wide nocase
        $domain17 = "accounts-telekom\.online" ascii wide nocase
        $domain18 = "accounts-ukr\.net-account\.space" ascii wide nocase
        $domain19 = "accounts-ukr\.net-verification\.online" ascii wide nocase
        $domain20 = "accounts-verification\.net-account\.space" ascii wide nocase
        $domain21 = "accounts-verify\.space" ascii wide nocase
        $domain22 = "accounts\.safe-mail\.space" ascii wide nocase
        $domain23 = "accounts\.secure-ua\.site" ascii wide nocase
        $domain24 = "accounts\.secure-ua\.website" ascii wide nocase
        $domain25 = "accounts\.verify-email\.space" ascii wide nocase
        $domain26 = "accountsverify\.top" ascii wide nocase
        $domain27 = "acount-pasport\.site" ascii wide nocase
        $domain28 = "acount-passport\.site" ascii wide nocase
        $domain29 = "acounts\.net-verification\.online" ascii wide nocase
        $domain30 = "aff-gos\.top" ascii wide nocase
        $domain31 = "ais-gos\.top" ascii wide nocase
        $domain32 = "akademia-mil\.space" ascii wide nocase
        $domain33 = "all-ukraine\.top" ascii wide nocase
        $domain34 = "alls-gos\.top" ascii wide nocase
        $domain35 = "americandeliriumsociety\.shop" ascii wide nocase
        $domain36 = "ams-gos\.top" ascii wide nocase
        $domain37 = "ao-opros\.top" ascii wide nocase
        $domain38 = "api\.passport-yandex\.ru" ascii wide nocase
        $domain39 = "aplikacje\.ron-mil\.space" ascii wide nocase
        $domain40 = "authorization-inbox\.site" ascii wide nocase
        $domain41 = "awa-opros\.top" ascii wide nocase
        $domain42 = "aws-opros\.top" ascii wide nocase
        $domain43 = "backstagemerch\.shop" ascii wide nocase
        $domain44 = "beez-gos\.top" ascii wide nocase
        $domain45 = "bel-oprosov\.top" ascii wide nocase
        $domain46 = "belaru-opros\.top" ascii wide nocase
        $domain47 = "bell-gos\.club" ascii wide nocase
        $domain48 = "besh-opros\.top" ascii wide nocase
        $domain49 = "bezpieczenstwo-danych\.website" ascii wide nocase
        $ip50 = "109.237.111.251" ascii wide
        $ip51 = "185.175.158.27" ascii wide
        $ip52 = "88.99.104.179" ascii wide
        $ip53 = "88.99.132.118" ascii wide
        $ip54 = "91.142.77.157" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC215
{
    meta:
        description = "Detects IOCs associated with APT UNC215"
        author = "APTtrail Automated Collection"
        apt_group = "UNC215"
        reference = "https://otx.alienvault.com/pulse/611232c3f696e5681585549a"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "103.59.144.183" ascii wide
        $ip1 = "103.79.78.48" ascii wide
        $ip2 = "139.59.81.253" ascii wide
        $ip3 = "141.164.52.232" ascii wide
        $ip4 = "159.89.168.83" ascii wide
        $ip5 = "34.65.151.250" ascii wide
        $ip6 = "47.75.49.32" ascii wide
        $ip7 = "85.204.74.143" ascii wide
        $ip8 = "89.35.178.105" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC2190
{
    meta:
        description = "Detects IOCs associated with APT UNC2190"
        author = "APTtrail Automated Collection"
        apt_group = "UNC2190"
        aliases = "54bb47h, sabbath"
        reference = "https://github.com/thetanz/ransomwatch/blob/main/docs/INDEX.md"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "4bb47h5qu4k7l4d7v5ix3i6ak6elysn3net4by4ihmvrhu7cvbskoqd\.onion" ascii wide nocase
        $domain1 = "54bb47h\.blog" ascii wide nocase
        $domain2 = "54bb47h5qu4k7l4d7v5ix3i6ak6elysn3net4by4ihmvrhu7cvbskoqd\.onion" ascii wide nocase
        $domain3 = "aequuira1aedeezais5i\.probes\.space" ascii wide nocase
        $domain4 = "aimee0febai5phoht2ti\.probes\.website" ascii wide nocase
        $domain5 = "cofeeloveers\.com" ascii wide nocase
        $domain6 = "datatransferdc\.com" ascii wide nocase
        $domain7 = "doratir\.com" ascii wide nocase
        $domain8 = "farhadl\.com" ascii wide nocase
        $domain9 = "frankir\.com" ascii wide nocase
        $domain10 = "gordonzon\.com" ascii wide nocase
        $domain11 = "greentuks\.com" ascii wide nocase
        $domain12 = "helpgoldr\.com" ascii wide nocase
        $domain13 = "jeithe7eijeefohch3qu\.probes\.site" ascii wide nocase
        $domain14 = "markettc\.biz" ascii wide nocase
        $domain15 = "probes\.site" ascii wide nocase
        $domain16 = "probes\.space" ascii wide nocase
        $domain17 = "probes\.website" ascii wide nocase
        $domain18 = "securingyourpc\.com" ascii wide nocase
        $domain19 = "security4themasses\.com" ascii wide nocase
        $domain20 = "tinysidney\.com" ascii wide nocase
        $ip21 = "45.141.84.182" ascii wide
        $ip22 = "45.146.166.24" ascii wide
        $ip23 = "45.147.230.137" ascii wide
        $ip24 = "45.147.230.221" ascii wide
        $ip25 = "45.79.55.129" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC2447
{
    meta:
        description = "Detects IOCs associated with APT UNC2447"
        author = "APTtrail Automated Collection"
        apt_group = "UNC2447"
        reference = "https://otx.alienvault.com/pulse/608c30d78049ae7a24b0b431"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "celomito\.com" ascii wide nocase
        $domain1 = "cosarm\.com" ascii wide nocase
        $domain2 = "feticost\.com" ascii wide nocase
        $domain3 = "portalcos\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC2452
{
    meta:
        description = "Detects IOCs associated with APT UNC2452"
        author = "APTtrail Automated Collection"
        apt_group = "UNC2452"
        aliases = "BlueBravo, NOBELIUM, SilverFish"
        reference = "https://blog.talosintelligence.com/2020/12/solarwinds-supplychain-coverage.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "1cloudserver\.com" ascii wide nocase
        $domain1 = "40ort\.750\.credit" ascii wide nocase
        $domain2 = "6a57jk2ba1d9keg15cbg\.appsync-api\.eu-west-1\.avsvmcloud\.com" ascii wide nocase
        $domain3 = "74d6b7b2\.app\.giftbox4u\.com" ascii wide nocase
        $domain4 = "7sbvaemscs0mc925tb99\.appsync-api\.us-west-2\.avsvmcloud\.com" ascii wide nocase
        $domain5 = "actualityworld\.com" ascii wide nocase
        $domain6 = "adagio\.betterworldshopping\.com" ascii wide nocase
        $domain7 = "admirer\.onehourcfo\.com" ascii wide nocase
        $domain8 = "adsprofitnetwork\.com" ascii wide nocase
        $domain9 = "aimsecurity\.net" ascii wide nocase
        $domain10 = "alertmeter\.info" ascii wide nocase
        $domain11 = "apexwebtech\.com" ascii wide nocase
        $domain12 = "appsprovider\.com" ascii wide nocase
        $domain13 = "appsync-api\.eu-west-1\.avsvmcloud\.com" ascii wide nocase
        $domain14 = "appsync-api\.us-east-1\.avsvmcloud\.com" ascii wide nocase
        $domain15 = "appsync-api\.us-east-2\.avsvmcloud\.com" ascii wide nocase
        $domain16 = "appsync-api\.us-west-2\.avsvmcloud\.com" ascii wide nocase
        $domain17 = "armrvrholo\.com" ascii wide nocase
        $domain18 = "assetdata\.net" ascii wide nocase
        $domain19 = "autonetonline\.com" ascii wide nocase
        $domain20 = "avsvmcloud\.com" ascii wide nocase
        $domain21 = "bacionera\.top" ascii wide nocase
        $domain22 = "backup\.awarfaregaming\.com" ascii wide nocase
        $domain23 = "bfilmnews\.com" ascii wide nocase
        $domain24 = "bigdataanalysts\.com" ascii wide nocase
        $domain25 = "bigtopweb\.com" ascii wide nocase
        $domain26 = "bmlor\.750\.credit" ascii wide nocase
        $domain27 = "builder\.visionarybusiness\.net" ascii wide nocase
        $domain28 = "camogit\.com" ascii wide nocase
        $domain29 = "cdnappservice\.firebaseio\.com" ascii wide nocase
        $domain30 = "champions\.gdtc\.org" ascii wide nocase
        $domain31 = "cityloss\.com" ascii wide nocase
        $domain32 = "coloradospringsroofing\.info" ascii wide nocase
        $domain33 = "combat\.strategyforgood\.com" ascii wide nocase
        $domain34 = "computerrepublic\.com" ascii wide nocase
        $domain35 = "content\.pcmsar\.net" ascii wide nocase
        $domain36 = "context\.septemberyears\.org" ascii wide nocase
        $domain37 = "crochetnews\.com" ascii wide nocase
        $domain38 = "cross-checking\.com" ascii wide nocase
        $domain39 = "d3ser9acyt7cdp\.cloudfront\.net" ascii wide nocase
        $domain40 = "daddy\.stlouisdemoday\.com" ascii wide nocase
        $domain41 = "dailydews\.com" ascii wide nocase
        $domain42 = "databasegalore\.com" ascii wide nocase
        $domain43 = "dataplane\.theyardservice\.com" ascii wide nocase
        $domain44 = "datatidy\.com" ascii wide nocase
        $domain45 = "datazr\.com" ascii wide nocase
        $domain46 = "defender5\.coachwithak\.com" ascii wide nocase
        $domain47 = "deftsecurity\.com" ascii wide nocase
        $domain48 = "diamondglobalnetwork\.com" ascii wide nocase
        $domain49 = "digitalcollege\.org" ascii wide nocase
        $ip50 = "179.43.141.188" ascii wide
        $ip51 = "179.43.141.188" ascii wide
        $ip52 = "179.43.141.188" ascii wide
        $ip53 = "185.189.151.182" ascii wide
        $ip54 = "185.225.69.69" ascii wide
        $ip55 = "216.243.39.167" ascii wide
        $ip56 = "5.75.159.186" ascii wide
        $ip57 = "5.75.159.186" ascii wide
        $ip58 = "5.75.159.186" ascii wide
        $ip59 = "5.75.159.186" ascii wide
        $ip60 = "5.75.159.186" ascii wide
        $ip61 = "5.75.159.186" ascii wide
        $ip62 = "91.219.239.43" ascii wide
        $ip63 = "91.219.239.54" ascii wide
        $ip64 = "91.219.239.54" ascii wide
        $ip65 = "98.225.248.37" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC2465
{
    meta:
        description = "Detects IOCs associated with APT UNC2465"
        author = "APTtrail Automated Collection"
        apt_group = "UNC2465"
        aliases = "smokedham"
        reference = "https://gist.github.com/drb-ra/179e8e9beca45bc10feba97cf8c5c7b1"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "app-cdn\.celixi6266\.workers\.dev" ascii wide nocase
        $domain1 = "cdn-app-server\.vewojo9572\.workers\.dev" ascii wide nocase
        $domain2 = "cdn-app-web\.piniyi9484\.workers\.dev" ascii wide nocase
        $domain3 = "cdn-server-1\.xiren77418\.workers\.dev" ascii wide nocase
        $domain4 = "cdn-server-2\.wesoc40288\.workers\.dev" ascii wide nocase
        $domain5 = "cdn-server-full\.taros12579\.workers\.dev" ascii wide nocase
        $domain6 = "cdn-web-server1\.techserver01\.workers\.dev" ascii wide nocase
        $domain7 = "cdn1\.cowivat156\.workers\.dev" ascii wide nocase
        $domain8 = "cdn1\.poyag17470\.workers\.dev" ascii wide nocase
        $domain9 = "dash-server\.servertech03\.workers\.dev" ascii wide nocase
        $domain10 = "ec2-app\.lewoha7320\.workers\.dev" ascii wide nocase
        $domain11 = "ec2-server\.bayaj19162\.workers\.dev" ascii wide nocase
        $domain12 = "ec2-server\.gegodec527\.workers\.dev" ascii wide nocase
        $domain13 = "ec2-server\.milago3967\.workers\.dev" ascii wide nocase
        $domain14 = "floral-paper-8eb1\.pihara4672\.workers\.dev" ascii wide nocase
        $domain15 = "keystore-explorer\.com" ascii wide nocase
        $domain16 = "mstore\.framfarmers\.co\.uk" ascii wide nocase
        $domain17 = "server-cdn\.jawigaw383\.workers\.dev" ascii wide nocase
        $domain18 = "server-cdn\.lafise2419\.workers\.dev" ascii wide nocase
        $domain19 = "server-cdn\.lecoc56350\.workers\.dev" ascii wide nocase
        $domain20 = "server-cdn\.sidoke9822\.workers\.dev" ascii wide nocase
        $domain21 = "server-cdn\.virej10913\.workers\.dev" ascii wide nocase
        $domain22 = "server-cdn\.xohahey822\.workers\.dev" ascii wide nocase
        $domain23 = "server-web-cdn\.detocim498\.workers\.dev" ascii wide nocase
        $domain24 = "server-web-cdn\.dones86497\.workers\.dev" ascii wide nocase
        $domain25 = "server-web-cdn\.kagoli5215\.workers\.dev" ascii wide nocase
        $domain26 = "server-web-cdn\.mevame4224\.workers\.dev" ascii wide nocase
        $domain27 = "server-web-cdn\.nefixeg373\.workers\.dev" ascii wide nocase
        $domain28 = "server-web-cdn\.pixece7948\.workers\.dev" ascii wide nocase
        $domain29 = "server-web-cdn\.ravebo3233\.workers\.dev" ascii wide nocase
        $domain30 = "server-web-cdn\.rojotoc516\.workers\.dev" ascii wide nocase
        $domain31 = "server-web-cdn\.vosax32455\.workers\.dev" ascii wide nocase
        $domain32 = "server-web-cdn\.yevobod379\.workers\.dev" ascii wide nocase
        $domain33 = "server-web-cdn1\.gekod80409\.workers\.dev" ascii wide nocase
        $domain34 = "soft-base-01\.ginigiy117\.workers\.dev" ascii wide nocase
        $domain35 = "soft-dns\.sejilod748\.workers\.dev" ascii wide nocase
        $domain36 = "web-app\.dasik14289\.workers\.dev" ascii wide nocase
        $domain37 = "work-server-1\.picalob750\.workers\.dev" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC2529
{
    meta:
        description = "Detects IOCs associated with APT UNC2529"
        author = "APTtrail Automated Collection"
        apt_group = "UNC2529"
        aliases = "doubleback, doubledrag, doubledrop"
        reference = "https://tria.ge/210601-fpxsgwd8p2"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "adupla\.net" ascii wide nocase
        $domain1 = "aibemarle\.com" ascii wide nocase
        $domain2 = "arcadiabay\.org" ascii wide nocase
        $domain3 = "austinheisey\.com" ascii wide nocase
        $domain4 = "bestcake\.ca" ascii wide nocase
        $domain5 = "bestwalletforbitcoin\.com" ascii wide nocase
        $domain6 = "bitcoinsacks\.com" ascii wide nocase
        $domain7 = "bonushelp\.com" ascii wide nocase
        $domain8 = "ceylonbungalows\.net" ascii wide nocase
        $domain9 = "chandol\.com" ascii wide nocase
        $domain10 = "clanvisits\.com" ascii wide nocase
        $domain11 = "closetdeal\.com" ascii wide nocase
        $domain12 = "daldhillon\.com" ascii wide nocase
        $domain13 = "desmoncreative\.com" ascii wide nocase
        $domain14 = "digitalagencyleeds\.com" ascii wide nocase
        $domain15 = "erbilmarriott\.com" ascii wide nocase
        $domain16 = "ethernetpedia\.com" ascii wide nocase
        $domain17 = "farmpork\.com" ascii wide nocase
        $domain18 = "fileamazon\.com" ascii wide nocase
        $domain19 = "gamesaccommodationscotland\.com" ascii wide nocase
        $domain20 = "gemralph\.com" ascii wide nocase
        $domain21 = "greathabibgroup\.com" ascii wide nocase
        $domain22 = "greeklife242\.com" ascii wide nocase
        $domain23 = "infomarketx\.com" ascii wide nocase
        $domain24 = "isjustlunch\.com" ascii wide nocase
        $domain25 = "jagunconsult\.com" ascii wide nocase
        $domain26 = "khodaycontrolsystem\.com" ascii wide nocase
        $domain27 = "klikbets\.net" ascii wide nocase
        $domain28 = "lasartoria\.net" ascii wide nocase
        $domain29 = "logicmyass\.com" ascii wide nocase
        $domain30 = "lottoangels\.com" ascii wide nocase
        $domain31 = "mangoldsengers\.com" ascii wide nocase
        $domain32 = "maninashop\.com" ascii wide nocase
        $domain33 = "oconeeveteransmemorial\.com" ascii wide nocase
        $domain34 = "onceprojects\.com" ascii wide nocase
        $domain35 = "p-leh\.com" ascii wide nocase
        $domain36 = "scottishhandcraft\.com" ascii wide nocase
        $domain37 = "seathisons\.com" ascii wide nocase
        $domain38 = "simcardhosting\.com" ascii wide nocase
        $domain39 = "skysatcam\.com" ascii wide nocase
        $domain40 = "smartnhappy\.com" ascii wide nocase
        $domain41 = "stayzarentals\.com" ascii wide nocase
        $domain42 = "stepearn\.com" ascii wide nocase
        $domain43 = "sugarmummylove\.com" ascii wide nocase
        $domain44 = "techooze\.com" ascii wide nocase
        $domain45 = "tigertigerbeads\.com" ascii wide nocase
        $domain46 = "totallyhealth-wealth\.com" ascii wide nocase
        $domain47 = "touristboardaccommodation\.com" ascii wide nocase
        $domain48 = "towncenterhotel\.com" ascii wide nocase
        $domain49 = "towncentrehotel\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC2565
{
    meta:
        description = "Detects IOCs associated with APT UNC2565"
        author = "APTtrail Automated Collection"
        apt_group = "UNC2565"
        reference = "https://otx.alienvault.com/pulse/63d94fda79bac208bafcdc09"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "kakiosk\.adsparkdev\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_UNC2596
{
    meta:
        description = "Detects IOCs associated with APT UNC2596"
        author = "APTtrail Automated Collection"
        apt_group = "UNC2596"
        aliases = "CVE-2023-36884, dustyhammock, meltingclaw"
        reference = "https://app.validin.com/detail?find=185.225.74.94&type=ip4&ref_id=65ec9bcbe4c#tab=resolutions"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "1drv\.fileshare\.direct" ascii wide nocase
        $domain1 = "1drv\.us\.com" ascii wide nocase
        $domain2 = "4qzm\.com" ascii wide nocase
        $domain3 = "adbefnts\.dev" ascii wide nocase
        $domain4 = "adcreative\.pictures" ascii wide nocase
        $domain5 = "adobe\.cloudcreative\.digital" ascii wide nocase
        $domain6 = "advanced-ip-scaner\.com" ascii wide nocase
        $domain7 = "advanced-ip-scanners\.com" ascii wide nocase
        $domain8 = "altimata\.org" ascii wide nocase
        $domain9 = "apisolving\.com" ascii wide nocase
        $domain10 = "aspx\.io" ascii wide nocase
        $domain11 = "bentaxworld\.com" ascii wide nocase
        $domain12 = "budgetnews\.org" ascii wide nocase
        $domain13 = "campanole\.com" ascii wide nocase
        $domain14 = "certifysop\.com" ascii wide nocase
        $domain15 = "cethernet\.com" ascii wide nocase
        $domain16 = "cloudcreative\.digital" ascii wide nocase
        $domain17 = "combinedresidency\.org" ascii wide nocase
        $domain18 = "copdaemi\.top" ascii wide nocase
        $domain19 = "correctiv\.sbs" ascii wide nocase
        $domain20 = "creativeadb\.com" ascii wide nocase
        $domain21 = "cwise\.store" ascii wide nocase
        $domain22 = "dashboard\.penofach\.com" ascii wide nocase
        $domain23 = "devhubs\.dev" ascii wide nocase
        $domain24 = "devolredir\.com" ascii wide nocase
        $domain25 = "digitalsolutionstime\.com" ascii wide nocase
        $domain26 = "dns-msn\.com" ascii wide nocase
        $domain27 = "dnsresolver\.online" ascii wide nocase
        $domain28 = "docstorage\.link" ascii wide nocase
        $domain29 = "drv2ms\.com" ascii wide nocase
        $domain30 = "drvmcprotect\.com" ascii wide nocase
        $domain31 = "economistjournal\.cloud" ascii wide nocase
        $domain32 = "fastshare\.click" ascii wide nocase
        $domain33 = "fileshare\.direct" ascii wide nocase
        $domain34 = "finformservice\.com" ascii wide nocase
        $domain35 = "gohazeldale\.com" ascii wide nocase
        $domain36 = "gov\.mil\.ua\.aspx\.io" ascii wide nocase
        $domain37 = "ilogicflow\.com" ascii wide nocase
        $domain38 = "journalctd\.live" ascii wide nocase
        $domain39 = "kayakahead\.net" ascii wide nocase
        $domain40 = "keepas\.org" ascii wide nocase
        $domain41 = "linedrv\.com" ascii wide nocase
        $domain42 = "mcprotect\.cloud" ascii wide nocase
        $domain43 = "mctelemetryzone\.com" ascii wide nocase
        $domain44 = "melamorri\.com" ascii wide nocase
        $domain45 = "mil\.ua\.aspx\.io" ascii wide nocase
        $domain46 = "mill\.co\.ua" ascii wide nocase
        $domain47 = "netstaticsinformation\.com" ascii wide nocase
        $domain48 = "notfiled\.com" ascii wide nocase
        $domain49 = "olminx\.com" ascii wide nocase
        $ip50 = "104.234.10.207" ascii wide
        $ip51 = "104.234.239.26" ascii wide
        $ip52 = "104.234.239.26" ascii wide
        $ip53 = "104.234.239.26" ascii wide
        $ip54 = "109.105.198.145" ascii wide
        $ip55 = "15.235.203.250" ascii wide
        $ip56 = "185.56.137.104" ascii wide
        $ip57 = "2.57.90.16" ascii wide
        $ip58 = "201.174.21.202" ascii wide
        $ip59 = "201.174.21.202" ascii wide
        $ip60 = "201.174.21.202" ascii wide
        $ip61 = "217.195.153.39" ascii wide
        $ip62 = "46.246.98.15" ascii wide
        $ip63 = "65.21.27.250" ascii wide
        $ip64 = "69.49.231.103" ascii wide
        $ip65 = "69.49.245.55" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC3500
{
    meta:
        description = "Detects IOCs associated with APT UNC3500"
        author = "APTtrail Automated Collection"
        apt_group = "UNC3500"
        reference = "https://otx.alienvault.com/pulse/6244606893ddbc9a6a5bbdeb"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "vpn599147072\.softether\.net" ascii wide nocase
        $ip1 = "34.92.40.189" ascii wide
        $ip2 = "34.92.40.189" ascii wide
        $ip3 = "45.76.98.184" ascii wide
        $ip4 = "45.76.98.184" ascii wide
        $ip5 = "45.76.98.184" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC3535
{
    meta:
        description = "Detects IOCs associated with APT UNC3535"
        author = "APTtrail Automated Collection"
        apt_group = "UNC3535"
        reference = "https://otx.alienvault.com/pulse/6244606893ddbc9a6a5bbdeb"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "187.109.15.2" ascii wide

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_UNC3886
{
    meta:
        description = "Detects IOCs associated with APT UNC3886"
        author = "APTtrail Automated Collection"
        apt_group = "UNC3886"
        aliases = "castletap, mopsled, redpenguin"
        reference = "https://censys.com/junos-and-redpenguin/"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "101.100.182.122" ascii wide
        $ip1 = "116.88.34.184" ascii wide
        $ip2 = "118.189.188.122" ascii wide
        $ip3 = "118.193.63.40" ascii wide
        $ip4 = "129.126.109.50" ascii wide
        $ip5 = "158.140.135.244" ascii wide
        $ip6 = "223.25.78.136" ascii wide
        $ip7 = "45.77.39.28" ascii wide
        $ip8 = "47.246.68.13" ascii wide
        $ip9 = "8.222.225.8" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC3890
{
    meta:
        description = "Detects IOCs associated with APT UNC3890"
        author = "APTtrail Automated Collection"
        apt_group = "UNC3890"
        reference = "https://www.mandiant.com/resources/suspected-iranian-actor-targeting-israeli-shipping"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "account\.office365update\.live" ascii wide nocase
        $domain1 = "account\.sdfsfsdf\.office365update\.live" ascii wide nocase
        $domain2 = "ads\.celebritylife\.news" ascii wide nocase
        $domain3 = "aspiremovecentraldays\.net" ascii wide nocase
        $domain4 = "celebritylife\.news" ascii wide nocase
        $domain5 = "com\.office365update\.live" ascii wide nocase
        $domain6 = "fileupload\.shop" ascii wide nocase
        $domain7 = "i\.login\.office365update\.live" ascii wide nocase
        $domain8 = "login\.office365update\.live" ascii wide nocase
        $domain9 = "login\.rnfacebook\.com" ascii wide nocase
        $domain10 = "login\.sdfsfsdf\.office365update\.live" ascii wide nocase
        $domain11 = "logincdn\.sdfsfsdf\.office365update\.live" ascii wide nocase
        $domain12 = "m\.login\.office365update\.live" ascii wide nocase
        $domain13 = "m\.login\.rnfacebook\.com" ascii wide nocase
        $domain14 = "m\.site\.rnfacebook\.com" ascii wide nocase
        $domain15 = "microsoft\.office365update\.live" ascii wide nocase
        $domain16 = "microsoftonline\.office365update\.live" ascii wide nocase
        $domain17 = "naturaldolls\.store" ascii wide nocase
        $domain18 = "ns1\.office365update\.live" ascii wide nocase
        $domain19 = "ns2\.office365update\.live" ascii wide nocase
        $domain20 = "office365update\.live" ascii wide nocase
        $domain21 = "outlook\.office365update\.live" ascii wide nocase
        $domain22 = "outlook\.sdfsfsdf\.office365update\.live" ascii wide nocase
        $domain23 = "pfizerpoll\.com" ascii wide nocase
        $domain24 = "rnfacebook\.com" ascii wide nocase
        $domain25 = "sdfsfsdf\.office365update\.live" ascii wide nocase
        $domain26 = "site\.rnfacebook\.com" ascii wide nocase
        $domain27 = "static\.login\.rnfacebook\.com" ascii wide nocase
        $domain28 = "static\.site\.rnfacebook\.com" ascii wide nocase
        $domain29 = "test\.office365update\.live" ascii wide nocase
        $domain30 = "xn--lirkedin-vkb\.com" ascii wide nocase
        $domain31 = "xxx-doll\.com" ascii wide nocase
        $ip32 = "161.35.123.176" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC3966
{
    meta:
        description = "Detects IOCs associated with APT UNC3966"
        author = "APTtrail Automated Collection"
        apt_group = "UNC3966"
        reference = "https://www.mandiant.com/resources/blog/unc961-multiverse-financially-motivated"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "ms-prod19-live\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_UNC4108
{
    meta:
        description = "Detects IOCs associated with APT UNC4108"
        author = "APTtrail Automated Collection"
        apt_group = "UNC4108"
        aliases = "ghostweaver"
        reference = "https://app.validin.com/detail?find=192.52.167.63&type=ip4&ref_id=5e5d97557ba#tab=resolutions"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "akami-cdns\.com" ascii wide nocase
        $domain1 = "cdns-clfr-dns\.com" ascii wide nocase
        $domain2 = "content-cdnsclfr\.com" ascii wide nocase
        $domain3 = "query-dns-cdn\.com" ascii wide nocase
        $domain4 = "query-js-ajax\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC4166
{
    meta:
        description = "Detects IOCs associated with APT UNC4166"
        author = "APTtrail Automated Collection"
        apt_group = "UNC4166"
        aliases = "SPAREPART, STOWAWAY"
        reference = "https://www.mandiant.com/resources/blog/trojanized-windows-installers-ukrainian-government"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "56nk4qmwxcdd72yiaro7bxixvgf5awgmmzpodub7phmfsqylezu2tsid\.onion\.moe" ascii wide nocase
        $domain1 = "cdnworld\.org" ascii wide nocase
        $domain2 = "ufowdauczwpa4enmzj2yyf7m4cbsjcaxxoyeebc2wdgzwnhvwhjf7iid\.onion\.moe" ascii wide nocase
        $domain3 = "ufowdauczwpa4enmzj2yyf7m4cbsjcaxxoyeebc2wdgzwnhvwhjf7iid\.onion\.ws" ascii wide nocase
        $ip4 = "193.142.30.166" ascii wide
        $ip5 = "91.205.230.66" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC4191
{
    meta:
        description = "Detects IOCs associated with APT UNC4191"
        author = "APTtrail Automated Collection"
        apt_group = "UNC4191"
        aliases = "bluehaze, darkdew, mistcloak"
        reference = "https://otx.alienvault.com/pulse/641ddcfa90e8b1f23b3089e1"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "closed\.theworkpc\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_UNC4210
{
    meta:
        description = "Detects IOCs associated with APT UNC4210"
        author = "APTtrail Automated Collection"
        apt_group = "UNC4210"
        aliases = "kopiluwak, quietcanary"
        reference = "https://www.mandiant.com/resources/blog/turla-galaxy-opportunity"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "manager\.surro\.am" ascii wide nocase
        $domain1 = "surro\.am" ascii wide nocase
        $ip2 = "194.67.209.186" ascii wide

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_UNC4221
{
    meta:
        description = "Detects IOCs associated with APT UNC4221"
        author = "APTtrail Automated Collection"
        apt_group = "UNC4221"
        reference = "https://cert.gov.ua/article/6281632 (# UAC-0185)"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "212nj0b42w\.web\.telegram-account\.host" ascii wide nocase
        $domain1 = "658pvbhj2k7veemmv4\.web\.telegram-account\.host" ascii wide nocase
        $domain2 = "accept-action\.site" ascii wide nocase
        $domain3 = "account-guard\.site" ascii wide nocase
        $domain4 = "account-saver\.com" ascii wide nocase
        $domain5 = "account-viewer\.com" ascii wide nocase
        $domain6 = "add-group\.site" ascii wide nocase
        $domain7 = "cancel-action\.site" ascii wide nocase
        $domain8 = "cancel-auth\.site" ascii wide nocase
        $domain9 = "check-active\.site" ascii wide nocase
        $domain10 = "check\.sign-cert\.com" ascii wide nocase
        $domain11 = "cloud\.account-viewer\.com" ascii wide nocase
        $domain12 = "cloud\.god-le\.net" ascii wide nocase
        $domain13 = "clouddrive\.world" ascii wide nocase
        $domain14 = "confirm-signal\.site" ascii wide nocase
        $domain15 = "confirm\.account-viewer\.com" ascii wide nocase
        $domain16 = "confirmphone\.site" ascii wide nocase
        $domain17 = "defender-bot\.site" ascii wide nocase
        $domain18 = "delta\.milgov\.site" ascii wide nocase
        $domain19 = "derzhposluhy\.com" ascii wide nocase
        $domain20 = "device\.redirecl\.com" ascii wide nocase
        $domain21 = "dhl\.redirecl\.com" ascii wide nocase
        $domain22 = "drive-share\.site" ascii wide nocase
        $domain23 = "drive\.redirecl\.com" ascii wide nocase
        $domain24 = "emtserviceca\.info" ascii wide nocase
        $domain25 = "get\.god-le\.com" ascii wide nocase
        $domain26 = "get\.in-touc\.com" ascii wide nocase
        $domain27 = "get\.mail-gov\.com" ascii wide nocase
        $domain28 = "get\.sign-cert\.com" ascii wide nocase
        $domain29 = "god-le\.com" ascii wide nocase
        $domain30 = "god-le\.net" ascii wide nocase
        $domain31 = "google\.drive-share\.site" ascii wide nocase
        $domain32 = "google\.share-drive\.site" ascii wide nocase
        $domain33 = "group-invitation\.site" ascii wide nocase
        $domain34 = "group-teneta\.online" ascii wide nocase
        $domain35 = "group\.kropyva\.site" ascii wide nocase
        $domain36 = "group\.teneta\.site" ascii wide nocase
        $domain37 = "helperanalytics\.ru" ascii wide nocase
        $domain38 = "homeskart\.shop" ascii wide nocase
        $domain39 = "homeway\.xyz" ascii wide nocase
        $domain40 = "i-ua\.account-guard\.site" ascii wide nocase
        $domain41 = "in-touc\.com" ascii wide nocase
        $domain42 = "ivanti\.account-viewer\.com" ascii wide nocase
        $domain43 = "join-group\.online" ascii wide nocase
        $domain44 = "kropyva\.group" ascii wide nocase
        $domain45 = "kropyva\.site" ascii wide nocase
        $domain46 = "live\.outloolc\.com" ascii wide nocase
        $domain47 = "mail-gov\.com" ascii wide nocase
        $domain48 = "mail-gov\.net" ascii wide nocase
        $domain49 = "mail\.outloolc\.com" ascii wide nocase
        $ip50 = "185.225.35.75" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC4553
{
    meta:
        description = "Detects IOCs associated with APT UNC4553"
        author = "APTtrail Automated Collection"
        apt_group = "UNC4553"
        aliases = "ridile"
        reference = "https://www.mandiant.com/resources/blog/lnk-between-browsers"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "2022-blanks\.site" ascii wide nocase
        $domain1 = "ashgrrwt\.click" ascii wide nocase
        $domain2 = "extenision-app\.com" ascii wide nocase
        $domain3 = "finandy\.info" ascii wide nocase
        $domain4 = "finandy\.online" ascii wide nocase
        $domain5 = "flnand\.online" ascii wide nocase
        $domain6 = "kz-smartbank\.com" ascii wide nocase
        $domain7 = "mareux\.online" ascii wide nocase
        $domain8 = "mmarx\.quest" ascii wide nocase
        $domain9 = "okxsat\.xyz" ascii wide nocase
        $domain10 = "pr-tracker\.online" ascii wide nocase
        $domain11 = "qivvi-3\.click" ascii wide nocase
        $domain12 = "serienjunkies\.us" ascii wide nocase
        $domain13 = "telegromcn\.org" ascii wide nocase
        $domain14 = "vceilinichego\.ru" ascii wide nocase
        $domain15 = "vse-blanki\.online" ascii wide nocase
        $ip16 = "146.70.79.75" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC4841
{
    meta:
        description = "Detects IOCs associated with APT UNC4841"
        author = "APTtrail Automated Collection"
        apt_group = "UNC4841"
        aliases = "SALTWATER, SEASIDE, SEASPY"
        reference = "https://dti.domaintools.com/inside-salt-typhoon-chinas-state-corporate-advanced-persistent-threat/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "aar\.gandhibludtric\.com" ascii wide nocase
        $domain1 = "aria-hidden\.com" ascii wide nocase
        $domain2 = "asparticrooftop\.com" ascii wide nocase
        $domain3 = "availabilitydesired\.us" ascii wide nocase
        $domain4 = "bestfindthetruth\.com" ascii wide nocase
        $domain5 = "caret-right\.com" ascii wide nocase
        $domain6 = "chatscreend\.com" ascii wide nocase
        $domain7 = "chekoodver\.com" ascii wide nocase
        $domain8 = "cloudprocenter\.com" ascii wide nocase
        $domain9 = "clubworkmistake\.com" ascii wide nocase
        $domain10 = "col-lg\.com" ascii wide nocase
        $domain11 = "colourtinctem\.com" ascii wide nocase
        $domain12 = "componfrom\.com" ascii wide nocase
        $domain13 = "e-forwardviewupdata\.com" ascii wide nocase
        $domain14 = "fessionalwork\.com" ascii wide nocase
        $domain15 = "fitbookcatwer\.com" ascii wide nocase
        $domain16 = "fjtest-block\.com" ascii wide nocase
        $domain17 = "followkoon\.com" ascii wide nocase
        $domain18 = "gandhibludtric\.com" ascii wide nocase
        $domain19 = "gesturefavour\.com" ascii wide nocase
        $domain20 = "getdbecausehub\.com" ascii wide nocase
        $domain21 = "goldenunder\.com" ascii wide nocase
        $domain22 = "hateupopred\.com" ascii wide nocase
        $domain23 = "incisivelyfut\.com" ascii wide nocase
        $domain24 = "junsamyoung\.com" ascii wide nocase
        $domain25 = "lookpumrron\.com" ascii wide nocase
        $domain26 = "morrowadded\.com" ascii wide nocase
        $domain27 = "mx01\.bestfindthetruth\.com" ascii wide nocase
        $domain28 = "newhkdaily\.com" ascii wide nocase
        $domain29 = "onlineeylity\.com" ascii wide nocase
        $domain30 = "qatarpenble\.com" ascii wide nocase
        $domain31 = "redbludfootvr\.com" ascii wide nocase
        $domain32 = "requiredvalue\.com" ascii wide nocase
        $domain33 = "ressicepro\.com" ascii wide nocase
        $domain34 = "shalaordereport\.com" ascii wide nocase
        $domain35 = "siderheycook\.com" ascii wide nocase
        $domain36 = "sinceretehope\.com" ascii wide nocase
        $domain37 = "singamofing\.com" ascii wide nocase
        $domain38 = "singnode\.com" ascii wide nocase
        $domain39 = "solveblemten\.com" ascii wide nocase
        $domain40 = "togetheroffway\.com" ascii wide nocase
        $domain41 = "toodblackrun\.com" ascii wide nocase
        $domain42 = "troublendsef\.com" ascii wide nocase
        $domain43 = "unfeelmoonvd\.com" ascii wide nocase
        $domain44 = "verfiedoccurr\.com" ascii wide nocase
        $domain45 = "waystrkeprosh\.com" ascii wide nocase
        $domain46 = "xdmgwctese\.com" ascii wide nocase
        $domain47 = "xxl17z\.dnslog\.cn" ascii wide nocase
        $ip48 = "101.229.146.218" ascii wide
        $ip49 = "101.229.146.218" ascii wide
        $ip50 = "103.146.179.101" ascii wide
        $ip51 = "103.146.179.101" ascii wide
        $ip52 = "103.27.108.62" ascii wide
        $ip53 = "103.27.108.62" ascii wide
        $ip54 = "103.77.192.13" ascii wide
        $ip55 = "103.77.192.13" ascii wide
        $ip56 = "103.77.192.88" ascii wide
        $ip57 = "103.77.192.88" ascii wide
        $ip58 = "103.93.78.142" ascii wide
        $ip59 = "103.93.78.142" ascii wide
        $ip60 = "104.156.229.226" ascii wide
        $ip61 = "104.156.229.226" ascii wide
        $ip62 = "104.223.20.222" ascii wide
        $ip63 = "104.223.20.222" ascii wide
        $ip64 = "107.148.149.156" ascii wide
        $ip65 = "107.148.219.227" ascii wide
        $ip66 = "107.148.219.227" ascii wide
        $ip67 = "107.148.219.53" ascii wide
        $ip68 = "107.148.219.54" ascii wide
        $ip69 = "107.148.219.54" ascii wide
        $ip70 = "107.148.219.55" ascii wide
        $ip71 = "107.148.219.55" ascii wide
        $ip72 = "107.148.223.196" ascii wide
        $ip73 = "107.148.223.196" ascii wide
        $ip74 = "107.173.62.158" ascii wide
        $ip75 = "107.173.62.158" ascii wide
        $ip76 = "137.175.19.25" ascii wide
        $ip77 = "137.175.19.25" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC4899
{
    meta:
        description = "Detects IOCs associated with APT UNC4899"
        author = "APTtrail Automated Collection"
        apt_group = "UNC4899"
        aliases = "JumpCloud"
        reference = "https://twitter.com/ThreatBookLabs/status/1686582979563581440"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "606qipai\.com" ascii wide nocase
        $domain1 = "alwaysckain\.com" ascii wide nocase
        $domain2 = "alwaysswarm\.com" ascii wide nocase
        $domain3 = "asplinc\.com" ascii wide nocase
        $domain4 = "basketsalute\.com" ascii wide nocase
        $domain5 = "bsef\.or\.kr" ascii wide nocase
        $domain6 = "canolagroove\.com" ascii wide nocase
        $domain7 = "centos-packages\.com" ascii wide nocase
        $domain8 = "centos-pkg\.org" ascii wide nocase
        $domain9 = "centos-repos\.org" ascii wide nocase
        $domain10 = "contortonset\.com" ascii wide nocase
        $domain11 = "dallynk\.com" ascii wide nocase
        $domain12 = "datadog-cloud\.com" ascii wide nocase
        $domain13 = "datadog-graph\.com" ascii wide nocase
        $domain14 = "launchruse\.com" ascii wide nocase
        $domain15 = "nomadpkg\.com" ascii wide nocase
        $domain16 = "nomadpkgs\.com" ascii wide nocase
        $domain17 = "primerosauxiliosperu\.com" ascii wide nocase
        $domain18 = "prontoposer\.com" ascii wide nocase
        $domain19 = "redhat-packages\.com" ascii wide nocase
        $domain20 = "reggedrobin\.com" ascii wide nocase
        $domain21 = "relysudden\.com" ascii wide nocase
        $domain22 = "rentedpushy\.com" ascii wide nocase
        $domain23 = "sizzlesierra\.com" ascii wide nocase
        $domain24 = "sweptshut\.com" ascii wide nocase
        $domain25 = "toyourownbeat\.com" ascii wide nocase
        $domain26 = "yolenny\.com" ascii wide nocase
        $domain27 = "zscaler-api\.org" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC4990
{
    meta:
        description = "Detects IOCs associated with APT UNC4990"
        author = "APTtrail Automated Collection"
        apt_group = "UNC4990"
        reference = "https://www.mandiant.com/resources/blog/unc4990-evolution-usb-malware"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "apiworld\.cf" ascii wide nocase
        $domain1 = "bobsmith\.apiworld\.cf" ascii wide nocase
        $domain2 = "captcha\.grouphelp\.top" ascii wide nocase
        $domain3 = "captcha\.tgbot\.it" ascii wide nocase
        $domain4 = "davebeerblog\.eu\.org" ascii wide nocase
        $domain5 = "eu1\.microtunnel\.it" ascii wide nocase
        $domain6 = "euserv3\.herokuapp\.com" ascii wide nocase
        $domain7 = "evinfeoptasw\.dedyn\.io" ascii wide nocase
        $domain8 = "geraldonsboutique\.altervista\.org" ascii wide nocase
        $domain9 = "lucaespo\.altervista\.org" ascii wide nocase
        $domain10 = "lucaesposito\.herokuapp\.com" ascii wide nocase
        $domain11 = "microtunnel\.it" ascii wide nocase
        $domain12 = "monumental\.ga" ascii wide nocase
        $domain13 = "ncnskjhrbefwifjhww\.tk" ascii wide nocase
        $domain14 = "studiofotografico35mm\.altervista\.org" ascii wide nocase
        $domain15 = "wjecpujpanmwm\.tk" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC5174
{
    meta:
        description = "Detects IOCs associated with APT UNC5174"
        author = "APTtrail Automated Collection"
        apt_group = "UNC5174"
        aliases = "snowlight, vshell"
        reference = "https://sysdig.com/blog/unc5174-chinese-threat-actor-vshell/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "apib\.googlespays\.com" ascii wide nocase
        $domain1 = "bootstrapcdn\.fun" ascii wide nocase
        $domain2 = "btt\.evil\.gooogleasia\.com" ascii wide nocase
        $domain3 = "c1oudf1are\.com" ascii wide nocase
        $domain4 = "chmobank\.com" ascii wide nocase
        $domain5 = "googlespays\.com" ascii wide nocase
        $domain6 = "https\.sex666vr\.com" ascii wide nocase
        $domain7 = "huionepay\.me" ascii wide nocase
        $domain8 = "javaw\.virustotal\.xyz" ascii wide nocase
        $domain9 = "ks\.evil\.gooogleasia\.com" ascii wide nocase
        $domain10 = "lin\.c1oudf1are\.com" ascii wide nocase
        $domain11 = "lin\.huionepay\.me" ascii wide nocase
        $domain12 = "lin\.telegrams\.icu" ascii wide nocase
        $domain13 = "mcafeecdn\.xyz" ascii wide nocase
        $domain14 = "mtls\.sex666vr\.com" ascii wide nocase
        $domain15 = "samsungcdn\.com" ascii wide nocase
        $domain16 = "start\.bootstrapcdn\.fun" ascii wide nocase
        $domain17 = "telegrams\.icu" ascii wide nocase
        $domain18 = "virustotal\.xyz" ascii wide nocase
        $domain19 = "vs\.gooogleasia\.com" ascii wide nocase
        $domain20 = "wg\.gooogleasia\.com" ascii wide nocase
        $ip21 = "124.221.120.25" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC5221
{
    meta:
        description = "Detects IOCs associated with APT UNC5221"
        author = "APTtrail Automated Collection"
        apt_group = "UNC5221"
        aliases = "uta0178"
        reference = "https://blog.eclecticiq.com/china-nexus-threat-actor-actively-exploiting-ivanti-endpoint-manager-mobile-cve-2025-4428-vulnerability"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "abbeglasses\.s3\.amazonaws\.com" ascii wide nocase
        $domain1 = "abode-dashboard-media\.s3\.ap-south-1\.amazonaws\.com" ascii wide nocase
        $domain2 = "api\.d-n-s\.name" ascii wide nocase
        $domain3 = "archivevalley-media\.s3\.amazonaws\.com" ascii wide nocase
        $domain4 = "blooming\.s3\.amazonaws\.com" ascii wide nocase
        $domain5 = "catcher\.requestcatcher\.com" ascii wide nocase
        $domain6 = "clickcom\.click" ascii wide nocase
        $domain7 = "clicko\.click" ascii wide nocase
        $domain8 = "duorhytm\.fun" ascii wide nocase
        $domain9 = "fconnect\.s3\.amazonaws\.com" ascii wide nocase
        $domain10 = "gpoaccess\.com" ascii wide nocase
        $domain11 = "line-api\.com" ascii wide nocase
        $domain12 = "openrbf\.s3\.amazonaws\.com" ascii wide nocase
        $domain13 = "psecure\.pro" ascii wide nocase
        $domain14 = "safe\.rocks" ascii wide nocase
        $domain15 = "secure-cama\.com" ascii wide nocase
        $domain16 = "shapefiles\.fews\.net\.s3\.amazonaws\.com" ascii wide nocase
        $domain17 = "symantke\.com" ascii wide nocase
        $domain18 = "telemetry\.psecure\.pro" ascii wide nocase
        $domain19 = "the-mentor\.s3\.amazonaws\.com" ascii wide nocase
        $domain20 = "tkshopqd\.s3\.amazonaws\.com" ascii wide nocase
        $domain21 = "tnegadge\.s3\.amazonaws\.com" ascii wide nocase
        $domain22 = "trkbucket\.s3\.amazonaws\.com" ascii wide nocase
        $domain23 = "webb-institute\.com" ascii wide nocase
        $ip24 = "146.0.228.66" ascii wide
        $ip25 = "146.0.228.66" ascii wide
        $ip26 = "45.227.255.213" ascii wide
        $ip27 = "66.42.68.120" ascii wide
        $ip28 = "8.137.112.245" ascii wide
        $ip29 = "81.2.216.78" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC5267
{
    meta:
        description = "Detects IOCs associated with APT UNC5267"
        author = "APTtrail Automated Collection"
        apt_group = "UNC5267"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/mitigating-dprk-it-worker-threat"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "daniel-ayala\.netlify\.app" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_UNC5537
{
    meta:
        description = "Detects IOCs associated with APT UNC5537"
        author = "APTtrail Automated Collection"
        apt_group = "UNC5537"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "146.70.117.210" ascii wide
        $ip1 = "146.70.117.56" ascii wide
        $ip2 = "146.70.119.24" ascii wide
        $ip3 = "146.70.124.216" ascii wide
        $ip4 = "146.70.165.227" ascii wide
        $ip5 = "146.70.166.176" ascii wide
        $ip6 = "146.70.171.112" ascii wide
        $ip7 = "146.70.171.99" ascii wide
        $ip8 = "154.47.30.137" ascii wide
        $ip9 = "154.47.30.150" ascii wide
        $ip10 = "162.33.177.32" ascii wide
        $ip11 = "169.150.201.25" ascii wide
        $ip12 = "173.44.63.112" ascii wide
        $ip13 = "176.123.3.132" ascii wide
        $ip14 = "176.123.6.193" ascii wide
        $ip15 = "176.220.186.152" ascii wide
        $ip16 = "184.147.100.29" ascii wide
        $ip17 = "185.156.46.163" ascii wide
        $ip18 = "185.213.155.241" ascii wide
        $ip19 = "185.248.85.14" ascii wide
        $ip20 = "185.248.85.59" ascii wide
        $ip21 = "192.252.212.60" ascii wide
        $ip22 = "193.32.126.233" ascii wide
        $ip23 = "194.230.144.126" ascii wide
        $ip24 = "194.230.144.50" ascii wide
        $ip25 = "194.230.145.67" ascii wide
        $ip26 = "194.230.145.76" ascii wide
        $ip27 = "194.230.147.127" ascii wide
        $ip28 = "194.230.148.99" ascii wide
        $ip29 = "194.230.158.107" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC5792
{
    meta:
        description = "Detects IOCs associated with APT UNC5792"
        author = "APTtrail Automated Collection"
        apt_group = "UNC5792"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/russia-targeting-signal-messenger"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "add-signal-group\.com" ascii wide nocase
        $domain1 = "add-signal-groups\.com" ascii wide nocase
        $domain2 = "group-signal\.com" ascii wide nocase
        $domain3 = "group-signal\.tech" ascii wide nocase
        $domain4 = "groups-signal\.site" ascii wide nocase
        $domain5 = "signal-device-off\.online" ascii wide nocase
        $domain6 = "signal-group-add\.com" ascii wide nocase
        $domain7 = "signal-group\.site" ascii wide nocase
        $domain8 = "signal-group\.tech" ascii wide nocase
        $domain9 = "signal-groups-add\.com" ascii wide nocase
        $domain10 = "signal-groups\.site" ascii wide nocase
        $domain11 = "signal-groups\.tech" ascii wide nocase
        $domain12 = "signal-security\.online" ascii wide nocase
        $domain13 = "signal-security\.site" ascii wide nocase
        $domain14 = "signalgroup\.site" ascii wide nocase
        $domain15 = "signals-group\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC5812
{
    meta:
        description = "Detects IOCs associated with APT UNC5812"
        author = "APTtrail Automated Collection"
        apt_group = "UNC5812"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/russian-espionage-influence-ukrainian-military-recruits-anti-mobilization-narratives"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "civildefense\.com\.ua" ascii wide nocase
        $domain1 = "fu-laravel\.onrender\.com" ascii wide nocase
        $domain2 = "h315225216\.nichost\.ru" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_UNC5952
{
    meta:
        description = "Detects IOCs associated with APT UNC5952"
        author = "APTtrail Automated Collection"
        apt_group = "UNC5952"
        reference = "https://x.com/pancak3lullz/status/1877080477510549779"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "12support\.top" ascii wide nocase
        $domain1 = "6559464\.com" ascii wide nocase
        $domain2 = "accesspoint\.cc" ascii wide nocase
        $domain3 = "admin\.flywidus\.co" ascii wide nocase
        $domain4 = "atgajroker\.icu" ascii wide nocase
        $domain5 = "atmolatori\.cyou" ascii wide nocase
        $domain6 = "atmolatori\.icu" ascii wide nocase
        $domain7 = "awedinetwork\.com" ascii wide nocase
        $domain8 = "beri1\.com" ascii wide nocase
        $domain9 = "clmhelp\.top" ascii wide nocase
        $domain10 = "cloud\.vshell\.io" ascii wide nocase
        $domain11 = "cogajroker\.icu" ascii wide nocase
        $domain12 = "cqhelp\.top" ascii wide nocase
        $domain13 = "csupport\.ch" ascii wide nocase
        $domain14 = "dealr\.help" ascii wide nocase
        $domain15 = "do68iyckuy\.emerge\.co\.zw" ascii wide nocase
        $domain16 = "dshelp\.top" ascii wide nocase
        $domain17 = "edg-rt1\.top" ascii wide nocase
        $domain18 = "elioua5\.top" ascii wide nocase
        $domain19 = "exnpanel1\.top" ascii wide nocase
        $domain20 = "fposhelp\.com" ascii wide nocase
        $domain21 = "gajrokerist\.icu" ascii wide nocase
        $domain22 = "gajrokerring\.icu" ascii wide nocase
        $domain23 = "gajrokerware\.icu" ascii wide nocase
        $domain24 = "glueconnect\.com" ascii wide nocase
        $domain25 = "gomolatori\.cyou" ascii wide nocase
        $domain26 = "gomolatori\.icu" ascii wide nocase
        $domain27 = "gthelp\.top" ascii wide nocase
        $domain28 = "gxclp2\.top" ascii wide nocase
        $domain29 = "help26\.ca" ascii wide nocase
        $domain30 = "helpmysupport\.top" ascii wide nocase
        $domain31 = "icrm-tr3\.top" ascii wide nocase
        $domain32 = "itmanagers\.io" ascii wide nocase
        $domain33 = "jjghelp\.top" ascii wide nocase
        $domain34 = "jxhelp\.top" ascii wide nocase
        $domain35 = "kaptohelp\.top" ascii wide nocase
        $domain36 = "kryzuxyzhosting\.com" ascii wide nocase
        $domain37 = "lamolatori\.cyou" ascii wide nocase
        $domain38 = "lamolatori\.icu" ascii wide nocase
        $domain39 = "lowcarbsupport\.nl" ascii wide nocase
        $domain40 = "lwhelp\.top" ascii wide nocase
        $domain41 = "medion-001-site1\.ctempurl\.com" ascii wide nocase
        $domain42 = "mgbhelp\.top" ascii wide nocase
        $domain43 = "mghelp\.top" ascii wide nocase
        $domain44 = "mkpanel\.connectagent\.online" ascii wide nocase
        $domain45 = "mohamedsisyxyz\.com" ascii wide nocase
        $domain46 = "molatoriby\.cyou" ascii wide nocase
        $domain47 = "molatoriby\.icu" ascii wide nocase
        $domain48 = "molatorier\.cyou" ascii wide nocase
        $domain49 = "molatorier\.icu" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNC6293
{
    meta:
        description = "Detects IOCs associated with APT UNC6293"
        author = "APTtrail Automated Collection"
        apt_group = "UNC6293"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/creative-phishing-academics-critics-of-russia"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "91.190.191.117" ascii wide

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_UNC961
{
    meta:
        description = "Detects IOCs associated with APT UNC961"
        author = "APTtrail Automated Collection"
        apt_group = "UNC961"
        reference = "https://otx.alienvault.com/pulse/6244606893ddbc9a6a5bbdeb"
        severity = "high"
        tlp = "white"

    strings:
        $ip0 = "107.181.187.184" ascii wide
        $ip1 = "107.181.187.184" ascii wide
        $ip2 = "149.28.200.140" ascii wide
        $ip3 = "149.28.71.70" ascii wide
        $ip4 = "162.33.178.149" ascii wide
        $ip5 = "185.172.129.215" ascii wide
        $ip6 = "195.149.87.87" ascii wide
        $ip7 = "34.102.54.152" ascii wide
        $ip8 = "45.61.136.188" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_UNCLASSIFIED
{
    meta:
        description = "Detects IOCs associated with APT UNCLASSIFIED"
        author = "APTtrail Automated Collection"
        apt_group = "UNCLASSIFIED"
        reference = "http://blog.ptsecurity.com/2019/07/ironpython-darkly-how-we-uncovered.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "008php\.com" ascii wide nocase
        $domain1 = "01mirror\.com\.ua" ascii wide nocase
        $domain2 = "0660sf\.com" ascii wide nocase
        $domain3 = "071790\.000webhostapp\.com" ascii wide nocase
        $domain4 = "1\.handprintscariness\.ru" ascii wide nocase
        $domain5 = "18center\.com" ascii wide nocase
        $domain6 = "20\.3323sf\.com" ascii wide nocase
        $domain7 = "2021olympic\.cn" ascii wide nocase
        $domain8 = "2021olympics\.jp" ascii wide nocase
        $domain9 = "2021olympicupdates\.com" ascii wide nocase
        $domain10 = "2021olympicupdates\.live" ascii wide nocase
        $domain11 = "2021olympicupdateslive\.com" ascii wide nocase
        $domain12 = "2073\.mobi" ascii wide nocase
        $domain13 = "24ua\.website" ascii wide nocase
        $domain14 = "25665\.club" ascii wide nocase
        $domain15 = "25665\.me" ascii wide nocase
        $domain16 = "300bt\.com" ascii wide nocase
        $domain17 = "33016\.club" ascii wide nocase
        $domain18 = "3323sf\.com" ascii wide nocase
        $domain19 = "4sdfaash\.mypi\.co" ascii wide nocase
        $domain20 = "4sdfaashe\.mypi\.co" ascii wide nocase
        $domain21 = "60431\.club" ascii wide nocase
        $domain22 = "7077\.000webhostapp\.com" ascii wide nocase
        $domain23 = "75735\.club" ascii wide nocase
        $domain24 = "77444\.club" ascii wide nocase
        $domain25 = "78276\.ussdns01\.heketwe\.com" ascii wide nocase
        $domain26 = "78276\.ussdns02\.heketwe\.com" ascii wide nocase
        $domain27 = "80001\.me" ascii wide nocase
        $domain28 = "816e-182-227-90-53\.ngrok\.io" ascii wide nocase
        $domain29 = "82813\.club" ascii wide nocase
        $domain30 = "86wts86a8j\.com" ascii wide nocase
        $domain31 = "881\.000webhostapp\.com" ascii wide nocase
        $domain32 = "EuDbSyncUp\.com" ascii wide nocase
        $domain33 = "Jdokdo\.ml" ascii wide nocase
        $domain34 = "Jospubs\.com" ascii wide nocase
        $domain35 = "MsCupDb\.com" ascii wide nocase
        $domain36 = "UsMobileSos\.com" ascii wide nocase
        $domain37 = "a\.00-online\.com" ascii wide nocase
        $domain38 = "a7788\.1apps\.com" ascii wide nocase
        $domain39 = "aaaaaaaahmad\.no-ip\.biz" ascii wide nocase
        $domain40 = "abbaass313\.hopto\.org" ascii wide nocase
        $domain41 = "abbarhs\.mypi\.co" ascii wide nocase
        $domain42 = "abbarhsa\.mypi\.co" ascii wide nocase
        $domain43 = "abc69696969\.vicp\.net" ascii wide nocase
        $domain44 = "abdillahzraibi\.no-ip\.biz" ascii wide nocase
        $domain45 = "abdou36\.noip\.me" ascii wide nocase
        $domain46 = "abevahack123\.no-ip\.biz" ascii wide nocase
        $domain47 = "acccountsgoog1e\.com" ascii wide nocase
        $domain48 = "account-mail\.info" ascii wide nocase
        $domain49 = "accountapp\.xyz" ascii wide nocase
        $ip50 = "103.117.120.129" ascii wide
        $ip51 = "103.117.120.181" ascii wide
        $ip52 = "103.117.120.182" ascii wide
        $ip53 = "103.233.11.162" ascii wide
        $ip54 = "103.97.128.53" ascii wide
        $ip55 = "104.248.153.204" ascii wide
        $ip56 = "104.248.153.204" ascii wide
        $ip57 = "104.255.66.139" ascii wide
        $ip58 = "108.181.165.94" ascii wide
        $ip59 = "111.20.145.84" ascii wide
        $ip60 = "111.90.150.37" ascii wide
        $ip61 = "122.10.82.65" ascii wide
        $ip62 = "122.10.93.136" ascii wide
        $ip63 = "13.211.167.218" ascii wide
        $ip64 = "135.125.107.221" ascii wide
        $ip65 = "137.184.67.33" ascii wide
        $ip66 = "137.220.180.39" ascii wide
        $ip67 = "138.68.56.176" ascii wide
        $ip68 = "138.68.56.176" ascii wide
        $ip69 = "143.110.189.141" ascii wide
        $ip70 = "146.70.161.78" ascii wide
        $ip71 = "147.78.46.40" ascii wide
        $ip72 = "147.78.46.40" ascii wide
        $ip73 = "150.241.97.10" ascii wide
        $ip74 = "154.82.92.160" ascii wide
        $ip75 = "158.160.5.218" ascii wide
        $ip76 = "161.97.167.88" ascii wide
        $ip77 = "165.232.186.197" ascii wide
        $ip78 = "165.232.186.197" ascii wide
        $ip79 = "167.179.66.121" ascii wide
        $url80 = "/admin/get\.php" ascii wide nocase
        $url81 = "/login/process\.php" ascii wide nocase
        $url82 = "/news\.php" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_USH
{
    meta:
        description = "Detects IOCs associated with APT USH"
        author = "APTtrail Automated Collection"
        apt_group = "USH"
        aliases = "unfading sea haze"
        reference = "https://blogapp.bitdefender.com/labs/content/files/2024/05/Bitdefender-Report-DeepDive-creat7721-en_EN.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "adswt\.com" ascii wide nocase
        $domain1 = "airst\.giize\.com" ascii wide nocase
        $domain2 = "api\.bitdefenderupdate\.org" ascii wide nocase
        $domain3 = "api\.simpletra\.com" ascii wide nocase
        $domain4 = "auth\.bitdefenderupdate\.com" ascii wide nocase
        $domain5 = "babystats\.dnset\.com" ascii wide nocase
        $domain6 = "bit\.kozow\.com" ascii wide nocase
        $domain7 = "bitdefenderupdate\.com" ascii wide nocase
        $domain8 = "bitdefenderupdate\.org" ascii wide nocase
        $domain9 = "bomloginset\.com" ascii wide nocase
        $domain10 = "cdn\.g8z\.net" ascii wide nocase
        $domain11 = "consilium\.dnset\.com" ascii wide nocase
        $domain12 = "dns-log\.d-n-s\.org\.uk" ascii wide nocase
        $domain13 = "dns\.g8z\.net" ascii wide nocase
        $domain14 = "employee\.mywire\.org" ascii wide nocase
        $domain15 = "fc\.adswt\.com" ascii wide nocase
        $domain16 = "helpdesk\.fxnxs\.com" ascii wide nocase
        $domain17 = "images\.emldn\.com" ascii wide nocase
        $domain18 = "link\.theworkguyoo\.com" ascii wide nocase
        $domain19 = "linklab\.blinklab\.com" ascii wide nocase
        $domain20 = "loadviber\.webredirect\.org" ascii wide nocase
        $domain21 = "mail\.adswt\.com" ascii wide nocase
        $domain22 = "mail\.bomloginset\.com" ascii wide nocase
        $domain23 = "mail\.pcygphil\.com" ascii wide nocase
        $domain24 = "mail\.simpletra\.com" ascii wide nocase
        $domain25 = "mail\.theworkguyoo\.com" ascii wide nocase
        $domain26 = "manags\.twilightparadox\.com" ascii wide nocase
        $domain27 = "message\.ooguy\.com" ascii wide nocase
        $domain28 = "news\.nevuer\.com" ascii wide nocase
        $domain29 = "newy\.hifiliving\.com" ascii wide nocase
        $domain30 = "ns2\.theworkguyoo\.com" ascii wide nocase
        $domain31 = "payroll\.mywire\.org" ascii wide nocase
        $domain32 = "pcygphil\.com" ascii wide nocase
        $domain33 = "provider\.giize\.com" ascii wide nocase
        $domain34 = "rest\.redirectme\.net" ascii wide nocase
        $domain35 = "simpletra\.com" ascii wide nocase
        $domain36 = "sopho\.kozow\.com" ascii wide nocase
        $domain37 = "spcg\.lunaticfridge\.com" ascii wide nocase
        $domain38 = "theworkguyoo\.com" ascii wide nocase
        $domain39 = "upupdate\.ooguy\.com" ascii wide nocase
        $domain40 = "word\.emldn\.com" ascii wide nocase
        $ip41 = "139.180.216.33" ascii wide
        $ip42 = "139.180.221.55" ascii wide
        $ip43 = "139.59.61.42" ascii wide
        $ip44 = "142.93.80.236" ascii wide
        $ip45 = "143.198.80.75" ascii wide
        $ip46 = "146.185.136.221" ascii wide
        $ip47 = "152.89.161.26" ascii wide
        $ip48 = "154.90.34.83" ascii wide
        $ip49 = "165.22.104.184" ascii wide
        $ip50 = "165.232.84.56" ascii wide
        $ip51 = "167.99.222.58" ascii wide
        $ip52 = "178.128.19.134" ascii wide
        $ip53 = "185.195.237.114" ascii wide
        $ip54 = "185.198.57.135" ascii wide
        $ip55 = "185.244.129.60" ascii wide
        $ip56 = "185.244.130.34" ascii wide
        $ip57 = "194.5.250.54" ascii wide
        $ip58 = "206.189.153.85" ascii wide
        $ip59 = "45.32.125.175" ascii wide
        $ip60 = "68.183.185.80" ascii wide
        $ip61 = "91.235.143.251" ascii wide
        $ip62 = "95.216.63.54" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_VAJRAELEPH
{
    meta:
        description = "Detects IOCs associated with APT VAJRAELEPH"
        author = "APTtrail Automated Collection"
        apt_group = "VAJRAELEPH"
        aliases = "APT-Q-43, VajraSpy"
        reference = "https://mp.weixin.qq.com/s/B0ElRhbqLzs-wGQh79fTww (Chinese)"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "appplace\.shop" ascii wide nocase
        $domain1 = "appz\.live" ascii wide nocase
        $domain2 = "appzshare\.club" ascii wide nocase
        $domain3 = "appzshare\.digital" ascii wide nocase
        $domain4 = "apzshare\.club" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_VENOMSPIDER
{
    meta:
        description = "Detects IOCs associated with APT VENOMSPIDER"
        author = "APTtrail Automated Collection"
        apt_group = "VENOMSPIDER"
        aliases = "goldenchickens, moreeggs, revc2"
        reference = "https://app.any.run/tasks/0397179e-485a-4b4c-bfb6-8c855ad24a71/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "anuffrost\.com" ascii wide nocase
        $domain1 = "api\.cloudservers\.kz" ascii wide nocase
        $domain2 = "api\.incapdns\.kz" ascii wide nocase
        $domain3 = "api\.sharefiles\.center" ascii wide nocase
        $domain4 = "api\.totalsphere\.center" ascii wide nocase
        $domain5 = "avadgray\.org" ascii wide nocase
        $domain6 = "beta\.w3\.org\.kz" ascii wide nocase
        $domain7 = "blog\.jasonlees\.com" ascii wide nocase
        $domain8 = "boldvertex\.store" ascii wide nocase
        $domain9 = "cast\.voxcdn\.kz" ascii wide nocase
        $domain10 = "contactlistsagregator\.com" ascii wide nocase
        $domain11 = "developer\.master\.org\.kz" ascii wide nocase
        $domain12 = "dns\.hahdyman\.com" ascii wide nocase
        $domain13 = "drive\.fileio\.center" ascii wide nocase
        $domain14 = "fileio\.center" ascii wide nocase
        $domain15 = "finatick\.com" ascii wide nocase
        $domain16 = "gdrive\.rest" ascii wide nocase
        $domain17 = "incapdns\.kz" ascii wide nocase
        $domain18 = "interrafcu\.com" ascii wide nocase
        $domain19 = "jonatechlab\.com" ascii wide nocase
        $domain20 = "mail\.incapdns\.kz" ascii wide nocase
        $domain21 = "mail\.rediffmail\.kz" ascii wide nocase
        $domain22 = "maps\.doaglas\.com" ascii wide nocase
        $domain23 = "master\.org\.kz" ascii wide nocase
        $domain24 = "monstrack\.org" ascii wide nocase
        $domain25 = "nopsec\.org" ascii wide nocase
        $domain26 = "onlinemail\.kz" ascii wide nocase
        $domain27 = "pub-ee3b9adcbb354679b5c35d5210673997\.r2\.dev" ascii wide nocase
        $domain28 = "qb-hos\.pages\.dev" ascii wide nocase
        $domain29 = "report\.monicabellucci\.kz" ascii wide nocase
        $domain30 = "ryanberardi\.com" ascii wide nocase
        $domain31 = "secure\.cloudserv\.ink" ascii wide nocase
        $domain32 = "seopager\.xyz" ascii wide nocase
        $domain33 = "sharefiles\.center" ascii wide nocase
        $domain34 = "stats\.wp\.org\.kz" ascii wide nocase
        $domain35 = "swiftvantage\.online" ascii wide nocase
        $domain36 = "swissblog\.org" ascii wide nocase
        $domain37 = "tonsandmillions\.com" ascii wide nocase
        $domain38 = "tool\.municipiodechepo\.org" ascii wide nocase
        $domain39 = "totalsphere\.center" ascii wide nocase
        $domain40 = "usstaffing\.services" ascii wide nocase
        $domain41 = "vad\.totalsphere\.center" ascii wide nocase
        $domain42 = "voxcdn\.kz" ascii wide nocase
        $domain43 = "w3\.org\.kz" ascii wide nocase
        $domain44 = "waveax\.net" ascii wide nocase
        $domain45 = "wetransfers\.io" ascii wide nocase
        $domain46 = "winapi\.net" ascii wide nocase
        $domain47 = "wp\.org\.kz" ascii wide nocase
        $domain48 = "yerra\.org" ascii wide nocase
        $ip49 = "170.75.168.151" ascii wide
        $ip50 = "208.85.17.52" ascii wide
        $ip51 = "217.69.8.13" ascii wide
        $ip52 = "65.20.104.138" ascii wide
        $ip53 = "65.20.104.138" ascii wide
        $ip54 = "65.20.104.150" ascii wide
        $ip55 = "65.20.104.212" ascii wide
        $ip56 = "65.20.107.145" ascii wide
        $ip57 = "65.20.99.10" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_VICESOCIETY
{
    meta:
        description = "Detects IOCs associated with APT VICESOCIETY"
        author = "APTtrail Automated Collection"
        apt_group = "VICESOCIETY"
        aliases = "Chily, PolyVice, RedAlert"
        reference = "https://github.com/thetanz/ransomwatch/blob/main/docs/INDEX.md"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "4hzyuotli6maqa4u\.onion" ascii wide nocase
        $domain1 = "fuckcisanet5nzv4d766izugxhnqqgiyllzfynyb4whzbqhzjojbn7id\.onion" ascii wide nocase
        $domain2 = "fuckfbrlvtibsdw5rxtfjxtog6dfgpz62ewoc2rpor2s6zd5nog4zxad\.onion" ascii wide nocase
        $domain3 = "ml3mjpuhnmse4kjij7ggupenw34755y4uj7t742qf7jg5impt5ulhkid\.onion" ascii wide nocase
        $domain4 = "vsociethok6sbprvevl4dlwbqrzyhxcxaqpvcqt5belwvsuxaxsutyad\.onion" ascii wide nocase
        $domain5 = "vsocietyjynbgmz4n4lietzmqrg2tab4roxwd2c2btufdwxi6v2pptyd\.onion" ascii wide nocase
        $domain6 = "wjdgz3btk257obba7aekowz7ylm33zb6hu4aetxc3bypfajixzvx4iad\.onion" ascii wide nocase
        $domain7 = "wmp2rvrkecyx72i3x7ejhyd3yr6fn5uqo7wfus7cz7qnwr6uzhcbrwad\.onion" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_VICIOUSPANDA
{
    meta:
        description = "Detects IOCs associated with APT VICIOUSPANDA"
        author = "APTtrail Automated Collection"
        apt_group = "VICIOUSPANDA"
        aliases = "byeby, microcin, mikroceen"
        reference = "https://app.any.run/tasks/38c37dfa-b070-4b28-b475-a09763f00d8c/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "612bb\.sheetsbrandnewday\.com" ascii wide nocase
        $domain1 = "9hnvb8917gzr\.com" ascii wide nocase
        $domain2 = "adyboh\.com" ascii wide nocase
        $domain3 = "ans\.moutw\.com" ascii wide nocase
        $domain4 = "apjgtipty\.com" ascii wide nocase
        $domain5 = "app\.obokay\.com" ascii wide nocase
        $domain6 = "apps\.uzdarakchi\.com" ascii wide nocase
        $domain7 = "bestrongerlouder\.com" ascii wide nocase
        $domain8 = "bmy\.hqoohoa\.com" ascii wide nocase
        $domain9 = "bur\.vueleslie\.com" ascii wide nocase
        $domain10 = "bzz\.utakatarefrain\.com" ascii wide nocase
        $domain11 = "cloud\.googleupdating\.net" ascii wide nocase
        $domain12 = "cloud\.msseces\.com" ascii wide nocase
        $domain13 = "cloud\.systemupdating\.com" ascii wide nocase
        $domain14 = "clouds\.googleupdating\.net" ascii wide nocase
        $domain15 = "clouds\.osppsvc\.com" ascii wide nocase
        $domain16 = "compdate\.my03\.com" ascii wide nocase
        $domain17 = "credibusco\.com" ascii wide nocase
        $domain18 = "dnsrequery\.com" ascii wide nocase
        $domain19 = "dw\.adyboh\.com" ascii wide nocase
        $domain20 = "esvnpe\.com" ascii wide nocase
        $domain21 = "feb\.kkooppt\.com" ascii wide nocase
        $domain22 = "forum\.mediaok\.info" ascii wide nocase
        $domain23 = "forum\.uzdarakchi\.com" ascii wide nocase
        $domain24 = "future-hope2011\.com" ascii wide nocase
        $domain25 = "googleupdating\.net" ascii wide nocase
        $domain26 = "heroisshit\.com" ascii wide nocase
        $domain27 = "hqoohoa\.com" ascii wide nocase
        $domain28 = "jocoly\.esvnpe\.com" ascii wide nocase
        $domain29 = "kkooppt\.com" ascii wide nocase
        $domain30 = "kliju\.wulinon\.com" ascii wide nocase
        $domain31 = "log\.bestrongerlouder\.com" ascii wide nocase
        $domain32 = "mediaok\.info" ascii wide nocase
        $domain33 = "moutw\.com" ascii wide nocase
        $domain34 = "msdtcupdate\.com" ascii wide nocase
        $domain35 = "nan\.thanhale\.com" ascii wide nocase
        $domain36 = "ns\.dnsrequery\.com" ascii wide nocase
        $domain37 = "obokay\.com" ascii wide nocase
        $domain38 = "offcialwrittencomplaint\.com" ascii wide nocase
        $domain39 = "owa\.obokay\.com" ascii wide nocase
        $domain40 = "parked\.wulinon\.com" ascii wide nocase
        $domain41 = "qrot\.apjgtipty\.com" ascii wide nocase
        $domain42 = "runtime\.heroisshit\.com" ascii wide nocase
        $domain43 = "sheetsbrandnewday\.com" ascii wide nocase
        $domain44 = "systemupdating\.com" ascii wide nocase
        $domain45 = "thanhale\.com" ascii wide nocase
        $domain46 = "update\.heroisshit\.com" ascii wide nocase
        $domain47 = "utakatarefrain\.com" ascii wide nocase
        $domain48 = "uzdarakchi\.com" ascii wide nocase
        $domain49 = "vueleslie\.com" ascii wide nocase
        $ip50 = "58.64.209.84" ascii wide
        $ip51 = "58.64.209.84" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_VOIDARACHNE
{
    meta:
        description = "Detects IOCs associated with APT VOIDARACHNE"
        author = "APTtrail Automated Collection"
        apt_group = "VOIDARACHNE"
        reference = "https://www.trendmicro.com/en_us/research/24/f/behind-the-great-wall-void-arachne-targets-chinese-speaking-user.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "103\.214\.146\.34new\.webcamcn\.xyz" ascii wide nocase
        $domain1 = "103\.214\.147\.101\.webcamcn\.xyz" ascii wide nocase
        $domain2 = "103\.214\.147\.14\.webcamcn\.xyz" ascii wide nocase
        $domain3 = "11\.webcamcn\.xyz" ascii wide nocase
        $domain4 = "11new\.webcamcn\.xyz" ascii wide nocase
        $domain5 = "156\.248\.54\.11\.webcamcn\.xyz" ascii wide nocase
        $domain6 = "156\.248\.54\.11new\.webcamcn\.xyz" ascii wide nocase
        $domain7 = "248\.54\.11\.webcamcn\.xyz" ascii wide nocase
        $domain8 = "248\.54\.11new\.webcamcn\.xyz" ascii wide nocase
        $domain9 = "54\.11\.webcamcn\.xyz" ascii wide nocase
        $domain10 = "54\.11new\.webcamcn\.xyz" ascii wide nocase
        $domain11 = "98\.159\.98\.114\.webcamcn\.xyz" ascii wide nocase
        $domain12 = "hm\.webcamcn\.xyz" ascii wide nocase
        $domain13 = "hm2\.webcamcn\.xyz" ascii wide nocase
        $domain14 = "hm3\.webcamcn\.xyz" ascii wide nocase
        $domain15 = "hm4\.webcamcn\.xyz" ascii wide nocase
        $domain16 = "hm6\.webcamcn\.xyz" ascii wide nocase
        $domain17 = "hm9\.webcamcn\.xyz" ascii wide nocase
        $domain18 = "webcamcn\.xyz" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_VOIDBLIZZARD
{
    meta:
        description = "Detects IOCs associated with APT VOIDBLIZZARD"
        author = "APTtrail Automated Collection"
        apt_group = "VOIDBLIZZARD"
        aliases = "laundry bear, void blizzard"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/05/27/new-russia-affiliated-actor-void-blizzard-targets-critical-sectors-for-espionage/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "aoc-gov\.us" ascii wide nocase
        $domain1 = "app-v4-mybos\.com" ascii wide nocase
        $domain2 = "avsgroup\.au" ascii wide nocase
        $domain3 = "bidscale\.net" ascii wide nocase
        $domain4 = "defraudatubanco\.com" ascii wide nocase
        $domain5 = "deloittesharepoint\.com" ascii wide nocase
        $domain6 = "ebsum\.eu" ascii wide nocase
        $domain7 = "ebsumlts\.eu" ascii wide nocase
        $domain8 = "ebsummlt\.eu" ascii wide nocase
        $domain9 = "ebsummt\.eu" ascii wide nocase
        $domain10 = "ebsumrnit\.eu" ascii wide nocase
        $domain11 = "ebsurnmit\.eu" ascii wide nocase
        $domain12 = "enticator-secure\.com" ascii wide nocase
        $domain13 = "it-sharepoint\.com" ascii wide nocase
        $domain14 = "m-365-app\.com" ascii wide nocase
        $domain15 = "maidservant\.shop" ascii wide nocase
        $domain16 = "mail-forgot\.com" ascii wide nocase
        $domain17 = "max-linear\.com" ascii wide nocase
        $domain18 = "microffice\.org" ascii wide nocase
        $domain19 = "micsrosoftonline\.com" ascii wide nocase
        $domain20 = "miscrsosoft\.com" ascii wide nocase
        $domain21 = "myspringbank\.com" ascii wide nocase
        $domain22 = "ourbelovedsainscore\.space" ascii wide nocase
        $domain23 = "outlook-office\.micsrosoftonline\.com" ascii wide nocase
        $domain24 = "portal-microsoftonline\.com" ascii wide nocase
        $domain25 = "propescom\.com" ascii wide nocase
        $domain26 = "redronesolutions\.cloud" ascii wide nocase
        $domain27 = "refundes\.net" ascii wide nocase
        $domain28 = "remerelli\.com" ascii wide nocase
        $domain29 = "spidergov\.org" ascii wide nocase
        $domain30 = "teamsupportonline\.top" ascii wide nocase
        $domain31 = "weblogmail\.live" ascii wide nocase
        $domain32 = "x9a7lm02kqaccountprotectionaccountsecuritynoreply\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_VOLATILECEDAR
{
    meta:
        description = "Detects IOCs associated with APT VOLATILECEDAR"
        author = "APTtrail Automated Collection"
        apt_group = "VOLATILECEDAR"
        aliases = "DeftTorero, LebaneseCedar, VolatileCedar"
        reference = "https://otx.alienvault.com/pulse/633acb17ed56f34d3779a9a4"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "carima2012\.site90\.com" ascii wide nocase
        $domain1 = "dotnetexplorer\.info" ascii wide nocase
        $domain2 = "dotntexplorere\.info" ascii wide nocase
        $domain3 = "erdotntexplore\.info" ascii wide nocase
        $domain4 = "explorerdotnt\.info" ascii wide nocase
        $domain5 = "saveweb\.wink\.ws" ascii wide nocase
        $domain6 = "xploreredotnet\.info" ascii wide nocase
        $ip7 = "200.159.87.196" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_WAGEMOLE
{
    meta:
        description = "Detects IOCs associated with APT WAGEMOLE"
        author = "APTtrail Automated Collection"
        apt_group = "WAGEMOLE"
        aliases = "beavertail, invisibleferret, tropidoor"
        reference = "https://asec.ahnlab.com/en/87299/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "blocktestingto\.com" ascii wide nocase
        $domain1 = "businesshire\.top" ascii wide nocase
        $domain2 = "cestlaviewellnessretreat\.com" ascii wide nocase
        $domain3 = "file\.cestlaviewellnessretreat\.com" ascii wide nocase
        $domain4 = "files\.cestlaviewellnessretreat\.com" ascii wide nocase
        $domain5 = "files\.hirog\.io" ascii wide nocase
        $domain6 = "greenhouselc\.com" ascii wide nocase
        $domain7 = "hirog\.io" ascii wide nocase
        $domain8 = "hopanatech\.com" ascii wide nocase
        $domain9 = "huguotechltd\.com" ascii wide nocase
        $domain10 = "inditechlab\.com" ascii wide nocase
        $domain11 = "nvidiasdk\.fly\.dev" ascii wide nocase
        $domain12 = "sunlotustech\.com" ascii wide nocase
        $domain13 = "tonywangtech\.com" ascii wide nocase
        $domain14 = "usconsultinghub\.blog" ascii wide nocase
        $domain15 = "usconsultinghub\.cloud" ascii wide nocase
        $domain16 = "wkjllc\.com" ascii wide nocase
        $ip17 = "172.86.93.139" ascii wide
        $ip18 = "185.235.241.208" ascii wide
        $ip19 = "45.8.146.93" ascii wide
        $ip20 = "86.104.72.247" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_WEAKESTLINK
{
    meta:
        description = "Detects IOCs associated with APT WEAKESTLINK"
        author = "APTtrail Automated Collection"
        apt_group = "WEAKESTLINK"
        reference = "https://securelist.com/blog/incidents/77562/breaking-the-weakest-link-of-the-strongest-chain/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "androidbak\.com" ascii wide nocase
        $domain1 = "droidback\.com" ascii wide nocase
        $domain2 = "endpointup\.com" ascii wide nocase
        $domain3 = "goodydaddy\.com" ascii wide nocase
        $domain4 = "siteanalysto\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_WEBKY
{
    meta:
        description = "Detects IOCs associated with APT WEBKY"
        author = "APTtrail Automated Collection"
        apt_group = "WEBKY"
        reference = "https://researchcenter.paloaltonetworks.com/2016/05/unit42-new-wekby-attacks-use-dns-requests-as-command-and-control-mechanism/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "glb\.it-desktop\.com" ascii wide nocase
        $domain1 = "globalprint-us\.com" ascii wide nocase
        $domain2 = "hi\.getgo2\.com" ascii wide nocase
        $domain3 = "intranetwabcam\.com" ascii wide nocase
        $domain4 = "local\.it-desktop\.com" ascii wide nocase
        $domain5 = "login\.access-mail\.com" ascii wide nocase
        $domain6 = "ns1\.logitech-usa\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_WHITECOMPANY
{
    meta:
        description = "Detects IOCs associated with APT WHITECOMPANY"
        author = "APTtrail Automated Collection"
        apt_group = "WHITECOMPANY"
        reference = "https://threatvector.cylance.com/en_us/home/the-white-company-inside-the-operation-shaheen-espionage-campaign.html"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "userz\.ignorelist\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_WICKEDPANDA
{
    meta:
        description = "Detects IOCs associated with APT WICKEDPANDA"
        author = "APTtrail Automated Collection"
        apt_group = "WICKEDPANDA"
        reference = "https://app.cdn.lookbookhq.com/lbhq-production/10339/content/original/9dd0e31a-c9c0-4e1c-aea1-f35d3e930f3d/CrowdStrike_GTR_2019_.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "money\.moneyhome\.biz" ascii wide nocase
        $domain1 = "voda\.dns04\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_WINDSHIFT
{
    meta:
        description = "Detects IOCs associated with APT WINDSHIFT"
        author = "APTtrail Automated Collection"
        apt_group = "WINDSHIFT"
        reference = "https://gsec.hitb.org/materials/sg2018/D1%20COMMSEC%20-%20In%20the%20Trails%20of%20WINDSHIFT%20APT%20-%20Taha%20Karim.pdf"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "domforworld\.com" ascii wide nocase
        $domain1 = "flux2key\.com" ascii wide nocase
        $domain2 = "string2me\.com" ascii wide nocase

    condition:
        any of ($domain*, $ip*, $url*)
}

rule APT_WINTERVIVERN
{
    meta:
        description = "Detects IOCs associated with APT WINTERVIVERN"
        author = "APTtrail Automated Collection"
        apt_group = "WINTERVIVERN"
        aliases = "sharpshooter, ta473"
        reference = "https://cert.gov.ua/article/3761104"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "applicationdevsoc\.com" ascii wide nocase
        $domain1 = "bugiplaysec\.com" ascii wide nocase
        $domain2 = "centr-security\.com" ascii wide nocase
        $domain3 = "marakanas\.com" ascii wide nocase
        $domain4 = "nepalihemp\.com" ascii wide nocase
        $domain5 = "ocs-romastassec\.com" ascii wide nocase
        $domain6 = "ocsp-reloads\.com" ascii wide nocase
        $domain7 = "ocsp-report\.com" ascii wide nocase
        $domain8 = "ocspdep\.com" ascii wide nocase
        $domain9 = "oscp-avanguard\.com" ascii wide nocase
        $domain10 = "recsecas\.com" ascii wide nocase
        $domain11 = "secure-daddy\.com" ascii wide nocase
        $domain12 = "securemanage\.com" ascii wide nocase
        $domain13 = "securetourspd\.com" ascii wide nocase
        $domain14 = "security-ocsp\.com" ascii wide nocase
        $domain15 = "troadsecow\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_WIRTE
{
    meta:
        description = "Detects IOCs associated with APT WIRTE"
        author = "APTtrail Automated Collection"
        apt_group = "WIRTE"
        reference = "https://app.any.run/tasks/4c404a75-4caf-430b-a901-c18bc8fb0824/"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "allaccounting\.ca" ascii wide nocase
        $domain1 = "bankjordan\.com" ascii wide nocase
        $domain2 = "dentalaccord\.com" ascii wide nocase
        $domain3 = "dentalmatrix\.net" ascii wide nocase
        $domain4 = "doctoressolis\.com" ascii wide nocase
        $domain5 = "easybackupcloud\.com" ascii wide nocase
        $domain6 = "economymentor\.com" ascii wide nocase
        $domain7 = "economystocking\.com" ascii wide nocase
        $domain8 = "egyptican\.com" ascii wide nocase
        $domain9 = "egyptskytours\.com" ascii wide nocase
        $domain10 = "egypttourism-online\.com" ascii wide nocase
        $domain11 = "ellemedic\.com" ascii wide nocase
        $domain12 = "est-clinic\.com" ascii wide nocase
        $domain13 = "finance-analyst\.com" ascii wide nocase
        $domain14 = "financecovers\.com" ascii wide nocase
        $domain15 = "financeinfoguide\.com" ascii wide nocase
        $domain16 = "firstohiobank\.com" ascii wide nocase
        $domain17 = "foxlove\.life" ascii wide nocase
        $domain18 = "healthcarb\.com" ascii wide nocase
        $domain19 = "healthoptionstoday\.com" ascii wide nocase
        $domain20 = "healthscratches\.com" ascii wide nocase
        $domain21 = "imagine-world\.com" ascii wide nocase
        $domain22 = "jordanrefugees\.com" ascii wide nocase
        $domain23 = "jordansons\.com" ascii wide nocase
        $domain24 = "king-pharmacy\.com" ascii wide nocase
        $domain25 = "kneeexercises\.net" ascii wide nocase
        $domain26 = "master-dental\.com" ascii wide nocase
        $domain27 = "micorsoft\.store" ascii wide nocase
        $domain28 = "microsoftliveforums\.com" ascii wide nocase
        $domain29 = "microsoftteams365\.com" ascii wide nocase
        $domain30 = "microsoftwindowshelp\.com" ascii wide nocase
        $domain31 = "neweconomysolution\.com" ascii wide nocase
        $domain32 = "niftybuysellchart\.com" ascii wide nocase
        $domain33 = "nutrition-information\.org" ascii wide nocase
        $domain34 = "office-update\.services" ascii wide nocase
        $domain35 = "office365-update\.co" ascii wide nocase
        $domain36 = "office365-update\.com" ascii wide nocase
        $domain37 = "omegaeyehospital\.com" ascii wide nocase
        $domain38 = "pocket-property\.com" ascii wide nocase
        $domain39 = "printspoolerupdates\.com" ascii wide nocase
        $domain40 = "qrdorks\.com" ascii wide nocase
        $domain41 = "saudiarabianow\.org" ascii wide nocase
        $domain42 = "saudiday\.org" ascii wide nocase
        $domain43 = "share2file\.pro" ascii wide nocase
        $domain44 = "stgeorgebankers\.com" ascii wide nocase
        $domain45 = "sun-tourist\.com" ascii wide nocase
        $domain46 = "suppertools\.com" ascii wide nocase
        $domain47 = "support-api\.financecovers\.com" ascii wide nocase
        $domain48 = "thefinanceinvest\.com" ascii wide nocase
        $domain49 = "theshortner\.com" ascii wide nocase
        $ip50 = "104.24.108.64" ascii wide
        $ip51 = "104.24.109.64" ascii wide
        $ip52 = "104.28.1.134" ascii wide
        $ip53 = "172.86.75.211" ascii wide
        $ip54 = "185.86.79.243" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_WUQIONGDONG
{
    meta:
        description = "Detects IOCs associated with APT WUQIONGDONG"
        author = "APTtrail Automated Collection"
        apt_group = "WUQIONGDONG"
        aliases = "apt-c-59, apt-q-11, shadowtiger"
        reference = "https://mp-weixin-qq-com.translate.goog/s/jX8D8d-4q46pKHS0AIVgjw?_x_tr_sl=zh-CN&_x_tr_tl=en&_x_tr_hl=zh-CN&_x_tr_pto=wapp"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "blue\.chinfoset\.com" ascii wide nocase
        $domain1 = "cchiwa\.com" ascii wide nocase
        $domain2 = "chinfoset\.com" ascii wide nocase
        $domain3 = "cloud\.unite\.un\.org\.docs-verify\.com" ascii wide nocase
        $domain4 = "common\.js\.ftp\.sh" ascii wide nocase
        $domain5 = "data\.cchiwa\.com" ascii wide nocase
        $domain6 = "datasectioninfo\.com" ascii wide nocase
        $domain7 = "docs-verify\.com" ascii wide nocase
        $domain8 = "guest-mailclouds\.com" ascii wide nocase
        $domain9 = "hao\.360\.mooo\.com" ascii wide nocase
        $domain10 = "helpdesk-mailservice\.com" ascii wide nocase
        $domain11 = "itoxtlthpw\.com" ascii wide nocase
        $domain12 = "lion\.waitnetwork\.net" ascii wide nocase
        $domain13 = "mail-drivecenter\.com" ascii wide nocase
        $domain14 = "mail-hostfile\.com" ascii wide nocase
        $domain15 = "mail\.datasectioninfo\.com" ascii wide nocase
        $domain16 = "microsoft\.ccivde\.com" ascii wide nocase
        $domain17 = "morning-place\.com" ascii wide nocase
        $domain18 = "ms0ffice\.guest-mailclouds\.com" ascii wide nocase
        $domain19 = "netease\.mail-drivecenter\.com" ascii wide nocase
        $domain20 = "netease\.smartsystem36\.com" ascii wide nocase
        $domain21 = "oversea-cnki\.net" ascii wide nocase
        $domain22 = "service-hq\.com" ascii wide nocase
        $domain23 = "smartsystem36\.com" ascii wide nocase
        $domain24 = "waitnetwork\.net" ascii wide nocase
        $ip25 = "37.120.140.233" ascii wide
        $ip26 = "62.112.8.79" ascii wide
        $ip27 = "66.70.220.100" ascii wide
        $ip28 = "88.150.227.110" ascii wide

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_XDSPY
{
    meta:
        description = "Detects IOCs associated with APT XDSPY"
        author = "APTtrail Automated Collection"
        apt_group = "XDSPY"
        aliases = "xdigo"
        reference = "https://cert.by/?p=1458 (Russian)"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "365downloading\.com" ascii wide nocase
        $domain1 = "aoc-upravleniye\.com" ascii wide nocase
        $domain2 = "best-downloader\.com" ascii wide nocase
        $domain3 = "boborux\.com" ascii wide nocase
        $domain4 = "bukhgalter-x5group\.com" ascii wide nocase
        $domain5 = "bystryvelosiped\.com" ascii wide nocase
        $domain6 = "cellporyad\.com" ascii wide nocase
        $domain7 = "chistyyvozdukh\.com" ascii wide nocase
        $domain8 = "chtcc\.net" ascii wide nocase
        $domain9 = "cracratutu\.com" ascii wide nocase
        $domain10 = "daftsync\.com" ascii wide nocase
        $domain11 = "documentsklad\.com" ascii wide nocase
        $domain12 = "doverennyye-fayly\.com" ascii wide nocase
        $domain13 = "download-365\.com" ascii wide nocase
        $domain14 = "download24center\.com" ascii wide nocase
        $domain15 = "downloading24\.com" ascii wide nocase
        $domain16 = "downloadsprimary\.com" ascii wide nocase
        $domain17 = "dropsklad\.com" ascii wide nocase
        $domain18 = "dversteklo\.com" ascii wide nocase
        $domain19 = "dwd765m\.com" ascii wide nocase
        $domain20 = "easy-download24\.com" ascii wide nocase
        $domain21 = "easytosay\.org" ascii wide nocase
        $domain22 = "fakturaaa\.com" ascii wide nocase
        $domain23 = "faylbox365\.com" ascii wide nocase
        $domain24 = "faylsklad\.com" ascii wide nocase
        $domain25 = "ferrariframework\.com" ascii wide nocase
        $domain26 = "file-bazar\.com" ascii wide nocase
        $domain27 = "file-download\.org" ascii wide nocase
        $domain28 = "file-magazin\.com" ascii wide nocase
        $domain29 = "filedownload\.email" ascii wide nocase
        $domain30 = "full-downloader\.com" ascii wide nocase
        $domain31 = "getthatupdate\.com" ascii wide nocase
        $domain32 = "global-downloader\.com" ascii wide nocase
        $domain33 = "jerseygameengine\.com" ascii wide nocase
        $domain34 = "just-downloads\.com" ascii wide nocase
        $domain35 = "khitrayalisitsa\.com" ascii wide nocase
        $domain36 = "khoroshayamych\.com" ascii wide nocase
        $domain37 = "kletchatayarubashka\.com" ascii wide nocase
        $domain38 = "krasnayastena\.com" ascii wide nocase
        $domain39 = "laultrachunk\.com" ascii wide nocase
        $domain40 = "magnitgroup\.com" ascii wide nocase
        $domain41 = "maiwegwurst\.com" ascii wide nocase
        $domain42 = "melodicprogress\.com" ascii wide nocase
        $domain43 = "migration-info\.com" ascii wide nocase
        $domain44 = "minisnowhair\.com" ascii wide nocase
        $domain45 = "moy-fayl\.com" ascii wide nocase
        $domain46 = "moy-pdf\.com" ascii wide nocase
        $domain47 = "my1businessconnection\.com" ascii wide nocase
        $domain48 = "nevynosimayapchela\.com" ascii wide nocase
        $domain49 = "nniir\.com" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

rule APT_XPATH
{
    meta:
        description = "Detects IOCs associated with APT XPATH"
        author = "APTtrail Automated Collection"
        apt_group = "XPATH"
        reference = "https://github.com/DoctorWebLtd/malware-iocs/blob/master/APT_XPath/README.adoc"
        severity = "high"
        tlp = "white"

    strings:
        $domain0 = "dns03\.cainformations\.com" ascii wide nocase
        $domain1 = "kkkfaster\.jumpingcrab\.com" ascii wide nocase
        $domain2 = "nicodonald\.accesscam\.org" ascii wide nocase
        $domain3 = "pneword\.net" ascii wide nocase
        $domain4 = "sultris\.com" ascii wide nocase
        $domain5 = "tv\.teldcomtv\.com" ascii wide nocase
        $domain6 = "v\.nnncity\.xyz" ascii wide nocase

    condition:
        2 of ($domain*, $ip*, $url*)
}

