const main = (config) => {

  // ================================================================
  // FlClash / Mihomo Perfect-Rules v1.0
  //
  // Architecture:
  //
  //   Airport Subscription
  //          ↓
  //   Keep Airport Proxy Nodes Only
  //          ↓
  //   Perfect-Rules Groups Only
  //          ↓
  //   Dynamic Region Groups
  //          ↓
  //   Perfect-Rules Service Groups
  //          ↓
  //   Remote Rule Providers
  //
  // ================================================================


  // ================================================================
  // 1. Basic configuration
  // ================================================================

  config["mixed-port"] = 7890;

  config["mode"] = "rule";

  config["unified-delay"] = true;

  config["tcp-concurrent"] = true;

  config["log-level"] = "error";

  // Disable IPv6 to prevent IPv4 / IPv6 exit mismatch.
  config["ipv6"] = false;

  config["allow-lan"] = false;

  config["find-process-mode"] = "always";

  config["keep-alive-interval"] = 30;

  config["keep-alive-idle"] = 30;

  config["disable-keep-alive"] = false;


  // ================================================================
  // 2. Profile
  // ================================================================

  config["profile"] = {
    "store-selected": true,
    "store-fake-ip": true
  };


  // ================================================================
  // 3. DNS
  // ================================================================

  config["dns"] = {

    "enable": true,

    "listen": "0.0.0.0:53",

    "prefer-h3": false,

    "ipv6": false,

    "enhanced-mode": "fake-ip",

    "fake-ip-range": "172.19.0.1/16",

    "fake-ip-filter": [
      "+.lan",
      "+.local",
      "+.localhost",
      "+.home.arpa",

      "time.*.com",
      "time.*.gov",
      "pool.ntp.org",

      "+.push.apple.com",

      "mesu.apple.com",
      "swscan.apple.com",

      "captive.apple.com",

      "connectivitycheck.gstatic.com",

      "connectivitycheck.android.com",

      "www.msftconnecttest.com",

      "www.msftncsi.com"
    ],

    "default-nameserver": [
      "223.5.5.5",
      "119.29.29.29"
    ],

    "nameserver": [
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ],

    "nameserver-policy": {

      "geosite:cn": [
        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query"
      ],

      "geosite:private": [
        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query"
      ],

      "geolocation-!cn": [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/dns-query"
      ]

    },

    "proxy-server-nameserver": [
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ],

    "direct-nameserver": [
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ],

    "fallback": [
      "https://cloudflare-dns.com/dns-query",
      "https://dns.google/dns-query"
    ],

    "fallback-filter": {

      "geoip": true,

      "geoip-code": "CN",

      "geosite": [
        "gfw"
      ],

      "domain": [
        "+.google.com",
        "+.googleapis.com",
        "+.googlevideo.com",
        "+.youtube.com",
        "+.github.com",
        "+.openai.com",
        "+.chatgpt.com",
        "+.anthropic.com",
        "+.claude.ai"
      ]

    }

  };


  // ================================================================
  // 4. TUN
  // ================================================================

  config["tun"] = {

    "enable": true,

    "device": "FlClash",

    "stack": "gvisor",

    "dns-hijack": [
      "0.0.0.0:53"
    ],

    "auto-route": true,

    "auto-detect-interface": false,

    "strict-route": true,

    "mtu": 1280,

    "inet4-address": [
      "172.19.0.1/30"
    ],

    "auto-redirect": false,

    "disable-icmp-forwarding": true

  };


  // ================================================================
  // 5. Sniffer
  // ================================================================

  config["sniffer"] = {

    "enable": true,

    "parse-pure-ip": true,

    "force-dns-mapping": true,

    "override-destination": true,

    "sniff": {

      "HTTP": {
        "ports": [
          80,
          "8080-8880"
        ]
      },

      "TLS": {
        "ports": [
          443,
          8443
        ]
      },

      "QUIC": {
        "ports": [
          443,
          8443
        ]
      }

    },

    "skip-domain": [
      "+.push.apple.com",
      "+.mijia.cloud"
    ]

  };


  // ================================================================
  // 6. NTP
  // ================================================================

  config["ntp"] = {

    "enable": true,

    "write-to-system": false,

    "server": "time.apple.com",

    "port": 123,

    "interval": 30

  };


  // ================================================================
  // 7. Original airport proxies
  // ================================================================

  const originalProxies = Array.isArray(config["proxies"])
    ? config["proxies"]
    : [];

  const proxyNames = [];

  originalProxies.forEach((proxy) => {

    if (proxy && proxy.name) {
      proxyNames.push(proxy.name);
    }

  });


  // ================================================================
  // 8. Filter informational pseudo-nodes
  // ================================================================

  // Subscription providers may expose traffic, expiry, announcement, or
  // account-information entries as if they were proxy nodes. Exclude only
  // clearly informational names from generated groups.
  function isInformationalNodeName(name) {
    if (!name) return true;

    const text = String(name).toLowerCase();

    const patterns = [
      /剩余流量/,
      /已用流量/,
      /流量统计/,
      /流量(?:查询|信息|用量|重置|剩余|已用|总量)/,
      /套餐.{0,8}(?:到期|过期|有效期|详情|余量)/,
      /(?:到期|过期|有效期).{0,8}(?:时间|日期|提醒|通知|套餐)/,
      /公告/,
      /通知/,
      /使用说明/,
      /使用须知/,
      /账号信息/,
      /账户信息/,
      /订阅信息/,
      /官网(?:地址|链接)?/,
      /群(?:组)?(?:号|链接|通知|公告)/,
      /(?:remaining|used|total)[\s_-]*(?:traffic|data)|(?:traffic|data)[\s_-]*(?:remaining|used|stats|usage|reset|left)/,
      /(?:expire|expiration|expiry).{0,12}(?:date|time|plan|subscription)/,
      /(?:plan|subscription).{0,12}(?:expire|expiration|expiry)/,
      /announcement/,
      /usage instructions/
    ];

    return patterns.some((pattern) => pattern.test(text));
  }

  const usableProxies = originalProxies.filter((proxy) => {
    return proxy && proxy.name && !isInformationalNodeName(proxy.name);
  });

  const usableProxyNames = usableProxies.map((proxy) => proxy.name);

  // ================================================================
  // 8. Airport proxy groups are intentionally discarded.
  //    Only actual proxy nodes are used to build new groups below.
  // ================================================================


  // ================================================================
  // 9. Perfect-Rules icon CDN
  // ================================================================

  const iconBaseURL =
    "https://cdn.jsdelivr.net/gh/n0de-sudo/Perfect-Rules@main/Clash/icons/";


  const groupIcons = {

    "Final": "Proxy.png",

    "国内直连": "China.png",

    "AI": "AI.png",

    "YouTube": "YouTube.png",

    "Google": "Google.png",

    "GitHub": "GitHub.png",

    "网络检测": "Network-test.png",

    "Netflix": "Netflix.png",

    "Spotify": "Spotify.png",

    "Steam": "Steam.png",

    "Telegram": "Telegram.png",

    "TikTok": "TikTok.png",

    "Apple": "Apple.png",

    "Microsoft": "Microsoft.png",

    "香港": "Hong_Kong.png",

    "台湾": "Taiwan.png",

    "日本": "Japan.png",

    "新加坡": "Singapore.png",

    "韩国": "Korea.png",

    "美国": "United_States.png",

    "加拿大": "Other.png",

    "英国": "Other.png",

    "其他地区": "Other.png"

  };


  function getGroupIcon(name) {

    if (!groupIcons[name]) {
      return undefined;
    }

    return iconBaseURL + groupIcons[name];

  }


  // ================================================================
  // 10. Managed groups
  // ================================================================

  const managedGroups = {

    "Final": true,

    "Proxy": true,

    "国内直连": true,

    "AI": true,

    "YouTube": true,

    "Google": true,

    "GitHub": true,

    "网络检测": true,

    "Netflix": true,

    "Spotify": true,

    "Steam": true,

    "Telegram": true,

    "TikTok": true,

    "Apple": true,

    "Microsoft": true,

    "香港": true,

    "台湾": true,

    "日本": true,

    "新加坡": true,

    "韩国": true,

    "美国": true,

    "加拿大": true,

    "英国": true,

    "其他地区": true

  };


  // ================================================================
  // 11. Built-in targets
  // ================================================================

  const builtinTargets = {

    "DIRECT": true,

    "REJECT": true,

    "REJECT-DROP": true,

    "PASS": true,

    "COMPATIBLE": true,

    "GLOBAL": true

  };


  // ================================================================
  // 12. Business group detection
  // ================================================================

  function isBusinessGroupName(name) {

    if (!name) {
      return false;
    }

    const text = String(name);

    const patterns = [

      /ai/i,
      /openai/i,
      /chatgpt/i,
      /claude/i,
      /gemini/i,

      /netflix/i,
      /disney/i,
      /disney\+/i,

      /youtube/i,
      /google/i,
      /github/i,

      /spotify/i,
      /steam/i,
      /tiktok/i,
      /telegram/i,

      /twitter/i,
      /x\.com/i,
      /facebook/i,
      /instagram/i,

      /流媒体/i,
      /媒体/i,
      /影音/i,
      /视频/i,

      /游戏/i,
      /游戏专用/i,

      /机场专用/i,
      /节点分流/i

    ];

    for (let i = 0; i < patterns.length; i++) {

      if (patterns[i].test(text)) {
        return true;
      }

    }

    return false;

  }


  // ================================================================
  // 13. Auto-select detection
  // ================================================================

  function isAutoSelectGroup(name) {

    if (!name) {
      return false;
    }

    return (

      /自动选择/i.test(name) ||

      /auto[\s_-]*select/i.test(name) ||

      /auto[\s_-]*test/i.test(name) ||

      /测速/i.test(name)

    );

  }


  // ================================================================
  // 14. Failover detection
  // ================================================================

  function isFailoverGroup(name) {

    if (!name) {
      return false;
    }

    return (

      /故障转移/i.test(name) ||

      /failover/i.test(name) ||

      /fallback/i.test(name)

    );

  }


  // ================================================================
  // 15-18. Discard all airport-provided proxy groups
  //
  // The subscription supplies proxy nodes only. All proxy groups are
  // rebuilt below by Perfect-Rules; no airport group is preserved.
  // ================================================================


  // ================================================================
  // 19. Remote Rule Provider base URL
  // ================================================================

  const ruleBaseURL =
    "https://cdn.jsdelivr.net/gh/n0de-sudo/Perfect-Rules@main/Clash/rules/";


  // ================================================================
  // 20. Rule Provider factory
  // ================================================================

  function createRuleProvider(filename) {

    return {

      "type": "http",

      "behavior": "classical",

      "format": "yaml",

      "url": ruleBaseURL + filename,

      "path": "./rules/" + filename,

      "interval": 86400

    };

  }


  // ================================================================
  // 21. Remote Rule Providers
  // ================================================================

  config["rule-providers"] = {

    "AI":
      createRuleProvider("ai.yaml"),

    "YouTube":
      createRuleProvider("youtube.yaml"),

    "Google":
      createRuleProvider("google.yaml"),

    "GitHub":
      createRuleProvider("github.yaml"),

    "Netflix":
      createRuleProvider("netflix.yaml"),

    "Spotify":
      createRuleProvider("spotify.yaml"),

    "Steam":
      createRuleProvider("steam.yaml"),

    "Telegram":
      createRuleProvider("telegram.yaml"),

    "TikTok":
      createRuleProvider("tiktok.yaml"),

    "Apple":
      createRuleProvider("apple.yaml"),

    "Microsoft":
      createRuleProvider("microsoft.yaml"),

    "NetworkTest":
      createRuleProvider("network-test.yaml")

  };


  // ================================================================
  // 22. Region detection
  // ================================================================

  const regionPatterns = {

    "香港": [

      /香港/i,
      /\bHK\b/i,
      /HKG/i,
      /Hong\s*Kong/i,
      /HongKong/i

    ],


    "台湾": [

      /台湾/i,
      /台灣/i,
      /\bTW\b/i,
      /TPE/i,
      /KHH/i,
      /TSA/i,
      /Taiwan/i,
      /Taipei/i

    ],


    "日本": [

      /日本/i,
      /\bJP\b/i,
      /NRT/i,
      /HND/i,
      /KIX/i,
      /CTS/i,
      /FUK/i,
      /Japan/i,
      /Tokyo/i,
      /Osaka/i

    ],


    "新加坡": [

      /新加坡/i,
      /\bSG\b/i,
      /SIN/i,
      /XSP/i,
      /Singapore/i

    ],


    "韩国": [

      /韩国/i,
      /韓國/i,
      /\bKR\b/i,
      /ICN/i,
      /GMP/i,
      /PUS/i,
      /Korea/i,
      /Seoul/i

    ],


    "美国": [

      /美国/i,
      /\bUS\b/i,
      /\bUSA\b/i,
      /LAX/i,
      /SFO/i,
      /JFK/i,
      /SJC/i,
      /United\s*States/i,
      /America/i,
      /Los\s*Angeles/i,
      /San\s*Jose/i,
      /New\s*York/i

    ],


    "加拿大": [

      /加拿大/i,
      /Canada/i,
      /Toronto/i,
      /Vancouver/i,
      /Montreal/i

    ],


    "英国": [

      /英国/i,
      /UK/i,
      /United\s*Kingdom/i,
      /England/i,
      /London/i,
      /Manchester/i

    ]

  };


  function detectRegion(proxyName) {

    for (const region in regionPatterns) {

      if (
        !Object.prototype.hasOwnProperty.call(
          regionPatterns,
          region
        )
      ) {
        continue;
      }


      const patterns =
        regionPatterns[region];


      for (let i = 0; i < patterns.length; i++) {

        if (patterns[i].test(proxyName)) {
          return region;
        }

      }

    }


    return "其他地区";

  }


  // ================================================================
  // 23. Build region node lists
  // ================================================================

  const regionNodes = {

    "香港": [],

    "台湾": [],

    "日本": [],

    "新加坡": [],

    "韩国": [],

    "美国": [],

    "加拿大": [],

    "英国": [],

    "其他地区": []

  };


  usableProxies.forEach((proxy) => {

    const region =
      detectRegion(String(proxy.name));


    regionNodes[region].push(
      proxy.name
    );

  });


  // ================================================================
  // 24. Region order
  // ================================================================

  const regionOrder = [

    "香港",

    "台湾",

    "日本",

    "新加坡",

    "韩国",

    "美国",

    "加拿大",

    "英国",

    "其他地区"

  ];


  // ================================================================
  // 25. Create manual region Select groups
  // ================================================================

  const regionGroups = [];


  regionOrder.forEach((region) => {

    const nodes =
      regionNodes[region];


    if (
      !nodes ||
      nodes.length === 0
    ) {
      return;
    }


    const group = {

      "name": region,

      "type": "select",

      "proxies": nodes

    };


    const icon =
      getGroupIcon(region);


    if (icon) {
      group["icon"] = icon;
    }


    regionGroups.push(group);

  });


  const availableRegions =
    regionGroups.map((group) => {

      return group.name;

    });


  // ================================================================
  // 26. Default node selector
  // ================================================================

  const defaultGroup = {

    "name": "Proxy",

    "type": "select",

    "proxies": usableProxyNames.slice()

  };


  // ================================================================
  // 26. Domestic Direct
  // ================================================================

  const domesticDirectGroup = {

    "name": "国内直连",

    "type": "select",

    "proxies": [
      "DIRECT"
    ]

  };


  const domesticIcon =
    getGroupIcon("国内直连");


  if (domesticIcon) {

    domesticDirectGroup["icon"] =
      domesticIcon;

  }


  // ================================================================
  // 27. Stray Traffic (fallback selector)
  // ================================================================

  const mainSelector = {

    "name": "Final",

    "type": "select",

    "proxies":
      ["Proxy"].concat(availableRegions, [
        "国内直连"
      ])

  };


  const mainIcon =
    getGroupIcon("Final");


  if (mainIcon) {

    mainSelector["icon"] =
      mainIcon;

  }


  // ================================================================
  // 28. Service groups
  // ================================================================

  function createBusinessGroup(name) {

    const group = {

      "name": name,

      "type": "select",

      "proxies":
        ["Proxy"].concat(availableRegions, [
          "国内直连"
        ])

    };


    const icon =
      getGroupIcon(name);


    if (icon) {
      group["icon"] = icon;
    }


    return group;

  }


  const businessGroups = [

    createBusinessGroup("AI"),

    createBusinessGroup("YouTube"),

    createBusinessGroup("Google"),

    createBusinessGroup("GitHub"),

    createBusinessGroup("Netflix"),

    createBusinessGroup("Spotify"),

    createBusinessGroup("Steam"),

    createBusinessGroup("Telegram"),

    createBusinessGroup("TikTok"),

    createBusinessGroup("Apple"),

    createBusinessGroup("Microsoft"),

    createBusinessGroup("网络检测")

  ];


  // ================================================================
  // 29. Final proxy-group architecture
  //
  //   Default node selector
  //          ↓
  //   Perfect-Rules service groups
  //          ↓
  //   Stray Traffic selector (after Microsoft)
  //          ↓
  //   Perfect-Rules region groups
  //          ↓
  //   Domestic Direct
  //
  // ================================================================

  const businessGroupsBeforeMicrosoft = businessGroups.filter((group) => {
    return group.name !== "Microsoft" && group.name !== "网络检测";
  });

  const microsoftGroup = businessGroups.find((group) => {
    return group.name === "Microsoft";
  });

  const networkTestGroup = businessGroups.find((group) => {
    return group.name === "网络检测";
  });

  config["proxy-groups"] =

    [defaultGroup]

      .concat(businessGroupsBeforeMicrosoft.filter((group) => {
        return group.name !== "Microsoft";
      }))

      .concat(microsoftGroup ? [microsoftGroup] : [])

      .concat([mainSelector])

      .concat(networkTestGroup ? [networkTestGroup] : [])

      .concat(regionGroups)

      .concat([domesticDirectGroup]);


  // ================================================================
  // 30. Routing rules
  //
  // Rule Provider order:
  //
  // NetworkTest
  // AI
  // YouTube
  // Google
  // GitHub
  // Netflix
  // Spotify
  // Steam
  // Telegram
  // TikTok
  // Apple
  // Microsoft
  // Private
  // China
  // MATCH
  //
  // YouTube MUST be before Google.
  //
  // ================================================================

  config["rules"] = [

    // --------------------------------------------------------------
    // Private / LAN
    // --------------------------------------------------------------

    "DOMAIN-SUFFIX,lan,DIRECT",

    "DOMAIN-SUFFIX,local,DIRECT",

    "DOMAIN-SUFFIX,localhost,DIRECT",

    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",

    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",

    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",

    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",


    // --------------------------------------------------------------
    // Network Test
    // --------------------------------------------------------------

    "RULE-SET,NetworkTest,网络检测",


    // --------------------------------------------------------------
    // AI
    // --------------------------------------------------------------

    "RULE-SET,AI,AI",


    // --------------------------------------------------------------
    // YouTube
    // --------------------------------------------------------------

    "RULE-SET,YouTube,YouTube",


    // --------------------------------------------------------------
    // Google
    // --------------------------------------------------------------

    "RULE-SET,Google,Google",


    // --------------------------------------------------------------
    // GitHub
    // --------------------------------------------------------------

    "RULE-SET,GitHub,GitHub",


    // --------------------------------------------------------------
    // Netflix
    // --------------------------------------------------------------

    "RULE-SET,Netflix,Netflix",


    // --------------------------------------------------------------
    // Spotify
    // --------------------------------------------------------------

    "RULE-SET,Spotify,Spotify",


    // --------------------------------------------------------------
    // Steam
    // --------------------------------------------------------------

    "RULE-SET,Steam,Steam",


    // --------------------------------------------------------------
    // Telegram
    // --------------------------------------------------------------

    "RULE-SET,Telegram,Telegram",


    // --------------------------------------------------------------
    // TikTok
    // --------------------------------------------------------------

    "RULE-SET,TikTok,TikTok",


    // --------------------------------------------------------------
    // Apple
    // --------------------------------------------------------------

    "RULE-SET,Apple,Apple",


    // --------------------------------------------------------------
    // Microsoft
    // --------------------------------------------------------------

    "RULE-SET,Microsoft,Microsoft",


    // --------------------------------------------------------------
    // Private
    // --------------------------------------------------------------

    "GEOSITE,private,国内直连",

    "GEOIP,private,国内直连,no-resolve",


    // --------------------------------------------------------------
    // China
    // --------------------------------------------------------------

    "GEOSITE,cn,国内直连",

    "GEOIP,cn,国内直连,no-resolve",


    // --------------------------------------------------------------
    // Final
    // --------------------------------------------------------------

    "MATCH,Final"

  ];


  // ================================================================
  // 31. Return generated config
  // ================================================================

  return config;

};