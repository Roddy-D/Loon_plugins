const IPPURE_URL = "https://my.ippure.com/v1/info";
const IPV4_API = "http://ip-api.com/json?lang=zh-CN";
const IPAPI_IS_URL = "https://api.ipapi.is/";
 
// 从环境参数获取节点名
const nodeName = $environment.params.node;
const maskIP = $persistentStore.read("MaskIP") === "true";

// 掩码函数
function maskIpAddress(ip) {
  if (!maskIP || !ip) return ip;
  // 处理 IPv4
  const parts = String(ip).split(".");
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.*.*`;
  }
  // 处理 IPv6
  if (ip.includes(":")) {
    const v6parts = ip.split(":");
    if (v6parts.length >= 4) {
      return `${v6parts.slice(0, 4).join(":")}:*`;
    }
  }
  return ip;
}

function httpGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    $httpClient.get({ url, node: nodeName, headers }, (err, resp, data) => {
      if (err) return reject(err);
      if (!data) return reject(new Error("empty response"));
      resolve({ resp, data });
    });
  });
}

function safeJsonParse(s) {
  try {
    return JSON.parse(s);
  } catch (_) {
    return null;
  }
}

function toInt(v) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.round(n) : null;
}


function severityMeta(sev) {
  if (sev >= 4) return { icon: "xmark.octagon.fill", color: "#8E0000" };
  if (sev >= 3) return { icon: "exclamationmark.triangle.fill", color: "#FF3B30" };
  if (sev >= 2) return { icon: "exclamationmark.circle.fill", color: "#FF9500" };
  if (sev >= 1) return { icon: "exclamationmark.circle", color: "#FFCC00" };
  return { icon: "checkmark.seal.fill", color: "#34C759" };
}



function gradeIppure(score) {
  const s = toInt(score);
  if (s === null) return { sev: 2, text: "IPPure：获取失败" };
  if (s >= 80) return { sev: 4, text: `IPPure：🛑 极高风险 (${s})` };
  if (s >= 70) return { sev: 3, text: `IPPure：⚠️ 高风险 (${s})` };
  if (s >= 40) return { sev: 1, text: `IPPure：🔶 中等风险 (${s})` };
  return { sev: 0, text: `IPPure：✅ 低风险 (${s})` };
}

// ipapi.is
function gradeIpapi(j) {
  if (!j || typeof j !== "object" || !("ip" in j)) {
    return { sev: 2, text: "ipapi：获取失败" };
  }

  const items = [];
  if (j.is_proxy === true) items.push("Proxy");
  if (j.is_vpn === true) items.push("VPN");
  if (j.is_tor === true) items.push("Tor");
  if (j.is_abuser === true) items.push("Abuser");
  if (j.is_datacenter === true) items.push("Datacenter");

  if (items.length === 0) {
    return { sev: 0, text: "ipapi：✅ 低风险（无标记）" };
  }

  const sev = j.is_abuser || j.is_tor ? 3 : items.length >= 2 ? 2 : 1;
  const label = sev >= 3 ? "⚠️ 高风险" : sev >= 2 ? "🔶 较高风险" : "🔶 有标记";
  return { sev, text: `ipapi：${label} (${items.join("/")})` };
}

// IP2Location.io
function parseIp2locationIo(data) {
  if (!data) return {
    usageType: null, fraudScore: null, isProxy: false, proxyType: "-", threat: "-",
    country: null, countryCode: null, city: null, asn: null, asOrg: null
  };
  const usageType = data.as_usage_type || null;
  const fraudScore = data.fraud_score ?? null;
  const isProxy = data.is_proxy || false;
  const proxyType = data.proxy_type || "-";
  const threat = data.threat || "-";
  const country = data.country || null;
  const countryCode = data.country_code || null;
  const city = data.city || null;
  const asn = data.asn || null;
  const asOrg = data.as_org || null;
  return { usageType, fraudScore, isProxy, proxyType, threat, country, countryCode, city, asn, asOrg };
}

function gradeIp2locationIo(fraudScore) {
  const s = toInt(fraudScore);
  if (s === null) return { sev: -1, text: null };
  if (s >= 66) return { sev: 3, text: `IP2Location.io：⚠️ 高风险 (${s})` };
  if (s >= 33) return { sev: 1, text: `IP2Location.io：🔶 中风险 (${s})` };
  return { sev: 0, text: `IP2Location.io：✅ 低风险 (${s})` };
}

function ip2locationHostingText(usageType) {
  const source = "（来源:IP2Location）";
  if (!usageType) return `IP类型：未知（获取失败）${source}`;

  // 类型映射表
  const typeMap = {
    "DCH": "🏢 数据中心/服务器",
    "WEB": "🏢 数据中心/服务器",
    "SES": "🏢 数据中心/服务器",
    "CDN": "🌐 CDN",
    "MOB": "📱 蜂窝移动网络",
    "ISP": "🏠 家庭宽带",
    "COM": "🏬 商业宽带",
    "EDU": "🎓 教育网络",
    "GOV": "🏛️ 政府网络",
    "MIL": "🎖️ 军用网络",
    "ORG": "🏢 组织机构",
    "RES": "🏠 住宅网络",
  };

  // 按 / 分割，支持 ISP/MOB 等复合类型
  const parts = String(usageType).toUpperCase().split("/");
  const descriptions = [];

  for (const part of parts) {
    const desc = typeMap[part];
    if (desc && !descriptions.includes(desc)) {
      descriptions.push(desc);
    }
  }

  if (descriptions.length === 0) {
    return `IP类型：❓ ${usageType} ${source}`;
  }

  return `IP类型：${descriptions.join(" / ")} (${usageType}) ${source}`;
}

// 判断 IP 类型是否有风险（数据中心/商业等）
function isRiskyUsageType(usageType) {
  if (!usageType) return false;
  const riskyTypes = ["DCH", "WEB", "SES", "COM", "CDN"];
  const parts = String(usageType).toUpperCase().split("/");
  return parts.some(part => riskyTypes.includes(part));
}

// DB-IP
function gradeDbip(html) {
  if (!html) return { sev: 2, text: "DB-IP：获取失败" };
  const riskTextMatch = html.match(/Estimated threat level for this IP address is\s*<span[^>]*>\s*([^<\s]+)\s*</i);
  const riskText = (riskTextMatch ? riskTextMatch[1] : "").toLowerCase();
  if (!riskText) return { sev: 2, text: "DB-IP：获取失败" };

  if (riskText === "high") return { sev: 3, text: "DB-IP：⚠️ 高风险 (high)" };
  if (riskText === "medium") return { sev: 1, text: "DB-IP：🔶 中风险 (medium)" };
  if (riskText === "low") return { sev: 0, text: "DB-IP：✅ 低风险 (low)" };
  return { sev: 2, text: `DB-IP：${riskText}` };
}

// Scamalytics
function gradeScamalytics(html) {
  if (!html) return { sev: 2, text: "Scamalytics：获取失败" };
  const scoreMatch = html.match(/Fraud\s*Score[:\s]*(\d+)/i)
    || html.match(/class="score"[^>]*>(\d+)/i)
    || html.match(/"score"\s*:\s*(\d+)/i);
  if (!scoreMatch) return { sev: 2, text: "Scamalytics：获取失败" };

  const s = toInt(scoreMatch[1]);
  if (s === null) return { sev: 2, text: "Scamalytics：获取失败" };
  if (s >= 90) return { sev: 4, text: `Scamalytics：🛑 极高风险 (${s})` };
  if (s >= 60) return { sev: 3, text: `Scamalytics：⚠️ 高风险 (${s})` };
  if (s >= 20) return { sev: 1, text: `Scamalytics：🔶 中风险 (${s})` };
  return { sev: 0, text: `Scamalytics：✅ 低风险 (${s})` };
}

// ipregistry
function gradeIpregistry(sec) {
  if (!sec) return { sev: 2, text: "ipregistry：获取失败" };

  const items = [];
  if (sec.is_proxy === true) items.push("Proxy");
  if (sec.is_tor === true) items.push("Tor");
  if (sec.is_vpn === true) items.push("VPN");
  if (sec.is_cloud_provider === true) items.push("Hosting");
  if (sec.is_abuser === true) items.push("Abuser");

  if (items.length === 0) {
    return { sev: 0, text: "ipregistry：✅ 低风险（无标记）" };
  }
  const sev = items.includes("Tor") ? 3 : items.includes("Abuser") ? 3 : items.length >= 2 ? 2 : 1;
  const label = sev >= 3 ? "⚠️ 高风险" : sev >= 2 ? "🔶 较高风险" : "🔶 有标记";
  return { sev, text: `ipregistry：${label} (${items.join("/")})` };
}

function flagEmoji(code) {
  if (!code) return "";
  let c = String(code).toUpperCase();
  if (c === "TW") c = "CN";
  if (c.length !== 2) return "";
  return String.fromCodePoint(...c.split("").map((x) => 127397 + x.charCodeAt(0)));
}

// 各家 API 请求

async function fetchIpapi(ip) {
  const { data } = await httpGet(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}`);
  return safeJsonParse(data);
}

async function fetchDbipHtml(ip) {
  const { data } = await httpGet(`https://db-ip.com/${encodeURIComponent(ip)}`);
  return String(data);
}

async function fetchScamalyticsHtml(ip) {
  const { data } = await httpGet(`https://scamalytics.com/ip/${encodeURIComponent(ip)}`);
  return String(data);
}

// 从 ipregistry.co/{ip} 详情页里，按字段名提取 Yes/No 布尔值
function extractIpregistrySecurityFlag(html, fieldName) {
  const re = new RegExp(
    `${fieldName}</span>[\\s\\S]{0,300}?<div class="(?:positive|negative)">[\\s\\S]{0,800}?(Yes|No)</div>`,
    "i"
  );
  const m = html.match(re);
  if (!m) return null;
  return m[1].trim().toLowerCase() === "yes";
}

// 直接抓取 ipregistry.co/{IP} 详情页解析 Security 板块
async function fetchIpregistry(ip) {
  const { data } = await httpGet(`https://ipregistry.co/${encodeURIComponent(ip)}`, {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  });
  const html = String(data);

  const isAbuser = extractIpregistrySecurityFlag(html, "Abuser");
  const isAttacker = extractIpregistrySecurityFlag(html, "Attacker");
  const isBogon = extractIpregistrySecurityFlag(html, "Bogon");
  const isCloudProvider = extractIpregistrySecurityFlag(html, "Cloud Provider");
  const isProxy = extractIpregistrySecurityFlag(html, "Proxy");
  const isRelay = extractIpregistrySecurityFlag(html, "Relay");
  const isTor = extractIpregistrySecurityFlag(html, "Tor");
  const isVpn = extractIpregistrySecurityFlag(html, "VPN");
  const isAnonymous = extractIpregistrySecurityFlag(html, "Anonymous");
  const isThreat = extractIpregistrySecurityFlag(html, "Threat");

  // 如果一个字段都没解析到，说明页面结构变了或者请求失败，视为获取失败
  const allNull = [isAbuser, isAttacker, isBogon, isCloudProvider, isProxy, isRelay, isTor, isVpn, isAnonymous, isThreat]
    .every(v => v === null);
  if (allNull) return null;

  return {
    is_abuser: isAbuser,
    is_attacker: isAttacker,
    is_bogon: isBogon,
    is_cloud_provider: isCloudProvider,
    is_proxy: isProxy,
    is_relay: isRelay,
    is_tor: isTor,
    is_vpn: isVpn,
    is_anonymous: isAnonymous,
    is_threat: isThreat,
  };
}

async function fetchIp2locationIo(ip) {
  const { data } = await httpGet(`https://www.ip2location.io/${encodeURIComponent(ip)}`);
  const html = String(data);

  // Usage Type
  let usageMatch = html.match(/Usage\s*Type<\/label>\s*<p[^>]*>\s*\(([A-Z]+)\)/i);
  if (!usageMatch) {
    usageMatch = html.match(/Usage\s*Type<\/label>\s*<p[^>]*>\s*([A-Z]+(?:\/[A-Z]+)?)\s*</i);
  }
  const usageType = usageMatch ? usageMatch[1] : null;

  const fraudMatch = html.match(/Fraud\s*Score<\/label>\s*<p[^>]*>\s*(\d+)/i);
  const fraudScore = fraudMatch ? toInt(fraudMatch[1]) : null;

  const proxyMatch = html.match(/>Proxy<\/label>\s*<p[^>]*>[^<]*<i[^>]*><\/i>\s*(Yes|No)/i);
  const isProxy = proxyMatch ? proxyMatch[1].toLowerCase() === "yes" : false;

  const proxyTypeMatch = html.match(/Proxy\s*Type<\/label>\s*<p[^>]*>\s*([^<]+)/i);
  const proxyType = proxyTypeMatch ? proxyTypeMatch[1].trim() : "-";

  const threatMatch = html.match(/>Threat<\/label>\s*<p[^>]*>\s*([^<]+)/i);
  const threat = threatMatch ? threatMatch[1].trim() : "-";

  // Country: >Country</label> ... <a ...>United States of America (US)</a>
  const countryMatch = html.match(/>Country<\/label>[\s\S]{0,300}?<a[^>]*>([^(<]+)\(([A-Z]{2})\)<\/a>/i);
  const country = countryMatch ? countryMatch[1].trim() : null;
  const countryCode = countryMatch ? countryMatch[2].trim() : null;

  // City: >City</label> <p class="ip-result">Los Angeles</p>
  const cityMatch = html.match(/>City<\/label>\s*<p[^>]*>([^<]+)<\/p>/i);
  const city = cityMatch ? cityMatch[1].trim() : null;

  // ASN: >ASN</label> ... <a ...>25820</a>
  const asnMatch = html.match(/>ASN<\/label>[\s\S]{0,300}?<a[^>]*>(\d+)<\/a>/i);
  const asn = asnMatch ? asnMatch[1].trim() : null;

  // AS (组织名): >AS</label> ... <a ...>IT7 Networks Inc</a>
  const asOrgMatch = html.match(/>AS<\/label>[\s\S]{0,300}?<a[^>]*>([^<]+)<\/a>/i);
  const asOrg = asOrgMatch ? asOrgMatch[1].trim() : null;

  return {
    as_usage_type: usageType,
    fraud_score: fraudScore,
    is_proxy: isProxy,
    proxy_type: proxyType,
    threat: threat,
    country,
    country_code: countryCode,
    city,
    asn,
    as_org: asOrg
  };
}


async function fetchIpinfoIo(ip) {
  const { data } = await httpGet(`https://ipinfo.io/${encodeURIComponent(ip)}`, {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html"
  });
  const html = String(data);


  const detected = [];
  const privacyTypes = ["VPN", "Proxy", "Tor", "Relay", "Hosting", "Residential Proxy"];
  for (const type of privacyTypes) {
    const regex = new RegExp(`aria-label="${type}\\s+Detected"`, "i");
    if (regex.test(html)) {
      detected.push(type);
    }
  }

  const asnTypeMatch = html.match(/>ASN type<\/span>\s*<\/td>\s*<td>([^<]+)</i);
  const asnType = asnTypeMatch ? asnTypeMatch[1].trim() : null;

  return { detected, asnType };
}

// ========== 主逻辑 ==========

(async () => {
  let ip = null;
  let cachedIpapiResponse = null;

  try {
    const { data: ipv4Data } = await httpGet(IPV4_API);
    const ipv4Json = safeJsonParse(ipv4Data);
    ip = ipv4Json?.query || ipv4Json?.ip || String(ipv4Data || "").trim();
  } catch (_) { }

  if (!ip) {
    try {
      const { data } = await httpGet(IPAPI_IS_URL);
      cachedIpapiResponse = safeJsonParse(data);
      if (cachedIpapiResponse && cachedIpapiResponse.ip) {
        ip = cachedIpapiResponse.ip;
      }
    } catch (_) { }
  }

  if (!ip) {
    $done({ title: "IP 纯净度", content: "获取 IPv4 失败", icon: "exclamationmark.triangle.fill" });
    return;
  }

  let ippureFraudScore = null;
  try {
    const { data } = await httpGet(IPPURE_URL);
    const base = safeJsonParse(data);
    if (base) ippureFraudScore = base.fraudScore;
  } catch (_) { }

  const tasks = {
    ipapi: cachedIpapiResponse ? Promise.resolve(cachedIpapiResponse) : fetchIpapi(ip),
    ip2locIo: fetchIp2locationIo(ip),
    ipinfoIo: fetchIpinfoIo(ip),
    dbipHtml: fetchDbipHtml(ip),
    scamHtml: fetchScamalyticsHtml(ip),
    ipregistry: fetchIpregistry(ip),
  };

  const results = await Promise.allSettled(
    Object.keys(tasks).map((k) => tasks[k].then((v) => [k, v]))
  );

  const ok = {};
  for (const r of results) {
    if (r.status === "fulfilled") {
      const [k, v] = r.value;
      ok[k] = v;
    }
  }

  const ipapiData = ok.ipapi || {};
  const ip2loc = parseIp2locationIo(ok.ip2locIo);
  const hostingLine = ip2locationHostingText(ip2loc.usageType);

  // ipapi 是否有效返回了地理信息/ASN，没有则回落到 IP2Location
  const ipapiHasLocation = !!(ipapiData.location?.country_code || ipapiData.location?.country);
  const ipapiHasAsn = !!ipapiData.asn?.asn;

  let countryCode, country, city;
  if (ipapiHasLocation) {
    countryCode = ipapiData.location?.country_code || "";
    country = ipapiData.location?.country || "";
    city = ipapiData.location?.city || "";
  } else if (ip2loc.country || ip2loc.city) {
    countryCode = ip2loc.countryCode || "";
    country = ip2loc.country || "";
    city = ip2loc.city || "";
  } else {
    countryCode = "";
    country = "";
    city = "";
  }
  const flag = flagEmoji(countryCode);

  let asnText;
  if (ipapiHasAsn) {
    asnText = `AS${ipapiData.asn.asn} ${ipapiData.asn.org || ""}`.trim();
  } else if (ip2loc.asn) {
    asnText = `AS${ip2loc.asn} ${ip2loc.asOrg || ""}`.trim();
  } else {
    asnText = "-";
  }

  const grades = [];
  grades.push(gradeIppure(ippureFraudScore));
  grades.push(gradeIpapi(ok.ipapi));
  const ip2locGrade = gradeIp2locationIo(ip2loc.fraudScore);
  if (ip2locGrade.text) grades.push(ip2locGrade);
  grades.push(gradeScamalytics(ok.scamHtml));
  grades.push(gradeDbip(ok.dbipHtml));
  grades.push(gradeIpregistry(ok.ipregistry));

  const maxSev = grades.reduce((m, g) => Math.max(m, g.sev ?? 2), 0);
  const meta = severityMeta(maxSev);

  const factorParts = [];
  // IP2Location.io Proxy 检测
  const ip2locProxyItems = [];
  if (ip2loc.isProxy) ip2locProxyItems.push("Proxy");
  if (ip2loc.proxyType && ip2loc.proxyType !== "-") {
    const typeMap = { "VPN": "VPN", "TOR": "Tor", "DCH": "数据中心代理", "PUB": "公共代理", "WEB": "Web代理", "RES": "住宅代理" };
    const typeDesc = typeMap[ip2loc.proxyType.toUpperCase()] || ip2loc.proxyType;
    ip2locProxyItems.push(typeDesc);
  }
  if (ip2loc.threat && ip2loc.threat !== "-") {
    ip2locProxyItems.push(`威胁:${ip2loc.threat}`);
  }
  if (ip2locProxyItems.length) {
    factorParts.push(`IP2Location 检测类型：${ip2locProxyItems.join("/")}`);
  }
  // ipapi 检测类型
  if (ok.ipapi) {
    const items = [];
    if (ok.ipapi.is_proxy === true) items.push("Proxy");
    if (ok.ipapi.is_tor === true) items.push("Tor");
    if (ok.ipapi.is_vpn === true) items.push("VPN");
    if (ok.ipapi.is_datacenter === true) items.push("Datacenter");
    if (ok.ipapi.is_abuser === true) items.push("Abuser");
    if (ok.ipapi.is_crawler === true) items.push("Crawler");
    if (items.length) factorParts.push(`ipapi 检测类型：${items.join("/")}`);
  }

  // ipinfo.io 检测类型
  if (ok.ipinfoIo && ok.ipinfoIo.detected && ok.ipinfoIo.detected.length) {
    factorParts.push(`ipinfo.io 检测类型：${ok.ipinfoIo.detected.join("/")}`);
  }
  // ipregistry 检测类型
  if (ok.ipregistry) {
    const sec = ok.ipregistry;
    const items = [];
    if (sec.is_proxy === true) items.push("Proxy");
    if (sec.is_tor === true) items.push("Tor");
    if (sec.is_relay === true) items.push("Relay");
    if (sec.is_vpn === true) items.push("VPN");
    if (sec.is_anonymous === true) items.push("Anonymous");
    if (sec.is_cloud_provider === true) items.push("Hosting");
    if (sec.is_abuser === true) items.push("Abuser");
    if (sec.is_attacker === true) items.push("Attacker");
    if (sec.is_bogon === true) items.push("Bogon");
    if (sec.is_threat === true) items.push("Threat");
    if (items.length) factorParts.push(`ipregistry 检测类型：${items.join("/")}`);
  }
  if (ip2locProxyItems.length === 0 && ip2loc.usageType && isRiskyUsageType(ip2loc.usageType)) {
    const usageDesc = {
      "DCH": "数据中心", "WEB": "Web托管", "SES": "搜索引擎",
      "COM": "商业宽带", "CDN": "CDN"
    };
    const usage = String(ip2loc.usageType).toUpperCase();
    const desc = usageDesc[usage] || usage;
    factorParts.push(`IP2Location 检测类型：${desc} (${ip2loc.usageType})`);
  }
  const riskLines = grades.map((g) => g.text).filter(Boolean);

  // 构建 HTML 输出
  let html = `<p style="text-align: center; font-family: -apple-system; font-size: large; font-weight: thin">`;
  html += `<b><font color=#6959CD>IP</font> : </b><font color=>${maskIpAddress(ip)}</font></br>`;
  html += `<b><font color=#6959CD>ASN</font> : </b><font color=>${asnText}</font></br>`;
  html += `<b><font color=#6959CD>位置</font> : </b><font color=>${flag} ${country} ${city}</font></br>`;
  html += `<b><font color=#6959CD>类型</font> : </b><font color=>${hostingLine.replace("IP类型：", "")}</font></br>`;

  // 多源评分
  html += `</br><b><font color=#FF6347>—— 多源评分 ——</font></b></br>`;
  for (const line of riskLines) {
    const [name, ...rest] = line.split("：");
    const result = rest.join("：");
    html += `<b>${name}</b>：${result}</br>`;
  }

  // IP类型风险
  if (factorParts.length) {
    html += `</br><b><font color=#FF6347>—— IP类型风险 ——</font></b></br>`;
    for (const factor of factorParts) {
      const [fname, ...frest] = factor.split("：");
      const fresult = frest.join("：");
      html += `<b>${fname}</b>：${fresult}</br>`;
    }
  }

  html += `</br><font color=#6959CD><b>节点</b> ➟ ${nodeName || "-"}</font>`;
  html += `</p>`;

  $done({
    title: "节点 IP 风险汇总",
    htmlMessage: html,
    icon: meta.icon,
    "title-color": meta.color,
  });
})().catch((e) => {
  const errHtml = `<p style="text-align: center; font-family: -apple-system; font-size: large; font-weight: bold;">` +
    `</br></br>🔴 请求失败：${String(e && e.message ? e.message : e)}</p>`;
  $done({
    title: "IP 纯净度",
    htmlMessage: errHtml,
    icon: "network.slash",
  });
});
