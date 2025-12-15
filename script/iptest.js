const IPPURE_URL = "https://my.ippure.com/v1/info";
const IPV4_API = "https://api4.ipify.org?format=json";

// 从环境参数获取节点名
const nodeName = $environment.params.node;

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

// ipapi.is - 免费直接可用
function gradeIpapi(j) {
  if (!j || !j.company) return { sev: 2, text: "ipapi：获取失败" };
  
  const abuserScoreText = j.company.abuser_score;
  if (!abuserScoreText || typeof abuserScoreText !== "string") {
    return { sev: 2, text: "ipapi：无评分" };
  }
  const m = abuserScoreText.match(/([0-9.]+)\s*\(([^)]+)\)/);
  if (!m) return { sev: 2, text: `ipapi：${abuserScoreText}` };

  const ratio = Number(m[1]);
  const level = String(m[2] || "").trim();
  const pct = Number.isFinite(ratio) ? `${Math.round(ratio * 10000) / 100}%` : "?";

  const sevByLevel = { "Very Low": 0, Low: 0, Elevated: 2, High: 3, "Very High": 4 };
  const sev = sevByLevel[level] ?? 2;
  const label = sev >= 4 ? "🛑 极高风险" : sev >= 3 ? "⚠️ 高风险" : sev >= 2 ? "🔶 较高风险" : "✅ 低风险";

  return { sev, text: `ipapi：${label} (${pct}, ${level})` };
}

// ipapi.is 判断 IP 类型
function ipapiHostingText(j) {
  if (!j) return "IP类型（ipapi）：未知（获取失败）";
  
  const isDc = j.is_datacenter === true;
  const isMobile = j.is_mobile === true;
  const asnType = String(j.asn?.type || "").toLowerCase();
  const companyType = String(j.company?.type || "").toLowerCase();
  
  if (isMobile) return `IP类型（ipapi）：📱 蜂窝移动网络 (mobile)（可能是）`;
  if (asnType === "hosting" || companyType === "hosting") return `IP类型（ipapi）：🏢 托管服务器 (hosting)（可能是）`;
  if (asnType === "isp" || companyType === "isp") return `IP类型（ipapi）：🏠 家庭宽带 (ISP)（可能是）`;
  if (asnType === "business" || companyType === "business") return `IP类型（ipapi）：🏬 商业宽带 (business)（可能是）`;
  if (asnType === "education" || companyType === "education") return `IP类型（ipapi）：🎓 教育网络 (education)（可能是）`;
  if (asnType === "government" || companyType === "government") return `IP类型（ipapi）：🏛️ 政府网络 (government)（可能是）`;
  
  const typeInfo = asnType || companyType || "unknown";
  return `IP类型（ipapi）：❓ ${typeInfo}`;
}

// DB-IP - 抓网页解析
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

// Scamalytics - 抓网页解析
function gradeScamalytics(html) {
  if (!html) return { sev: 2, text: "Scamalytics：获取失败" };
  // 页面上有 "Fraud Score: XX" 或 class="score" 里的数字
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

// IPWhois - 免费 API
function gradeIpwhois(j) {
  if (!j || !j.security) return { sev: 2, text: "IPWhois：获取失败" };
  
  const sec = j.security;
  const items = [];
  if (sec.proxy === true) items.push("Proxy");
  if (sec.tor === true) items.push("Tor");
  if (sec.vpn === true) items.push("VPN");
  if (sec.hosting === true) items.push("Hosting");
  
  if (items.length === 0) {
    return { sev: 0, text: "IPWhois：✅ 低风险（无标记）" };
  }
  const sev = items.includes("Tor") ? 3 : items.length >= 2 ? 2 : 1;
  const label = sev >= 3 ? "⚠️ 高风险" : sev >= 2 ? "🔶 较高风险" : "🔶 有标记";
  return { sev, text: `IPWhois：${label} (${items.join("/")})` };
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
  // https://api.ipapi.is/?q=IP - 免费，无需 key
  const { data } = await httpGet(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}`);
  return safeJsonParse(data);
}

async function fetchDbipHtml(ip) {
  // https://db-ip.com/IP - 抓网页
  const { data } = await httpGet(`https://db-ip.com/${encodeURIComponent(ip)}`);
  return String(data);
}

async function fetchScamalyticsHtml(ip) {
  // https://scamalytics.com/ip/IP - 抓网页
  const { data } = await httpGet(`https://scamalytics.com/ip/${encodeURIComponent(ip)}`);
  return String(data);
}

async function fetchIpwhois(ip) {
  // https://ipwhois.io/widget?ip=IP - 免费
  const { data } = await httpGet(`https://ipwhois.io/widget?ip=${encodeURIComponent(ip)}&lang=en`, {
    "Referer": "https://ipwhois.io/",
    "Accept": "*/*",
  });
  return safeJsonParse(data);
}

// ========== 主逻辑 ==========

(async () => {
  let ip = null;
  try {
    const { data: ipv4Data } = await httpGet(IPV4_API);
    const ipv4Json = safeJsonParse(ipv4Data);
    ip = ipv4Json?.ip || String(ipv4Data || "").trim();
  } catch (_) {}

  if (!ip) {
    $done({ title: "IP 纯净度", content: "获取 IPv4 失败", icon: "exclamationmark.triangle.fill" });
    return;
  }

  let ippureFraudScore = null;
  try {
    const { data } = await httpGet(IPPURE_URL);
    const base = safeJsonParse(data);
    if (base) ippureFraudScore = base.fraudScore;
  } catch (_) {}

  const tasks = {
    ipapi: fetchIpapi(ip),
    dbipHtml: fetchDbipHtml(ip),
    scamHtml: fetchScamalyticsHtml(ip),
    ipwhois: fetchIpwhois(ip),
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
  const asnText = ipapiData.asn?.asn ? `AS${ipapiData.asn.asn} ${ipapiData.asn.org || ""}`.trim() : "-";
  const countryCode = ipapiData.location?.country_code || "";
  const country = ipapiData.location?.country || "";
  const city = ipapiData.location?.city || "";
  const flag = flagEmoji(countryCode);

  const hostingLine = ipapiHostingText(ok.ipapi);

  const grades = [];
  grades.push(gradeIppure(ippureFraudScore));
  grades.push(gradeIpapi(ok.ipapi));
  grades.push(gradeScamalytics(ok.scamHtml));
  grades.push(gradeDbip(ok.dbipHtml));
  grades.push(gradeIpwhois(ok.ipwhois));

  const maxSev = grades.reduce((m, g) => Math.max(m, g.sev ?? 2), 0);
  const meta = severityMeta(maxSev);

  const factorParts = [];
  if (ok.ipapi) {
    const items = [];
    if (ok.ipapi.is_proxy === true) items.push("Proxy");
    if (ok.ipapi.is_tor === true) items.push("Tor");
    if (ok.ipapi.is_vpn === true) items.push("VPN");
    if (ok.ipapi.is_datacenter === true) items.push("Datacenter");
    if (ok.ipapi.is_abuser === true) items.push("Abuser");
    if (ok.ipapi.is_crawler === true) items.push("Crawler");
    if (items.length) factorParts.push(`ipapi 因子：${items.join("/")}`);
  }
  if (ok.ipwhois && ok.ipwhois.security) {
    const sec = ok.ipwhois.security;
    const items = [];
    if (sec.proxy === true) items.push("Proxy");
    if (sec.tor === true) items.push("Tor");
    if (sec.vpn === true) items.push("VPN");
    if (sec.hosting === true) items.push("Hosting");
    if (items.length) factorParts.push(`IPWhois 因子：${items.join("/")}`);
  }
  const factorText = factorParts.length ? `\n\n——风险因子——\n${factorParts.join("\n")}` : "";

  const riskLines = grades.map((g) => g.text).join("\n");

  $done({
    title: "节点 IP 风险汇总",
    content:
`IP：${ip}
ASN：${asnText}
位置：${flag} ${country} ${city}
${hostingLine}
节点：${nodeName || "-"}

——多源评分——
${riskLines}${factorText}`,
    icon: meta.icon,
    "title-color": meta.color,
  });
})().catch((e) => {
  $done({
    title: "IP 纯净度",
    content: `请求失败：${String(e && e.message ? e.message : e)}`,
    icon: "network.slash",
  });
});
