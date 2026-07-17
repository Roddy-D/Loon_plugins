const IP_API = "http://ip-api.com/json?lang=zh-CN";
const IP_API_BACKUP = "https://ipinfo.io/json"; // 备用数据源
const GLOBALPING_API = "https://api.globalping.io/v1/measurements";
// 大陆探测点
const CN_LOCATIONS = [
  { magic: "shanghai", limit: 1 },
  { magic: "beijing", limit: 1 },
  { magic: "guangzhou", limit: 1 }
];
// 海外视角探测点
const OVERSEAS_LOCATIONS = [
  { magic: "hong kong", limit: 1 },
  { magic: "taipei", limit: 1 },
  { magic: "tokyo", limit: 1 },
  { magic: "seoul", limit: 1 },
  { magic: "los angeles", limit: 1 },
  { magic: "boston", limit: 1 },
  { magic: "frankfurt", limit: 1 },
  { magic: "amsterdam", limit: 1 }
];
const GLOBALPING_LOCATIONS = [...CN_LOCATIONS, ...OVERSEAS_LOCATIONS];
// 海外点位中至少需要多少个可达，才算正常
const OVERSEAS_REACHABLE_THRESHOLD = 5;
const CN_CITIES = new Set(CN_LOCATIONS.map((l) => l.magic.toLowerCase()));
const REQUEST_TIMEOUT = 10000; // 请求超时时间(毫秒)
const RESULT_DELAY = 4000; // 首次等待探测时间(毫秒)
const RESULT_RETRY_DELAY = 3000; // 重试等待时间(毫秒)
const RESULT_MAX_RETRIES = 3; // 轮询最大重试次数

// 城市 -> 中文地名 映射
const CITY_LABEL_MAP = {
  Shanghai: "上海",
  Beijing: "北京",
  Guangzhou: "广东",
  "Los Angeles": "洛杉矶",
  Boston: "波士顿",
  Tokyo: "东京",
  Seoul: "首尔",
  Taipei: "台湾",
  "Hong Kong": "香港",
  Frankfurt: "法兰克福",
  Amsterdam: "阿姆斯特丹"
};

// 获取 Loon 环境参数
const params = typeof $environment !== "undefined" && $environment.params ? $environment.params : {};
const nodeName = params.node || "";
const nodeInfo = params.nodeInfo || {};
const maskIP = typeof $persistentStore !== "undefined" && $persistentStore.read("MaskIP") === "true";

// IP 掩码函数：开启后仅显示前两段(v4)或前四组(v6)，其余用 * 遮盖
function maskIpAddress(ip) {
  if (!maskIP || !ip) return ip;
  const parts = String(ip).split(".");
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.*.*`;
  }
  if (String(ip).includes(":")) {
    const v6parts = String(ip).split(":");
    if (v6parts.length >= 4) {
      return `${v6parts.slice(0, 4).join(":")}:*`;
    }
  }
  return ip;
}

// 对 "IP:端口" 或纯 IP 字符串做掩码，保留端口部分
function maskTarget(target) {
  if (!maskIP || !target) return target;
  const str = String(target);
  const v6WithPort = str.match(/^\[([^\]]+)\](:\d+)?$/);
  if (v6WithPort) {
    return `[${maskIpAddress(v6WithPort[1])}]${v6WithPort[2] || ""}`;
  }
  const lastColon = str.lastIndexOf(":");
  const looksLikeV4WithPort = lastColon > -1 && str.slice(0, lastColon).split(".").length === 4;
  if (looksLikeV4WithPort) {
    return `${maskIpAddress(str.slice(0, lastColon))}${str.slice(lastColon)}`;
  }
  return maskIpAddress(str);
}

if (!nodeName) {
  finishError("未获取到节点名称，请长按具体节点运行此脚本。");
} else {
  run();
}

async function run() {
  try {
    // 并行执行：节点连通性测试、本机直连测试、远端服务器可用性测试
    const [nodeRes, directRes, remoteRes] = await Promise.all([checkGeo(nodeName), checkDirectConnectivity(), checkRemote(nodeInfo)]);

    render(nodeRes, directRes, remoteRes);
  } catch (error) {
    finishError(`执行异常: ${error.message}`);
  }
}

// === 核心检测逻辑 ===

async function checkGeo(node) {
  try {
    const data = await requestJson(IP_API, node, "GET");
    if (data && data.status === "fail") {
      return { ok: false, error: data.message || "IP 查询失败" };
    }
    return { ok: true, data };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

// 本机直连检测：两个数据源并发竞速，任一成功即视为本机网络正常，
// 避免 ip-api.com 单点超时/被限流导致的误判。
function raceForFirstSuccess(promises) {
  return new Promise((resolve, reject) => {
    let remaining = promises.length;
    const errors = [];
    promises.forEach((p) => {
      p.then(resolve).catch((err) => {
        errors.push(err);
        remaining--;
        if (remaining === 0) {
          reject(errors[0] || new Error("全部请求失败"));
        }
      });
    });
  });
}

async function checkDirectConnectivity() {
  const attempts = [
    requestJson(IP_API, "DIRECT", "GET").then((data) => {
      if (data && data.status === "fail") throw new Error(data.message || "IP 查询失败");
      return data;
    }),
    requestJson(IP_API_BACKUP, "DIRECT", "GET")
  ];

  try {
    const data = await raceForFirstSuccess(attempts);
    return { ok: true, data };
  } catch (error) {
    return { ok: false, error: error.message || "本机网络请求全部失败" };
  }
}

async function checkRemote(info) {
  const address = info?.address ? String(info.address) : "";
  const port = info?.port ? Number(info.port) : 0;

  if (!address || !port) {
    return { available: false, reachable: false, error: "未获取到节点底层 IP/端口，请对具体节点运行" };
  }

  const target = `${address}:${port}`;

  const body = {
    type: "ping",
    target: address,
    locations: GLOBALPING_LOCATIONS,
    measurementOptions: {
      protocol: "TCP",
      port: port,
      packets: 3
    }
  };

  try {
    const submission = await requestJson(GLOBALPING_API, null, "POST", body);
    const measurementId = submission?.id;
    if (!measurementId) {
      return { available: false, reachable: false, target, error: "Globalping 探测任务提交失败或被限流" };
    }

    // 首次等待并获取结果
    await wait(RESULT_DELAY);
    let result = await getRemoteResult(measurementId);

    // 若仍在进行中，按重试间隔轮询，直到完成或达到最大重试次数
    let retries = 0;
    while (result.status === "in-progress" && retries < RESULT_MAX_RETRIES) {
      await wait(RESULT_RETRY_DELAY);
      result = await getRemoteResult(measurementId);
      retries++;
    }

    if (result.status === "in-progress" && result.items.length === 0) {
      return { available: false, reachable: false, target, error: "Globalping 探测响应超时，暂未返回结果" };
    }

    return {
      available: true,
      reachable: result.reachable,
      data: result.items,
      target,
      cnReachableCount: result.cnReachableCount,
      cnTotalCount: result.cnTotalCount,
      overseasReachableCount: result.overseasReachableCount,
      overseasTotalCount: result.overseasTotalCount
    };
  } catch (error) {
    return { available: false, reachable: false, target, error: `不可用: ${error.message}` };
  }
}

async function getRemoteResult(measurementId) {
  const result = await requestJson(`${GLOBALPING_API}/${measurementId}`, null, "GET");
  let reachable = false;
  let cnReachableCount = 0;
  let cnTotalCount = 0;
  let overseasReachableCount = 0;
  let overseasTotalCount = 0;

  const probeResults = Array.isArray(result?.results) ? result.results : [];

  const items = probeResults.map((probeResult) => {
    const probe = probeResult?.probe || {};
    const stats = probeResult?.result?.stats || {};
    const avgMs = Number(stats.avg);
    const loss = Number(stats.loss);

    const isReachable = Number.isFinite(avgMs) && avgMs >= 0 && loss !== 100;
    if (isReachable) reachable = true;

    const isCn = CN_CITIES.has(String(probe.city || "").toLowerCase());
    if (isCn) {
      cnTotalCount++;
      if (isReachable) cnReachableCount++;
    } else {
      overseasTotalCount++;
      if (isReachable) overseasReachableCount++;
    }

    return {
      flag: getFlag(probe.country),
      cityLabel: CITY_LABEL_MAP[probe.city] || "",
      msStr: isReachable ? formatMs(avgMs) : "--.--ms"
    };
  });

  return {
    reachable,
    status: result?.status,
    items,
    cnReachableCount,
    cnTotalCount,
    overseasReachableCount,
    overseasTotalCount
  };
}

// === 网络请求与工具函数 ===

function requestJson(url, node, method, jsonBody) {
  return new Promise((resolve, reject) => {
    const options = {
      url,
      headers: {
        Accept: "application/json",
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Loon Node Check"
      }
    };
    if (node) options.node = node;
    if (jsonBody) {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(jsonBody);
    }

    // JS 层级并发控制超时
    let isSettled = false;
    const timer = setTimeout(() => {
      if (!isSettled) {
        isSettled = true;
        reject(new Error("请求超时"));
      }
    }, REQUEST_TIMEOUT);

    const callback = (error, response, body) => {
      if (isSettled) return;
      isSettled = true;
      clearTimeout(timer);

      if (error) return reject(new Error(error));

      const status = Number(response?.status);
      if (status < 200 || status >= 300) return reject(new Error(`HTTP ${status}`));

      try {
        resolve(JSON.parse(body));
      } catch (e) {
        reject(new Error("JSON 格式解析失败"));
      }
    };

    if (method === "POST") {
      $httpClient.post(options, callback);
    } else {
      $httpClient.get(options, callback);
    }
  });
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function formatMs(ms) {
  if (ms >= 10000) return `${Math.floor(ms)}ms`;
  if (ms >= 1000)
    return `${Math.floor(ms)
      .toString()
      .replace(/\B(?=(\d{3})+(?!\d))/g, ",")}ms`;
  if (ms >= 100) return `${ms.toFixed(1)}ms`;
  if (ms >= 10) return `${ms.toFixed(2)}ms`;
  if (ms <= 0) return "0.00ms";
  return `${ms.toFixed(3)}ms`;
}

function getFlag(countryCode) {
  if (!countryCode || String(countryCode).length !== 2) return "🌍";
  const code = String(countryCode).toUpperCase();
  // 台湾旗改用萨摩亚国旗
  if (code === "TW") return "🇼🇸";
  const points = code.split("").map((char) => 127397 + char.charCodeAt());
  return String.fromCodePoint(...points);
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// === 渲染与输出 UI ===

function render(node, direct, remote) {
  // 构建纯文本 (Fallback) 与 HTML
  const textParts = [];
  const htmlParts = [];

  // 1. 节点代理块
  let nodeText = `【节点代理】: ${node.ok ? "✅ 正常" : "❌ 不可达"}`;
  let nodeHtml = `<b>节点代理</b>: ${node.ok ? "✅ 正常" : "❌ 不可达"}`;
  if (node.ok && node.data) {
    const d = node.data;
    const loc = [d.country, d.regionName || d.region, d.city].filter(Boolean).join(" - ");
    const maskedIp = maskIpAddress(d.ip || d.query);
    nodeText += `\n ├ IP: ${maskedIp}\n ├ 位置: ${loc}\n └ ISP: ${d.isp || d.organization}`;
    nodeHtml += `<br/><b>IP</b>: ${escapeHtml(maskedIp)}`;
    if (loc) nodeHtml += `<br/><b>位置</b>: ${escapeHtml(loc)}`;
    nodeHtml += `<br/><b>ISP</b>: ${escapeHtml(d.isp || d.organization)}`;
  } else if (node.error) {
    nodeText += `\n └ ${node.error}`;
    nodeHtml += `<br/><small style="color: gray;">${escapeHtml(node.error)}</small>`;
  }
  textParts.push(nodeText);
  htmlParts.push(nodeHtml);

  // 2. 本机网络块
  let directText = `【本机网络】: ${direct.ok ? "✅ 正常" : "❌ 异常"}`;
  let directHtml = `<b>本机网络</b>: ${direct.ok ? "✅ 正常" : "❌ 异常"}`;
  if (!direct.ok && direct.error) {
    directText += `\n └ ${direct.error}`;
    directHtml += `<br/><small style="color: gray;">${escapeHtml(direct.error)}</small>`;
  }
  textParts.push(directText);
  htmlParts.push(directHtml);

  // 3. 远端探测块（每行两个地区）
  let remoteText = "";
  let remoteHtml = "";
  if (!remote.available) {
    remoteText = `【远端探测】: ⚠️ 未完成\n └ ${remote.error || "未知原因"}`;
    remoteHtml = `<b>远端探测</b>: ⚠️ 未完成<br/><small style="color: gray;">${escapeHtml(remote.error)}</small>`;
  } else {
    remoteText = `【远端探测】: ${remote.reachable ? "✅ 可达" : "❌ 不可达"}`;
    remoteHtml = `<b>远端探测</b>: ${remote.reachable ? "✅ 可达" : "❌ 不可达"}`;

    if (remote.data && remote.data.length > 0) {
      remoteText += "\n";
      for (const item of remote.data) {
        // 没有中文映射的地区只显示国旗，不显示地名文字
        const label = item.cityLabel ? `${item.flag}${item.cityLabel}` : item.flag;
        remoteHtml += `<br/>${label} ${item.msStr}`;
        remoteText += ` ${label} ${item.msStr}\n`;
      }
      remoteText = remoteText.trimEnd();
    }
  }
  textParts.push(remoteText);
  htmlParts.push(remoteHtml);

  // 4. 诊断结论
  let conclusion = "";
  if (!remote.available) {
    conclusion = "❓ 数据不足，无法完成远端探测判断";
  } else {
    const cnBlocked = remote.cnTotalCount > 0 && remote.cnReachableCount === 0;
    const overseasOk = remote.overseasReachableCount >= OVERSEAS_REACHABLE_THRESHOLD;
    const localBlocked = !direct.ok || !node.ok;

    if (localBlocked && cnBlocked && overseasOk) {
      conclusion = `🚫 该 IP 疑似被 GFW 定向阻断\n(本机与大陆探针均无法连通，但海外 ${remote.overseasReachableCount}/${remote.overseasTotalCount} 个探针可达)`;
    } else if (direct.ok && node.ok) {
      conclusion = "✅ 当前节点一切正常，可顺利连通";
    } else if (!direct.ok) {
      conclusion = "⚠️ 本机网络异常，可能为网络波动导致";
    } else if (!overseasOk && remote.overseasTotalCount > 0) {
      conclusion = `💤 节点疑似已离线\n(海外探针仅 ${remote.overseasReachableCount}/${remote.overseasTotalCount} 个可达，非定向阻断特征)`;
    } else {
      conclusion = "❓ 数据不足，无法精确判断";
    }
  }

  textParts.push(`【诊断结论】\n${conclusion}`);
  htmlParts.push(`<b>📋 诊断结论</b><br/>${escapeHtml(conclusion).replace(/\n/g, "<br/>")}`);

  // 5. 目标节点信息
  const typeStr = nodeInfo.type ? ` · ${nodeInfo.type}` : "";
  let targetText = `【当前节点】\n 📍 ${nodeName}${typeStr}`;
  let targetHtml = `<b>节点</b>: <span style="color: #467fcf; font-weight: bold;">${escapeHtml(nodeName)}${escapeHtml(
    typeStr
  )}</span>`;
  textParts.push(targetText);
  htmlParts.push(targetHtml);

  // 完成输出
  $done({
    title: "🌐 节点阻断检测报告",
    content: textParts.join("\n\n"), // 为不支持 HTML 的视图提供完美的纯文本降级
    htmlMessage: `<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; font-size: 15px; line-height: 1.6; color: inherit; word-break: break-all;">${htmlParts.join(
      "<br/><br/>"
    )}</div>`
  });
}

function finishError(message) {
  $done({
    title: "🌐 节点阻断检测",
    content: `🛑 ${message}`,
    htmlMessage: `<div style="font-family: -apple-system, sans-serif; font-size: 16px; color: inherit;"><b>🛑 ${escapeHtml(
      message
    )}</b></div>`
  });
}
