let DoH = "cloudflare-dns.com";
const jsonDoH = `https://${DoH}/resolve`;
const dnsDoH = `https://${DoH}/dns-query`;
let DoH路径 = 'dns-query';
export default {
  async fetch(request, env) {
    if (env.DOH) {
      DoH = env.DOH;
      const match = DoH.match(/:\/\/([^\/]+)/);
      if (match) {
        DoH = match[1];
      }
    }
    DoH路径 = env.PATH || env.TOKEN || DoH路径;//DoH路径也单独设置 变量PATH
    if (DoH路径.includes("/")) DoH路径 = DoH路径.split("/")[1];
    const url = new URL(request.url);
    const path = url.pathname;
    const hostname = url.hostname;

    // 处理 OPTIONS 预检请求
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '86400'
        }
      });
    }

    // 如果请求路径，则作为 DoH 服务器处理
    if (path === `/${DoH路径}`) {
      return await DOHRequest(request);
    }

    // 添加IP地理位置信息查询代理
    if (path === '/ip-info') {
      if (env.TOKEN) {
        const token = url.searchParams.get('token');
        if (token != env.TOKEN) {
          return new Response(JSON.stringify({ error: "Token不正确" }), {
            status: 403,
            headers: {
              "content-type": "application/json; charset=UTF-8",
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
      }

      const ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
      if (!ip) {
        return new Response(JSON.stringify({ error: "IP参数未提供" }), {
          status: 400,
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      try {
        // 使用Worker代理请求HTTP的IP API
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);

        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }

        const data = await response.json();

        // 返回数据给客户端，并添加CORS头
        return new Response(JSON.stringify(data, null, 4), {
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });

      } catch (error) {
        console.error("IP查询失败:", error);
        return new Response(JSON.stringify({
          error: `IP查询失败: ${error.message}`,
          status: 'error'
        }), {
          status: 500,
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
    }

    // 如果请求参数中包含 domain 和 doh，则执行 DNS 解析
    if (url.searchParams.has("doh")) {
      const domain = url.searchParams.get("domain") || url.searchParams.get("name") || "www.google.com";
      const doh = url.searchParams.get("doh") || dnsDoH;
      const type = url.searchParams.get("type") || "all"; // 默认同时查询 A 和 AAAA

      // 如果使用的是当前站点，则使用 DoH 服务
      if (doh.includes(url.host)) {
        return await handleLocalDohRequest(domain, type, hostname);
      }

      try {
        // 根据请求类型进行不同的处理
        if (type === "all") {
          // 同时请求 A、AAAA 和 NS 记录，使用新的查询函数
          const ipv4Result = await queryDns(doh, domain, "A");
          const ipv6Result = await queryDns(doh, domain, "AAAA");
          const nsResult = await queryDns(doh, domain, "NS");

          // 合并结果 - 修改Question字段处理方式以兼容不同格式
          const combinedResult = {
            Status: ipv4Result.Status || ipv6Result.Status || nsResult.Status,
            TC: ipv4Result.TC || ipv6Result.TC || nsResult.TC,
            RD: ipv4Result.RD || ipv6Result.RD || nsResult.RD,
            RA: ipv4Result.RA || ipv6Result.RA || nsResult.RA,
            AD: ipv4Result.AD || ipv6Result.AD || nsResult.AD,
            CD: ipv4Result.CD || ipv6Result.CD || nsResult.CD,

            // 修改处理Question字段的方式，兼容对象格式和数组格式
            Question: [],

            Answer: [...(ipv4Result.Answer || []), ...(ipv6Result.Answer || [])],
            ipv4: {
              records: ipv4Result.Answer || []
            },
            ipv6: {
              records: ipv6Result.Answer || []
            },
            ns: {
              records: []
            }
          };

          // 正确处理Question字段，无论是对象还是数组
          if (ipv4Result.Question) {
            if (Array.isArray(ipv4Result.Question)) {
              combinedResult.Question.push(...ipv4Result.Question);
            } else {
              combinedResult.Question.push(ipv4Result.Question);
            }
          }

          if (ipv6Result.Question) {
            if (Array.isArray(ipv6Result.Question)) {
              combinedResult.Question.push(...ipv6Result.Question);
            } else {
              combinedResult.Question.push(ipv6Result.Question);
            }
          }

          if (nsResult.Question) {
            if (Array.isArray(nsResult.Question)) {
              combinedResult.Question.push(...nsResult.Question);
            } else {
              combinedResult.Question.push(nsResult.Question);
            }
          }

          // 处理NS记录 - 可能在Answer或Authority部分
          const nsRecords = [];

          // 从Answer部分收集NS记录
          if (nsResult.Answer && nsResult.Answer.length > 0) {
            nsResult.Answer.forEach(record => {
              if (record.type === 2) { // NS记录类型是2
                nsRecords.push(record);
              }
            });
          }

          // 从Authority部分收集NS和SOA记录
          if (nsResult.Authority && nsResult.Authority.length > 0) {
            nsResult.Authority.forEach(record => {
              if (record.type === 2 || record.type === 6) { // NS=2, SOA=6
                nsRecords.push(record);
                // 也添加到总Answer数组
                combinedResult.Answer.push(record);
              }
            });
          }

          // 设置NS记录集合
          combinedResult.ns.records = nsRecords;

          return new Response(JSON.stringify(combinedResult, null, 2), {
            headers: { "content-type": "application/json; charset=UTF-8" }
          });
        } else {
          // 普通的单类型查询，使用新的查询函数
          const result = await queryDns(doh, domain, type);
          return new Response(JSON.stringify(result, null, 2), {
            headers: { "content-type": "application/json; charset=UTF-8" }
          });
        }
      } catch (err) {
        console.error("DNS 查询失败:", err);
        return new Response(JSON.stringify({
          error: `DNS 查询失败: ${err.message}`,
          doh: doh,
          domain: domain,
          stack: err.stack
        }, null, 2), {
          headers: { "content-type": "application/json; charset=UTF-8" },
          status: 500
        });
      }
    }

    if (env.URL302) return Response.redirect(env.URL302, 302);
    else if (env.URL) {
      if (env.URL.toString().toLowerCase() == 'nginx') {
        return new Response(await nginx(), {
          headers: {
            'Content-Type': 'text/html; charset=UTF-8',
          },
        });
      } else return await 代理URL(env.URL, url);
    } else return await HTML();
  }
}

// 查询DNS的通用函数
async function queryDns(dohServer, domain, type) {
  // 构造 DoH 请求 URL
  const dohUrl = new URL(dohServer);
  dohUrl.searchParams.set("name", domain);
  dohUrl.searchParams.set("type", type);

  // 尝试多种请求头格式
  const fetchOptions = [
    // 标准 application/dns-json
    {
      headers: { 'Accept': 'application/dns-json' }
    },
    // 部分服务使用没有指定 Accept 头的请求
    {
      headers: {}
    },
    // 另一个尝试 application/json
    {
      headers: { 'Accept': 'application/json' }
    },
    // 稳妥起见，有些服务可能需要明确的用户代理
    {
      headers: {
        'Accept': 'application/dns-json',
        'User-Agent': 'Mozilla/5.0 DNS Client'
      }
    }
  ];

  let lastError = null;

  // 依次尝试不同的请求头组合
  for (const options of fetchOptions) {
    try {
      const response = await fetch(dohUrl.toString(), options);

      // 如果请求成功，解析JSON
      if (response.ok) {
        const contentType = response.headers.get('content-type') || '';
        // 检查内容类型是否兼容
        if (contentType.includes('json') || contentType.includes('dns-json')) {
          return await response.json();
        } else {
          // 对于非标准的响应，仍尝试进行解析
          const textResponse = await response.text();
          try {
            return JSON.parse(textResponse);
          } catch (jsonError) {
            throw new Error(`无法解析响应为JSON: ${jsonError.message}, 响应内容: ${textResponse.substring(0, 100)}`);
          }
        }
      }

      // 错误情况记录，继续尝试下一个选项
      const errorText = await response.text();
      lastError = new Error(`DoH 服务器返回错误 (${response.status}): ${errorText.substring(0, 200)}`);

    } catch (err) {
      // 记录错误，继续尝试下一个选项
      lastError = err;
    }
  }

  // 所有尝试都失败，抛出最后一个错误
  throw lastError || new Error("无法完成 DNS 查询");
}

// 处理本地 DoH 请求的函数 - 直接调用 DoH，而不是自身服务
async function handleLocalDohRequest(domain, type, hostname) {
  try {
    if (type === "all") {
      // 同时请求 A、AAAA 和 NS 记录
      const ipv4Promise = queryDns(dnsDoH, domain, "A");
      const ipv6Promise = queryDns(dnsDoH, domain, "AAAA");
      const nsPromise = queryDns(dnsDoH, domain, "NS");

      // 等待所有请求完成
      const [ipv4Result, ipv6Result, nsResult] = await Promise.all([ipv4Promise, ipv6Promise, nsPromise]);

      // 准备NS记录数组
      const nsRecords = [];

      // 从Answer和Authority部分收集NS记录
      if (nsResult.Answer && nsResult.Answer.length > 0) {
        nsRecords.push(...nsResult.Answer.filter(record => record.type === 2));
      }

      if (nsResult.Authority && nsResult.Authority.length > 0) {
        nsRecords.push(...nsResult.Authority.filter(record => record.type === 2 || record.type === 6));
      }

      // 合并结果
      const combinedResult = {
        Status: ipv4Result.Status || ipv6Result.Status || nsResult.Status,
        TC: ipv4Result.TC || ipv6Result.TC || nsResult.TC,
        RD: ipv4Result.RD || ipv6Result.RD || nsResult.RD,
        RA: ipv4Result.RA || ipv6Result.RA || nsResult.RA,
        AD: ipv4Result.AD || ipv6Result.AD || nsResult.AD,
        CD: ipv4Result.CD || ipv6Result.CD || nsResult.CD,
        Question: [...(ipv4Result.Question || []), ...(ipv6Result.Question || []), ...(nsResult.Question || [])],
        Answer: [
          ...(ipv4Result.Answer || []),
          ...(ipv6Result.Answer || []),
          ...nsRecords
        ],
        ipv4: {
          records: ipv4Result.Answer || []
        },
        ipv6: {
          records: ipv6Result.Answer || []
        },
        ns: {
          records: nsRecords
        }
      };

      return new Response(JSON.stringify(combinedResult, null, 2), {
        headers: {
          "content-type": "application/json; charset=UTF-8",
          'Access-Control-Allow-Origin': '*'
        }
      });
    } else {
      // 普通的单类型查询
      const result = await queryDns(dnsDoH, domain, type);
      return new Response(JSON.stringify(result, null, 2), {
        headers: {
          "content-type": "application/json; charset=UTF-8",
          'Access-Control-Allow-Origin': '*'
        }
      });
    }
  } catch (err) {
    console.error("DoH 查询失败:", err);
    return new Response(JSON.stringify({
      error: `DoH 查询失败: ${err.message}`,
      stack: err.stack
    }, null, 2), {
      headers: {
        "content-type": "application/json; charset=UTF-8",
        'Access-Control-Allow-Origin': '*'
      },
      status: 500
    });
  }
}

// DoH 请求处理函数
async function DOHRequest(request) {
  const { method, headers, body } = request;
  const UA = headers.get('User-Agent') || 'DoH Client';
  const url = new URL(request.url);
  const { searchParams } = url;

  try {
    // 直接访问端点的处理
    if (method === 'GET' && !url.search) {
      // 如果是直接访问或浏览器访问，返回友好信息
      return new Response('Bad Request', {
        status: 400,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    // 根据请求方法和参数构建转发请求
    let response;

    if (method === 'GET' && searchParams.has('name')) {
      const searchDoH = searchParams.has('type') ? url.search : url.search + '&type=A';
      // 处理 JSON 格式的 DoH 请求
      response = await fetch(dnsDoH + searchDoH, {
        headers: {
          'Accept': 'application/dns-json',
          'User-Agent': UA
        }
      });
      // 如果 DoHUrl 请求非成功（状态码 200），则再请求 jsonDoH
      if (!response.ok) response = await fetch(jsonDoH + searchDoH, {
        headers: {
          'Accept': 'application/dns-json',
          'User-Agent': UA
        }
      });
    } else if (method === 'GET') {
      // 处理 base64url 格式的 GET 请求
      response = await fetch(dnsDoH + url.search, {
        headers: {
          'Accept': 'application/dns-message',
          'User-Agent': UA
        }
      });
    } else if (method === 'POST') {
      // 处理 POST 请求
      response = await fetch(dnsDoH, {
        method: 'POST',
        headers: {
          'Accept': 'application/dns-message',
          'Content-Type': 'application/dns-message',
          'User-Agent': UA
        },
        body: body
      });

    } else {
      // 其他不支持的请求方式
      return new Response('不支持的请求格式: DoH请求需要包含name或dns参数，或使用POST方法', {
        status: 400,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`DoH 返回错误 (${response.status}): ${errorText.substring(0, 200)}`);
    }

    // 创建一个新的响应头对象
    const responseHeaders = new Headers(response.headers);
    // 设置跨域资源共享 (CORS) 的头部信息
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    responseHeaders.set('Access-Control-Allow-Headers', '*');

    // 返回响应
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  } catch (error) {
    console.error("DoH 请求处理错误:", error);
    return new Response(JSON.stringify({
      error: `DoH 请求处理错误: ${error.message}`,
      stack: error.stack
    }, null, 4), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
}

async function HTML() {
  // 否则返回 HTML 页面
  const html = `<h1>hello</h1>`;

  // return new Response(html, {
  //   headers: { "content-type": "text/html;charset=UTF-8" }
  // });
    return new Response(null, {
    status: 301,
    headers: {"Location": "https://051214.xyz"}
    });
    
}

async function 代理URL(代理网址, 目标网址) {
  const 网址列表 = await 整理(代理网址);
  const 完整网址 = 网址列表[Math.floor(Math.random() * 网址列表.length)];

  // 解析目标 URL
  const 解析后的网址 = new URL(完整网址);
  console.log(解析后的网址);
  // 提取并可能修改 URL 组件
  const 协议 = 解析后的网址.protocol.slice(0, -1) || 'https';
  const 主机名 = 解析后的网址.hostname;
  let 路径名 = 解析后的网址.pathname;
  const 查询参数 = 解析后的网址.search;

  // 处理路径名
  if (路径名.charAt(路径名.length - 1) == '/') {
    路径名 = 路径名.slice(0, -1);
  }
  路径名 += 目标网址.pathname;

  // 构建新的 URL
  const 新网址 = `${协议}://${主机名}${路径名}${查询参数}`;

  // 反向代理请求
  const 响应 = await fetch(新网址);

  // 创建新的响应
  let 新响应 = new Response(响应.body, {
    status: 响应.status,
    statusText: 响应.statusText,
    headers: 响应.headers
  });

  // 添加自定义头部，包含 URL 信息
  //新响应.headers.set('X-Proxied-By', 'Cloudflare Worker');
  //新响应.headers.set('X-Original-URL', 完整网址);
  新响应.headers.set('X-New-URL', 新网址);

  return 新响应;
}

async function 整理(内容) {
  // 将制表符、双引号、单引号和换行符都替换为逗号
  // 然后将连续的多个逗号替换为单个逗号
  var 替换后的内容 = 内容.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',');

  // 删除开头和结尾的逗号（如果有的话）
  if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
  if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);

  // 使用逗号分割字符串，得到地址数组
  const 地址数组 = 替换后的内容.split(',');

  return 地址数组;
}

async function nginx() {
  const text = `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
  return text;
}
