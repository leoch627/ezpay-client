package main

// agent 本地面板页面。
//
// 单页，原生 JS，零外部依赖（不能引 CDN——这台机器经常没外网）。
// 四个区块：状态 / 设置 / 日志 / 微信进程。
//
// 为什么不用外部文件 + go:embed：
//   agent 是一个 exe，用户会单独拷走。内嵌字符串最省事，
//   少一个"文件忘了带"的故障点。

import "net/http"

func (a *agent) handlePanelIndex(w http.ResponseWriter, r *http.Request) {
	// 根路径以外不处理，避免抢 /hook/payment
	if r.URL.Path != "/" && r.URL.Path != "/panel" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(agentPanelHTML))
}

const agentPanelHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>微信挂机代理</title>
<style>
:root{
  --bg:#f6f7f9;--panel:#fff;--line:#e6e8ec;--text:#1c1e21;--dim:#6b7280;--dim2:#9aa1ab;
  --ok:#12a150;--okbg:#e8f7ee;--warn:#b26a00;--warnbg:#fff5e5;--err:#c62b2b;--errbg:#fdeaea;
  --accent:#0b6cff;--accentbg:#eaf2ff;--r:10px;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#17191c;--panel:#1e2126;--line:#2c3037;--text:#e6e8eb;--dim:#9aa1ab;--dim2:#6b7280;
  --ok:#3ecf74;--okbg:#16301f;--warn:#e0a83c;--warnbg:#332a17;--err:#ef6b6b;--errbg:#331b1b;
  --accent:#5b9dff;--accentbg:#17243a;
}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
  font:14px/1.55 "Segoe UI","Microsoft YaHei",system-ui,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:20px 18px 60px}
header{display:flex;align-items:center;gap:10px;margin-bottom:18px;flex-wrap:wrap}
h1{font-size:19px;margin:0;font-weight:600}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:20px;
  font-size:11.5px;background:var(--line);color:var(--dim)}
.badge .d{width:6px;height:6px;border-radius:50%;background:currentColor}
.badge.ok{background:var(--okbg);color:var(--ok)}
.badge.warn{background:var(--warnbg);color:var(--warn)}
.badge.err{background:var(--errbg);color:var(--err)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:16px;margin-bottom:14px}
.card h2{font-size:13px;margin:0 0 12px;font-weight:600;color:var(--dim)}
.kv{display:grid;grid-template-columns:130px 1fr;gap:10px;padding:8px 0;font-size:12.5px;align-items:center}
.kv+.kv{border-top:1px solid var(--line)}
.kv .k{color:var(--dim)}
.kv .v{min-width:0;word-break:break-all}
.mono{font-family:Consolas,"Cascadia Mono",monospace;font-size:11.5px}
input,select{width:100%;padding:8px 11px;font-size:13px;font-family:inherit;color:var(--text);
  background:var(--bg);border:1px solid var(--line);border-radius:7px;outline:none}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accentbg)}
label{display:block;font-size:12px;color:var(--dim);margin:10px 0 6px}
label:first-child{margin-top:0}
button{padding:7px 14px;font-size:12.5px;font-family:inherit;cursor:pointer;color:var(--text);
  background:var(--panel);border:1px solid var(--line);border-radius:7px}
button:hover{background:var(--line)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.primary:hover{filter:brightness(1.07)}
button:disabled{opacity:.5;cursor:not-allowed}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.note{display:none;padding:9px 12px;border-radius:7px;font-size:12px;margin-top:10px}
.note.on{display:block}
.note.ok{background:var(--okbg);color:var(--ok)}
.note.err{background:var(--errbg);color:var(--err)}
.note.info{background:var(--accentbg);color:var(--accent)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:12px;
  font:12px/1.6 Consolas,"Cascadia Mono",monospace;overflow:auto;max-height:420px;margin:0;
  white-space:pre-wrap;word-break:break-all}
.num{font-variant-numeric:tabular-nums}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line)}
th{color:var(--dim);font-weight:600;font-size:11px}
tr:last-child td{border-bottom:0}
.hint{font-size:11px;color:var(--dim2);margin-top:6px}
</style>
</head>
<body>
<div class="wrap">

<header>
  <h1>微信挂机代理</h1>
  <span class="badge" id="bVersion">—</span>
  <span class="badge" id="bConn"><i class="d"></i>连接中</span>
  <span class="badge" id="bHook"><i class="d"></i>Hook —</span>
  <div style="flex:1"></div>
  <button id="btnRefresh">刷新</button>
</header>

<!-- 状态 -->
<div class="card">
  <h2>运行状态</h2>
  <div class="kv"><span class="k">代理名称</span><span class="v" id="sAgentId">—</span></div>
  <div class="kv"><span class="k">主机</span><span class="v" id="sHost">—</span></div>
  <div class="kv"><span class="k">已运行</span><span class="v num" id="sUptime">—</span></div>
  <div class="kv"><span class="k">收款站地址</span><span class="v mono" id="sServer">—</span></div>
  <div class="kv"><span class="k">接入令牌</span><span class="v mono" id="sToken">—</span></div>
  <div class="kv"><span class="k">本地监听</span><span class="v mono" id="sListen">—</span></div>
  <div class="kv"><span class="k">待转发</span><span class="v num" id="sOutbox">0</span></div>
  <div class="kv"><span class="k">最近错误</span><span class="v" id="sLastErr">—</span></div>
</div>

<!-- 微信 & Hook -->
<div class="card">
  <h2>微信与 Hook</h2>
  <div class="kv"><span class="k">微信版本</span><span class="v" id="wVer">—</span></div>
  <div class="kv"><span class="k">微信路径</span><span class="v mono" id="wPath">—</span></div>
  <div class="kv"><span class="k">运行状态</span><span class="v" id="wRun">—</span></div>
  <div class="kv"><span class="k">收款账号</span><span class="v mono" id="wWxid">—</span></div>
  <div class="kv"><span class="k">Hook 状态</span><span class="v" id="hState">—</span></div>
  <div class="kv"><span class="k">命中特征</span><span class="v mono" id="hPattern">—</span></div>
  <div class="kv"><span class="k">捕获 / 识别</span><span class="v num" id="hCounts">0 / 0</span></div>
  <div class="kv"><span class="k">转发 成功/失败</span><span class="v num" id="hPost">0 / 0</span></div>
  <div class="kv"><span class="k">去重丢弃</span><span class="v num" id="hDedup">0</span></div>
  <div class="kv"><span class="k">说明</span><span class="v" id="hDetail">—</span></div>
  <div class="note err on" id="wrongProcWarn" style="display:none"></div>
  <div class="row" style="margin-top:12px">
    <button id="btnProcs">查看微信进程</button>
    <button class="primary" id="btnInject">自动注入</button>
  </div>
  <div class="note" id="injectNote"></div>
  <div id="procBox" style="display:none;margin-top:12px">
    <table><thead><tr><th>PID</th><th>内存</th><th>加载 Weixin.dll</th><th>版本</th><th></th></tr></thead>
    <tbody id="procBody"></tbody></table>
    <div class="hint">只有「加载 Weixin.dll = 是」的那个才是主进程，注错会报「Weixin.dll未加载」。</div>
  </div>
</div>

<!-- 设置 -->
<div class="card">
  <h2>上游设置</h2>
  <label>网关地址</label>
  <input id="fServer" placeholder="https://pay.example.com">
  <label>代理名称</label>
  <input id="fAgentId" placeholder="office-pc">
  <label>接入令牌（留空表示不修改）</label>
  <input id="fToken" placeholder="wxa_xxxx">
  <div class="hint" id="fTokenHint"></div>
  <div class="row" style="margin-top:14px">
    <button class="primary" id="btnSave">保存并重连</button>
    <button id="btnReload">重新读取</button>
  </div>
  <div class="note" id="saveNote"></div>
  <div class="hint" id="cfgPathHint"></div>
</div>

<!-- 日志 -->
<div class="card">
  <h2>日志</h2>
  <div class="row" style="margin-bottom:10px">
    <select id="fLevel" style="width:130px">
      <option value="all">全部</option>
      <option value="warn">警告</option>
      <option value="error">错误</option>
    </select>
    <select id="fTail" style="width:110px">
      <option value="200">最近 200 行</option>
      <option value="400" selected>最近 400 行</option>
      <option value="1000">最近 1000 行</option>
    </select>
    <button id="btnLogs">刷新日志</button>
    <button id="btnOpenLogs">打开日志目录</button>
  </div>
  <pre id="logBox">（点「刷新日志」加载）</pre>
  <div class="hint" id="logPath"></div>
</div>

</div>

<script>
(function(){
  var $ = function(id){ return document.getElementById(id); };

  function api(method, path, body){
    var opt = { method: method, headers: {} };
    if (body !== undefined) {
      opt.headers['Content-Type'] = 'application/json';
      opt.body = JSON.stringify(body);
    }
    return fetch(path, opt).then(function(r){
      return r.text().then(function(t){
        var d = null;
        try { d = t ? JSON.parse(t) : null; } catch(e) { d = { raw: t }; }
        if (!r.ok) {
          var msg = (d && (d.error || (d.problems && d.problems.join('；')))) || ('HTTP ' + r.status);
          throw new Error(msg);
        }
        return d;
      });
    });
  }

  function fmtUptime(s){
    s = Math.max(0, s|0);
    var d = Math.floor(s/86400), h = Math.floor(s%86400/3600), m = Math.floor(s%3600/60);
    if (d) return d + ' 天 ' + h + ' 小时';
    if (h) return h + ' 小时 ' + m + ' 分';
    return m + ' 分 ' + (s%60) + ' 秒';
  }

  function setBadge(el, cls, text){
    el.className = 'badge ' + cls;
    el.innerHTML = '<i class="d"></i>' + text;
  }

  var HOOK_STATES = {
    0:'初始化',1:'Weixin.dll未加载',2:'扫描中',3:'特征未命中',4:'前导不安全',
    5:'跳板分配失败',6:'打补丁失败',7:'已安装',8:'已卸载',9:'版本不支持'
  };

  function render(d){
    setBadge($('bVersion'), '', 'v' + (d.version||'dev'));

    if (d.connected) setBadge($('bConn'), 'ok', '已连网关');
    else if (!d.hasToken || !d.serverUrl) setBadge($('bConn'), 'warn', '未配置');
    else setBadge($('bConn'), 'err', '连不上网关');

    if (d.hook.attached) setBadge($('bHook'), 'ok', 'Hook 已安装');
    else if (d.hook.state) setBadge($('bHook'), 'warn', d.hook.state);
    else setBadge($('bHook'), 'warn', 'Hook 未注入');

    $('sAgentId').textContent = d.agentId || '—';
    $('sHost').textContent = d.hostname || '—';
    $('sUptime').textContent = fmtUptime(d.uptimeSec);
    $('sServer').textContent = d.serverUrl || '（未配置）';
    $('sToken').textContent = d.hasToken ? '已保存（DPAPI 加密）' : '未配置';
    $('sListen').textContent = d.listenAddr || '—';
    $('sOutbox').textContent = d.outbox;
    $('sLastErr').textContent = d.lastErr || '—';
    $('sLastErr').style.color = d.lastErr ? 'var(--err)' : '';

    $('wVer').textContent = d.wechat.version || '—';
    $('wPath').textContent = d.wechat.exePath || '—';
    $('wRun').textContent = d.wechat.running ? ('运行中 · PID ' + d.wechat.pid) : '未运行';
    $('wRun').style.color = d.wechat.running ? 'var(--ok)' : 'var(--dim)';
    $('wWxid').textContent = d.wechat.wxid || '（还没收到过款）';

    var stName = HOOK_STATES[d.hook.stateCode] || d.hook.state || '—';
    $('hState').textContent = stName;
    $('hState').style.color = d.hook.attached ? 'var(--ok)' : 'var(--warn)';

    // 注错进程：状态板指向的不是加载了 Weixin.dll 的主进程
    var wrong = d.hook.wrongProcess;
    var warnBox = $('wrongProcWarn');
    if (wrong) {
      warnBox.style.display = 'block';
      warnBox.innerHTML = '<b>⚠ 注入的进程不对</b><br>' +
        '状态来自 PID ' + (d.hook.pid || '?') + '，它不是加载了 Weixin.dll 的主进程，' +
        '所以钩不上。点「查看微信进程」，挑「加载 Weixin.dll = 是」的那个（通常是内存最大的，这里应该是 PID ' +
        (d.wechat.pid || '?') + '）。' +
        '<br><br><b>注意</b>：微信里如果还挂着旧版 wxhook.dll，它不会自动换掉。' +
        '必须<b>完全退出微信</b>（托盘图标也退出）重新打开，再注入。';
    } else {
      warnBox.style.display = 'none';
    }
    $('hPattern').textContent = d.hook.patternId || '—';
    $('hCounts').textContent = d.hook.callbackCount + ' / ' + d.hook.paymentCount;
    $('hPost').textContent = d.hook.postOk + ' / ' + d.hook.postFail;
    $('hDedup').textContent = d.hook.dedupDrop;
    $('hDetail').textContent = d.hook.detail || d.injector.note || '—';
  }

  var statTimer = null;

  function poll(){
    api('GET', '/api/stat').then(render).catch(function(e){
      $('sLastErr').textContent = '读取状态失败：' + e.message;
    });
  }

  function startPoll(){
    if (statTimer) clearInterval(statTimer);
    poll();
    statTimer = setInterval(poll, 2000);
  }

  // ── 设置 ──
  function loadSettings(){
    api('GET', '/api/settings').then(function(d){
      $('fServer').value = d.serverUrl || '';
      $('fAgentId').value = d.agentId || '';
      $('fToken').value = '';
      $('fTokenHint').textContent = d.hasToken
        ? ('当前令牌 ' + (d.tokenMasked||'') + '，留空则不修改')
        : '还没有令牌：去网关面板「代理」页生成';
      $('cfgPathHint').textContent = '配置文件：' + (d.cfgPath || 'data\\agent.json');
    }).catch(function(e){
      note('saveNote','err','读取设置失败：' + e.message);
    });
  }

  function note(id, cls, msg){
    var n = $(id);
    n.className = 'note on ' + cls;
    n.textContent = msg;
  }

  $('btnSave').onclick = function(){
    var body = {
      serverUrl: $('fServer').value.trim(),
      agentId: $('fAgentId').value.trim()
    };
    var tok = $('fToken').value.trim();
    if (tok) body.agentToken = tok;

    if (!body.agentId) return note('saveNote','err','代理名称不能为空');
    if (body.serverUrl && !/^https?:\/\//i.test(body.serverUrl))
      return note('saveNote','err','网关地址必须以 http:// 或 https:// 开头');

    $('btnSave').disabled = true;
    api('POST','/api/settings', body).then(function(){
      note('saveNote','ok','已保存，正在用新配置连接网关…');
      $('fToken').value = '';
      setTimeout(loadSettings, 600);
      setTimeout(poll, 1500);
    }).catch(function(e){
      note('saveNote','err','保存失败：' + e.message);
    }).then(function(){
      $('btnSave').disabled = false;
    });
  };

  $('btnReload').onclick = loadSettings;
  $('btnRefresh').onclick = function(){ poll(); loadSettings(); };

  // ── 注入 ──
  $('btnInject').onclick = function(){
    $('btnInject').disabled = true;
    note('injectNote','info','正在找微信进程并注入…');
    api('POST','/api/inject', {}).then(function(d){
      if (d.ok) {
        note('injectNote','ok', d.message || '注入成功');
      } else {
        note('injectNote','err', d.error || '注入失败');
      }
      setTimeout(poll, 1200);
    }).catch(function(e){
      note('injectNote','err','注入失败：' + e.message);
    }).then(function(){ $('btnInject').disabled = false; });
  };

  $('btnProcs').onclick = function(){
    var box = $('procBox');
    box.style.display = 'block';
    api('GET','/api/wechat-procs').then(function(d){
      var tb = $('procBody');
      tb.innerHTML = '';
      if (!d.procs || !d.procs.length) {
        tb.innerHTML = '<tr><td colspan="5" style="color:var(--dim2)">没有找到微信进程</td></tr>';
        return;
      }
      d.procs.forEach(function(p){
        var tr = document.createElement('tr');
        tr.innerHTML = '<td class="num">' + p.pid + '</td>' +
          '<td class="num">' + p.memMb + ' MB</td>' +
          '<td>' + (p.hasDll
            ? '<span style="color:var(--ok)">是</span>'
            : '<span style="color:var(--dim2)">否</span>') + '</td>' +
          '<td class="mono">' + (p.version||'—') + '</td>' +
          '<td><button data-pid="' + p.pid + '">注入这个</button></td>';
        tr.querySelector('button').onclick = function(){
          var btn = this;
          btn.disabled = true;
          api('POST','/api/inject', { pid: p.pid }).then(function(r){
            note('injectNote', r.ok ? 'ok':'err', r.ok ? (r.message||'已注入') : (r.error||'失败'));
            setTimeout(poll, 1200);
          }).catch(function(e){
            note('injectNote','err', e.message);
          }).then(function(){ btn.disabled = false; });
        };
        tb.appendChild(tr);
      });
    }).catch(function(e){
      $('procBody').innerHTML = '<tr><td colspan="5" style="color:var(--err)">' + e.message + '</td></tr>';
    });
  };

  // ── 日志 ──
  function loadLogs(){
    var lv = $('fLevel').value;
    var tail = $('fTail').value;
    var qs = '/api/logs?tail=' + tail + (lv !== 'all' ? ('&level=' + lv) : '');
    api('GET', qs).then(function(d){
      var box = $('logBox');
      if (!d.lines || !d.lines.length) {
        box.textContent = d.note || '（没有日志）';
      } else {
        box.textContent = d.lines.join('\n');
        box.scrollTop = box.scrollHeight;
      }
      $('logPath').textContent = d.path ? ('日志：' + d.path) : '';
    }).catch(function(e){
      $('logBox').textContent = '读取失败：' + e.message;
    });
  }

  $('btnLogs').onclick = loadLogs;
  $('fLevel').onchange = loadLogs;
  $('fTail').onchange = loadLogs;
  $('btnOpenLogs').onclick = function(){
    api('POST','/api/open-logs', {}).then(function(d){
      $('logPath').textContent = '已打开：' + d.dir;
    }).catch(function(e){
      $('logPath').textContent = '打开失败：' + e.message;
    });
  };

  // ── 启动 ──
  startPoll();
  loadSettings();
  loadLogs();

  document.addEventListener('visibilitychange', function(){
    if (document.hidden) {
      if (statTimer) { clearInterval(statTimer); statTimer = null; }
    } else {
      startPoll();
    }
  });
})();
</script>
</body>
</html>
`
