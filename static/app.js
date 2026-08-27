(function () {
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const $ = (id) => document.getElementById(id);

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(
        () => true,
        () => copyFallback(text)
      );
    }
    return Promise.resolve(copyFallback(text));
  }

  function copyFallback(text) {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch (e) {
      return false;
    }
  }

  function buildCopyBtn(text, label) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = label;
    btn.className = 'ghost';
    btn.addEventListener('click', async () => {
      btn.textContent = '复制中...';
      const ok = await copyText(text);
      btn.textContent = ok ? '已复制' : '复制失败';
      setTimeout(() => { btn.textContent = label; }, 1500);
    });
    return btn;
  }

  async function api(url, body) {
    const method = body === undefined ? 'GET' : 'POST';
    const opts = { method, headers: {} };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.headers['X-CSRF-Token'] = csrf;
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    const type = res.headers.get('Content-Type') || '';
    if (res.status === 302 || !type.includes('application/json')) {
      window.location.href = '/login';
      throw new Error('会话已失效，请重新登录');
    }
    return res.json();
  }

  function show(el, ok, text) {
    el.textContent = text;
    el.classList.remove('hidden');
    el.classList.toggle('error', !ok);
  }

  function renderKeystore(records, selectedId) {
    const sel = $('keystore-sel');
    const cur = sel.value;
    sel.innerHTML = '';
    const opt0 = document.createElement('option');
    opt0.value = '';
    opt0.textContent = '＋ 新建密钥（手动填写）';
    sel.appendChild(opt0);
    (records || []).forEach((r) => {
      const o = document.createElement('option');
      o.value = r.id;
      o.textContent = (r.src_user || '?') + '@' + (r.src_host || '?') + ' · ' + r.key_type +
        ' · ' + (r.created_at || '');
      sel.appendChild(o);
    });
    if (selectedId && [...sel.options].some((o) => o.value === selectedId)) {
      sel.value = selectedId;
    } else if (cur && [...sel.options].some((o) => o.value === cur)) {
      sel.value = cur;
    } else {
      sel.value = '';
    }
  }

  async function refreshKeystore(selectId) {
    try {
      const r = await api('/api/keystore/list');
      if (r.ok) renderKeystore(r.records || [], selectId || '');
    } catch (e) { /* 会话失效已跳转 */ }
  }

  function clearSelectionFields() {
    // 新建模式: 清空发起端与公钥, 保留端口/类型默认
    $('src-ip').value = '';
    $('src-user').value = '';
    $('src-os').value = 'linux';
    $('src-os-hint').classList.add('hidden');
    $('dst-pubkey').value = '';
    $('dst-pubkey').readOnly = true;
    $('src-result').classList.add('hidden');
  }

  async function applyKeystore(id) {
    if (!id) { clearSelectionFields(); return; }
    try {
      const r = await api('/api/keystore/get?id=' + encodeURIComponent(id));
      if (!r.ok) { show($('src-result'), false, '❌ 读取失败：' + (r.error || '未知')); return; }
      const rec = r.record;
      $('src-ip').value = rec.src_host || '';
      $('src-user').value = rec.src_user || '';
      $('src-port').value = rec.src_port || 22;
      $('src-os').value = rec.src_platform === 'windows' ? 'windows' : 'linux';
      $('src-os-hint').classList.toggle('hidden', rec.src_platform !== 'windows');
      $('src-type').value = rec.key_type === 'rsa' ? 'rsa' : 'ed25519';
      if (rec.public_key) {
        $('dst-pubkey').value = rec.public_key;
        $('dst-pubkey').readOnly = false;
      }
      const osName = rec.src_platform === 'windows' ? 'Windows' : 'Linux';
      const div = $('src-result');
      div.textContent = '';
      div.classList.remove('hidden', 'error');
      div.appendChild(document.createTextNode(
        '✅ 已选择历史密钥：' + (rec.src_user || '') + '@' + (rec.src_host || '') +
        '（' + osName + ' · ' + rec.key_type + '）\n'
      ));
      const pre = document.createElement('pre');
      pre.textContent = (rec.priv_path || '私钥路径未知') + '\n\n公钥：\n' + (rec.public_key || '');
      div.appendChild(pre);
      if (rec.private_key) {
        div.appendChild(buildCopyBtn(rec.private_key, '复制私钥内容'));
      }
      if (rec.public_key) {
        div.appendChild(buildCopyBtn(rec.public_key, '复制公钥'));
      }
      div.appendChild(document.createElement('br'));
      div.appendChild(document.createTextNode('公钥已自动填入下方接受端，填好目标机信息即可部署。'));
    } catch (e) {
      show($('src-result'), false, '请求出错：' + e.message);
    }
  }

  $('keystore-sel').addEventListener('change', () => {
    applyKeystore($('keystore-sel').value);
  });

  // 平台切换: 显示对应提示/字段
  $('src-os').addEventListener('change', () => {
    $('src-os-hint').classList.toggle('hidden', $('src-os').value !== 'windows');
  });
  $('dst-os').addEventListener('change', () => {
    $('row-router-user').classList.toggle('hidden', $('dst-os').value !== 'routeros');
  });
  $('dst-auth').addEventListener('change', () => {
    $('row-dst-key').classList.toggle('hidden', $('dst-auth').value !== 'key');
  });

  // 发起端: 生成私钥
  $('btn-gen').addEventListener('click', async () => {
    const btn = $('btn-gen');
    btn.disabled = true; btn.textContent = '正在生成...';
    try {
      const r = await api('/api/gen-remote', {
        host: $('src-ip').value.trim(),
        port: parseInt($('src-port').value || '22', 10),
        user: $('src-user').value.trim(),
        password: $('src-pass').value,
        platform: $('src-os').value,
        key_type: $('src-type').value,
      });
      if (!r.ok) { show($('src-result'), false, '❌ 生成失败：' + (r.error || '未知错误')); return; }
      const osName = $('src-os').value === 'windows' ? 'Windows' : 'Linux';
      const div = $('src-result');
      div.textContent = '';
      div.classList.remove('hidden', 'error');
      div.appendChild(document.createTextNode(
        '✅ 已生成私钥于 ' + osName + ' 发起端：\n' + r.priv_path + '\n\n公钥：\n' + r.public +
        '\n\n下方接受端将自动填入该公钥。'
      ));
      $('dst-pubkey').value = r.public;
      $('dst-pubkey').readOnly = false;
      // 若已保存到密钥库, 刷新下拉并选中
      if (r.keystore_id) {
        await refreshKeystore(r.keystore_id);
      }
    } catch (e) {
      show($('src-result'), false, '请求出错：' + e.message);
    } finally {
      btn.disabled = false; btn.textContent = '生成私钥';
    }
  });

  // 接受端: 部署公钥
  $('btn-deploy').addEventListener('click', async () => {
    const btn = $('btn-deploy');
    btn.disabled = true; btn.textContent = '正在部署...';
    try {
      const r = await api('/api/deploy-remote', {
        host: $('dst-ip').value.trim(),
        port: parseInt($('dst-port').value || '22', 10),
        user: $('dst-user').value.trim(),
        password: $('dst-pass').value,
        platform: $('dst-os').value,
        router_user: $('dst-router-user').value.trim() || undefined,
        public_key: $('dst-pubkey').value.trim(),
        auth_key: $('dst-auth').value === 'key' ? $('dst-authkey').value.trim() : undefined,
      });
      if (!r.ok) { show($('dst-result'), false, '❌ 部署失败：' + (r.error || '未知错误')); return; }
      const osName = $('dst-os').value === 'routeros' ? 'RouterOS' : 'Linux';
      show($('dst-result'), true,
        '✅ 公钥已部署到 ' + osName + ' ' + $('dst-ip').value.trim() +
        '（' + r.target + '）。');
    } catch (e) {
      show($('dst-result'), false, '请求出错：' + e.message);
    } finally {
      btn.disabled = false; btn.textContent = '部署公钥';
    }
  });

  // 初始加载密钥库
  refreshKeystore('');
})();
