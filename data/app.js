/**
 * ESP32 WiFi Sniffer - Web Application
 */

// ==================== 全局状态 ====================
const state = {
    connected: false,
    ws: null,
    reconnectInterval: 5000,
    currentTab: 'dashboard',
    lang: localStorage.getItem('lang') || 'en',
    networks: [],
    packets: [],
    logs: [],
    handshake: { msg1: false, msg2: false, msg3: false, msg4: false },
    attack: { running: false, progress: 0 },
    stats: {
        totalPackets: 0,
        networksFound: 0,
        channel: 1,
        rssi: 0
    }
};

// ==================== 中英文翻译 ====================
const i18n = {
    en: {
        // Header & Status
        connected: 'Connected',
        disconnected: 'Disconnected',
        // Dashboard
        statistics: 'Statistics',
        totalPackets: 'Total Packets',
        networksFound: 'Networks Found',
        currentChannel: 'Current Channel',
        rssi: 'RSSI',
        wifiInfo: 'WiFi Info',
        apIp: 'AP IP',
        connectedClients: 'Connected Clients',
        uptime: 'Uptime',
        quickActions: 'Quick Actions',
        packetRate: 'Packet Rate',
        // Networks tab
        networks: 'Networks',
        filterNetworks: 'Filter networks...',
        ssid: 'SSID',
        bssid: 'BSSID',
        channel: 'Channel',
        security: 'Security',
        packets: 'Packets',
        actions: 'Actions',
        refresh: 'Refresh',
        select: 'Select',
        capture: 'Capture',
        // Capture tab
        captureControl: 'Capture Control',
        targetBssid: 'Target BSSID',
        handshakeCapture: 'Handshake Capture',
        noHandshake: 'No handshake captured',
        handshakeCaptured: 'Handshake captured! Quality',
        capturing: 'Capturing handshake...',
        download: 'Download',
        files: 'Files',
        allHop: 'All (Hop)',
        // Attack tab
        attack: 'Attack',
        warningLabel: 'Warning: These features are for authorized security testing only!',
        deauthAttack: 'Deauth Attack',
        targetStation: 'Target Station (optional)',
        reasonCode: 'Reason Code',
        startDeauth: 'Start Deauth',
        stop: 'Stop',
        dictionaryAttack: 'Dictionary Attack',
        handshakeFile: 'Handshake File',
        dictionary: 'Dictionary',
        selectHandshake: 'Select handshake...',
        selectDictionary: 'Select dictionary...',
        startAttack: 'Start Attack',
        tested: 'Tested',
        speed: 'Speed',
        pleaseEnterBssid: 'Please enter target BSSID',
        confirmDeauth: 'WARNING: This will disconnect clients from the network. Continue?',
        // Logs tab
        logs: 'Logs',
        clear: 'Clear',
        export: 'Export',
        allLevels: 'All Levels',
        // Footer
        securityResearch: 'For security research only',
        webLoaded: 'Web interface loaded',
        scanStarted: 'WiFi scan started',
        sniffStarted: 'Packet sniffing started',
        sniffStopped: 'Packet sniffing stopped',
        networkSelected: 'Selected network',
        handshakeStarted: 'Handshake capture started for',
        deauthStarted: 'Deauth attack started on',
        attackStopped: 'Attack stopped',
        dictAttackStarted: 'Dictionary attack started',
        deviceReset: 'Device reset',
        selectHandshakeAndDict: 'Please select handshake file and dictionary',
    },
    zh: {
        // Header & Status
        connected: '已连接',
        disconnected: '未连接',
        // Dashboard
        statistics: '统计信息',
        totalPackets: '总数据包',
        networksFound: '发现网络',
        currentChannel: '当前信道',
        rssi: '信号强度',
        wifiInfo: 'WiFi 信息',
        apIp: 'AP 地址',
        connectedClients: '已连接客户端',
        uptime: '运行时间',
        quickActions: '快捷操作',
        packetRate: '数据包速率',
        // Networks tab
        networks: '网络列表',
        filterNetworks: '筛选网络...',
        ssid: 'SSID',
        bssid: 'BSSID',
        channel: '信道',
        security: '加密',
        packets: '数据包',
        actions: '操作',
        refresh: '刷新',
        select: '选中',
        capture: '捕获',
        // Capture tab
        captureControl: '抓包控制',
        targetBssid: '目标 BSSID',
        handshakeCapture: '握手包捕获',
        noHandshake: '未捕获到握手包',
        handshakeCaptured: '握手包已捕获！质量',
        capturing: '正在捕获握手包...',
        download: '下载',
        files: '文件列表',
        allHop: '全信道跳频',
        // Attack tab
        attack: '攻击',
        warningLabel: '⚠️ 警告：这些功能仅用于授权的安全测试！',
        deauthAttack: 'Deauth 攻击',
        targetStation: '目标设备 MAC（可选）',
        reasonCode: '原因码',
        startDeauth: '⚠️ 开始攻击',
        stop: '停止',
        dictionaryAttack: '字典攻击',
        handshakeFile: '握手包文件',
        dictionary: '字典文件',
        selectHandshake: '选择握手包...',
        selectDictionary: '选择字典...',
        startAttack: '▶️ 开始攻击',
        tested: '已测试',
        speed: '速度',
        pleaseEnterBssid: '请输入目标 BSSID',
        confirmDeauth: '⚠️ 警告：这将断开目标网络的客户端连接。确定继续吗？',
        // Logs tab
        logs: '日志',
        clear: '清空',
        export: '导出',
        allLevels: '所有级别',
        // Footer
        securityResearch: '仅供安全研究使用',
        webLoaded: 'Web 界面已加载',
        scanStarted: 'WiFi 扫描已启动',
        sniffStarted: '数据包嗅探已启动',
        sniffStopped: '数据包嗅探已停止',
        networkSelected: '已选中网络',
        handshakeStarted: '开始捕获握手包',
        deauthStarted: 'Deauth 攻击已启动',
        attackStopped: '攻击已停止',
        dictAttackStarted: '字典攻击已启动',
        deviceReset: '设备已重置',
        selectHandshakeAndDict: '请选择握手包文件和字典文件',
    }
};

function T(key) {
    return i18n[state.lang][key] || key;
}

function toggleLanguage() {
    state.lang = state.lang === 'en' ? 'zh' : 'en';
    localStorage.setItem('lang', state.lang);
    applyLanguage();
}

function applyLanguage() {
    const btn = document.getElementById('lang-toggle');
    btn.textContent = state.lang === 'en' ? 'EN | 中文' : '中文 | EN';
    document.documentElement.lang = state.lang === 'en' ? 'en' : 'zh-CN';

    // Tab buttons
    document.querySelector('[data-tab="dashboard"]').textContent = T('statistics');
    document.querySelector('[data-tab="networks"]').textContent = T('networks');
    document.querySelector('[data-tab="capture"]').textContent = T('captureControl');
    document.querySelector('[data-tab="attack"]').textContent = T('attack');
    document.querySelector('[data-tab="logs"]').textContent = T('logs');

    // Dashboard card 1
    document.querySelector('#dashboard .card-grid .card:nth-child(1) h3').textContent = '📊 ' + T('statistics');
    document.querySelector('#dashboard .card-grid .card:nth-child(1) .stat-row:nth-child(1) .stat-label').textContent = T('totalPackets') + ':';
    document.querySelector('#dashboard .card-grid .card:nth-child(1) .stat-row:nth-child(2) .stat-label').textContent = T('networksFound') + ':';
    document.querySelector('#dashboard .card-grid .card:nth-child(1) .stat-row:nth-child(3) .stat-label').textContent = T('currentChannel') + ':';
    document.querySelector('#dashboard .card-grid .card:nth-child(1) .stat-row:nth-child(4) .stat-label').textContent = T('rssi') + ':';

    // Dashboard card 2
    document.querySelector('#dashboard .card-grid .card:nth-child(2) h3').textContent = '📡 ' + T('wifiInfo');
    document.querySelector('#dashboard .card-grid .card:nth-child(2) .stat-row:nth-child(1) .stat-label').textContent = T('apIp') + ':';
    document.querySelector('#dashboard .card-grid .card:nth-child(2) .stat-row:nth-child(2) .stat-label').textContent = T('connectedClients') + ':';
    document.querySelector('#dashboard .card-grid .card:nth-child(2) .stat-row:nth-child(3) .stat-label').textContent = T('uptime') + ':';

    // Dashboard card 3
    document.querySelector('#dashboard .card-grid .card:nth-child(3) h3').textContent = '🎯 ' + T('quickActions');
    document.getElementById('btn-scan').textContent = state.lang === 'en' ? 'Start Scan' : '开始扫描';
    document.getElementById('btn-sniff').textContent = state.lang === 'en' ? 'Start Sniff' : '开始抓包';
    document.getElementById('btn-reset').textContent = state.lang === 'en' ? 'Reset' : '重置';

    // Dashboard card 4 (outside card-grid)
    // document.querySelector('#dashboard > .card:last-child h3').textContent = '📈 ' + T('packetRate');
    const packetRateTitle = document.querySelector('#dashboard > .card:last-child h3');
    if (packetRateTitle) packetRateTitle.textContent = '📈 ' + T('packetRate');

    // Networks tab
    document.getElementById('btn-refresh-networks').textContent = '🔄 ' + T('refresh');
    document.getElementById('network-filter').placeholder = T('filterNetworks');
    const ths = document.querySelectorAll('#networks-table th');
    ths[0].textContent = T('ssid');
    ths[1].textContent = T('bssid');
    ths[2].textContent = T('channel');
    ths[3].textContent = T('rssi');
    ths[4].textContent = T('security');
    ths[5].textContent = T('packets');
    ths[6].textContent = T('actions');

    // Capture tab labels
    document.querySelector('#capture .card-grid .card:nth-child(1) h3').textContent = '📦 ' + T('captureControl');
    const captureLabels = document.querySelectorAll('#capture .card-grid .card:nth-child(1) label');
    if (captureLabels[0]) captureLabels[0].textContent = T('channel') + ':';
    if (captureLabels[1]) captureLabels[1].textContent = T('targetBssid') + ':';
    document.getElementById('btn-capture-start').textContent = '▶️ ' + (state.lang === 'en' ? 'Start' : '开始');
    document.getElementById('btn-capture-stop').textContent = '⏹️ ' + T('stop');

    document.querySelector('#capture .card-grid .card:nth-child(2) h3').textContent = '🤝 ' + T('handshakeCapture');
    document.getElementById('handshake-text').textContent = T('noHandshake');
    document.getElementById('btn-download-handshake').textContent = '⬇️ ' + T('download');

    document.querySelector('#capture > .card h3').textContent = '💾 ' + T('files');

    // Update all select option text
    const allHopOption = document.querySelector('#capture-channel option');
    if (allHopOption) allHopOption.textContent = T('allHop');

    // Attack tab
    const warningBox = document.querySelector('#attack .warning-box');
    if (warningBox) warningBox.innerHTML = '⚠️ <strong>' + T('warningLabel') + '</strong>';

    document.querySelector('#attack .card-grid .card:nth-child(1) h3').textContent = '💥 ' + T('deauthAttack');
    const deauthLabels = document.querySelectorAll('#attack .card-grid .card:nth-child(1) label');
    if (deauthLabels[0]) deauthLabels[0].textContent = T('targetBssid') + ':';
    if (deauthLabels[1]) deauthLabels[1].textContent = T('targetStation') + ':';
    if (deauthLabels[2]) deauthLabels[2].textContent = T('reasonCode') + ':';
    document.getElementById('btn-deauth-start').textContent = T('startDeauth');
    document.getElementById('btn-deauth-stop').textContent = T('stop');

    document.querySelector('#attack .card-grid .card:nth-child(2) h3').textContent = '🔓 ' + T('dictionaryAttack');
    const dictLabels = document.querySelectorAll('#attack .card-grid .card:nth-child(2) label');
    if (dictLabels[0]) dictLabels[0].textContent = T('handshakeFile') + ':';
    if (dictLabels[1]) dictLabels[1].textContent = T('dictionary') + ':';
    const selectOptions = document.querySelectorAll('#dict-handshake option');
    if (selectOptions[0]) selectOptions[0].textContent = T('selectHandshake');
    const dictOptions = document.querySelectorAll('#dict-file option');
    if (dictOptions[0]) dictOptions[0].textContent = T('selectDictionary');
    document.getElementById('btn-dict-start').textContent = T('startAttack');
    document.getElementById('btn-dict-stop').textContent = T('stop');

    // Logs tab
    document.getElementById('btn-clear-logs').textContent = T('clear');
    document.getElementById('btn-export-logs').textContent = T('export');
    const logOptions = document.querySelectorAll('#log-level option');
    logOptions[0].textContent = T('allLevels');

    // Footer
    document.querySelector('footer p').textContent = 'ESP32 WiFi Sniffer v1.0.0 | ' + T('securityResearch');
}

// ==================== WebSocket 连接 ====================
function connectWebSocket() {
    const wsUrl = `ws://${window.location.hostname}:81/ws`;
    
    state.ws = new WebSocket(wsUrl);
    
    state.ws.onopen = () => {
        console.log('WebSocket connected');
        state.connected = true;
        updateConnectionStatus();
        requestStatus();
    };
    
    state.ws.onclose = () => {
        console.log('WebSocket disconnected');
        state.connected = false;
        updateConnectionStatus();
        setTimeout(connectWebSocket, state.reconnectInterval);
    };
    
    state.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
    };
    
    state.ws.onmessage = (event) => {
        handleMessage(JSON.parse(event.data));
    };
}

function updateConnectionStatus() {
    const statusEl = document.getElementById('connection-status');
    if (state.connected) {
        statusEl.textContent = T('connected');
        statusEl.className = 'status connected';
    } else {
        statusEl.textContent = T('disconnected');
        statusEl.className = 'status disconnected';
    }
}

function requestStatus() {
    if (state.ws && state.ws.readyState === WebSocket.OPEN) {
        state.ws.send(JSON.stringify({ cmd: 'get_status' }));
    }
}

// ==================== 消息处理 ====================
function handleMessage(data) {
    switch (data.type) {
        case 'status':
            updateStatus(data);
            break;
        case 'scan_result':
            addNetwork(data.data);
            break;
        case 'scan_complete':
            addLog('info', T('scanStarted'));
            break;
        case 'packet':
            handlePacket(data.data);
            break;
        case 'handshake':
            updateHandshake(data.data);
            break;
        case 'attack_progress':
            updateAttackProgress(data.data);
            break;
        case 'log':
            addLog(data.level, data.message);
            break;
    }
}

function updateStatus(data) {
    state.stats.totalPackets = data.packets || 0;
    state.stats.networksFound = data.networks || 0;
    state.stats.channel = data.channel || 1;
    state.stats.rssi = data.rssi || 0;
    
    document.getElementById('stat-packets').textContent = state.stats.totalPackets;
    document.getElementById('stat-networks').textContent = state.stats.networksFound;
    document.getElementById('stat-channel').textContent = state.stats.channel;
    document.getElementById('stat-rssi').textContent = state.stats.rssi + ' dBm';
    document.getElementById('wifi-clients').textContent = data.wifi?.ap_clients || 0;
    
    // 更新模式标签
    const modeBadge = document.getElementById('mode-badge');
    const modes = ['IDLE', 'SCANNING', 'SNIFFING', 'HANDSHAKE', 'DEAUTH', 'ATTACK', 'WEB'];
    modeBadge.textContent = modes[data.mode] || 'UNKNOWN';
    
    // 更新运行时间
    const uptime = data.uptime || 0;
    const hours = Math.floor(uptime / 3600);
    const minutes = Math.floor((uptime % 3600) / 60);
    const seconds = uptime % 60;
    document.getElementById('stat-uptime').textContent = 
        `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

function handlePacket(data) {
    state.stats.totalPackets++;
    document.getElementById('stat-packets').textContent = state.stats.totalPackets;
    
    // 更新图表
    updatePacketChart();
}

function addNetwork(network) {
    // 检查是否已存在
    const existing = state.networks.find(n => n.bssid === network.bssid);
    if (existing) {
        Object.assign(existing, network);
    } else {
        state.networks.push(network);
    }
    
    updateNetworksTable();
}

function updateNetworksTable() {
    const tbody = document.getElementById('networks-tbody');
    const filter = document.getElementById('network-filter')?.value.toLowerCase() || '';
    
    tbody.innerHTML = state.networks
        .filter(n => !filter || n.ssid.toLowerCase().includes(filter) || n.bssid.toLowerCase().includes(filter))
        .map(n => `
            <tr>
                <td>${escapeHtml(n.ssid)}</td>
                <td>${n.bssid}</td>
                <td>${n.channel}</td>
                <td>${n.rssi} dBm</td>
                <td>${n.auth}</td>
                <td>${n.packets}</td>
                <td>
                    <button class="btn btn-small" onclick="selectNetwork('${n.bssid}', ${n.channel})">Select</button>
                    <button class="btn btn-small btn-danger" onclick="captureHandshake('${n.bssid}')">Capture</button>
                </td>
            </tr>
        `).join('');
}

function updateHandshake(data) {
    state.handshake = {
        msg1: data.msg1,
        msg2: data.msg2,
        msg3: data.msg3,
        msg4: data.msg4
    };
    
    // 更新指示器
    document.getElementById('msg1').className = 'msg-indicator ' + (data.msg1 ? 'received' : '');
    document.getElementById('msg2').className = 'msg-indicator ' + (data.msg2 ? 'received' : '');
    document.getElementById('msg3').className = 'msg-indicator ' + (data.msg3 ? 'received' : '');
    document.getElementById('msg4').className = 'msg-indicator ' + (data.msg4 ? 'received' : '');
    
    // 更新进度条
    const quality = data.quality || 0;
    document.getElementById('handshake-progress').style.width = quality + '%';
    
    // 更新文本
    const statusText = data.complete ? 
        `✅ ${T('handshakeCaptured')}: ${quality}%` : 
        `⏳ ${T('capturing')} ${quality}%`;
    document.getElementById('handshake-text').textContent = statusText;
    
    // 启用下载按钮
    document.getElementById('btn-download-handshake').disabled = !data.valid;
}

function updateAttackProgress(data) {
    state.attack.progress = data.progress || 0;
    
    const progressBar = document.querySelector('#dict-progress .progress-fill');
    if (progressBar) {
        progressBar.style.width = state.attack.progress + '%';
    }
    
    const statsText = `${T('tested')}: ${data.tested}/${data.total} | ${T('speed')}: ${data.speed.toFixed(1)} p/s`;
    document.getElementById('dict-stats').textContent = statsText;
}

function addLog(level, message) {
    const timestamp = new Date().toLocaleTimeString();
    state.logs.push({ timestamp, level, message });
    
    // 限制日志数量
    if (state.logs.length > 1000) {
        state.logs.shift();
    }
    
    updateLogDisplay();
}

function updateLogDisplay() {
    const container = document.getElementById('log-container');
    const levelFilter = document.getElementById('log-level')?.value || 'all';
    
    const filtered = state.logs.filter(l => levelFilter === 'all' || l.level === levelFilter);
    
    container.innerHTML = filtered.map(l => `
        <div class="log-line log-${l.level}">
            <span class="log-time">${l.timestamp}</span>
            <span class="log-level">[${l.level.toUpperCase()}]</span>
            <span class="log-message">${escapeHtml(l.message)}</span>
        </div>
    `).join('');
    
    // 自动滚动到底部
    container.scrollTop = container.scrollHeight;
}

// ==================== 图表 ====================
let packetChart = null;
let packetHistory = [];

function initPacketChart() {
    const canvas = document.getElementById('packet-chart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // 初始化历史数据
    packetHistory = new Array(100).fill(0);
    
    drawChart(ctx);
    
    // 定期更新
    setInterval(() => {
        packetHistory.shift();
        packetHistory.push(state.stats.totalPackets);
        drawChart(ctx);
    }, 1000);
}

function drawChart(ctx) {
    const width = ctx.canvas.width;
    const height = ctx.canvas.height;
    
    ctx.clearRect(0, 0, width, height);
    
    // 绘制网格
    ctx.strokeStyle = '#333';
    ctx.lineWidth = 1;
    for (let i = 0; i < 5; i++) {
        const y = (height / 4) * i;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
    }
    
    // 绘制数据线
    ctx.strokeStyle = '#4CAF50';
    ctx.lineWidth = 2;
    ctx.beginPath();
    
    const maxVal = Math.max(...packetHistory, 1);
    
    packetHistory.forEach((val, i) => {
        const x = (width / (packetHistory.length - 1)) * i;
        const y = height - (val / maxVal) * height * 0.9;
        
        if (i === 0) {
            ctx.moveTo(x, y);
        } else {
            ctx.lineTo(x, y);
        }
    });
    
    ctx.stroke();
}

function updatePacketChart() {
    // 图表会在定时器中更新
}

// ==================== API 调用 ====================
async function apiCall(endpoint, method = 'GET', data = null) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json'
        }
    };
    
    if (data) {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(`/api/${endpoint}`, options);
        return await response.json();
    } catch (error) {
        console.error('API call failed:', error);
        return { success: false, error: error.message };
    }
}

// ==================== 操作函数 ====================
async function startScan() {
    addLog('info', 'Starting scan...');
    const result = await apiCall('scan');
    if (result.success) {
        state.networks = [];
        addLog('success', 'Scan started successfully');
    } else {
        addLog('error', 'Failed to start scan: ' + (result.error || 'Unknown error'));
    }
}

async function startSniff() {
    const channel = document.getElementById('capture-channel')?.value || 0;
    addLog('info', `Starting capture on channel ${channel}...`);
    const result = await apiCall(`capture/start?channel=${channel}`, 'POST');
    if (result.success) {
        addLog('success', T('sniffStarted'));
    } else {
        addLog('error', 'Failed to start capture: ' + (result.error || 'Unknown error'));
    }
}

async function stopSniff() {
    const result = await apiCall('capture/stop', 'POST');
    if (result.success) addLog('info', T('sniffStopped'));
}

function selectNetwork(bssid, channel) {
    document.getElementById('capture-bssid').value = bssid;
    document.getElementById('deauth-bssid').value = bssid;
    document.getElementById('capture-channel').value = channel;
    addLog('info', `${T('networkSelected')}: ${bssid} (CH${channel})`);
}

async function captureHandshake(bssid) {
    const result = await apiCall(`capture/start?bssid=${bssid}`, 'POST');
    if (result.success) {
        addLog('info', `${T('handshakeStarted')} ${bssid}`);
    }
}

async function startDeauth() {
    const bssid = document.getElementById('deauth-bssid').value;
    const station = document.getElementById('deauth-station').value;
    const reason = document.getElementById('deauth-reason').value;
    
    if (!bssid) {
        alert(T('pleaseEnterBssid'));
        return;
    }
    
    if (!confirm(T('confirmDeauth'))) {
        return;
    }
    
    const params = new URLSearchParams({ bssid, reason });
    if (station) params.append('station', station);
    
    const result = await apiCall(`attack/start?${params.toString()}`, 'POST');
    if (result.success) {
        addLog('warning', `${T('deauthStarted')} ${bssid}`);
    }
}

async function stopDeauth() {
    const result = await apiCall('attack/stop', 'POST');
    if (result.success) addLog('info', T('attackStopped'));
}

async function startDictAttack() {
    const handshake = document.getElementById('dict-handshake').value;
    const dict = document.getElementById('dict-file').value;
    
    if (!handshake || !dict) {
        alert(T('selectHandshakeAndDict'));
        return;
    }
    
    const result = await apiCall(`attack/start?type=dict&handshake=${handshake}&dict=${dict}`, 'POST');
    if (result.success) {
        addLog('info', T('dictAttackStarted'));
        state.attack.running = true;
    }
}

async function stopDictAttack() {
    const result = await apiCall('attack/stop', 'POST');
    if (result.success) {
        addLog('info', T('attackStopped'));
        state.attack.running = false;
    }
}

async function downloadHandshake() {
    window.location.href = '/api/handshake/download?format=hccapx';
}

async function downloadCapture() {
    window.location.href = '/api/capture/download';
}

async function resetDevice() {
    if (!confirm('Reset all state?')) return;
    
    const result = await apiCall('reset', 'POST');
    if (result.success) {
        addLog('info', T('deviceReset'));
        state.networks = [];
        state.logs = [];
        updateNetworksTable();
        updateLogDisplay();
    }
}

// ==================== 工具函数 ====================
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ==================== 事件监听 ====================
document.addEventListener('DOMContentLoaded', () => {
    // 应用语言设置
    applyLanguage();

    // 连接 WebSocket
    connectWebSocket();
    
    // 初始化图表
    initPacketChart();
    
    // 标签页切换
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            
            // 更新按钮状态
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            // 更新内容显示
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById(tab).classList.add('active');
            
            state.currentTab = tab;
        });
    });
    
    // 按钮事件
    document.getElementById('btn-scan')?.addEventListener('click', startScan);
    document.getElementById('btn-sniff')?.addEventListener('click', startSniff);
    document.getElementById('btn-reset')?.addEventListener('click', resetDevice);
    document.getElementById('btn-refresh-networks')?.addEventListener('click', startScan);
    document.getElementById('btn-capture-start')?.addEventListener('click', startSniff);
    document.getElementById('btn-capture-stop')?.addEventListener('click', stopSniff);
    document.getElementById('btn-deauth-start')?.addEventListener('click', startDeauth);
    document.getElementById('btn-deauth-stop')?.addEventListener('click', stopDeauth);
    document.getElementById('btn-dict-start')?.addEventListener('click', startDictAttack);
    document.getElementById('btn-dict-stop')?.addEventListener('click', stopDictAttack);
    document.getElementById('btn-download-handshake')?.addEventListener('click', downloadHandshake);
    document.getElementById('btn-clear-logs')?.addEventListener('click', () => {
        state.logs = [];
        updateLogDisplay();
    });
    document.getElementById('btn-export-logs')?.addEventListener('click', () => {
        const blob = new Blob([state.logs.map(l => `[${l.timestamp}] [${l.level}] ${l.message}`).join('\n')], 
                              { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'sniffer-logs.txt';
        a.click();
    });
    
    // 过滤器
    document.getElementById('network-filter')?.addEventListener('input', updateNetworksTable);
    document.getElementById('log-level')?.addEventListener('change', updateLogDisplay);
    
    // 定期请求状态
    setInterval(requestStatus, 5000);
    
    // 初始日志
    addLog('info', 'Web interface loaded');
});
