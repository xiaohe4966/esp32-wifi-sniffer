/**
 * ESP32 WiFi Sniffer - Web Application
 */

// ==================== 全局状态 ====================
const state = {
    connected: false,
    ws: null,
    reconnectInterval: 5000,
    currentTab: 'dashboard',
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
        statusEl.textContent = 'Connected';
        statusEl.className = 'status connected';
    } else {
        statusEl.textContent = 'Disconnected';
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
            addLog('info', 'WiFi scan completed');
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
        `✅ Handshake captured! Quality: ${quality}%` : 
        `⏳ Capturing handshake... ${quality}%`;
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
    
    const statsText = `Tested: ${data.tested}/${data.total} | Speed: ${data.speed.toFixed(1)} p/s`;
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
    const result = await apiCall('scan');
    if (result.success) {
        addLog('info', 'WiFi scan started');
        state.networks = [];
    }
}

async function startSniff() {
    const channel = document.getElementById('capture-channel')?.value || 0;
    const result = await apiCall(`capture/start?channel=${channel}`, 'POST');
    if (result.success) {
        addLog('info', 'Packet sniffing started');
    }
}

async function stopSniff() {
    const result = await apiCall('capture/stop', 'POST');
    if (result.success) {
        addLog('info', 'Packet sniffing stopped');
    }
}

function selectNetwork(bssid, channel) {
    document.getElementById('capture-bssid').value = bssid;
    document.getElementById('deauth-bssid').value = bssid;
    document.getElementById('capture-channel').value = channel;
    addLog('info', `Selected network: ${bssid} (CH${channel})`);
}

async function captureHandshake(bssid) {
    const result = await apiCall(`capture/start?bssid=${bssid}`, 'POST');
    if (result.success) {
        addLog('info', `Handshake capture started for ${bssid}`);
    }
}

async function startDeauth() {
    const bssid = document.getElementById('deauth-bssid').value;
    const station = document.getElementById('deauth-station').value;
    const reason = document.getElementById('deauth-reason').value;
    
    if (!bssid) {
        alert('Please enter target BSSID');
        return;
    }
    
    if (!confirm('WARNING: This will disconnect clients from the network. Continue?')) {
        return;
    }
    
    const params = new URLSearchParams({ bssid, reason });
    if (station) params.append('station', station);
    
    const result = await apiCall(`attack/start?${params.toString()}`, 'POST');
    if (result.success) {
        addLog('warning', `Deauth attack started on ${bssid}`);
    }
}

async function stopDeauth() {
    const result = await apiCall('attack/stop', 'POST');
    if (result.success) {
        addLog('info', 'Attack stopped');
    }
}

async function startDictAttack() {
    const handshake = document.getElementById('dict-handshake').value;
    const dict = document.getElementById('dict-file').value;
    
    if (!handshake || !dict) {
        alert('Please select handshake file and dictionary');
        return;
    }
    
    const result = await apiCall(`attack/start?type=dict&handshake=${handshake}&dict=${dict}`, 'POST');
    if (result.success) {
        addLog('info', 'Dictionary attack started');
        state.attack.running = true;
    }
}

async function stopDictAttack() {
    const result = await apiCall('attack/stop', 'POST');
    if (result.success) {
        addLog('info', 'Dictionary attack stopped');
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
        addLog('info', 'Device reset');
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
