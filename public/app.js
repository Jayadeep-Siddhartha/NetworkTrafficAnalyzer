// Store application state
const state = {
    trafficData: [],
    detectedThreats: [],
    sslAuditResults: [],
    stats: {
      totalPackets: 0,
      protocolCounts: {},
      encryptedCount: 0,
      unencryptedCount: 0
    },
    isConnected: false,
    activeTab: 'live'
  };
  
  // WebSocket connection
  let ws = null;
  
  // Connect to WebSocket server
  function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    try {
      ws = new WebSocket(wsUrl);
      
      ws.onopen = () => {
        console.log('WebSocket connected');
        updateConnectionStatus(true);
      };
      
      ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        
        if (message.type === 'packet') {
          handlePacket(message.data);
        } else if (message.type === 'stats') {
          handleStats(message.data);
        } else if (message.type === 'ssl_audit') {
          handleSslAudit(message.data);
        } else if (message.type === 'status') {
          handleStatusMessage(message.data);
        }
      };
      
      ws.onclose = () => {
        console.log('WebSocket disconnected');
        updateConnectionStatus(false);
        
        // Attempt to reconnect after 5 seconds
        setTimeout(connectWebSocket, 5000);
      };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        updateConnectionStatus(false, 'Connection error');
      };
    } catch (error) {
      console.error('WebSocket connection failed:', error);
      updateConnectionStatus(false, `Failed to connect: ${error.message}`);
      
      // Attempt to reconnect after 5 seconds
      setTimeout(connectWebSocket, 5000);
    }
  }
  
  // Handle packet data
  function handlePacket(packet) {
    // Add to traffic data
    state.trafficData.unshift(packet);
    
    // Keep only last 100 packets
    if (state.trafficData.length > 100) {
      state.trafficData = state.trafficData.slice(0, 100);
    }
    
    // Update UI
    updateLivePackets();
    updateTrafficHeatmap();
  }
  
  // Handle stats data
  function handleStats(stats) {
    state.stats = stats;
    
    if (stats.threats) {
      state.detectedThreats = stats.threats;
      updateThreats();
    }
    
    // Update UI
    document.getElementById('total-packets').textContent = stats.totalPackets.toLocaleString();
    document.getElementById('protocol-count').textContent = Object.keys(stats.protocolCounts).length;
    
    const encryptedPercent = stats.totalPackets ? 
      Math.round((stats.encryptedCount / stats.totalPackets) * 100) : 0;
    document.getElementById('encrypted-percent').textContent = `${encryptedPercent}%`;
    
    document.getElementById('threat-count').textContent = state.detectedThreats.length;
    
    updateProtocolChart();
  }
  
  // Handle SSL audit data
  function handleSslAudit(data) {
    state.sslAuditResults = data;
    updateSslAudit();
  }
  
  // Handle status message
  function handleStatusMessage(status) {
    const connectionStatus = document.getElementById('connection-status');
    
    if (status.usingRealCapture) {
      connectionStatus.innerHTML = `<span class="font-medium">✅ Using real packet capture</span>`;
      connectionStatus.className = 'p-2 text-sm rounded mb-4 bg-green-100 text-green-800';
    } else {
      connectionStatus.innerHTML = `<span class="font-medium">⚠️ Using simulated data</span>`;
      if (status.captureError) {
        connectionStatus.innerHTML += `<br><span class="text-xs">Error: ${status.captureError}</span>`;
      }
      connectionStatus.className = 'p-2 text-sm rounded mb-4 bg-yellow-100 text-yellow-800';
    }
  }
  
  // Update connection status
  function updateConnectionStatus(connected, error = null) {
    state.isConnected = connected;
    
    const statusEl = document.getElementById('connection-status');
    
    if (connected) {
      if (statusEl.innerHTML.includes('Using real packet capture') || 
          statusEl.innerHTML.includes('Using simulated data')) {
        // Already updated by status message
        return;
      }
      
      statusEl.innerHTML = 'Connected - Waiting for data...';
      statusEl.className = 'p-2 text-sm rounded mb-4 bg-green-100 text-green-800';
    } else {
      statusEl.innerHTML = `Disconnected ${error ? `(${error})` : ''}`;
      statusEl.className = 'p-2 text-sm rounded mb-4 bg-red-100 text-red-800';
    }
  }
  
  // Update live packets table
  function updateLivePackets() {
    const tbody = document.getElementById('live-packets');
    
    if (state.trafficData.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" class="p-2 text-center text-gray-500">No packets captured yet</td>
        </tr>
      `;
      return;
    }
    
    tbody.innerHTML = state.trafficData.map(packet => `
      <tr class="border-b">
        <td class="p-2 text-sm">${new Date(packet.timestamp).toLocaleTimeString()}</td>
        <td class="p-2 text-sm">${packet.sourceIp}:${packet.sourcePort}</td>
        <td class="p-2 text-sm">${packet.destIp}:${packet.destPort}</td>
        <td class="p-2 text-sm">${packet.protocol}</td>
        <td class="p-2 text-sm text-right">${packet.size} B</td>
        <td class="p-2 text-center">
          ${packet.encrypted ? 
            '<span class="text-green-600">✓</span>' : 
            '<span class="text-red-600">✗</span>'}
        </td>
      </tr>
    `).join('');
  }
  
  // Update protocol chart
  function updateProtocolChart() {
    const chartEl = document.getElementById('protocol-chart');
    const protocols = Object.keys(state.stats.protocolCounts);
    
    if (protocols.length === 0) {
      chartEl.innerHTML = '<div class="text-gray-500 w-full text-center">No protocol data available</div>';
      return;
    }
    
    const total = protocols.reduce((sum, protocol) => sum + state.stats.protocolCounts[protocol], 0);
    
    chartEl.innerHTML = protocols.map(protocol => {
      const percentage = total ? (state.stats.protocolCounts[protocol] / total * 100).toFixed(1) : 0;
      const isEncrypted = ['HTTPS', 'SSH', 'FTPS', 'SMTPS'].includes(protocol);
      
      return `
        <div class="flex-1 mr-1 last:mr-0 min-w-24 mb-2" title="${protocol}: ${percentage}%">
          <div class="mb-1 text-xs font-medium">${protocol}</div>
          <div class="h-4 rounded overflow-hidden">
            <div class="${isEncrypted ? 'bg-green-500' : 'bg-yellow-500'}" style="width: ${percentage}%; height: 100%;"></div>
          </div>
          <div class="text-xs mt-1">${percentage}%</div>
        </div>
      `;
    }).join('');
  }
  
  // Update threats list
  function updateThreats() {
    const tbody = document.getElementById('threat-list');
    
    if (state.detectedThreats.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="4" class="p-2 text-center text-gray-500">No threats detected</td>
        </tr>
      `;
      return;
    }
    
    tbody.innerHTML = state.detectedThreats.map(threat => {
      const severityClass = 
        threat.severity === 'High' ? 'bg-red-100 text-red-800' :
        threat.severity === 'Medium' ? 'bg-yellow-100 text-yellow-800' :
        'bg-green-100 text-green-800';
        
      return `
        <tr class="border-b">
          <td class="p-2">${threat.type}</td>
          <td class="p-2">${threat.source}</td>
          <td class="p-2">${new Date(threat.timestamp).toLocaleTimeString()}</td>
          <td class="p-2">
            <span class="px-2 py-1 rounded-full text-xs ${severityClass}">
              ${threat.severity}
            </span>
          </td>
        </tr>
      `;
    }).join('');
  }
  
  // Update SSL audit results
  function updateSslAudit() {
    const tbody = document.getElementById('ssl-list');
  
    if (state.sslAuditResults.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="5" class="p-2 text-center text-gray-500">No SSL/TLS data available</td>
        </tr>
      `;
      return;
    }
  
    tbody.innerHTML = state.sslAuditResults.map(item => {
      const gradeClass = 
        item.grade === 'A+' ? 'bg-green-100 text-green-800' :
        item.grade === 'A' ? 'bg-green-100 text-green-800' :
        item.grade === 'B' ? 'bg-blue-100 text-blue-800' :
        item.grade === 'C' ? 'bg-yellow-100 text-yellow-800' :
        'bg-red-100 text-red-800';
  
      return `
        <tr class="border-b">
          <td class="p-2">${item.host}</td>
          <td class="p-2">
            <span class="px-2 py-1 rounded-full text-xs ${gradeClass}">${item.grade}</span>
          </td>
          <td class="p-2 text-xs">${item.certValidFrom || 'N/A'}</td>
          <td class="p-2 text-xs">${item.certValidTo || 'N/A'}</td>
          <td class="p-2">
            ${item.issues.length > 0 ? 
              `<ul class="list-disc list-inside">
                ${item.issues.map(issue => `<li class="text-sm text-gray-600">${issue}</li>`).join('')}
              </ul>` : 
              '<span class="text-green-600 text-sm">No issues</span>'}
          </td>
        </tr>
      `;
    }).join('');
  }
  
  
  // Update traffic heatmap
  function updateTrafficHeatmap() {
    const heatmapEl = document.getElementById('heatmap-list');
    
    // Group traffic by source IP
    const sourceIps = {};
    state.trafficData.forEach(packet => {
      if (!sourceIps[packet.sourceIp]) {
        sourceIps[packet.sourceIp] = 0;
      }
      sourceIps[packet.sourceIp]++;
    });
    
    // Sort by traffic volume
    const sortedIps = Object.keys(sourceIps).sort((a, b) => sourceIps[b] - sourceIps[a]).slice(0, 10);
    
    if (sortedIps.length === 0) {
      heatmapEl.innerHTML = '<div class="text-gray-500 text-center">No traffic data available</div>';
      return;
    }
    
    heatmapEl.innerHTML = sortedIps.map(ip => {
      // Calculate intensity based on packet count
      const intensity = Math.min(100, Math.max(10, (sourceIps[ip] / state.trafficData.length) * 100 * 5));
      const opacity = Math.max(0.3, Math.min(0.9, intensity/100));
      
      return `
        <div class="mb-2 flex items-center">
          <div class="w-32 overflow-hidden whitespace-nowrap text-ellipsis mr-2">${ip}</div>
          <div class="flex-1 h-6 bg-gray-100 relative">
            <div class="absolute top-0 left-0 h-full bg-blue-500" 
                 style="width: ${intensity}%; opacity: ${opacity};"></div>
          </div>
          <div class="ml-2 w-12 text-right">${sourceIps[ip]}</div>
        </div>
      `;
    }).join('');
  }
  
  // Tab switching
function setupTabs() {
    const tabs = ['live', 'visualize', 'threats', 'ssl', 'heatmap'];
  
    tabs.forEach(tab => {
      const tabButton = document.getElementById(`tab-${tab}`);
      const tabContent = document.getElementById(`content-${tab}`);
  
      tabButton.addEventListener('click', () => {
        state.activeTab = tab;
  
        // Highlight active tab and show corresponding content
        tabs.forEach(t => {
          const btn = document.getElementById(`tab-${t}`);
          const content = document.getElementById(`content-${t}`);
  
          if (t === tab) {
            btn.classList.add('bg-blue-100', 'text-blue-800', 'font-semibold');
            btn.classList.remove('bg-white', 'text-gray-600');
            content.classList.remove('hidden');
          } else {
            btn.classList.remove('bg-blue-100', 'text-blue-800', 'font-semibold');
            btn.classList.add('bg-white', 'text-gray-600');
            content.classList.add('hidden');
          }
        });
      });
    });
  }
  
  // Initialize app
  document.addEventListener('DOMContentLoaded', () => {
    connectWebSocket();
    setupTabs();
  });
  