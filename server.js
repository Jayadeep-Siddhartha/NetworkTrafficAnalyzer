const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');
const { X509Certificate } = require('crypto');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const clients = new Set();
let packetCaptureActive = false;
let captureError = null;

const stats = {
  totalPackets: 0,
  protocolCounts: {},
  encryptedCount: 0,
  unencryptedCount: 0,
  threats: [],
  sslAuditResults: []
};

const ipPortMap = new Map();
const auditedHosts = new Set();

const sourceActivity = new Map(); // Used to track time-based intrusion

function detectThreat(packetInfo) {
  const { sourceIp, destPort, protocol, size, encrypted } = packetInfo;
  const key = sourceIp;

  // Track destination ports for port scan detection
  if (!ipPortMap.has(key)) ipPortMap.set(key, new Set());
  ipPortMap.get(key).add(destPort);

  // Port Scan Detection
  if (ipPortMap.get(key).size > 20) {
    return {
      id: crypto.randomUUID(),
      type: 'Port Scan',
      source: sourceIp,
      timestamp: new Date().toISOString(),
      severity: 'Medium'
    };
  }

  // Track timestamps for DoS/flooding
  if (!sourceActivity.has(key)) sourceActivity.set(key, []);
  const now = Date.now();
  const timestamps = sourceActivity.get(key);
  timestamps.push(now);

  // Clean up old timestamps
  while (timestamps.length && now - timestamps[0] > 10000) {
    timestamps.shift();
  }

  // Flooding / DoS Attempt
  if (timestamps.length > 100) {
    return {
      id: crypto.randomUUID(),
      type: 'Flooding / DoS Attempt',
      source: sourceIp,
      timestamp: new Date().toISOString(),
      severity: 'High'
    };
  }

  // Encrypted traffic on uncommon ports
  if (encrypted && destPort !== 443 && destPort > 1024) {
    return {
      id: crypto.randomUUID(),
      type: 'Encrypted Traffic on Uncommon Port',
      source: sourceIp,
      timestamp: new Date().toISOString(),
      severity: 'Low'
    };
  }

  // Abnormal DNS packet (too large)
  if (protocol === 'DNS' && size > 512) {
    return {
      id: crypto.randomUUID(),
      type: 'Abnormal DNS Packet Size',
      source: sourceIp,
      timestamp: new Date().toISOString(),
      severity: 'Medium'
    };
  }

  // TCP Packet Storm
  if (protocol === 'TCP' && size > 10000) {
    return {
      id: crypto.randomUUID(),
      type: 'Unusually Large TCP Packet',
      source: sourceIp,
      timestamp: new Date().toISOString(),
      severity: 'Medium'
    };
  }

  return null;
}


function runSslAudit(host) {
  if (auditedHosts.has(host)) return;
  auditedHosts.add(host);

  console.log(`Running SSL audit for: ${host}`);

  const command = process.platform === 'win32'
    ? `echo | openssl s_client -connect ${host}:443 -servername ${host}`
    : `openssl s_client -connect ${host}:443 -servername ${host} < /dev/null`;

  exec(command, { timeout: 10000 }, (err, stdout, stderr) => {
    if (err) {
      console.error('OpenSSL error for', host, ':', err.message);
      return;
    }

    const issues = [];
    let certValidFrom = 'N/A';
    let certValidTo = 'N/A';

    if (/TLSv1(\.0|\.1)?/i.test(stdout)) issues.push('TLS 1.0/1.1 supported');
    if (/RC4/i.test(stdout)) issues.push('Weak cipher: RC4');
    if (/self[- ]signed/i.test(stdout)) issues.push('Self-signed certificate');
    if (/verify error/i.test(stdout)) issues.push('Verification errors present');
    if (!/Cipher *: *(?!0000)/i.test(stdout)) issues.push('No valid cipher negotiated');
    if (/Cipher is NULL/i.test(stdout)) issues.push('NULL cipher used');
    if (/Compression: *YES/i.test(stdout)) issues.push('Compression enabled (CRIME attack risk)');

    const certBlock = stdout.match(/-+BEGIN CERTIFICATE-+[\s\S]*?-+END CERTIFICATE-+/);
    if (certBlock) {
      try {
        const certObj = new X509Certificate(certBlock[0]);
        const expiryDate = new Date(certObj.validTo);
        const now = new Date();
        certValidFrom = certObj.validFrom;
        certValidTo = certObj.validTo;

        if (expiryDate < now) {
          issues.push('Certificate expired');
        }

        if (certObj.subject && !certObj.subject.includes(`CN=${host}`)) {
          issues.push(`Certificate CN mismatch: ${certObj.subject}`);
        }
      } catch (e) {
        issues.push('Error parsing certificate');
      }
    } else {
      issues.push('No certificate returned');
    }

    const grade =
      issues.length === 0 ? 'A+' :
      issues.length === 1 ? 'A' :
      issues.length === 2 ? 'B' :
      issues.length === 3 ? 'C' : 'D';

    const result = {
      host,
      issues,
      grade,
      certValidFrom,
      certValidTo
    };

    stats.sslAuditResults.push(result);
    broadcast({ type: 'ssl_audit', data: stats.sslAuditResults });
  });
}

function classifyProtocol(sourcePort, destPort) {
  const knownPorts = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP', 53: 'DNS',
    67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP', 110: 'POP3', 123: 'NTP',
    135: 'RPC', 137: 'NETBIOS-NS', 138: 'NETBIOS-DGM', 139: 'NETBIOS-SSN',
    143: 'IMAP', 161: 'SNMP', 162: 'SNMP-TRAP', 179: 'BGP', 194: 'IRC',
    443: 'HTTPS', 465: 'SMTPS', 514: 'SYSLOG', 520: 'RIP',
    587: 'SMTP-SSL', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
    1080: 'SOCKS', 1433: 'MSSQL', 1521: 'ORACLE', 1723: 'PPTP',
    2049: 'NFS', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 8000: 'HTTP-ALT', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT'
  };
  return knownPorts[sourcePort] || knownPorts[destPort] || 'TCP';
}

// The rest of the code remains unchanged (packet capture logic, broadcast, and WebSocket setup).


try {
  const Cap = require('cap').Cap;
  const interfaces = Cap.deviceList();
  const wifiInterface = interfaces.find(i => i.description?.includes('Wi-Fi'));
  const interfaceName = wifiInterface ? wifiInterface.name : interfaces[0]?.name;

  if (!interfaceName) throw new Error('No suitable interface found');

  const cap = new Cap();
  const filter = 'tcp or udp';
  const bufSize = 65535;
  const buffer = Buffer.alloc(bufSize);

  const linkType = cap.open(interfaceName, filter, bufSize, buffer);
  packetCaptureActive = true;

  if (cap.setMinBytes) cap.setMinBytes(0);

  cap.on('packet', (nbytes) => {
    try {
      if (linkType === 'ETHERNET') {
        const ethernetHeaderLength = 14;
        const ipVersion = (buffer[ethernetHeaderLength] & 0xf0) >> 4;

        if (ipVersion === 4) {
          const ipHeaderLength = (buffer[ethernetHeaderLength] & 0x0f) * 4;
          const sourceIp = `${buffer[ethernetHeaderLength + 12]}.${buffer[ethernetHeaderLength + 13]}.${buffer[ethernetHeaderLength + 14]}.${buffer[ethernetHeaderLength + 15]}`;
          const destIp = `${buffer[ethernetHeaderLength + 16]}.${buffer[ethernetHeaderLength + 17]}.${buffer[ethernetHeaderLength + 18]}.${buffer[ethernetHeaderLength + 19]}`;
          const protoId = buffer[ethernetHeaderLength + 9];

          let protocol = 'Unknown';
          let encrypted = false;
          let sourcePort = 0;
          let destPort = 0;

          const transportOffset = ethernetHeaderLength + ipHeaderLength;

          if (protoId === 6 || protoId === 17) {
            sourcePort = buffer.readUInt16BE(transportOffset);
            destPort = buffer.readUInt16BE(transportOffset + 2);
            protocol = classifyProtocol(sourcePort, destPort);

            const encryptedPorts = new Set([22, 443, 465, 993, 995, 990, 1194, 500, 4500]);
            const tlsHandshake =
              buffer[transportOffset] === 0x16 &&
              buffer[transportOffset + 1] === 0x03 &&
              buffer[transportOffset + 2] >= 0x01 &&
              buffer[transportOffset + 2] <= 0x04;

            encrypted = encryptedPorts.has(sourcePort) || encryptedPorts.has(destPort) || tlsHandshake;
          }

          const packetInfo = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            sourceIp, destIp, sourcePort, destPort,
            protocol, size: nbytes, encrypted
          };

          stats.totalPackets++;
          stats.protocolCounts[protocol] = (stats.protocolCounts[protocol] || 0) + 1;
          encrypted ? stats.encryptedCount++ : stats.unencryptedCount++;

          const threat = detectThreat(packetInfo);
          if (threat) {
            stats.threats.push(threat);
            // if (stats.threats.length > 100) stats.threats = stats.threats.slice(-100);
            broadcast({ type: 'threat', data: threat });
          }
          

          if (protocol === 'HTTPS') {
            runSslAudit(destIp);
          }

          broadcast({ type: 'packet', data: packetInfo });
          broadcast({ type: 'stats', data: stats });
        }
      }
    } catch (err) {
      console.error('Packet processing error:', err.message);
    }
  });

  cap.on('error', err => {
    console.error('Cap error:', err.message);
    captureError = err.message;
    packetCaptureActive = false;
  });

} catch (err) {
  console.error('Packet capture setup error:', err);
  captureError = err.message;
  packetCaptureActive = false;
}

function broadcast(message) {
  const str = JSON.stringify(message);
  clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(str);
    }
  });
}

wss.on('connection', ws => {
  clients.add(ws);
  console.log('Client connected');

  if (!packetCaptureActive) {
    ws.send(JSON.stringify({
      type: 'error',
      data: { message: 'Real-time packet capture is not available: ' + (captureError || 'Unknown error') }
    }));
    ws.close();
  } else {
    ws.send(JSON.stringify({ type: 'status', data: { usingRealCapture: true } }));
    ws.send(JSON.stringify({ type: 'stats', data: stats }));
    ws.send(JSON.stringify({ type: 'ssl_audit', data: stats.sslAuditResults }));
  }

  ws.on('close', () => {
    clients.delete(ws);
    console.log('Client disconnected');
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Open http://localhost:${PORT} in your browser`);
  if (!packetCaptureActive) {
    console.log('WARNING: Real-time packet capture is not available. Error: ' + captureError);
  }
});
