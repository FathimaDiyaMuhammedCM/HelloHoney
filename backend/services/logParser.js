// Log file parser supporting Syslog, CSV, TSV, JSON, JSON-Lines, Common Web Log, and Raw Honeypot logs.
"use strict";

const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

const VALID_EVENT_TYPES = new Set(['CONNECTION', 'FAILED_LOGIN', 'TEST_LOGIN', 'DISCONNECT', 'PORT_PROBE', 'WEB_PROBE', 'SUSPICIOUS_REQUEST']);
const VALID_SEVERITIES = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO']);

function sanitizeEventType(type) {
  if (!type) return 'CONNECTION';
  const upper = String(type).trim().toUpperCase().replace(/[-\s]/g, '_');
  if (VALID_EVENT_TYPES.has(upper)) return upper;
  if (upper.includes('FAIL') || upper.includes('INVALID') || upper.includes('AUTH') || upper.includes('REJECT') || upper.includes('DENY')) return 'FAILED_LOGIN';
  if (upper.includes('PORT') || upper.includes('SCAN') || upper.includes('PROBE')) return 'PORT_PROBE';
  if (upper.includes('WEB') || upper.includes('HTTP') || upper.includes('URL') || upper.includes('CGI')) return 'WEB_PROBE';
  if (upper.includes('DISCONNECT') || upper.includes('CLOSE') || upper.includes('BYE')) return 'DISCONNECT';
  if (upper.includes('ATTACK') || upper.includes('EXPLOIT') || upper.includes('SUSPICIOUS') || upper.includes('MALWARE')) return 'SUSPICIOUS_REQUEST';
  return 'CONNECTION';
}

function sanitizeSeverity(sev, eventType) {
  if (sev) {
    const s = String(sev).trim().toUpperCase();
    if (VALID_SEVERITIES.has(s)) return s;
  }
  if (eventType === 'SUSPICIOUS_REQUEST') return 'HIGH';
  if (eventType === 'FAILED_LOGIN' || eventType === 'PORT_PROBE' || eventType === 'WEB_PROBE') return 'MEDIUM';
  if (eventType === 'DISCONNECT') return 'LOW';
  return 'INFO';
}

function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h) + str.charCodeAt(i);
    h |= 0;
  }
  return Math.abs(h);
}

// Regex patterns
const RFC3164_RE = /^(?:<\d+>)?\s*([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[\s]+)(?:\[\d+\])?:\s*(.*)$/;
const ISO_SYSLOG_RE = /^(?:<\d+>)?(?:1\s+)?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+([^:\[\s]+)(?:\[\d+\])?:\s*(.*)$/;
const APACHE_LOG_RE = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)\s+[^"]*"\s+(\d+)/;
const FAILED_PW_RE = /failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)/i;
const ACCEPTED_PW_RE = /accepted password for (\S+) from ([\d.]+) port (\d+)/i;
const INVALID_USER_RE = /invalid user (\S+) from ([\d.]+)/i;
const CONNECT_RE = /(?:connection from|connected from|connection received from)\s+([\d.]+)(?:\s+port\s+(\d+))?/i;
const DISCONNECT_RE = /(?:connection closed|disconnected|received disconnect)\s+(?:by|from\s+)?([\d.]+)?/i;
const WEB_REQ_RE = /(?:GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+(\/\S*)\s+HTTP/i;
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

function parseSyslogDate(monthStr, dayStr, timeStr) {
  const now = new Date();
  const month = MONTHS[monthStr.toLowerCase()] ?? now.getMonth();
  const day = parseInt(dayStr, 10);
  const [h, m, s] = timeStr.split(':').map(Number);
  const date = new Date(now.getFullYear(), month, day, h || 0, m || 0, s || 0);
  // If date is in the future by > 1 day, assume previous year
  if (date > new Date(now.getTime() + 86400000)) {
    date.setFullYear(now.getFullYear() - 1);
  }
  return date.toISOString();
}

function parseSyslogLine(line) {
  const cleanLine = line.trim();
  if (!cleanLine) return null;

  let ts = new Date().toISOString();
  let service = 'sshd';
  let msg = cleanLine;

  const mRfc = RFC3164_RE.exec(cleanLine);
  if (mRfc) {
    const [, month, day, time, , srv, message] = mRfc;
    ts = parseSyslogDate(month, day, time);
    service = srv;
    msg = message;
  } else {
    const mIso = ISO_SYSLOG_RE.exec(cleanLine);
    if (mIso) {
      const [, isoTime, , srv, message] = mIso;
      try { ts = new Date(isoTime).toISOString(); } catch (_) { ts = new Date().toISOString(); }
      service = srv;
      msg = message;
    }
  }

  // Check failed password
  const fm = FAILED_PW_RE.exec(msg);
  if (fm) {
    return {
      timestamp: ts,
      sourceIP: fm[2],
      sourcePort: parseInt(fm[3], 10) || 0,
      destinationPort: 22,
      service,
      protocol: 'TCP',
      eventType: 'FAILED_LOGIN',
      username: fm[1],
      status: 'failed',
      severity: 'MEDIUM',
      sessionId: 'SYS-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, logSource: 'syslog' }
    };
  }

  // Check invalid user
  const im = INVALID_USER_RE.exec(msg);
  if (im) {
    return {
      timestamp: ts,
      sourceIP: im[2],
      sourcePort: 0,
      destinationPort: 22,
      service,
      protocol: 'TCP',
      eventType: 'FAILED_LOGIN',
      username: im[1],
      status: 'failed',
      severity: 'MEDIUM',
      sessionId: 'SYS-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, logSource: 'syslog' }
    };
  }

  // Check accepted password
  const sm = ACCEPTED_PW_RE.exec(msg);
  if (sm) {
    return {
      timestamp: ts,
      sourceIP: sm[2],
      sourcePort: parseInt(sm[3], 10) || 0,
      destinationPort: 22,
      service,
      protocol: 'TCP',
      eventType: 'TEST_LOGIN',
      username: sm[1],
      status: 'success',
      severity: 'MEDIUM',
      sessionId: 'SYS-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, logSource: 'syslog' }
    };
  }

  // Check connect
  const cm = CONNECT_RE.exec(msg);
  if (cm) {
    return {
      timestamp: ts,
      sourceIP: cm[1],
      sourcePort: cm[2] ? parseInt(cm[2], 10) : 0,
      destinationPort: 22,
      service,
      protocol: 'TCP',
      eventType: 'CONNECTION',
      status: 'connected',
      severity: 'INFO',
      sessionId: 'SYS-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, logSource: 'syslog' }
    };
  }

  // Check disconnect
  const dm = DISCONNECT_RE.exec(msg);
  if (dm) {
    const sip = dm[1] || (msg.match(IP_RE)?.[0] || '127.0.0.1');
    return {
      timestamp: ts,
      sourceIP: sip,
      destinationPort: 22,
      service,
      protocol: 'TCP',
      eventType: 'DISCONNECT',
      status: 'disconnected',
      severity: 'LOW',
      sessionId: 'SYS-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, logSource: 'syslog' }
    };
  }

  // Check web request inside syslog or raw line
  const wm = WEB_REQ_RE.exec(msg);
  if (wm) {
    const path = wm[1];
    const suspicious = ['/admin', '/.env', '/wp-admin', '/config', '/backup', '/phpmyadmin', '/setup', '/actuator', '/etc'].some(p => path.toLowerCase().includes(p));
    const ipMatch = msg.match(IP_RE);
    const sip = ipMatch ? ipMatch[0] : '127.0.0.1';
    return {
      timestamp: ts,
      sourceIP: sip,
      destinationPort: 80,
      service: 'HTTP',
      protocol: 'TCP',
      eventType: suspicious ? 'WEB_PROBE' : 'CONNECTION',
      status: suspicious ? 'probed' : 'connected',
      severity: suspicious ? 'HIGH' : 'INFO',
      sessionId: 'SYS-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, path, logSource: 'syslog' }
    };
  }

  // Apache / Nginx format
  const am = APACHE_LOG_RE.exec(cleanLine);
  if (am) {
    const [, ip, , method, path, statusCode] = am;
    const suspicious = parseInt(statusCode, 10) === 404 || parseInt(statusCode, 10) === 403 ||
      ['/admin', '/.env', '/wp-admin', '/config', '/phpmyadmin', '/shell', '/api'].some(p => path.toLowerCase().includes(p));
    return {
      timestamp: ts,
      sourceIP: ip,
      destinationPort: 80,
      service: 'HTTP',
      protocol: 'TCP',
      eventType: suspicious ? 'WEB_PROBE' : 'CONNECTION',
      status: suspicious ? 'probed' : 'connected',
      severity: suspicious ? 'HIGH' : 'INFO',
      sessionId: 'WEB-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, method, path, statusCode, logSource: 'web' }
    };
  }

  // Fallback: If line contains an IP address, extract it as an event
  const ipMatch = cleanLine.match(IP_RE);
  if (ipMatch) {
    const sip = ipMatch[0];
    const lower = cleanLine.toLowerCase();
    let evType = 'CONNECTION';
    let sev = 'INFO';
    let srv = 'SSH';
    let status = 'connected';

    if (lower.includes('fail') || lower.includes('invalid') || lower.includes('denied') || lower.includes('reject') || lower.includes('bad password')) {
      evType = 'FAILED_LOGIN';
      sev = 'MEDIUM';
      status = 'failed';
    } else if (lower.includes('probe') || lower.includes('scan') || lower.includes('nmap')) {
      evType = 'PORT_PROBE';
      sev = 'MEDIUM';
      status = 'probed';
    } else if (lower.includes('get ') || lower.includes('post ') || lower.includes('http') || lower.includes('url')) {
      evType = 'WEB_PROBE';
      sev = 'MEDIUM';
      status = 'probed';
      srv = 'HTTP';
    } else if (lower.includes('disconnect') || lower.includes('closed') || lower.includes('exit')) {
      evType = 'DISCONNECT';
      sev = 'LOW';
      status = 'disconnected';
    }

    if (lower.includes('http') || lower.includes('nginx') || lower.includes('apache')) srv = 'HTTP';
    if (lower.includes('ftp')) srv = 'FTP';
    if (lower.includes('telnet')) srv = 'TELNET';

    return {
      timestamp: ts,
      sourceIP: sip,
      destinationPort: srv === 'HTTP' ? 80 : 22,
      service: srv,
      protocol: 'TCP',
      eventType: evType,
      status,
      severity: sev,
      sessionId: 'LOG-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, logSource: 'generic' }
    };
  }

  return null;
}

function parseCsv(text) {
  const rows = [];
  const lines = text.split(/\r?\n/).filter(l => l.trim());
  if (lines.length < 2) return rows;

  // Determine delimiter
  const first = lines[0];
  const delim = first.includes('\t') ? '\t' : (first.includes(';') ? ';' : ',');

  const headers = first.split(delim).map(h => h.trim().toLowerCase().replace(/['"]/g, ''));

  function findCol(keywords) {
    return headers.findIndex(h => keywords.some(k => h === k || h.includes(k)));
  }

  const ipIdx = findCol(['sourceip', 'src_ip', 'source_ip', 'ip', 'client_ip', 'source', 'host', 'attacker']);
  const timeIdx = findCol(['timestamp', 'time', 'date', 'datetime', 'logged_at', 'created_at']);
  const eventIdx = findCol(['eventtype', 'event_type', 'type', 'action', 'activity', 'event']);
  const serviceIdx = findCol(['service', 'app', 'protocol_service']);
  const protoIdx = findCol(['protocol', 'proto']);
  const userIdx = findCol(['username', 'user', 'account', 'login']);
  const statusIdx = findCol(['status', 'outcome', 'result', 'state']);
  const sevIdx = findCol(['severity', 'level', 'priority']);
  const sportIdx = findCol(['sourceport', 'src_port', 'sport']);
  const dportIdx = findCol(['destinationport', 'dst_port', 'dport', 'port']);

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    const vals = line.split(delim).map(v => v.trim().replace(/^["']|["']$/g, ''));
    if (!vals.length) continue;

    const sip = (ipIdx >= 0 ? vals[ipIdx] : '') || line.match(IP_RE)?.[0] || '127.0.0.1';
    let ts = (timeIdx >= 0 ? vals[timeIdx] : '') || new Date().toISOString();
    try { ts = new Date(ts).toISOString(); } catch (_) { ts = new Date().toISOString(); }

    const rawEvType = eventIdx >= 0 ? vals[eventIdx] : '';
    const rawSev = sevIdx >= 0 ? vals[sevIdx] : '';
    const evType = sanitizeEventType(rawEvType || 'CONNECTION');
    const sev = sanitizeSeverity(rawSev, evType);
    const service = (serviceIdx >= 0 ? vals[serviceIdx] : '') || (evType === 'WEB_PROBE' ? 'HTTP' : 'SSH');
    const status = (statusIdx >= 0 ? vals[statusIdx] : '') || (evType === 'FAILED_LOGIN' ? 'failed' : 'connected');

    rows.push({
      timestamp: ts,
      sourceIP: sip,
      sourcePort: sportIdx >= 0 ? parseInt(vals[sportIdx], 10) || 0 : 0,
      destinationPort: dportIdx >= 0 ? parseInt(vals[dportIdx], 10) || (service === 'HTTP' ? 80 : 22) : (service === 'HTTP' ? 80 : 22),
      service,
      protocol: (protoIdx >= 0 ? vals[protoIdx] : '') || 'TCP',
      eventType: evType,
      username: userIdx >= 0 ? vals[userIdx] : undefined,
      status,
      severity: sev,
      sessionId: 'CSV-' + (simpleHash(line) & 0xfffffff),
      metadata: { raw: line, logSource: 'csv' }
    });
  }

  return rows;
}

function normalizeJsonEvent(obj) {
  if (!obj || typeof obj !== 'object') return null;

  const sip = obj.sourceIP || obj.src_ip || obj.source_ip || obj.ip || obj.client_ip || obj.host || '127.0.0.1';
  let ts = obj.timestamp || obj.time || obj.date || obj['@timestamp'] || new Date().toISOString();
  try { ts = new Date(ts).toISOString(); } catch (_) { ts = new Date().toISOString(); }

  const evType = sanitizeEventType(obj.eventType || obj.event_type || obj.type || obj.action || obj.event || 'CONNECTION');
  const sev = sanitizeSeverity(obj.severity || obj.level || obj.priority, evType);
  const service = obj.service || (evType === 'WEB_PROBE' ? 'HTTP' : 'SSH');

  return {
    ...obj,
    eventId: obj.eventId,
    timestamp: ts,
    sourceIP: String(sip),
    sourcePort: obj.sourcePort ? Number(obj.sourcePort) : (obj.src_port ? Number(obj.src_port) : undefined),
    destinationPort: obj.destinationPort ? Number(obj.destinationPort) : (obj.dst_port ? Number(obj.dst_port) : (service === 'HTTP' ? 80 : 22)),
    service,
    protocol: obj.protocol || obj.proto || 'TCP',
    eventType: evType,
    username: obj.username || obj.user,
    passwordEcho: obj.passwordEcho || (obj.password ? `len=${String(obj.password).length} sha-prefix=***` : undefined),
    status: obj.status || (evType === 'FAILED_LOGIN' ? 'failed' : 'connected'),
    severity: sev,
    sessionId: obj.sessionId || ('JSON-' + (simpleHash(JSON.stringify(obj)) & 0xfffffff)),
    metadata: { ...(obj.metadata || {}), logSource: 'json' }
  };
}

function parseJson(text) {
  const trimmed = text.trim();
  // 1. Try full JSON parse (Array or Object)
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) {
      return parsed.map(normalizeJsonEvent).filter(Boolean);
    }
    if (parsed && typeof parsed === 'object') {
      if (Array.isArray(parsed.events)) return parsed.events.map(normalizeJsonEvent).filter(Boolean);
      if (Array.isArray(parsed.logs)) return parsed.logs.map(normalizeJsonEvent).filter(Boolean);
      if (Array.isArray(parsed.data)) return parsed.data.map(normalizeJsonEvent).filter(Boolean);
      const ev = normalizeJsonEvent(parsed);
      return ev ? [ev] : [];
    }
  } catch (_) {}

  // 2. Try JSON lines (NDJSON)
  const rows = [];
  for (const line of trimmed.split(/\r?\n/)) {
    const l = line.trim();
    if (!l) continue;
    try {
      const obj = JSON.parse(l);
      const ev = normalizeJsonEvent(obj);
      if (ev) rows.push(ev);
    } catch (_) {}
  }
  return rows;
}

function parse(text) {
  if (!text || typeof text !== 'string') return [];
  const trimmed = text.trim();
  if (!trimmed) return [];

  // 1. Check if it's JSON
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    const jsonEvents = parseJson(trimmed);
    if (jsonEvents.length > 0) return jsonEvents;
  }

  // 2. Check if it's CSV / TSV
  const firstLine = trimmed.split(/\r?\n/)[0] || '';
  const firstLower = firstLine.toLowerCase();
  const isDelimited = firstLine.includes(',') || firstLine.includes('\t') || firstLine.includes(';');
  const hasCsvHeaders = isDelimited && (
    firstLower.includes('ip') || firstLower.includes('source') || firstLower.includes('time') ||
    firstLower.includes('date') || firstLower.includes('event') || firstLower.includes('user')
  );

  if (hasCsvHeaders) {
    const csvEvents = parseCsv(trimmed);
    if (csvEvents.length > 0) return csvEvents;
  }

  // 3. Line by line parsing for Syslog, Apache, Cowrie, or text logs
  const lines = trimmed.split(/\r?\n/);
  const events = [];
  for (const line of lines) {
    const ev = parseSyslogLine(line);
    if (ev) events.push(ev);
  }

  // 4. If nothing parsed yet, check if any line can be parsed via JSON lines
  if (!events.length) {
    const jsonLines = parseJson(trimmed);
    if (jsonLines.length > 0) return jsonLines;
  }

  return events;
}

module.exports = { parse, parseSyslogLine, parseCsv, parseJson, sanitizeEventType, sanitizeSeverity };
