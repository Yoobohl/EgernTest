/**
 * Dr.COM Traffic Widget for Egern (generic script).
 * Reads only /drcom/chkstatus; does not perform login/logout or send credentials.
 *
 * env:
 *   DRCOM_API_URL   - The campus chkstatus URL
 *   TRAFFIC_UNIT    - KB (default), B, or MB, describing Dr.COM raw numeric fields
 *   REFRESH_MINUTES - Desired refresh interval, default 5 (iOS may defer refreshes)
 */

const DEFAULT_API_URL =
  'http://10.100.88.2/drcom/chkstatus?callback=dr1003&jsVersion=4.1&v=630&lang=zh';

const C = {
  background: '#0F141B',
  surface: '#1B242D',
  primary: '#F4F7FA',
  muted: '#9AA9B8',
  green: '#45D6A0',
  blue: '#73B9FF',
  amber: '#FFCA71',
  red: '#FF737F',
};

function label(text, size = 12, color = C.muted, weight = 'regular') {
  return {
    type: 'text',
    text: String(text),
    font: { size, weight },
    textColor: color,
    maxLines: 1,
    minScale: 0.65,
  };
}

function icon(name, color = C.muted, size = 15) {
  return {
    type: 'image',
    src: `sf-symbol:${name}`,
    color,
    width: size,
    height: size,
  };
}

function row(children, gap = 6, alignItems = 'center') {
  return { type: 'stack', direction: 'row', alignItems, gap, children };
}

function col(children, gap = 5) {
  return { type: 'stack', direction: 'column', alignItems: 'start', gap, children };
}

function root(children, refreshMinutes, gap = 8, padding = 16) {
  return {
    type: 'widget',
    backgroundColor: C.background,
    padding,
    gap,
    refreshAfter: new Date(Date.now() + refreshMinutes * 60_000).toISOString(),
    children,
  };
}

function parseStatusResponse(body) {
  const raw = String(body).trim().replace(/^\uFEFF/, '');
  let parsed = raw;
  const jsonp = raw.match(/^[\w$]+(?:\.[\w$]+)*\s*\(\s*([\s\S]*?)\s*\)\s*;?\s*$/);
  if (jsonp) parsed = jsonp[1];
  const data = JSON.parse(parsed);
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('状态接口未返回对象');
  }
  return data;
}

function numeric(value) {
  if (value === undefined || value === null || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function formatTraffic(value, inputUnit) {
  const number = numeric(value);
  if (number === null) return '--';
  const factor = inputUnit === 'B' ? 1 : inputUnit === 'MB' ? 1048576 : 1024;
  const bytes = number * factor;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let result = bytes;
  let i = 0;
  while (result >= 1024 && i < units.length - 1) {
    result /= 1024;
    i++;
  }
  return `${result.toFixed(result >= 100 ? 0 : result >= 10 ? 1 : 2)} ${units[i]}`;
}

function makeData(data, inputUnit) {
  const online = String(data.result) === '1';
  const download = numeric(data.actdf);
  const upload = numeric(data.actuf);
  const total = numeric(data.flow) ??
    (download !== null && upload !== null ? download + upload : null);
  return {
    online,
    download: formatTraffic(download, inputUnit),
    upload: formatTraffic(upload, inputUnit),
    total: formatTraffic(total, inputUnit),
    ip: String(data.v4ip || data.v46ip || data.olip || '--'),
  };
}

function stateLine(online) {
  return row([
    icon('wifi', C.green, 16),
    label('Dr.COM', 14, C.primary, 'semibold'),
    { type: 'spacer' },
    label(online ? '● 在线' : '● 离线', 11, online ? C.green : C.red, 'medium'),
  ]);
}

function metric(title, symbol, value, tint, big = false) {
  return col([
    row([icon(symbol, tint, 13), label(title, 11, C.muted, 'medium')], 5),
    label(value, big ? 24 : 19, C.primary, 'bold'),
  ], 4);
}

function errorWidget(family, text, minutes, title = '无法获取流量') {
  if (family === 'accessoryInline') {
    return root([label(`Dr.COM · ${title}`, 12, C.primary)], minutes, 0, 0);
  }
  if (family === 'accessoryCircular') {
    return root(col([icon('wifi.slash', C.red, 17), label('离线', 11, C.primary)], 4), minutes, 0, 2);
  }
  if (family === 'accessoryRectangular') {
    return root([
      label(`Dr.COM · ${title}`, 13, C.primary, 'semibold'),
      label(text, 11, C.muted),
    ], minutes, 3, 2);
  }
  return root([
    row([icon('wifi.exclamationmark', C.red, 16), label('Dr.COM', 14, C.primary, 'bold')]),
    { type: 'spacer' },
    label(title, 17, C.primary, 'semibold'),
    label(text, 11, C.muted),
  ], minutes, 8, 15);
}

function renderWidget(info, family, refreshMinutes) {
  if (family === 'accessoryInline') {
    return root([
      label(`Dr.COM ↓${info.download} ↑${info.upload} · ${info.ip}`, 12, C.primary),
    ], refreshMinutes, 0, 0);
  }
  if (family === 'accessoryCircular') {
    return root([
      icon('wifi', C.green, 15),
      label(info.total.replace(' ', ''), 13, C.primary, 'bold'),
      label('已用', 10, C.muted),
    ], refreshMinutes, 2, 1);
  }
  if (family === 'accessoryRectangular') {
    return root([
      row([icon('wifi', C.green, 14), label('Dr.COM 已用流量', 12, C.primary, 'semibold')], 5),
      label(`↓ ${info.download}   ↑ ${info.upload}`, 13, C.primary, 'medium'),
      label(`IP ${info.ip}`, 11, C.muted),
    ], refreshMinutes, 2, 2);
  }
  if (family === 'systemSmall') {
    return root([
      stateLine(info.online),
      { type: 'spacer', length: 3 },
      row([icon('arrow.down', C.blue, 14), label('下载', 12, C.muted)]),
      label(info.download, 23, C.primary, 'bold'),
      row([icon('arrow.up', C.green, 13), label('上传', 12, C.muted), { type: 'spacer' }, label(info.upload, 13, C.primary, 'semibold')]),
      { type: 'spacer' },
      label(info.ip, 11, C.muted, 'medium'),
    ], refreshMinutes, 5, 13);
  }

  // Medium/Large/ExtraLarge: two-column traffic indicators + total + IPv4.
  return root([
    stateLine(info.online),
    { type: 'spacer' },
    row([
      { ...metric('下载 · Download', 'arrow.down', info.download, C.blue, true), flex: 1 },
      { ...metric('上传 · Upload', 'arrow.up', info.upload, C.green, true), flex: 1 },
    ], 14, 'start'),
    { type: 'spacer' },
    {
      type: 'stack', direction: 'row', gap: 6, alignItems: 'center',
      backgroundColor: C.surface, borderRadius: 9, padding: [8, 10],
      children: [
        icon('network', C.muted, 12),
        label(info.ip, 12, C.primary, 'medium'),
        { type: 'spacer' },
        label(`总量 ${info.total}`, 11, C.muted),
      ],
    },
  ], refreshMinutes, 7, 16);
}

export default async function(ctx) {
  const env = ctx.env || {};
  const family = ctx.widgetFamily || 'systemMedium';
  const unit = String(env.TRAFFIC_UNIT || 'KB').trim().toUpperCase();
  const requestedMinutes = Number(env.REFRESH_MINUTES || 5);
  const minutes = Number.isFinite(requestedMinutes)
    ? Math.min(60, Math.max(5, requestedMinutes)) : 5;
  const api = String(env.DRCOM_API_URL || DEFAULT_API_URL).trim();

  if (!/^https?:\/\//i.test(api)) {
    return errorWidget(family, '检查 DRCOM_API_URL', minutes, '接口地址无效');
  }

  try {
    // Query string is only a cache buster; no credentials are sent.
    const url = `${api}${api.includes('?') ? '&' : '?'}_=${Date.now()}`;
    const response = await ctx.http.get(url, {
      policy: 'DIRECT',  // Local private-IP gateway must never go via a remote proxy.
      timeout: 6000,
      redirect: 'error',
      headers: { Accept: 'application/json, application/javascript, text/plain, */*' },
    });
    if (response.status !== 200) throw new Error(`HTTP ${response.status}`);
    const status = parseStatusResponse(await response.text());
    const data = makeData(status, ['KB', 'B', 'MB'].includes(unit) ? unit : 'KB');
    if (!data.online) return errorWidget(family, '认证状态不是在线，请先登录校园网', minutes, '未认证');
    if (data.download === '--' || data.upload === '--') {
      return errorWidget(family, '接口未提供 actdf / actuf 字段', minutes, '上下行数据缺失');
    }
    return renderWidget(data, family, minutes);
  } catch (error) {
    // Avoid exposing complete request URLs or private identifiers in the widget.
    const msg = error && error.message ? String(error.message).slice(0, 55) : '请求失败';
    return errorWidget(family, msg, minutes);
  }
}
