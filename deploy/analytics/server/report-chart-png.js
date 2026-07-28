/*
 * Минимальный PNG-рендерер графика для писем.
 *
 * Почтовые клиенты (Gmail, Outlook, Яндекс, Mail.ru) вырезают inline SVG,
 * поэтому в письмо график уходит растром. Кодек и растеризация написаны здесь,
 * чтобы не тянуть нативные зависимости (sharp/resvg) в alpine-образ.
 */

const zlib = require('zlib');

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c;
  }
  return table;
})();

function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i += 1) {
    c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  }
  return (c ^ -1) >>> 0;
}

function pngChunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([length, typeBuf, data, crc]);
}

/** Truecolor 8-bit PNG, фильтр 0 — минимальный валидный вариант. */
function encodePng(width, height, rgb) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const stride = width * 3;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y += 1) {
    const src = y * stride;
    const dst = y * (stride + 1);
    raw[dst] = 0;
    rgb.copy(raw, dst + 1, src, src + stride);
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

/*
 * Шрифт 5x7 — только символы, которые встречаются в подписях осей:
 * цифры, разделители и единицы скорости (бит/с, Кбит/с … Пбит/с).
 */
const GLYPHS = {
  '0': [0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E],
  '1': [0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E],
  '2': [0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F],
  '3': [0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E],
  '4': [0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02],
  '5': [0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E],
  '6': [0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E],
  '7': [0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
  '8': [0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E],
  '9': [0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C],
  '.': [0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C],
  ',': [0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C, 0x08],
  ':': [0x00, 0x0C, 0x0C, 0x00, 0x0C, 0x0C, 0x00],
  '/': [0x01, 0x02, 0x02, 0x04, 0x08, 0x08, 0x10],
  '-': [0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00],
  ' ': [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
  К: [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
  М: [0x11, 0x1B, 0x15, 0x11, 0x11, 0x11, 0x11],
  Г: [0x1F, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10],
  Т: [0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
  П: [0x1F, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11],
  б: [0x07, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E],
  и: [0x00, 0x00, 0x11, 0x13, 0x15, 0x19, 0x11],
  т: [0x00, 0x00, 0x1F, 0x04, 0x04, 0x04, 0x04],
  с: [0x00, 0x00, 0x0E, 0x11, 0x10, 0x11, 0x0E],
};

const GLYPH_W = 5;
const GLYPH_H = 7;

function parseColor(value, fallback = [47, 111, 235]) {
  const s = String(value || '').trim();
  const hex = /^#?([0-9a-f]{6})$/i.exec(s);
  if (hex) {
    const n = parseInt(hex[1], 16);
    return [(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF];
  }
  const short = /^#?([0-9a-f]{3})$/i.exec(s);
  if (short) {
    const [r, g, b] = short[1].split('');
    return [parseInt(r + r, 16), parseInt(g + g, 16), parseInt(b + b, 16)];
  }
  return fallback;
}

class Canvas {
  constructor(width, height, background = [255, 255, 255]) {
    this.width = width;
    this.height = height;
    this.data = Buffer.alloc(width * height * 3);
    this.fillRect(0, 0, width, height, background);
  }

  setPixel(x, y, color) {
    const px = Math.round(x);
    const py = Math.round(y);
    if (px < 0 || py < 0 || px >= this.width || py >= this.height) return;
    const off = (py * this.width + px) * 3;
    this.data[off] = color[0];
    this.data[off + 1] = color[1];
    this.data[off + 2] = color[2];
  }

  fillRect(x, y, w, h, color) {
    const x0 = Math.max(0, Math.round(x));
    const y0 = Math.max(0, Math.round(y));
    const x1 = Math.min(this.width, Math.round(x + w));
    const y1 = Math.min(this.height, Math.round(y + h));
    for (let py = y0; py < y1; py += 1) {
      for (let px = x0; px < x1; px += 1) {
        const off = (py * this.width + px) * 3;
        this.data[off] = color[0];
        this.data[off + 1] = color[1];
        this.data[off + 2] = color[2];
      }
    }
  }

  strokeRect(x, y, w, h, color) {
    this.fillRect(x, y, w, 1, color);
    this.fillRect(x, y + h - 1, w, 1, color);
    this.fillRect(x, y, 1, h, color);
    this.fillRect(x + w - 1, y, 1, h, color);
  }

  /** Пунктир по горизонтали — линии сетки. */
  dashedHLine(x0, x1, y, color, dash = 4, gap = 4) {
    let x = Math.round(x0);
    const end = Math.round(x1);
    while (x < end) {
      this.fillRect(x, y, Math.min(dash, end - x), 1, color);
      x += dash + gap;
    }
  }

  /** Целочисленный Брезенхэм: на нецелых координатах цикл не сходится к концу линии. */
  line(rawX0, rawY0, rawX1, rawY1, color, thickness = 1) {
    let x = Math.round(rawX0);
    let y = Math.round(rawY0);
    const ex = Math.round(rawX1);
    const ey = Math.round(rawY1);
    const dx = Math.abs(ex - x);
    const dy = Math.abs(ey - y);
    const sx = x < ex ? 1 : -1;
    const sy = y < ey ? 1 : -1;
    let err = dx - dy;
    const half = Math.floor(thickness / 2);
    const maxSteps = dx + dy + 2;

    for (let guard = 0; guard < maxSteps; guard += 1) {
      if (thickness <= 1) {
        this.setPixel(x, y, color);
      } else {
        this.fillRect(x - half, y - half, thickness, thickness, color);
      }
      if (x === ex && y === ey) break;
      const e2 = 2 * err;
      if (e2 > -dy) {
        err -= dy;
        x += sx;
      }
      if (e2 < dx) {
        err += dx;
        y += sy;
      }
    }
  }

  text(x, y, str, color, scale = 1) {
    let cursor = Math.round(x);
    for (const ch of String(str)) {
      const glyph = GLYPHS[ch];
      if (glyph) {
        for (let row = 0; row < GLYPH_H; row += 1) {
          const bits = glyph[row];
          for (let col = 0; col < GLYPH_W; col += 1) {
            if (bits & (1 << (GLYPH_W - 1 - col))) {
              this.fillRect(cursor + col * scale, y + row * scale, scale, scale, color);
            }
          }
        }
      }
      cursor += (GLYPH_W + 1) * scale;
    }
  }
}

function textWidth(str, scale = 1) {
  return String(str).length * (GLYPH_W + 1) * scale;
}

/**
 * Рисует линейный график: сетка, подписи осей, серии.
 * Легенда не рисуется — в письме она выводится HTML, чтобы не тащить
 * в шрифт весь алфавит названий (ASN, страны, порты).
 */
function renderChartPng({
  series = [],
  yTicks = [],
  xTicks = [],
  width = 920,
  height = 280,
  scale = 2,
} = {}) {
  const W = width * scale;
  const H = height * scale;
  const padL = 96 * scale;
  const padR = 16 * scale;
  const padT = 12 * scale;
  const padB = 30 * scale;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  const canvas = new Canvas(W, H, [255, 255, 255]);
  const gridColor = [225, 227, 232];
  const axisColor = [176, 180, 189];
  const textColor = [104, 110, 122];

  canvas.fillRect(padL, padT, plotW, plotH, [250, 250, 251]);
  canvas.strokeRect(padL, padT, plotW, plotH, axisColor);

  const fontScale = Math.max(1, Math.round(scale));
  const glyphH = GLYPH_H * fontScale;

  for (const tick of yTicks) {
    const ratio = Math.min(1, Math.max(0, Number(tick.ratio) || 0));
    const y = Math.round(padT + plotH - ratio * plotH);
    if (ratio > 0) canvas.dashedHLine(padL + 1, padL + plotW - 1, y, gridColor, 5 * scale, 4 * scale);
    const label = String(tick.text || '');
    canvas.text(
      padL - 8 * scale - textWidth(label, fontScale),
      y - Math.floor(glyphH / 2),
      label,
      textColor,
      fontScale,
    );
  }

  for (const tick of xTicks) {
    const ratio = Math.min(1, Math.max(0, Number(tick.ratio) || 0));
    const x = Math.round(padL + ratio * plotW);
    canvas.fillRect(x, padT + plotH, 1, 4 * scale, axisColor);
    const label = String(tick.text || '');
    canvas.text(
      x - Math.round(textWidth(label, fontScale) / 2),
      padT + plotH + 8 * scale,
      label,
      textColor,
      fontScale,
    );
  }

  const thickness = Math.max(1, Math.round(1.8 * scale));
  for (const s of series) {
    const values = Array.isArray(s.values) ? s.values : [];
    if (!values.length) continue;
    const color = parseColor(s.color);
    const xAt = (i) => (values.length === 1
      ? padL + plotW / 2
      : padL + (i * plotW) / (values.length - 1));
    const yAt = (v) => padT + plotH - Math.min(1, Math.max(0, v)) * plotH;

    if (values.length === 1) {
      canvas.fillRect(xAt(0) - thickness, yAt(values[0]) - thickness, thickness * 2, thickness * 2, color);
      continue;
    }
    for (let i = 1; i < values.length; i += 1) {
      canvas.line(xAt(i - 1), yAt(values[i - 1]), xAt(i), yAt(values[i]), color, thickness);
    }
  }

  return {
    buffer: encodePng(W, H, canvas.data),
    width,
    height,
    pixelWidth: W,
    pixelHeight: H,
  };
}

module.exports = {
  encodePng,
  renderChartPng,
  Canvas,
  parseColor,
};
