const { randomInt } = require("node:crypto");
const config = require("../config");

const C = config.auth.captcha;
const COLORS = ["#093479", "#006fff", "#4f8d17"];

/** Returns { text, image } where image is an SVG data-URI (no external libraries needed). */
function createCaptchaImage() {
  const text = Array.from({ length: C.length }, () => C.alphabet[randomInt(C.alphabet.length)]).join("");
  const step = C.width / (C.length + 0.5);
  const lines = [0, 1, 2]
    .map((i) => `<line x1="${randomInt(30)}" y1="${randomInt(C.height)}" x2="${C.width - randomInt(30)}" y2="${randomInt(C.height)}" stroke="${COLORS[i]}" stroke-opacity="0.35" stroke-width="1.5"/>`)
    .join("");
  const glyphs = [...text]
    .map((ch, i) => {
      const x = Math.round(step * (i + 0.6));
      const rot = randomInt(36) - 18;
      return `<text x="${x}" y="${32 + randomInt(8) - 4}" font-size="26" font-weight="800" font-family="monospace" fill="${COLORS[randomInt(3)]}" transform="rotate(${rot} ${x} 28)">${ch}</text>`;
    })
    .join("");
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${C.width} ${C.height}" width="${C.width}" height="${C.height}"><rect width="100%" height="100%" fill="#f1f5ff"/>${lines}${glyphs}</svg>`;
  return { text, image: `data:image/svg+xml;base64,${Buffer.from(svg).toString("base64")}` };
}

module.exports = { createCaptchaImage };
