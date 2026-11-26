/** One response shape for the whole API: { success, data } or { success:false, error:{code,message} }. */
const ok = (res, data = {}, status = 200) => res.status(status).json({ success: true, data });
const fail = (res, status, code, message, extra = {}) => res.status(status).json({ success: false, error: { code, message, ...extra } });

module.exports = { ok, fail };
