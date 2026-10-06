function pad(n, w = 4) { return String(n).padStart(w, '0'); }

async function nextId(Model, field, prefix) {
  const count = await Model.countDocuments();
  const d = new Date();
  const stamp = `${d.getFullYear()}${pad(d.getMonth() + 1, 2)}${pad(d.getDate(), 2)}`;
  return `${prefix}-${stamp}-${pad(count + 1, 4)}`;
}

function uid(prefix = 'EVT') {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 100000)}`;
}

module.exports = { nextId, uid };
