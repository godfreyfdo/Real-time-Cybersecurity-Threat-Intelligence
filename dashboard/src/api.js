const BASE = 'https://yg1h9ibm76.execute-api.us-east-1.amazonaws.com/prod'
export async function getThreats(limit = 100) {
  const r = await fetch(`${BASE}/threats?limit=${limit}`)
  return r.json()
}
export async function getStats() {
  const r = await fetch(`${BASE}/stats`)
  return r.json()
}