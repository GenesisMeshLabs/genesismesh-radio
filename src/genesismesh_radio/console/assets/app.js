"use strict";
const byId = (name) => document.getElementById(name);
let identity = null, csrf = "", busy = false;
const intentKey = "gm-home-pilot-intent-v1";
let intent = null;
try { intent = JSON.parse(localStorage.getItem(intentKey)); } catch { /* No stored intent. */ }
if (intent && (typeof intent.command_id !== "string" || !/^[0-9a-f-]{36}$/.test(intent.command_id))) intent = null;
function notice(text) { byId("notice").textContent = text; }
async function api(path, method = "GET", body) {
  const headers = {};
  if (method === "POST") { headers["Content-Type"] = "application/json"; headers["X-Console-Request"] = "1"; if(csrf) headers["X-CSRF-Token"] = csrf; }
  const response = await fetch(path, {method, headers, credentials:"same-origin", cache:"no-store", ...(body ? {body:JSON.stringify(body)} : {})});
  const data = await response.json();
  if (!response.ok) { const error = new Error(data.code || "Request unavailable"); error.status = response.status; throw error; }
  return data;
}
function setIdentity(data) {
  identity = data; csrf = data ? data.csrf : "";
  byId("login-panel").hidden = !!data; byId("workspace").hidden = !data;
  byId("identity").textContent = data ? `${data.username} · ${data.role}` : "Signed out";
  byId("mode").textContent = data ? ({simulated_authority_and_radio:"Demo · simulated authority and radio",real_authority_simulated_radio:"Real authority · simulated radio",configured_bridge:"Configured bridge · verify physical status separately"}[data.mode]) : "Home operator console";
  byId("submit-command").disabled = !data || data.role !== "operator" || !!intent;
}
function rows(target, values) {
  const parent = byId(target); parent.replaceChildren();
  for (const value of values) { const row = document.createElement("div"); row.textContent = value; parent.append(row); }
  if (!values.length) { const empty = document.createElement("p"); empty.textContent = "No observations yet."; parent.append(empty); }
}
function clearResult() {
  byId("request-id").textContent = intent ? intent.command_id : "No request yet";
  byId("outcome").textContent = intent ? "Unconfirmed" : "—";
  byId("report").textContent = "—";
  byId("authorization-id").textContent = "—";
  byId("permission-source").textContent = "—";
  byId("request-detail").textContent = intent ? "Awaiting the result for this request ID." : "Submit a request to follow its result.";
  byId("new-request").disabled = true;
}
function result(command, expectedId) {
  if (!intent || intent.command_id !== expectedId) return;
  if (!command || command.command_id !== expectedId) {
    clearResult(); byId("request-detail").textContent = "The response did not match this request ID. Keep the original ID for reconciliation."; return;
  }
  byId("request-id").textContent = expectedId;
  byId("outcome").textContent = command.state || "Unknown";
  byId("report").textContent = command.report_status || "Unknown";
  byId("authorization-id").textContent = command.authorization_id || "Not available";
  byId("permission-source").textContent = command.authority || "Not available";
  byId("request-detail").textContent = command.result ? JSON.stringify(command.result) : "Awaiting an authenticated device result.";
  byId("new-request").disabled = !["confirmed", "denied", "rejected", "expired"].includes(command.state);
}
async function lookup() {
  if (!intent) return;
  const expectedId = intent.command_id;
  byId("request-id").textContent = expectedId;
  try { result((await api(`/api/commands/${encodeURIComponent(expectedId)}`)).command, expectedId); }
  catch(error) { if(!intent || intent.command_id!==expectedId) return; byId("outcome").textContent = "Unconfirmed"; byId("request-detail").textContent = `${error.message}. Retain this request ID; no automatic resend.`; byId("new-request").disabled = true; }
}
async function refresh() {
  if (!identity || busy) return; busy = true;
  try {
    const data = await api("/api/status"), state = data.bridge;
    byId("health").textContent = data.process_health.ready ? "Running" : "Unavailable";
    byId("events").textContent = String(state.event_count);
    const telemetry = state.latest_telemetry || [], now = Date.now()/1000;
    byId("freshness").textContent = telemetry.length ? `Latest reading ${Math.max(0,Math.round(now-telemetry[0].received_at))} seconds ago. Freshness is not an authority check.` : "No sensor observation received.";
    rows("observations", telemetry.map(t => `Device ${t.device_id} · metric ${t.details.metric}: ${t.details.value} · ${Math.max(0, Math.round(now-t.received_at))}s old${now-t.received_at>30 ? " · STALE" : ""}`));
    rows("commands", (state.commands || []).map(c=> `${c.command_id} · device ${c.device_id} · ${c.state} · evidence ${c.report_status}`));
    const previous = byId("device").value; byId("device").replaceChildren();
    for(const device of state.devices || []) { const option = document.createElement("option"); option.value = device.device_id; option.textContent = `${device.device_id} · ${device.resource_id}`; option.dataset.minimum = device.min_interval; option.dataset.maximum = device.max_interval; byId("device").append(option); }
    if(previous) byId("device").value = previous;
    bounds(); await lookup(); notice("Local observations refreshed. Dispatch and device outcome are tracked separately.");
  } catch(error) { notice(`${error.message}. Displayed observations may be stale.`); if(error.status===401) setIdentity(null); }
  finally { busy = false; }
}
function bounds() { const option = byId("device").selectedOptions[0]; if(option) { byId("interval").min=option.dataset.minimum; byId("interval").max=option.dataset.maximum; } }
byId("device").addEventListener("change", bounds);
byId("login-form").addEventListener("submit", async event=> {
  event.preventDefault(); const form = event.target, button=form.querySelector("button"); button.disabled=true;
  try { const data=await api("/api/login","POST",{username:form.elements.username.value,password:form.elements.password.value}); form.elements.password.value=""; setIdentity(data); await refresh(); }
  catch(error) { notice(error.message); } finally { button.disabled=false; }
});
byId("logout").addEventListener("click", async()=>{ try{await api("/api/logout","POST",{}); setIdentity(null); notice("Signed out. Server session invalidated.");}catch(error){notice(error.message);} });
byId("refresh").addEventListener("click", refresh); byId("lookup").addEventListener("click", lookup);
byId("new-request").addEventListener("click",()=>{ intent=null; localStorage.removeItem(intentKey); byId("submit-command").disabled=identity.role!=="operator"; clearResult(); });
byId("command-form").addEventListener("submit", async event=>{
  event.preventDefault(); if(intent || identity.role!=="operator") return;
  intent={command_id:crypto.randomUUID(),device_id:Number(byId("device").value),interval_seconds:Number(byId("interval").value),ttl:Number(byId("ttl").value)};
  try {localStorage.setItem(intentKey,JSON.stringify(intent));}catch{intent=null; notice("Request ID could not be saved. No command was submitted.");return;}
  const submitted = {...intent}, expectedId = submitted.command_id;
  byId("submit-command").disabled=true; clearResult();
  try{result((await api("/api/commands","POST",submitted)).command, expectedId); if(intent && intent.command_id===expectedId) notice("Request recorded. Check the device outcome before treating it as complete.");}
  catch(error){if(!intent || intent.command_id!==expectedId) return; notice(`${error.message}. Keep this request ID and check its result.`);await lookup();}
});
document.addEventListener("visibilitychange",()=>{if(!document.hidden)refresh();});
setInterval(()=>{if(!document.hidden)refresh();},5000);
api("/api/session").then(data=>{setIdentity(data);refresh();}).catch(()=>setIdentity(null));
