// Interface C2C. Aucune regle metier ici : les ecrans viennent du registre `c2c-api` (le meme que la CLI) et chaque action
// passe par `run_command`. Un appel destructif demande confirmation ici ET est refuse par le backend sans confirmation.
import { invoke } from "@tauri-apps/api/core";
import "./style.css";

type Risk = "read" | "common" | "destructive";
type ArgKind = { type: "text" } | { type: "bool" } | { type: "choice"; values: string[] };
interface ArgSpec { name: string; kind: ArgKind; required: boolean; help: string }
interface Cmd { name: string; cli: string; summary: string; risk: Risk; has_execute: boolean; target: "local" | "machine"; args: ArgSpec[] }
interface Output { ok: boolean; text: string; data: any }
interface Machine { name: string; address: string; agent: boolean; wakeable: boolean }

const state = {
  commands: [] as Cmd[],
  machines: [] as Machine[],
  machine: "" as string, // "" = cette machine
  // "overview" | "local" | "m:<machine>" | "commands" | "journal"
  page: "overview" as string,
  info: { config: "", config_ok: true, config_error: null as string | null, client_name: null as string | null },
  statuses: {} as Record<string, string>, // derniere etat connu de chaque machine (online / offline / unknown)
  history: {} as Record<string, string[]>, // echantillons recents (o = en ligne, x = hors ligne), conserves entre deux ouvertures
  lastPoll: 0,
};
const HISTORY_MAX = 90;
const POLL_MS = 30_000; // sondage de l'etat des machines (statut Tailscale : aucun secret)
const AUTO_MS = 20_000; // rafraichissement automatique des cartes de lecture
const timers: number[] = [];

// ---------- utilitaires DOM (textContent uniquement : aucune donnee distante n'est interpretee comme du HTML) ----------
type Child = Node | string | null | undefined | false;
function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, any> = {}, ...kids: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, "");
    else if (v !== false && v != null) el.setAttribute(k, String(v));
  }
  for (const c of kids) if (c) el.append(c instanceof Node ? c : document.createTextNode(c));
  return el;
}

async function run(name: string, args: Record<string, unknown> = {}, confirmed = false): Promise<Output> {
  return invoke<Output>("run_command", { machine: state.machine || null, name, args, confirmed });
}

function errText(e: unknown): string {
  return typeof e === "string" ? e : (e as Error)?.message ?? JSON.stringify(e);
}

function confirmDialog(title: string, body: string, danger: boolean, okLabel = "Confirmer"): Promise<boolean> {
  return new Promise((resolve) => {
    const close = (v: boolean) => { bg.remove(); resolve(v); };
    const bg = h("div", { class: "modal-bg" },
      h("div", { class: "modal" + (danger ? " danger" : "") },
        h("h3", {}, title),
        h("p", {}, body),
        h("div", { class: "row" },
          h("button", { class: "btn" + (danger ? " danger" : " primary"), onclick: () => close(true) }, okLabel),
          h("button", { class: "btn", onclick: () => close(false) }, "Annuler"))));
    document.body.append(bg);
  });
}

/// Lance une commande en demandant confirmation si CET appel est destructif (regle fournie par le backend).
async function runGuarded(name: string, args: Record<string, unknown>, label: string): Promise<Output | null> {
  const risk = await invoke<Risk>("risk", { name, args });
  let confirmed = false;
  if (risk === "destructive") {
    if (!(await confirmDialog("Action destructive", `${label}\n\nCette action peut couper une session ou retirer un appareil. Confirmer ?`, true, "Oui, exécuter"))) return null;
    confirmed = true;
  } else if (risk === "common" && args.execute === true) {
    // Action courante : confirmation legere, sauf pour les simples reglages.
    if (!(await confirmDialog("Exécuter ?", label, false, "Exécuter"))) return null;
  }
  return run(name, args, confirmed);
}

// ---------- rendu d'une sortie ----------
function renderOutput(box: HTMLElement, o: Output | null, err?: string) {
  box.replaceChildren();
  if (err) { box.append(h("div", { class: "err" }, err)); return; }
  if (!o) return;
  box.append(h("div", { class: o.ok ? "" : "err" }, o.ok ? "" : "Résultat négatif"));
  if (o.text) box.append(h("pre", {}, o.text));
  if (o.data != null) box.append(h("details", {}, h("summary", { class: "muted" }, "Données structurées"), h("pre", {}, JSON.stringify(o.data, null, 2))));
}

// ---------- carte generique d'une commande (parite : toutes les commandes du registre) ----------
function commandCard(c: Cmd): HTMLElement {
  const inputs: Record<string, () => unknown> = {};
  const form = h("div", {});
  for (const a of c.args) {
    if (a.name === "execute") continue; // porte par les boutons Simuler / Executer
    if (a.kind.type === "bool") {
      const cb = h("input", { type: "checkbox" });
      inputs[a.name] = () => cb.checked;
      form.append(h("label", { class: "f check" }, cb, `${a.name} — ${a.help}`));
    } else if (a.kind.type === "choice") {
      const sel = h("select", {}, ...(a.required ? [] : [h("option", { value: "" }, "(aucun)")]), ...a.kind.values.map((v) => h("option", { value: v }, v)));
      inputs[a.name] = () => sel.value || null;
      form.append(h("label", { class: "f" }, `${a.name}${a.required ? " *" : ""} — ${a.help}`, sel));
    } else {
      const inp = h("input", { type: "text", placeholder: a.help });
      inputs[a.name] = () => inp.value.trim() || null;
      form.append(h("label", { class: "f" }, `${a.name}${a.required ? " *" : ""} — ${a.help}`, inp));
    }
  }
  const out = h("div", {});
  const go = async (execute: boolean, btn: HTMLButtonElement) => {
    const args: Record<string, unknown> = {};
    for (const [k, f] of Object.entries(inputs)) args[k] = f();
    if (c.has_execute) args.execute = execute;
    btn.disabled = true;
    try {
      const o = await runGuarded(c.name, args, `${c.name} ${JSON.stringify(args)}${state.machine ? ` sur ${state.machine}` : ""}`);
      renderOutput(out, o);
    } catch (e) { renderOutput(out, null, errText(e)); }
    btn.disabled = false;
  };
  const b1 = h("button", { class: "btn" + (c.has_execute ? "" : " primary"), onclick: (e: Event) => go(false, e.currentTarget as HTMLButtonElement) }, c.has_execute ? "Simuler" : "Lancer");
  const row = h("div", { class: "row" }, b1);
  if (c.has_execute) row.append(h("button", { class: "btn " + (c.risk === "destructive" ? "danger" : "primary"), onclick: (e: Event) => go(true, e.currentTarget as HTMLButtonElement) }, "Exécuter"));
  return h("div", { class: "card" },
    h("h2", {}, c.name, h("span", { class: "badge " + c.risk }, c.risk), c.target === "local" ? h("span", { class: "badge" }, "ici") : null),
    h("p", { class: "sum" }, c.summary), form, row, out);
}

// ---------- tableau de bord : cartes dediees, alimentees par les memes commandes ----------
function panel(title: string, load: (body: HTMLElement, reload: () => void) => Promise<void>, actions: Child[] = [], manual = ""): HTMLElement {
  const body = h("div", {});
  const stamp = h("span", { class: "live" });
  const refresh = h("button", { class: "btn small" }, "Actualiser");
  const go = async (silent: boolean) => {
    refresh.disabled = true;
    if (!silent) body.replaceChildren(h("span", { class: "muted" }, "…"));
    try {
      await load(body, () => void go(false));
      stamp.textContent = "mis à jour " + new Date().toLocaleTimeString();
    } catch (e) { body.replaceChildren(h("div", { class: "err" }, errText(e))); }
    refresh.disabled = false;
  };
  refresh.addEventListener("click", () => void go(false));
  const card = h("div", { class: "card" }, h("div", { class: "row between" }, h("h2", {}, title), h("div", { class: "row" }, stamp, ...actions, refresh)), body);
  // `manual` : carte qui demande un secret a 1Password : elle ne se charge que sur clic, jamais a l'ouverture ni toute seule.
  if (manual) { refresh.textContent = "Charger"; body.append(h("div", { class: "muted" }, manual)); return card; }
  void go(false);
  // Rafraichissement automatique des cartes de lecture, seulement si la fenetre est visible et qu'aucune boite de dialogue n'est ouverte.
  timers.push(window.setInterval(() => {
    if (!card.isConnected || document.hidden || document.querySelector(".modal-bg") || refresh.disabled) return;
    void go(true);
  }, AUTO_MS));
  return card;
}

// ---------- etat des machines : sondage periodique, historique, notifications ----------
function toast(text: string, kind: "ok" | "ko" | "" = "") {
  let box = document.querySelector(".toasts");
  if (!box) { box = h("div", { class: "toasts" }); document.body.append(box); }
  const t = h("div", { class: "toast " + kind }, text);
  box.append(t);
  window.setTimeout(() => t.remove(), 8000);
  try { if (document.hidden && "Notification" in window && Notification.permission === "granted") new Notification("C2C", { body: text }); } catch { /* notification systeme indisponible : le toast suffit */ }
}

function loadHistory() {
  try { state.history = JSON.parse(localStorage.getItem("c2c.history") ?? "{}"); } catch { state.history = {}; }
}

async function pollStatus(): Promise<void> {
  const o = await run("status");
  const first = state.lastPoll === 0;
  state.lastPoll = Date.now();
  for (const m of o.data.machines as any[]) {
    const prev = state.statuses[m.name];
    state.statuses[m.name] = m.state;
    if (m.state === "online" || m.state === "offline") {
      const hist = (state.history[m.name] ??= []);
      hist.push(m.state === "online" ? "o" : "x");
      if (hist.length > HISTORY_MAX) hist.splice(0, hist.length - HISTORY_MAX);
    }
    if (!first && prev && prev !== m.state && (m.state === "online" || m.state === "offline")) {
      toast(`${m.name} : ${m.state === "online" ? "est revenue en ligne" : "est passée hors ligne"}`, m.state === "online" ? "ok" : "ko");
    }
  }
  try { localStorage.setItem("c2c.history", JSON.stringify(state.history)); } catch { /* stockage indisponible : l'historique reste en memoire */ }
  document.querySelectorAll<HTMLElement>("[data-dot]").forEach((d) => { d.className = "dot " + dotClass(state.statuses[d.dataset.dot!]); });
}

function dotClass(s?: string) { return s === "online" ? "ok" : s === "offline" ? "ko" : ""; }
function stateLabel(s?: string) { return s === "online" ? "en ligne" : s === "offline" ? "hors ligne" : "inconnu"; }
function strip(name: string): HTMLElement {
  const hist = state.history[name] ?? [];
  return h("div", { class: "strip", title: `${hist.length} dernières mesures` }, ...hist.map((c) => h("i", { class: c === "o" ? "ok" : "ko" })));
}

async function wakeMachine(name: string) {
  if (!(await confirmDialog("Réveiller", `Envoyer le paquet de réveil à ${name} via le Pi ?`, false, "Réveiller"))) return;
  try { const o = await run("wake", { name, execute: true }); toast(o.ok ? `Réveil envoyé à ${name}` : `Réveil de ${name} : résultat négatif`, o.ok ? "ok" : "ko"); } catch (e) { toast(errText(e), "ko"); }
}

// ---------- vue d'ensemble ----------
function overviewPage(): HTMLElement[] {
  const kpis = h("div", { class: "kpis" });
  const grid = h("div", { class: "grid" });
  const draw = () => {
    const names = state.machines.map((m) => m.name);
    const on = names.filter((n) => state.statuses[n] === "online").length;
    const off = names.filter((n) => state.statuses[n] === "offline").length;
    kpis.replaceChildren(
      h("div", { class: "kpi" }, h("b", {}, `${on}/${names.length}`), h("span", {}, "machines en ligne")),
      h("div", { class: "kpi" }, h("b", { class: off ? "err" : "" }, String(off)), h("span", {}, "hors ligne")),
      h("div", { class: "kpi" }, h("b", {}, String(state.machines.filter((m) => m.agent).length)), h("span", {}, "pilotables (agent)")));
    grid.replaceChildren(...state.machines.map((m) => h("button", { class: "tile", onclick: () => go("m:" + m.name) },
      h("div", { class: "name" }, h("span", { class: "dot " + dotClass(state.statuses[m.name]) }), m.name,
        h("span", { class: "badge" }, m.agent ? "agent" : "supervision seule")),
      h("div", { class: "addr" }, `${m.address} — ${stateLabel(state.statuses[m.name])}`),
      strip(m.name))));
  };
  const refresh = async () => { try { await pollStatus(); } catch (e) { grid.replaceChildren(h("div", { class: "err" }, errText(e))); return; } draw(); };
  draw();
  void refresh();
  timers.push(window.setInterval(() => { if (grid.isConnected && !document.hidden) void refresh(); }, POLL_MS));
  return [h("div", { class: "page-head" }, h("h2", {}, "Vue d'ensemble"), h("span", { class: "sub" }, "état du homelab, mis à jour automatiquement"), h("span", { class: "spacer" }),
    h("button", { class: "btn small", onclick: () => void refresh() }, "Actualiser")), kpis, grid];
}

// ---------- page d'une machine ----------
function machinePage(m: Machine | null): HTMLElement[] {
  const title = m ? m.name : `Cette machine${state.info.client_name ? " (" + state.info.client_name + ")" : ""}`;
  const head = h("div", { class: "page-head" }, m ? h("span", { "data-dot": m.name, class: "dot " + dotClass(state.statuses[m.name]) }) : null,
    h("h2", {}, title), m ? h("span", { class: "sub" }, `${m.address} — ${stateLabel(state.statuses[m.name])}`) : null, h("span", { class: "spacer" }),
    m?.wakeable && state.statuses[m.name] !== "online" ? h("button", { class: "btn", onclick: () => void wakeMachine(m.name) }, "Réveiller") : null);
  if (m && !m.agent) {
    return [head, h("div", { class: "grid" },
      h("div", { class: "card" }, h("h2", {}, "Supervision"), h("p", { class: "sum" }, "Cette machine n'a pas d'agent C2C : seul son état réseau est suivi (Tailscale). Un agent en lecture seule pourra être installé plus tard, avec ton accord."),
        h("div", { class: "muted" }, "Historique de présence"), strip(m.name)))];
  }
  const cards = [healthPanel(), displayPanel(), sunshinePanel(), networkPanel()];
  if (m) cards.unshift(h("div", { class: "card" }, h("h2", {}, "Historique de présence"), strip(m.name)));
  return [head, h("div", { class: "grid" }, ...cards)];
}

function healthPanel(): HTMLElement {
  return panel(`Santé${state.machine ? " — " + state.machine : ""}`, async (body) => {
    const o = await run("health-check");
    const list = (o.data.checks as any[]).map((c) => h("div", { class: "row" }, h("span", { class: "dot " + (c.ok ? "ok" : "ko") }), c.name, c.detail ? h("span", { class: "muted" }, c.detail) : null));
    body.replaceChildren(h("div", { class: o.ok ? "" : "err" }, o.ok ? "Tout est sain." : "Un ou plusieurs contrôles échouent."), ...list);
  });
}

function displayPanel(): HTMLElement {
  return panel(`Affichage${state.machine ? " — " + state.machine : ""}`, async (body, reload) => {
    const [st, ses, prof, mode] = await Promise.all([run("display-status"), run("session-status"), run("display-profile"), run("display-mode")]);
    const screens = (st.data.screens as any[]).map((s) => h("tr", {}, h("td", {}, s.id), h("td", {}, s.active ? "actif" : "—"), h("td", {}, s.primary ? "principal" : ""), h("td", {}, s.active ? `${s.mode.w}x${s.mode.h}@${s.mode.hz}` : "")));
    const seg = (items: string[], cur: string | null, onPick: (v: string) => void) => h("div", { class: "seg" }, ...items.map((v) => h("button", { class: v === cur ? "on" : "", onclick: () => onPick(v) }, v)));
    const setMode = async (m: string) => { try { await runGuarded("display-mode", { mode: m }, `Imposer le mode ${m}`); } catch (e) { alert(errText(e)); } reload(); };
    const setProfile = async (p: string) => { try { await runGuarded("display-profile", { name: p }, `Profil ${p}`); } catch (e) { alert(errText(e)); } reload(); };
    const profiles = (prof.data.profiles as any[]).map((p) => p.name);
    body.replaceChildren(
      h("div", { class: "muted" }, `Session distante : ${ses.data.session === true ? "active" : ses.data.session === false ? "aucune" : "inconnue"}`),
      h("table", {}, h("tbody", {}, ...screens)),
      h("div", { class: "row" }, "Disposition imposée :", seg(["auto", "local", "remote"], mode.data.mode, setMode)),
      h("div", { class: "row" }, "Profil virtuel :", seg(["defaut", ...profiles], prof.data.active ?? "defaut", setProfile)),
      h("div", { class: "muted" }, `Disposition correcte — local : ${st.data.local_ok ? "oui" : "non"}, distante : ${st.data.remote_ok ? "oui" : "non"}`));
  });
}

function sunshinePanel(): HTMLElement {
  const note = "Cette carte lit ton mot de passe Sunshine dans le 1Password de CET appareil : une autorisation te sera demandée au clic sur « Charger ».";
  return panel(`Sunshine${state.machine ? " — " + state.machine : ""}`, async (body) => {
    const [cl, pend] = await Promise.all([run("sunshine.clients"), run("sunshine.pending")]);
    const clients = ((cl.data.named_certs as any[]) ?? []).map((c) => h("div", { class: "row between" }, h("span", {}, c.name, h("span", { class: "muted" }, " " + c.uuid)),
      h("button", { class: "btn danger", onclick: async () => {
        try { const o = await runGuarded("sunshine.unpair", { uuid: c.uuid, execute: true }, `Retirer l'appareil « ${c.name} » (${c.uuid})`); if (o) renderOutput(body, o); } catch (e) { renderOutput(body, null, errText(e)); }
      } }, "Retirer")));
    const pairings = ((pend.data.pairings as any[]) ?? []);
    const pin = h("input", { type: "text", placeholder: "PIN à 4 chiffres", maxlength: 4, style: "min-width:110px;width:110px" });
    const name = h("input", { type: "text", placeholder: "nom de l'appareil", value: "appareil" });
    const send = h("button", { class: "btn primary", onclick: async () => {
      try { const o = await runGuarded("sunshine.pin", { pin: pin.value.trim(), name: name.value.trim(), execute: true }, `Appairer « ${name.value} »`); if (o) renderOutput(body, o); } catch (e) { renderOutput(body, null, errText(e)); }
    } }, "Appairer");
    body.replaceChildren(
      h("div", { class: "muted" }, "Appareils appairés"), ...(clients.length ? clients : [h("div", { class: "muted" }, "aucun")]),
      h("div", { class: "muted", style: "margin-top:10px" }, pairings.length ? `Demande en attente : ${pairings.map((p) => `${p.name} (${p.address})`).join(", ")}` : "Aucune demande en attente (affichez le PIN sur l'appareil)."),
      h("div", { class: "row" }, pin, name, send));
  }, [], note);
}

function networkPanel(): HTMLElement {
  return panel(`Réseau${state.machine ? " — " + state.machine : ""}`, async (body) => {
    const o = await run("net-health");
    body.replaceChildren(h("div", {}, `Verdict : ${o.data.verdict}`), h("pre", {}, o.text));
  });
}

// ---------- journal ----------
function journalView(): HTMLElement[] {
  const limit = h("input", { type: "text", value: "50", style: "min-width:70px;width:70px" });
  const out = h("div", {});
  const load = async () => {
    try {
      const o = await run("audit-show", { limit: Number(limit.value) || 50 });
      const rows = (o.data.entries as any[]).slice().reverse().map((e) => h("tr", {}, h("td", {}, String(e.ts).replace("T", " ").slice(0, 19)), h("td", {}, e.actor), h("td", {}, e.action), h("td", {}, e.target), h("td", { class: e.outcome === "ok" ? "" : "err" }, e.outcome), h("td", { class: "muted" }, e.detail)));
      out.replaceChildren(h("table", {}, h("thead", {}, h("tr", {}, ...["Date (UTC)", "Auteur", "Action", "Cible", "Résultat", "Détail"].map((t) => h("th", {}, t)))), h("tbody", {}, ...rows)));
    } catch (e) { out.replaceChildren(h("div", { class: "err" }, errText(e))); }
  };
  const verify = h("div", {});
  const check = async () => { try { renderOutput(verify, await run("audit-verify")); } catch (e) { renderOutput(verify, null, errText(e)); } };
  load();
  return [h("div", { class: "card" },
    h("div", { class: "row between" }, h("h2", {}, `Journal d'audit${state.machine ? " — " + state.machine : ""}`),
      h("div", { class: "row" }, "Dernières :", limit, h("button", { class: "btn", onclick: load }, "Actualiser"), h("button", { class: "btn", onclick: check }, "Vérifier l'intégrité"))),
    verify, out)];
}

// ---------- structure de la page ----------
function go(page: string) {
  state.page = page;
  if (page === "local") state.machine = "";
  else if (page.startsWith("m:")) { const m = state.machines.find((x) => "m:" + x.name === page); state.machine = m?.agent ? m.name : ""; }
  render();
}

function setTheme(t: "light" | "dark") {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("c2c.theme", t); } catch { /* theme non conserve */ }
}
function currentTheme(): "light" | "dark" {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}
function initTheme() {
  let t: string | null = null;
  try { t = localStorage.getItem("c2c.theme"); } catch { /* ignore */ }
  setTheme(t === "light" || t === "dark" ? t : window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark");
}

/// Machine visee par les pages « Commandes » et « Journal ».
function targetSelect(): HTMLElement {
  return h("select", { onchange: (e: Event) => { state.machine = (e.target as HTMLSelectElement).value; render(); } },
    h("option", { value: "" }, `Cette machine${state.info.client_name ? " (" + state.info.client_name + ")" : ""}`),
    ...state.machines.filter((m) => m.agent).map((m) => h("option", { value: m.name, selected: m.name === state.machine }, m.name)));
}

function render() {
  timers.splice(0).forEach((t) => clearInterval(t));
  const root = document.getElementById("app")!;
  const item = (id: string, label: string, dotFor?: string) => h("button", { class: "nav-item" + (state.page === id ? " on" : ""), onclick: () => go(id) },
    dotFor ? h("span", { "data-dot": dotFor, class: "dot " + dotClass(state.statuses[dotFor]) }) : null, h("span", { class: "grow" }, label));
  const side = h("aside", { class: "side" }, h("h1", {}, "C2C"),
    item("overview", "Vue d'ensemble"),
    h("div", { class: "sect" }, "Machines"),
    item("local", `Cette machine${state.info.client_name ? " (" + state.info.client_name + ")" : ""}`),
    ...state.machines.map((m) => item("m:" + m.name, m.name, m.name)),
    h("div", { class: "sect" }, "Outils"),
    item("commands", "Toutes les commandes"), item("journal", "Journal"),
    h("span", { class: "spacer" }),
    h("button", { class: "nav-item", onclick: () => { setTheme(currentTheme() === "dark" ? "light" : "dark"); render(); } }, h("span", { class: "grow" }, currentTheme() === "dark" ? "Thème clair" : "Thème sombre")));
  const content = h("div", { class: "content" });
  if (!state.info.config_ok) content.append(h("div", { class: "banner" }, `Configuration illisible (${state.info.config}) : ${state.info.config_error}`));
  if (state.page === "overview") content.append(...overviewPage());
  else if (state.page === "local") content.append(...machinePage(null));
  else if (state.page.startsWith("m:")) content.append(...machinePage(state.machines.find((m) => "m:" + m.name === state.page) ?? null));
  else if (state.page === "commands") {
    const grid = h("div", { class: "grid" });
    let group = "";
    for (const c of state.commands) {
      const g = c.name.split(".")[0].split("-")[0];
      if (g !== group) { group = g; grid.append(h("div", { class: "group-title" }, g)); }
      grid.append(commandCard(c));
    }
    content.append(h("div", { class: "page-head" }, h("h2", {}, "Toutes les commandes"), h("span", { class: "sub" }, "même registre que la CLI"), h("span", { class: "spacer" }), "Machine pilotée", targetSelect()), grid);
  } else {
    content.append(h("div", { class: "page-head" }, h("h2", {}, "Journal"), h("span", { class: "spacer" }), "Machine pilotée", targetSelect()), h("div", { class: "grid single" }, ...journalView()));
  }
  root.replaceChildren(h("div", { class: "shell" }, side, content));
}

async function boot() {
  initTheme();
  loadHistory();
  try {
    const reg = await invoke<{ commands: Cmd[] }>("registry");
    state.commands = reg.commands;
    state.info = await invoke("app_info");
    state.machines = state.info.config_ok ? await invoke<Machine[]>("machines") : [];
    // Un client (portable, telephone) pilote en general une autre machine : on ouvre sur la vue d'ensemble, machine pilotee par defaut.
    if (state.info.client_name) state.machine = state.machines.find((m) => m.agent)?.name ?? "";
  } catch (e) { document.getElementById("app")!.textContent = "Erreur au démarrage : " + errText(e); return; }
  render();
  // Sondage de fond : meme hors de la vue d'ensemble, pour l'historique, les pastilles et les notifications.
  window.setInterval(() => { if (!document.hidden && state.page !== "overview") void pollStatus().catch(() => undefined); }, POLL_MS);
  if (state.page !== "overview") void pollStatus().catch(() => undefined);
}

boot();
