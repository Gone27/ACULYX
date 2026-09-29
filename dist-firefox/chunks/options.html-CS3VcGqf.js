import "./modulepreload-polyfill-DaKOjhqt.js";
import { L as LocalStorage, s as sendToBackground, e as SEVERITY_ORDER } from "./messaging-FA_Ch_Z4.js";
const ALL_SEVERITIES = [...SEVERITY_ORDER];
let modeRadios;
let severityCheckboxes;
let retainDaysInput;
let allowlistEl;
let allowlistEmptyMsg;
let saveBtn;
let saveStatus;
let sectionAllowlist;
let workingOrigins = [];
document.addEventListener("DOMContentLoaded", () => {
  modeRadios = document.querySelectorAll('input[name="monitoringMode"]');
  severityCheckboxes = document.querySelectorAll('input[name="severity"]');
  retainDaysInput = getEl("retain-history-days");
  allowlistEl = getEl("allowlist");
  allowlistEmptyMsg = getEl("allowlist-empty");
  saveBtn = getEl("save-btn");
  saveStatus = getEl("save-status");
  sectionAllowlist = getEl("section-allowlist");
  wireModeRadios();
  wireSaveButton();
  void loadAndPopulate();
});
async function loadAndPopulate() {
  let settings;
  try {
    settings = await LocalStorage.getSettings();
  } catch {
    setStatus("Failed to load settings.", true);
    return;
  }
  for (const radio of modeRadios) {
    radio.checked = radio.value === settings.monitoringMode;
  }
  updateAllowlistVisibility(settings.monitoringMode);
  const filterSet = new Set(settings.severityFilter);
  for (const cb of severityCheckboxes) {
    cb.checked = filterSet.has(cb.value);
  }
  retainDaysInput.value = String(settings.retainHistoryDays);
  workingOrigins = [...settings.allowedOrigins];
  renderAllowlist();
}
function wireSaveButton() {
  saveBtn.addEventListener("click", () => {
    void handleSave();
  });
}
async function handleSave() {
  clearStatus();
  const settings = readFormValues();
  if (settings.retainHistoryDays < 0 || settings.retainHistoryDays > 365) {
    setStatus("Retain days must be between 0 and 365.", true);
    return;
  }
  try {
    await LocalStorage.setSettings(settings);
    await sendToBackground({ type: "SETTINGS_CHANGED", settings });
    setStatus("Settings saved ✓", false);
  } catch {
    setStatus("Failed to save settings.", true);
    return;
  }
  setTimeout(() => clearStatus(), 3e3);
}
function readFormValues() {
  let monitoringMode = "per-site";
  for (const radio of modeRadios) {
    if (radio.checked) {
      const val = radio.value;
      if (val === "per-site" || val === "all-sites" || val === "off") {
        monitoringMode = val;
      }
      break;
    }
  }
  const severityFilter = [];
  for (const cb of severityCheckboxes) {
    if (cb.checked) {
      const val = cb.value;
      if (ALL_SEVERITIES.includes(val)) {
        severityFilter.push(val);
      }
    }
  }
  const retainHistoryDays = Math.max(0, Math.min(365, parseInt(retainDaysInput.value, 10) || 0));
  return {
    monitoringMode,
    allowedOrigins: [...workingOrigins],
    severityFilter,
    retainHistoryDays
  };
}
function renderAllowlist() {
  while (allowlistEl.firstChild) {
    allowlistEl.removeChild(allowlistEl.firstChild);
  }
  if (workingOrigins.length === 0) {
    allowlistEmptyMsg.hidden = false;
    return;
  }
  allowlistEmptyMsg.hidden = true;
  for (const origin of workingOrigins) {
    allowlistEl.appendChild(buildAllowlistItem(origin));
  }
}
function buildAllowlistItem(origin) {
  const li = document.createElement("li");
  li.className = "allowlist-item";
  const originSpan = document.createElement("span");
  originSpan.className = "allowlist-origin";
  originSpan.textContent = origin;
  originSpan.title = origin;
  const removeBtn = document.createElement("button");
  removeBtn.type = "button";
  removeBtn.className = "btn-remove";
  removeBtn.textContent = "Remove";
  removeBtn.addEventListener("click", () => {
    removeOrigin(origin);
  });
  li.appendChild(originSpan);
  li.appendChild(removeBtn);
  return li;
}
function removeOrigin(origin) {
  workingOrigins = workingOrigins.filter((o) => o !== origin);
  renderAllowlist();
}
function wireModeRadios() {
  for (const radio of modeRadios) {
    radio.addEventListener("change", () => {
      if (radio.checked) {
        updateAllowlistVisibility(radio.value);
      }
    });
  }
}
function updateAllowlistVisibility(mode) {
  const visible = mode === "per-site";
  if (visible) {
    sectionAllowlist.removeAttribute("hidden");
  } else {
    sectionAllowlist.setAttribute("hidden", "");
  }
}
function setStatus(msg, isError) {
  saveStatus.textContent = msg;
  if (isError) {
    saveStatus.classList.add("error");
  } else {
    saveStatus.classList.remove("error");
  }
}
function clearStatus() {
  saveStatus.textContent = "";
  saveStatus.classList.remove("error");
}
function getEl(id) {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing required element #${id}`);
  return el;
}
//# sourceMappingURL=options.html-CS3VcGqf.js.map
