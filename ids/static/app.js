const alertChartCtx = document.getElementById("alertChart");
const trafficChartCtx = document.getElementById("trafficChart");
const topSourcesChartCtx = document.getElementById("topSourcesChart");
const topPortsChartCtx = document.getElementById("topPortsChart");
const alertsBody = document.getElementById("alertsBody");
const domainsBody = document.getElementById("domainsBody");
const activeAttacks = document.getElementById("activeAttacks");
const tlsSources = document.getElementById("tlsSources");
const interceptionStatus = document.getElementById("interceptionStatus");
const httpsToggle = document.getElementById("httpsToggle");

let currentProtocolFilter = "ALL";
let currentSort = { key: "timestamp", direction: "desc" };
let lastAlertTimestamp = null;

const alertChart = new Chart(alertChartCtx, {
  type: "doughnut",
  data: {
    labels: [],
    datasets: [
      {
        data: [],
        backgroundColor: ["#38bdf8", "#f97316", "#ef4444", "#22c55e"],
      },
    ],
  },
  options: {
    animation: {
      duration: 600,
    },
    plugins: {
      legend: {
        position: "bottom",
      },
    },
  },
});

const trafficChart = new Chart(trafficChartCtx, {
  type: "line",
  data: {
    labels: [],
    datasets: [],
  },
  options: {
    responsive: true,
    animation: {
      duration: 600,
    },
    plugins: {
      legend: {
        position: "bottom",
      },
    },
    scales: {
      y: {
        ticks: {
          callback: (value) => `${value} pkt`,
        },
      },
    },
  },
});

const topSourcesChart = new Chart(topSourcesChartCtx, {
  type: "bar",
  data: {
    labels: [],
    datasets: [
      {
        label: "Packets",
        data: [],
        backgroundColor: "#38bdf8",
      },
    ],
  },
  options: {
    plugins: {
      legend: {
        display: false,
      },
    },
  },
});

const topPortsChart = new Chart(topPortsChartCtx, {
  type: "bar",
  data: {
    labels: [],
    datasets: [
      {
        label: "Hits",
        data: [],
        backgroundColor: "#f97316",
      },
    ],
  },
  options: {
    plugins: {
      legend: {
        display: false,
      },
    },
  },
});

const protocolColors = {
  TCP: "#38bdf8",
  UDP: "#f97316",
  ICMP: "#ef4444",
  DNS: "#22c55e",
  HTTP: "#a855f7",
  HTTPS: "#0ea5e9",
  IP: "#94a3b8",
};

function renderAlerts(alerts) {
  const filtered =
    currentProtocolFilter === "ALL"
      ? alerts
      : alerts.filter((alert) => alert.protocol === currentProtocolFilter);

  const sorted = [...filtered].sort((a, b) => {
    const direction = currentSort.direction === "asc" ? 1 : -1;
    if (a[currentSort.key] < b[currentSort.key]) return -1 * direction;
    if (a[currentSort.key] > b[currentSort.key]) return 1 * direction;
    return 0;
  });

  const newest = sorted[0];
  if (newest && newest.timestamp !== lastAlertTimestamp) {
    alertsBody.classList.add("flash");
    setTimeout(() => alertsBody.classList.remove("flash"), 1000);
    lastAlertTimestamp = newest.timestamp;
  }

  alertsBody.innerHTML = "";
  sorted.forEach((alert) => {
    const row = document.createElement("div");
    row.className = `table-row table-body-row expandable ${
      alert.severity === "Critical" ? "critical" : ""
    }`;
    row.innerHTML = `
      <span>${new Date(alert.timestamp).toLocaleTimeString()}</span>
      <span>${alert.src_ip}</span>
      <span>${alert.dst_ip}</span>
      <span>${alert.protocol}</span>
      <span>${alert.alert_type}</span>
      <span><span class="badge ${alert.severity}">${alert.severity}</span></span>
      <span>${alert.category}</span>
      <span>${alert.dst_port ?? "-"}</span>
    `;
    row.addEventListener("click", () => {
      const details = row.nextSibling;
      if (details && details.classList.contains("expand-details")) {
        details.remove();
      } else {
        const detailsRow = document.createElement("div");
        detailsRow.className = "expand-details";
        detailsRow.textContent = alert.details;
        row.after(detailsRow);
      }
    });
    alertsBody.appendChild(row);
  });
}

function updateAlertChart(alertCounts) {
  const labels = Object.keys(alertCounts || {});
  alertChart.data.labels = labels;
  alertChart.data.datasets[0].data = labels.map((label) => alertCounts[label]);
  alertChart.update();
}

function updateTrafficChart(packetsPerMinute) {
  const labels = packetsPerMinute.map((item) => item.minute);
  const protocols = new Set();
  packetsPerMinute.forEach((item) => {
    Object.keys(item.protocols).forEach((protocol) => protocols.add(protocol));
  });

  const datasets = Array.from(protocols).map((protocol) => {
    return {
      label: protocol,
      data: packetsPerMinute.map((item) => item.protocols[protocol] || 0),
      borderColor: protocolColors[protocol] || "#94a3b8",
      backgroundColor: "transparent",
      tension: 0.3,
    };
  });

  trafficChart.data.labels = labels;
  trafficChart.data.datasets = datasets;
  trafficChart.update();
}

function updateTopSources(topSourcesData) {
  topSourcesChart.data.labels = topSourcesData.map((item) => item.ip);
  topSourcesChart.data.datasets[0].data = topSourcesData.map(
    (item) => item.count
  );
  topSourcesChart.update();
}

function updateTopPorts(topPortsData) {
  topPortsChart.data.labels = topPortsData.map((item) => item.port);
  topPortsChart.data.datasets[0].data = topPortsData.map(
    (item) => item.count
  );
  topPortsChart.update();
}

function renderDomains(domains) {
  domainsBody.innerHTML = "";
  domains.forEach((domain) => {
    const row = document.createElement("div");
    row.className = "table-row table-body-row";
    row.innerHTML = `
      <span>${new Date(domain.timestamp).toLocaleTimeString()}</span>
      <span>${domain.domain}</span>
      <span>${domain.source_ip}</span>
      <span>${domain.protocol}</span>
    `;
    domainsBody.appendChild(row);
  });
}

function renderActiveAttacks(alerts) {
  activeAttacks.innerHTML = "";
  alerts.slice(0, 5).forEach((alert) => {
    const item = document.createElement("li");
    item.innerHTML = `
      <strong>${alert.alert_type}</strong>
      <span class="muted">${alert.src_ip} → ${alert.dst_ip}</span>
    `;
    activeAttacks.appendChild(item);
  });
}

function renderTlsSources(sources) {
  tlsSources.innerHTML = "";
  sources.forEach((source) => {
    const item = document.createElement("li");
    item.textContent = `${source.ip} (${source.count})`;
    tlsSources.appendChild(item);
  });
}

function updateInterceptionStatus(status) {
  interceptionStatus.textContent = status.details;
  if (status.enabled) {
    httpsToggle.classList.add("enabled");
    httpsToggle.textContent = status.mode === "lab" ? "Lab Mode" : "Enabled";
  } else {
    httpsToggle.classList.remove("enabled");
    httpsToggle.textContent = "Disabled";
  }
}

async function refreshData() {
  const [alertsResponse, statsResponse, domainsResponse] = await Promise.all([
    fetch("/api/alerts"),
    fetch("/api/stats"),
    fetch("/api/domains"),
  ]);
  const alerts = await alertsResponse.json();
  const stats = await statsResponse.json();
  const domains = await domainsResponse.json();

  renderAlerts(alerts);
  renderActiveAttacks(alerts);
  updateAlertChart(stats.alert_counts || {});
  updateTrafficChart(stats.packets_per_minute || []);
  updateTopSources(stats.top_sources || []);
  updateTopPorts(stats.top_ports || []);
  renderDomains(domains);
  renderTlsSources(stats.tls_sources || []);
  updateInterceptionStatus(stats.interception || { enabled: false, mode: "passive" });
}

function bindFilters() {
  document.querySelectorAll(".filter").forEach((button) => {
    button.addEventListener("click", () => {
      document
        .querySelectorAll(".filter")
        .forEach((el) => el.classList.remove("active"));
      button.classList.add("active");
      currentProtocolFilter = button.dataset.protocol;
      refreshData();
    });
  });
  const defaultButton = document.querySelector('.filter[data-protocol="ALL"]');
  if (defaultButton) {
    defaultButton.classList.add("active");
  }
}

function bindSorting() {
  document.querySelectorAll(".table-header span").forEach((header) => {
    header.addEventListener("click", () => {
      const key = header.dataset.sort;
      if (!key) return;
      if (currentSort.key === key) {
        currentSort.direction = currentSort.direction === "asc" ? "desc" : "asc";
      } else {
        currentSort = { key, direction: "desc" };
      }
      refreshData();
    });
  });
}

httpsToggle.addEventListener("click", async () => {
  const enabled = !httpsToggle.classList.contains("enabled");
  const mode = enabled ? "lab" : "passive";
  const response = await fetch("/api/interception", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled, mode }),
  });
  const status = await response.json();
  updateInterceptionStatus(status);
});

bindFilters();
bindSorting();
refreshData();
setInterval(refreshData, 2000);
