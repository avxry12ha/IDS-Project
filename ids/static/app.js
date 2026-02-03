const alertChartCtx = document.getElementById("alertChart");
const trafficChartCtx = document.getElementById("trafficChart");
const alertsBody = document.getElementById("alertsBody");

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
    plugins: {
      legend: {
        position: "bottom",
      },
    },
    scales: {
      y: {
        ticks: {
          callback: (value) => `${value} bytes`,
        },
      },
    },
  },
});

const protocolColors = {
  TCP: "#38bdf8",
  UDP: "#f97316",
  ICMP: "#ef4444",
  IP: "#22c55e",
};

function renderAlerts(alerts) {
  alertsBody.innerHTML = "";
  alerts.forEach((alert) => {
    const row = document.createElement("div");
    row.className = "table-row table-body-row";
    row.innerHTML = `
      <span>${new Date(alert.timestamp).toLocaleTimeString()}</span>
      <span>${alert.src_ip}</span>
      <span>${alert.dst_ip}</span>
      <span>${alert.alert_type}</span>
      <span class="severity-${alert.severity}">${alert.severity}</span>
      <span>${alert.details}</span>
    `;
    alertsBody.appendChild(row);
  });
}

function updateAlertChart(alertCounts) {
  alertChart.data.labels = alertCounts.map((item) => item.alert_type);
  alertChart.data.datasets[0].data = alertCounts.map((item) => item.count);
  alertChart.update();
}

function updateTrafficChart(trafficSummary) {
  const labels = [...new Set(trafficSummary.map((item) => item.bucket))];
  const protocols = [...new Set(trafficSummary.map((item) => item.protocol))];
  const datasets = protocols.map((protocol) => {
    const data = labels.map((label) => {
      const match = trafficSummary.find(
        (item) => item.bucket === label && item.protocol === protocol
      );
      return match ? match.bytes : 0;
    });
    return {
      label: protocol,
      data,
      borderColor: protocolColors[protocol] || "#94a3b8",
      backgroundColor: "transparent",
      tension: 0.3,
    };
  });

  trafficChart.data.labels = labels;
  trafficChart.data.datasets = datasets;
  trafficChart.update();
}

async function refreshData() {
  const [alertsResponse, summaryResponse] = await Promise.all([
    fetch("/api/alerts"),
    fetch("/api/summary"),
  ]);
  const alerts = await alertsResponse.json();
  const summary = await summaryResponse.json();
  renderAlerts(alerts);
  updateAlertChart(summary.alert_counts || []);
  updateTrafficChart(summary.traffic_summary || []);
}

refreshData();
setInterval(refreshData, 5000);
