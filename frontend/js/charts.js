/**
 * Chart.js Visualizations for Aegis AI-NIDS SOC Dashboard
 */

let trafficTimelineChart = null;
let threatTypesChart = null;
let mitreRadarChart = null;

const chartColors = {
  cyan: '#06b6d4',
  cyanFill: 'rgba(6, 182, 212, 0.15)',
  rose: '#f43f5e',
  roseFill: 'rgba(244, 63, 94, 0.2)',
  amber: '#f59e0b',
  purple: '#a855f7',
  indigo: '#6366f1',
  emerald: '#10b981',
  slate: '#475569'
};

function initCharts() {
  // 1. Traffic Timeline Chart
  const ctxTimeline = document.getElementById('trafficTimelineChart').getContext('2d');
  
  const initialLabels = Array.from({ length: 14 }, (_, i) => `${i * 2}s ago`).reverse();
  const initialBenign = [12, 18, 15, 22, 19, 28, 24, 30, 26, 32, 29, 35, 31, 38];
  const initialAttacks = [0, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 2, 0, 1];

  trafficTimelineChart = new Chart(ctxTimeline, {
    type: 'line',
    data: {
      labels: initialLabels,
      datasets: [
        {
          label: 'Benign Flows',
          data: initialBenign,
          borderColor: chartColors.cyan,
          backgroundColor: chartColors.cyanFill,
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 2,
          pointHoverRadius: 5
        },
        {
          label: 'Attacks Intercepted',
          data: initialAttacks,
          borderColor: chartColors.rose,
          backgroundColor: chartColors.roseFill,
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: chartColors.rose,
          pointHoverRadius: 6
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        mode: 'index',
        intersect: false
      },
      plugins: {
        legend: {
          position: 'top',
          labels: {
            color: '#94a3b8',
            font: { family: 'JetBrains Mono', size: 11 },
            boxWidth: 12
          }
        },
        tooltip: {
          backgroundColor: '#0f172a',
          borderColor: '#334155',
          borderWidth: 1,
          titleFont: { family: 'JetBrains Mono' },
          bodyFont: { family: 'JetBrains Mono' }
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(51, 65, 85, 0.25)' },
          ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
        },
        y: {
          grid: { color: 'rgba(51, 65, 85, 0.25)' },
          ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } },
          beginAtZero: true
        }
      }
    }
  });

  // 2. Threat Vector Donut Chart
  const ctxDonut = document.getElementById('threatTypesChart').getContext('2d');
  threatTypesChart = new Chart(ctxDonut, {
    type: 'doughnut',
    data: {
      labels: ['DDoS Flood', 'Port Scan', 'Brute Force', 'Web Exploit', 'C2 Beacon', 'Exfiltration'],
      datasets: [{
        data: [4, 3, 2, 3, 1, 1],
        backgroundColor: [
          '#f43f5e', // DDoS (Rose)
          '#f59e0b', // Port Scan (Amber)
          '#fb923c', // Brute Force (Orange)
          '#dc2626', // Web (Red)
          '#a855f7', // C2 (Purple)
          '#ec4899'  // Exfil (Pink)
        ],
        borderWidth: 1,
        borderColor: '#0f172a'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#94a3b8',
            font: { family: 'JetBrains Mono', size: 10 },
            boxWidth: 10,
            padding: 8
          }
        }
      },
      cutout: '72%'
    }
  });

  // 3. MITRE ATT&CK Matrix Radar Chart
  const ctxRadar = document.getElementById('mitreRadarChart').getContext('2d');
  mitreRadarChart = new Chart(ctxRadar, {
    type: 'radar',
    data: {
      labels: ['Discovery', 'Impact (DoS)', 'Initial Access', 'Execution', 'Command & Control', 'Exfiltration', 'Credential Access'],
      datasets: [{
        label: 'Threat Intensity',
        data: [8, 9, 6, 7, 5, 4, 7],
        borderColor: '#06b6d4',
        backgroundColor: 'rgba(6, 182, 212, 0.25)',
        borderWidth: 2,
        pointBackgroundColor: '#06b6d4',
        pointRadius: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        r: {
          angleLines: { color: 'rgba(51, 65, 85, 0.4)' },
          grid: { color: 'rgba(51, 65, 85, 0.3)' },
          pointLabels: {
            color: '#94a3b8',
            font: { family: 'JetBrains Mono', size: 9 }
          },
          ticks: { display: false, beginAtZero: true, max: 10 }
        }
      }
    }
  });
}

function updateTimelineChart(isThreat) {
  if (!trafficTimelineChart) return;

  const benignData = trafficTimelineChart.data.datasets[0].data;
  const attackData = trafficTimelineChart.data.datasets[1].data;

  // Shift and push
  benignData.shift();
  attackData.shift();

  if (isThreat) {
    attackData.push((attackData[attackData.length - 1] || 0) + 1);
    benignData.push(benignData[benignData.length - 1] || 15);
  } else {
    attackData.push(Math.max(0, (attackData[attackData.length - 1] || 1) - 1));
    benignData.push(Math.floor(Math.random() * 15) + 20);
  }

  trafficTimelineChart.update('none');
}

function updateThreatTypesChart(attacksByType) {
  if (!threatTypesChart || !attacksByType) return;

  const labels = Object.keys(attacksByType);
  const data = Object.values(attacksByType);

  if (labels.length > 0) {
    threatTypesChart.data.labels = labels;
    threatTypesChart.data.datasets[0].data = data;
    threatTypesChart.update();
  }
}
