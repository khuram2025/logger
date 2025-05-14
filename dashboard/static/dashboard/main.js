document.addEventListener('DOMContentLoaded', function () {
    // Sidebar Accordion
    const collapsibleHeaders = document.querySelectorAll('.collapsible-header');
    collapsibleHeaders.forEach(header => {
        header.addEventListener('click', function () {
            const contentId = this.dataset.target;
            const content = document.getElementById(contentId);
            const icon = this.querySelector('i');
            content.classList.toggle('open');
            if (content.classList.contains('open')) {
                icon.classList.remove('fa-plus');
                icon.classList.add('fa-minus');
            } else {
                icon.classList.remove('fa-minus');
                icon.classList.add('fa-plus');
            }
        });
    });
    // Initialize open sections
    document.querySelectorAll('.collapsible-content.open').forEach(openContent => {
        const header = document.querySelector(`.collapsible-header[data-target="${openContent.id}"]`);
        if (header) {
            const icon = header.querySelector('i');
            icon.classList.remove('fa-plus');
            icon.classList.add('fa-minus');
        }
    });

    // Sample Log Data
    const logData = [
        { ts: "08/20 10:06:21 AM", waf: "FLAGGED", ip: "10.114.223.70", uri: "/", req: "GET", res: "200", len: "214 B", dur: 67, tl: "|||" },
        { ts: "08/20 10:05:04 AM", waf: "PASSED", ip: "10.114.223.70", uri: "/", req: "GET", res: "200", len: "214 B", dur: 69, tl: "|||" },
        { ts: "08/20 10:04:51 AM", waf: "PASSED", ip: "10.114.223.70", uri: "/", req: "GET", res: "200", len: "214 B", dur: 68, tl: "|||" },
        { ts: "08/20 10:03:54 AM", waf: "PASSED", ip: "10.114.223.70", uri: "/", req: "GET", res: "200", len: "214 B", dur: 52, tl: "|||" },
        { ts: "08/20 10:03:52 AM", waf: "PASSED", ip: "10.114.223.70", uri: "/", req: "GET", res: "200", len: "214 B", dur: 50, tl: "|||" },
        { ts: "08/20 10:03:51 AM", waf: "PASSED", ip: "10.114.223.70", uri: "/", req: "GET", res: "200", len: "214 B", dur: 50, tl: "|||" },
        { ts: "08/20 10:03:46 AM", waf: "PASSED", ip: "10.114.223.70", uri: "/", req: "GET", res: "200", len: "214 B", dur: 53, tl: "|||" },
        { ts: "08/20 10:03:38 AM", waf: "PASSED", ip: "10.114.223.70", uri: "/", req: "GET", res: "200", len: "214 B", dur: 51, tl: "|||" },
        { ts: "08/20 9:38:35 AM", waf: "FLAGGED", ip: "10.114.223.70", uri: "/", req: "GET", res: "200", len: "214 B", dur: 52, tl: "|||" },
        { ts: "08/20 9:38:29 AM", waf: "FLAGGED", ip: "10.114.223.70", uri: "/", req: "GET", res: "200", len: "214 B", dur: 68, tl: "|||" },
        { ts: "08/20 9:38:04 AM", waf: "FLAGGED", ip: "10.114.223.70", uri: "/", req: "GET", res: "200", len: "214 B", dur: 69, tl: "|||" },
    ];

    const logsTableBody = document.getElementById('logsTableBody');
    const maxDuration = Math.max(...logData.map(log => log.dur), 100); // Ensure maxDuration is at least 100 for percentage calculation

    logData.forEach((log, index) => {
        const row = logsTableBody.insertRow();
        row.innerHTML = `
            <td>${log.ts}</td>
            <td><span class="status-label ${log.waf === 'FLAGGED' ? 'status-flagged' : 'status-passed'}">${log.waf}</span></td>
            <td>${log.ip}</td>
            <td>${log.uri}</td>
            <td>${log.req}</td>
            <td>${log.res}</td>
            <td>${log.len}</td>
            <td>
                <div class="duration-cell">
                    <span>${log.dur}ms</span>
                    <div class="duration-bar" style="width: ${Math.max(10, (log.dur / maxDuration) * 80)}%;"></div>
                </div>
            </td>
            <td>${log.tl}</td>
            <td><button class="expand-log-button" data-log-index="${index}"><i class="fas fa-plus"></i></button></td>
        `;
    });

    // Log Row Expansion
    logsTableBody.addEventListener('click', function(event) {
        const target = event.target.closest('.expand-log-button');
        if (target) {
            const logIndex = parseInt(target.dataset.logIndex);
            const log = logData[logIndex];
            const icon = target.querySelector('i');
            const currentRow = target.closest('tr');
            
            const existingDetailRow = currentRow.nextElementSibling;
            if (existingDetailRow && existingDetailRow.classList.contains('expanded-log-details')) {
                existingDetailRow.remove();
                icon.classList.remove('fa-minus');
                icon.classList.add('fa-plus');
            } else {
                const detailRow = logsTableBody.insertRow(currentRow.rowIndex);
                detailRow.classList.add('expanded-log-details');
                const cell = detailRow.insertCell();
                cell.colSpan = 10; // Span all columns
                cell.innerHTML = `<pre>${JSON.stringify(log, null, 2)}</pre><p><em>Detailed log view (like in input_file_2.jpeg) would be structured here.</em></p>`;
                icon.classList.remove('fa-plus');
                icon.classList.add('fa-minus');
            }
        }
    });

    // Chart.js Configuration
    const ctx = document.getElementById('logsChart').getContext('2d');
    const logsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Wed 14', '', 'Thu 15', '', 'Fri 16', '', 'Sat 17', '', 'Aug 18', '', 'Mon 19', '', 'Tue 20'],
            datasets: [{
                label: 'Non-Significant Logs',
                data: [100, 150, 120, 180, 200, 220, 300, 250, 4000, 4200, 1000, 800, 2000],
                backgroundColor: '#4CAF50', // Green
                barPercentage: 0.7,
                categoryPercentage: 0.7
            }, {
                label: 'Significant Logs',
                data: [20, 30, 25, 35, 40, 45, 600, 50, 2000, 2100, 500, 400, 1000],
                backgroundColor: '#FF9800', // Orange
                barPercentage: 0.7,
                categoryPercentage: 0.7
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                x: {
                    stacked: true,
                    grid: {
                        display: false
                    },
                    ticks: {
                        font: { size: 10 }
                    }
                },
                y: {
                    stacked: true,
                    beginAtZero: true,
                    grid: {
                        color: '#e9ecef'
                    },
                    ticks: {
                        font: { size: 10 },
                        callback: function(value) {
                            if (value >= 1000) return (value/1000) + 'k';
                            return value;
                        }
                    }
                }
            },
            plugins: {
                legend: {
                    display: false // Custom legend is below chart
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            }
        }
    });

    // Modal Handling
    const wafRulesLink = document.getElementById('wafRulesLink');
    const modal = document.getElementById('wafRulesModal');
    const closeModalButtons = document.querySelectorAll('.close-modal-button');

    wafRulesLink.addEventListener('click', function(e) {
        e.preventDefault();
        modal.style.display = 'block';
    });

    closeModalButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            modal.style.display = 'none';
        });
    });

    window.onclick = function(event) {
        if (event.target == modal) {
            modal.style.display = 'none';
        }
    };
});
