document.addEventListener('DOMContentLoaded', function() {
    const severityCtx = document.getElementById('severityChart').getContext('2d');
    new Chart(severityCtx, {
        type: 'doughnut',
        data: {
            labels: ['HIGH', 'MEDIUM', 'LOW'],
            datasets: [{
                data: [high, medium, low],
                backgroundColor: ['#a00817','rgb(201, 111, 9)', 'rgb(1, 94, 1)']
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });

    const barColours = portNums.map(port => {
        if (highRiskPortNums.includes(port)) return '#a00817';
        if (mediumRiskPortNums.includes(port)) return 'rgb(201, 111, 9)';
        return 'rgb(1, 94, 1)'
    });

    const portsCtx = document.getElementById('portsChart').getContext('2d');
    new Chart(portsCtx, {
        type: 'bar',
        data: {
            labels: portLabels,
            datasets: [{
                label: 'Hits',
                data: portCounts,
                backgroundColor: barColours
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                }
            }
        }
    });
});


