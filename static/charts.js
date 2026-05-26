const chartDefaults = {
    color: 'oklch(0.62 0.012 250)',
    borderColor: 'oklch(0.30 0.012 250)',
    backgroundColor: 'transparent'
};

Chart.defaults.color = chartDefaults.color;
Chart.defaults.borderColor = chartDefaults.borderColor;

document.addEventListener('DOMContentLoaded', function() {
    const severityCanvas = document.getElementById('severityChart');
    if (severityCanvas) {
        const severityCtx = severityCanvas.getContext('2d');
        new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: ['HIGH', 'MEDIUM', 'LOW'],
                datasets: [{
                    data: [high, medium, low],
                    backgroundColor: ['#a00817','rgb(201, 111, 9)', 'rgb(1, 94, 1)'],
                    borderWidth: 0
                }]
            },
            options: {
                animation: {
                    duration: 800,
                    easing: 'easeInOutQuart'
                },
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: 'oklch(0.62 0.012 250)'
                        }
                    }
                }
            }
        });
    }

    const portsCanvas = document.getElementById('portsChart');
    if (portsCanvas) {
        const barColours = portNums.map(port => {
            if (highRiskPortNums.includes(port)) return '#a00817';
            if (mediumRiskPortNums.includes(port)) return 'rgb(201, 111, 9)';
            return 'rgb(1, 94, 1)';
        });

        const portsCtx = portsCanvas.getContext('2d');
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
                animation: {
                    duration: 800,
                    easing: 'easeInOutQuart'
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        grid: {
                            color: 'oklch(0.25 0.010 250)'
                        },
                        ticks: {
                            color: 'oklch(0.62 0.012 250)'
                        }
                    },
                    y: {
                        grid: {
                            color: 'oklch(0.25 0.010 250)'
                        },
                        ticks: {
                            color: 'oklch(0.62 0.012 250)'
                        }
                    }
                }
            }
        });
    }

    const ipsCanvas = document.getElementById('ipsChart');
    if (ipsCanvas) {
        const ipsCtx = ipsCanvas.getContext('2d');
        new Chart(ipsCtx, {
            type: 'bar',
            data: {
                labels: ipLabels,
                datasets: [{
                    label: 'Ports Probed',
                    data: ipCounts,
                    backgroundColor: 'oklch(0.78 0.13 220)'
                }]
            },
            options: {
                animation: {
                    duration: 800,
                    easing: 'easeInOutQuart'
                },
                indexAxis: 'y',
                responsive: true,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        grid:  { color: 'oklch(0.25 0.010 250)' },
                        ticks: { color: 'oklch(0.62 0.012 250)' }
                    },
                    y: {
                        grid: { color: 'oklch(0.25 0.010 250)' },
                        ticks: { color: 'oklch(0.62 0.012 250)', font: { family: 'Geist Mono' } }
                    }
                }

            }
        });
    }

    const scannerCanvas = document.getElementById('scannerChart');
    if (scannerCanvas) {
        const scannerCtx = scannerCanvas.getContext('2d');
        new Chart(scannerCtx, {
            type: 'doughnut',
            data: {
                labels: scannerLabels,
                datasets: [{
                    data: scannerData,
                    backgroundColor: ['oklch(0.78 0.13 220)', '#a00817', 'oklch(0.78 0.18 70)', 'oklch(0.72 0.14 145)'],
                    borderWidth: 0

                }]
            },
            options: {
                animation: {
                    duration: 800,
                    easing: 'easeInOutQuart'
                },
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: 'oklch(0.62 0.012 250)'
                        }
                    }
                }
            }
        });
    }

    const threatCanvas = document.getElementById('threatChart');
    if (threatCanvas) {
        const threatCtx = threatCanvas.getContext('2d');
        new Chart(threatCtx, {
            type: 'bar',
            data: {
                labels: threatLabels,
                datasets: [{
                    label: 'Threat Score',
                    data: threatScores,
                    backgroundColor: threatColours
                }]
            },
            options: {
                animation: {
                    duration: 800,
                    easing: 'easeInOutQuart'
                },
                indexAxis: 'y',
                responsive: true,
                plugins: {
                    legend: { display: false}
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        max: 100,
                        grid: { color: 'oklch(0.25 0.010 250)' },
                        ticks: { color: 'oklch(0.62 0.012 250)' }
                    },
                    y: {
                        grid: { color: 'oklch(0.25 0.010 250)' },
                        ticks: { color: 'oklch(0.62 0.012 250)', font: { family: 'Geist Mono' } }
                    }
                }
            }
        });
    }
});