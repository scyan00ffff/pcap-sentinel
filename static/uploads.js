document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('pcap-upload').addEventListener('change', function() {
        if (this.files.length > 0) {
            const formData = new FormData();
            formData.append('file', this.files[0]);

            fetch('/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.href = '/processing';
                }
            });
        }
    });

    document.getElementById('rescan-btn').addEventListener('click', function() {
        fetch('/rescan', {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.href = '/processing';
            }
        });
    });

    function poll() {
        console.log('[DEBUG] Polling...');
        fetch('/progress')
        .then(response => response.json())
        .then(data => {
            console.log('[DEBUG] Progress data:', data);
            if (data.status === 'complete') {
                window.location.href = '/';
            } else if (data.status === 'running') {
                const percent = (data.completed / data.total) * 100;
                document.getElementById('progress-bar').style.width = percent + '%';
                document.getElementById('progress-label').textContent = 'Running ' + data.current_detector + '...';
                document.getElementById('progress-fraction').textContent = data.completed + ' of ' + data.total + ' scanners complete';
                setTimeout(poll, 100);
            } else {
                setTimeout(poll, 100);
            }
        });
    }

    if (document.getElementById('progress-bar')) {
        poll();
    }


        if (document.getElementById('progress-bar')) {
            poll();
        }

    const darkModeToggle = document.getElementById('dark-mode-toggle');

    if (localStorage.getItem('darkMode') === 'enabled') {
        document.body.classList.add('dark');
        darkModeToggle.textContent = '☀️ Light Mode';
    }

    darkModeToggle.addEventListener('click', function() {
        document.body.classList.toggle('dark');
        if (document.body.classList.contains('dark')) {
            localStorage.setItem('darkMode', 'enabled');
            darkModeToggle.textContent = '☀️ Light Mode';
        } else {
            localStorage.setItem('darkMode', 'disabled');
            darkModeToggle.textContent = '🌙 Dark Mode';
        }
    });
    
});

