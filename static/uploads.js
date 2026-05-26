document.addEventListener('DOMContentLoaded', function() {

    // check if this is a new server session
    fetch('/session')
    .then(response => response.json())
    .then(data => {
        const storedSession = localStorage.getItem('sessionId');
        if (storedSession !== data.session_id) {
            localStorage.removeItem('captureFile');
            localStorage.removeItem('statusText');
            localStorage.removeItem('statusState');
            localStorage.setItem('sessionId', data.session_id);
        } else {
            const savedFile = localStorage.getItem('captureFile');
            if (savedFile) updateCaptureChip(savedFile);
            const savedStatus = localStorage.getItem('statusText');
            const savedState = localStorage.getItem('statusState');
            if (savedStatus) updateStatus(savedStatus, savedState);
        }
    });

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
                    const filename = document.getElementById('pcap-upload').files[0].name;
                    updateCaptureChip(filename);
                    updateStatus('analysing...', 'analysing');
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
                updateStatus('analysing...', 'analysing');
                window.location.href = '/processing';
            }
        });
    });

    function poll() {
        fetch('/progress')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'complete') {
                updateStatus('scan complete', 'complete');
                setTimeout(() => { window.location.href = '/'; }, 500);
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

    function updateCaptureChip(filename) {
        const chip = document.getElementById('capture-chip');
        if (chip && filename) {
            chip.innerHTML = `<span style="color:var(--fg-4)">capture</span> <b>${filename}</b>`;
            localStorage.setItem('captureFile', filename);
        }
    }

    function updateStatus(state, type) {
        const dot = document.querySelector('.tb-status-dot');
        const statusText = document.getElementById('status-text');
        if (dot) {
            dot.className = 'tb-status-dot';
            if (type === 'complete') dot.classList.add('complete');
            if (type === 'analysing') dot.classList.add('analysing');
        }
        if (statusText) statusText.textContent = state;
        localStorage.setItem('statusText', state);
        localStorage.setItem('statusState', type || '');
    }

});