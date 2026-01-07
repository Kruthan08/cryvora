// Particle animation for background
function createParticles() {
    const particlesContainer = document.getElementById('particles');
    for (let i = 0; i < 50; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 10 + 's';
        particle.style.width = particle.style.height = Math.random() * 10 + 5 + 'px';
        particlesContainer.appendChild(particle);
    }
}
createParticles();

// Request notification 
if ('Notification' in window) {
    Notification.requestPermission();
}

const theme = localStorage.getItem('cryvoraTheme') || 'light';
if (theme === 'dark') {
    document.body.classList.add('bg-dark', 'text-light');
}

// Navigation
document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.section').forEach(sec => sec.classList.remove('active'));
        document.getElementById(btn.dataset.section).classList.add('active');
    });
});

// Load data
function loadData() {
    const history = JSON.parse(localStorage.getItem('cryvoraHistory') || '[]');
    const reports = JSON.parse(localStorage.getItem('cryvoraReports') || '[]');

    document.getElementById('totalScans').textContent = history.length;
    document.getElementById('recentAlerts').textContent = history.filter(h => h.risk === 'Malicious').length > 0 ? 'Yes' : 'None';
    document.getElementById('lastScan').textContent = history.length > 0 ? new Date(history[0].timestamp).toLocaleString() : 'None';

    const historyList = document.getElementById('historyList');
    historyList.innerHTML = '';
    history.forEach(item => {
        const li = document.createElement('li');
        li.className = 'list-group-item';
        li.textContent = `${item.type}: ${item.input} - ${item.risk} (${new Date(item.timestamp).toLocaleString()})`;
        historyList.appendChild(li);
    });

    const reportsList = document.getElementById('reportsList');
    reportsList.innerHTML = '';
    reports.forEach(item => {
        const li = document.createElement('li');
        li.className = 'list-group-item';
        li.textContent = `${item.report} (${new Date(item.timestamp).toLocaleString()})`;
        reportsList.appendChild(li);
    });
}
loadData();

document.getElementById('themeToggle').addEventListener('click', () => {
    document.body.classList.toggle('bg-dark');
    document.body.classList.toggle('text-light');
    const currentTheme = document.body.classList.contains('bg-dark') ? 'dark' : 'light';
    localStorage.setItem('cryvoraTheme', currentTheme);
});

// Clear data
document.getElementById('clearDataBtn').addEventListener('click', () => {
    if (confirm('Clear all data?')) {
        localStorage.removeItem('cryvoraHistory');
        localStorage.removeItem('cryvoraReports');
        loadData();
        alert('Data cleared!');
    }
});

// Input validation
function validateUrl(url) {
    const urlRegex = /^https?:\/\/[^\s/$.?#].[^\s]*$/i;
    return urlRegex.test(url);
}

// Global progress bar
function updateProgress(percent) {
    const progressBar = document.getElementById('globalProgressBar');
    const progress = document.getElementById('globalProgress');
    progress.style.display = 'block';
    progressBar.style.width = `${percent}%`;
    if (percent === 100) {
        setTimeout(() => progress.style.display = 'none', 1000);
    }
}

// Analyze URL
document.getElementById('checkBtn').addEventListener('click', async () => {
    const url = document.getElementById('urlInput').value.trim();
    if (!validateUrl(url)) return alert('Please enter a valid URL starting with http:// or https://');

    document.getElementById('urlSpinner').style.display = 'inline-block';
    updateProgress(20);
    try {
        const response = await fetch('http://localhost:3000/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        updateProgress(60);
        const result = await response.json();

        document.getElementById('result').innerHTML = `<p><strong>Risk:</strong> ${result.risk}</p><p><strong>Details:</strong> ${result.details}</p>`;
        document.getElementById('result').style.display = 'block';

        let threatPercent = result.confidence || 0;
        document.getElementById('threatGauge').style.width = `${threatPercent}%`;
        document.getElementById('threatGauge').className = `progress-bar ${threatPercent < 30 ? 'bg-success' : threatPercent < 70 ? 'bg-warning' : 'bg-danger'}`;
        document.getElementById('confidence').textContent = `Confidence: ${threatPercent}%`;

        if (result.risk === 'Malicious' && Notification.permission === 'granted') {
            new Notification('Cryvora Alert', { body: 'High-risk threat!' });
        }

        const screenshotUrl = `https://api.screenshot.rocks/?url=${encodeURIComponent(url)}&width=400&height=300`;
        document.getElementById('screenshot').src = screenshotUrl;
        document.getElementById('screenshot').style.display = 'block';

        document.getElementById('shareBtn').style.display = 'inline-block';
        document.getElementById('exportBtn').style.display = 'inline-block';

        const history = JSON.parse(localStorage.getItem('cryvoraHistory') || '[]');
        history.unshift({ type: 'URL', input: url, risk: result.risk, timestamp: Date.now() });
        if (history.length > 10) history.pop();
        localStorage.setItem('cryvoraHistory', JSON.stringify(history));
        loadData();

        updateProgress(100);
    } catch (error) {
        alert('Error analyzing URL. Retrying...');
        console.error(error);
        // Retry once
        setTimeout(() => document.getElementById('checkBtn').click(), 2000);
    } finally {
        document.getElementById('urlSpinner').style.display = 'none';
    }
});

// Quick Scan (basic checks only)
document.getElementById('quickScanBtn').addEventListener('click', () => {
    const url = document.getElementById('urlInput').value.trim();
    if (!validateUrl(url)) return alert('Please enter a valid URL.');

    updateProgress(50);
    // Regex-based quick checks
    const phishingRegex = /\b(?:login|bank|secure|account)\.[a-z]{2,}\.[a-z]{2,}/i; // Detects subdomains like bank.login.fake.com
    const suspiciousTldRegex = /\.(xyz|top|club|info|biz)$/i;
    let risk = 'Safe';
    let details = 'Quick scan passed. ';

    if (phishingRegex.test(url)) {
        risk = 'Suspicious';
        details += 'Potential phishing pattern detected. ';
    }
    if (suspiciousTldRegex.test(url)) {
        risk = 'Suspicious';
        details += 'Suspicious TLD. ';
    }

    document.getElementById('result').innerHTML = `<p><strong>Risk:</strong> ${risk}</p><p><strong>Details:</strong> ${details}</p>`;
    document.getElementById('result').style.display = 'block';
    document.getElementById('threatGauge').style.width = risk === 'Suspicious' ? '50%' : '0%';
    document.getElementById('threatGauge').className = `progress-bar ${risk === 'Suspicious' ? 'bg-warning' : 'bg-success'}`;
    document.getElementById('confidence').textContent = `Confidence: ${risk === 'Suspicious' ? 50 : 0}%`;

    updateProgress(100);
});

// Analyze Image
document.getElementById('uploadBtn').addEventListener('click', async () => {
    const file = document.getElementById('imageInput').files[0];
    if (!file) return alert('Select an image!');

    document.getElementById('imageSpinner').style.display = 'inline-block';
    updateProgress(30);
    const formData = new FormData();
    formData.append('image', file);

    try {
        const response = await fetch('http://localhost:3000/analyze-image', {
            method: 'POST',
            body: formData
        });
        updateProgress(70);
        const result = await response.json();

        document.getElementById('result').innerHTML = `<p><strong>Risk:</strong> ${result.risk}</p><p><strong>Details:</strong> ${result.details}</p>`;
        document.getElementById('result').style.display = 'block';

        let threatPercent = result.confidence || 0;
        document.getElementById('threatGauge').style.width = `${threatPercent}%`;
        document.getElementById('threatGauge').className = `progress-bar ${threatPercent < 30 ? 'bg-success' : threatPercent < 70 ? 'bg-warning' : 'bg-danger'}`;
        document.getElementById('confidence').textContent = `Confidence: ${threatPercent}%`;

        const reader = new FileReader();
        reader.onload = () => {
            document.getElementById('uploadedImage').src = reader.result;
            document.getElementById('uploadedImage').style.display = 'block';
        };
        reader.readAsDataURL(file);

        document.getElementById('shareBtn').style.display = 'inline-block';
        document.getElementById('exportBtn').style.display = 'inline-block';

        const history = JSON.parse(localStorage.getItem('cryvoraHistory') || '[]');
        history.unshift({ type: 'Image', input: file.name, risk: result.risk, timestamp: Date.now() });
        if (history.length > 10) history.pop();
        localStorage.setItem('cryvoraHistory', JSON.stringify(history));
        loadData();

        updateProgress(100);
    } catch (error) {
        alert('Error analyzing image. Retrying...');
        console.error(error);
        setTimeout(() => document.getElementById('uploadBtn').click(), 2000);
    } finally {
        document.getElementById('imageSpinner').style.display = 'none';
    }
});

// Report Scam
document.getElementById('reportBtn').addEventListener('click', () => {
    const report = prompt('Describe the scam:');
    if (report) {
        const reports = JSON.parse(localStorage.getItem('cryvoraReports') || '[]');
        reports.push({ report, timestamp: Date.now() });
        localStorage.setItem('cryvoraReports', JSON.stringify(reports));
        loadData();
        alert('Report submitted!');
    }
});

// Share on Twitter
document.getElementById('shareBtn').addEventListener('click', () => {
    const risk = document.querySelector('#result p strong').nextSibling.textContent.trim();
    const tweetText = `Cryvora found it ${risk.toLowerCase()}! #Cryvora`;
    window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(tweetText)}`, '_blank');
});

// Export as image
document.getElementById('exportBtn').addEventListener('click', () => {
    html2canvas(document.querySelector('.container')).then(canvas => {
        const link = document.createElement('a');
        link.download = 'cryvora-scan.png';
        link.href = canvas.toDataURL();
        link.click();
    });
});


document.getElementById('aiSearchBtn').addEventListener('click', async () => {
    const input = document.getElementById('aiInput').value.trim();      
    const platform = document.getElementById('platformSelect').value;                                   //ai block code basic search
    if (!input) return alert('Enter input for AI analysis!');   

    document.getElementById('aiSpinner').style.display = 'inline-block';
    updateProgress(40);
    try {
        const response = await fetch('http://localhost:3000/ai-analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ input, platform })
        });
        updateProgress(80);
        const result = await response.json();

        document.getElementById('aiResult').innerHTML = `<p><strong>AI Analysis:</strong> ${result.analysis}</p><p><strong>Action:</strong> ${result.action}</p>`;
        document.getElementById('aiResult').style.display = 'block';

        if (result.action.includes('Blocked')) {
            console.log(`Blocked ${platform}: ${input}`);
            alert(`${platform} blocked successfully!`);
        }

        updateProgress(100);
    } catch (error) {
        alert('AI analysis failed. Retrying...');
        console.error(error);
        setTimeout(() => document.getElementById('aiSearchBtn').click(), 2000);
    } finally {
        document.getElementById('aiSpinner').style.display = 'none';
    }
});


document.addEventListener('DOMContentLoaded', () => {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
});