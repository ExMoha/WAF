let requests = [];

function Request(timestamp, ip, method, path, score) {
    this.id = requests.length + 1;
    this.timestamp = timestamp;
    this.ip = ip;
    this.method = method;
    this.path = path;
    this.score = score;
    this.severity = score => {
	if (score >= 10)
	    return 'Critical'
	else if (score >= 8)
	    return 'High';
	else
	    return 'Medium'
    }
}

function parseLogFile(content) {
    const lines = content.split('\n').filter(line => line.trim() !== '');
    requests = [];
    
    lines.forEach((line, index) => {
        const parts = line.trim().split('|');
        
        if (parts.length >= 5) {
            const timestamp = parts[0];
            const ipPart = parts[2].trim();
            const methodPart = parts[3].trim();
            const pathPart = parts[4].trim();
            const scorePart = parts[5].trim();
            
            const ip = ipPart.startsWith('IP:') ? ipPart.substring(3).trim() : ipPart;
            
            const method = methodPart.startsWith('Method:') ? methodPart.substring(7).trim() : methodPart;
            
            const path = pathPart.startsWith('Path:') ? pathPart.substring(5).trim() : pathPart;

            const score = scorePart.startsWith('Score:') ? scorePart.substring(6).trim() : scorePart;
            
            requests.push(new Request(timestamp, ip, method, path, score));
        }
    });
    
    updateTable();
}

function updateTable() {
    const tbody = document.getElementById('dynamic-body');
    tbody.innerHTML = '';
    
    requests.forEach(req => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${req.id}</td>
            <td>${req.timestamp}</td>
            <td>${req.ip}</td>
            <td>${req.method}</td>
            <td>${req.path}</td>
            <td>${req.score}</td>
	    <td>${req.severity(req.score)}</td>
        `;
        tbody.appendChild(row);
    });
}

async function loadWafLog() {
    try {
        const response = await fetch('waf.log');
        if (response.ok) {
            const content = await response.text();
            parseLogFile(content);
        } else {
            console.log('waf.log not found on server');
        }
    } catch (error) {
        console.log('Error fetching waf.log:', error.message);
    }
}

const exportBtn = document.getElementById('export');
exportBtn.addEventListener('click', () => {
    const dataStr = JSON.stringify(requests, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'requests.json';
    link.click();
    URL.revokeObjectURL(url);
});

document.addEventListener('DOMContentLoaded', () => {
    loadWafLog();
});
