// TICE Frontend JavaScript - script.js
// Save this as: frontend/script.js

// Configuration
const API_BASE_URL = 'http://127.0.0.1:5000';
let analysisHistory = [];

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    updateCorrelationMatrix();
    updateHeatmap();
    
    // Start real-time monitoring simulation
    setInterval(() => {
        const events = parseInt(document.getElementById('eventsProcessed').textContent.replace(',', ''));
        document.getElementById('eventsProcessed').textContent = (events + Math.floor(Math.random() * 10 + 1)).toLocaleString();
    }, 5000);
    
    // Add enter key support for input
    document.getElementById('targetInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            analyzeTarget();
        }
    });
}

// Main analysis function - connects to backend
async function analyzeTarget() {
    const type = document.getElementById('detectionType').value;
    const target = document.getElementById('targetInput').value.trim();
    
    if (!target) {
        alert('Please enter a target to analyze');
        return;
    }

    // Update UI to show loading
    const btn = document.getElementById('analyzeBtn');
    const btnText = document.getElementById('analyzeText');
    btn.disabled = true;
    btnText.innerHTML = '<span class="loading"></span>Analyzing...';

    try {
        // Call backend API
        const response = await fetch(`${API_BASE_URL}/api/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                target: target,
                type: type
            })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
            throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
        }

        const results = await response.json();
        
        // Display results
        displayResults(results, target, type);

        // Update stats with rolling animation
        animateNumber(document.getElementById('sourcesChecked'), results.sources.length, 500);
        animateNumber(document.getElementById('threatScore'), results.overallScore, 800);

        // Update graphical dashboard
        updateMetricCards(results);
        updateBarChart(results.sources);
        updatePieChart(results.findings);
        updateHeatmap();

        // Update monitoring stats
        updateMonitoringStats();

        // Add to history
        analysisHistory.push({ 
            target, 
            type, 
            results, 
            timestamp: new Date() 
        });

        // Update correlation matrix
        updateCorrelationMatrix();

        // Add to timeline
        addToTimeline(target, type, results.overallScore);

    } catch (error) {
        console.error('Analysis error:', error);
        const container = document.getElementById('resultsContainer');
        let errorMessage = error.message;
        
        // Provide more helpful error messages
        if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
            errorMessage = 'Cannot connect to backend server. Please ensure the server is running.';
        }
        
        container.innerHTML = `
            <div style="padding: 20px; text-align: center; color: var(--color-danger);">
                <h3>❌ Analysis Failed</h3>
                <p><strong>Error:</strong> ${errorMessage}</p>
                <p style="font-size: 13px; color: var(--color-text-secondary); margin-top: 10px;">
                    Make sure the backend server is running at ${API_BASE_URL}<br>
                    Start it with: <code>cd backend && python app.py</code>
                </p>
                <button onclick="testConnection()" style="margin-top: 10px; padding: 8px 16px; background: var(--color-primary); color: white; border: none; border-radius: 4px; cursor: pointer;">
                    Test Connection
                </button>
            </div>
        `;
    } finally {
        // Reset button
        btn.disabled = false;
        btnText.textContent = 'Analyze Threat';
    }
}

function displayResults(results, target, type) {
    const container = document.getElementById('resultsContainer');
    
    const severityClass = results.overallScore > 80 ? 'badge-critical' : 
                         results.overallScore > 60 ? 'badge-high' :
                         results.overallScore > 40 ? 'badge-medium' : 'badge-low';
    
    const statusText = results.malicious ? 'MALICIOUS' : 'CLEAN';
    
    let html = `
        <div style="margin-bottom: 20px; padding: 16px; background: rgba(99, 102, 241, 0.1); border-radius: 6px; border-left: 4px solid var(--color-primary);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <div>
                    <strong style="font-size: 16px;">Target Analysis: ${target}</strong>
                    <div style="font-size: 12px; color: var(--color-text-secondary); margin-top: 4px;">
                        Type: ${type.toUpperCase()} | Analyzed: ${new Date(results.timestamp).toLocaleString()}
                    </div>
                </div>
                <span class="badge ${severityClass}">${statusText}</span>
            </div>
            <div style="font-size: 14px;">
                <strong>Overall Threat Score:</strong> ${results.overallScore}/100
            </div>
        </div>
    `;

    // Source Results
    if (results.sources && results.sources.length > 0) {
        html += '<h4 style="margin-bottom: 12px; font-size: 14px;">🔍 Intelligence Source Results</h4>';
        results.sources.forEach(source => {
            const sourceClass = source.detected ? 'badge-danger' : 'badge-low';
            
            // Update API list item color based on threat level
            updateApiSourceColor(source.name, source.score);
            
            html += `
                <div class="threat-item">
                    <div class="threat-header">
                        <span class="threat-name">${source.name}</span>
                        <span class="badge ${sourceClass}">${source.detected ? 'DETECTED' : 'CLEAN'}</span>
                    </div>
                    <div class="threat-details">
                        Threat Score: ${source.score}/100 | Checked: ${new Date(source.timestamp).toLocaleTimeString()}
                    </div>
                </div>
            `;
        });
    }

    // Detailed Findings
    if (results.findings && results.findings.length > 0) {
        html += '<h4 style="margin: 20px 0 12px 0; font-size: 14px;">⚠️ Threat Findings</h4>';
        results.findings.forEach(finding => {
            const findingClass = finding.severity === 'Critical' ? 'badge-critical' :
                                finding.severity === 'High' ? 'badge-high' : 'badge-medium';
            html += `
                <div class="threat-item">
                    <div class="threat-header">
                        <span class="threat-name">${finding.type}</span>
                        <span class="badge ${findingClass}">${finding.severity}</span>
                    </div>
                    <div class="threat-details">
                        Source: ${finding.source}<br>
                        ${finding.details}
                    </div>
                </div>
            `;
        });
    }

    // Correlations
    if (results.correlations && results.correlations.length > 0) {
        html += '<h4 style="margin: 20px 0 12px 0; font-size: 14px;">🔗 Correlation Analysis</h4>';
        html += '<ul style="list-style: none; padding: 0;">';
        results.correlations.forEach(corr => {
            html += `<li style="padding: 8px; background: rgba(99, 102, 241, 0.1); margin-bottom: 6px; border-radius: 4px; font-size: 13px;">• ${corr}</li>`;
        });
        html += '</ul>';
    }

    // Mitigation
    if (results.mitigation && results.mitigation.length > 0) {
        html += '<h4 style="margin: 20px 0 12px 0; font-size: 14px;">🛡️ Recommended Actions</h4>';
        html += '<ul style="list-style: none; padding: 0;">';
        results.mitigation.forEach(action => {
            html += `<li style="padding: 8px; background: rgba(16, 185, 129, 0.1); margin-bottom: 6px; border-radius: 4px; font-size: 13px;">${action}</li>`;
        });
        html += '</ul>';
    }

    container.innerHTML = html;
}

function updateApiSourceColor(sourceName, score) {
    const apiMap = {
        'VirusTotal': 'api-virustotal',
        'AbuseIPDB': 'api-abuseipdb',
        'AlienVault OTX': 'api-alienvault'
    };

    const apiId = apiMap[sourceName];
    if (!apiId) return;

    const apiElement = document.getElementById(apiId);
    if (!apiElement) return;

    // Remove existing threat classes
    apiElement.classList.remove('threat-high', 'threat-medium', 'threat-low');

    // Add color based on threat score
    if (score >= 70) {
        apiElement.classList.add('threat-high');
    } else if (score >= 40) {
        apiElement.classList.add('threat-medium');
    } else {
        apiElement.classList.add('threat-low');
    }
}

// Helper function to animate number changes
function animateNumber(element, targetValue, duration) {
    if (!element) return;
    const startValue = parseInt(element.textContent) || 0;
    const increment = (targetValue - startValue) / (duration / 16);
    let currentValue = startValue;
    const startTime = Date.now();
    
    function update() {
        const elapsed = Date.now() - startTime;
        if (elapsed < duration) {
            currentValue += increment;
            element.textContent = Math.round(currentValue);
            requestAnimationFrame(update);
        } else {
            element.textContent = targetValue;
        }
    }
    update();
}

// Update metric cards
function updateMetricCards(results) {
    if (results.overallScore !== undefined) {
        animateNumber(document.getElementById('metricThreatScore'), results.overallScore, 500);
    }
    if (results.findings) {
        animateNumber(document.getElementById('metricDetections'), results.findings.length, 500);
    }
    if (results.sources) {
        document.getElementById('metricSources').textContent = results.sources.length;
    }
}

// Update bar chart
function updateBarChart(sources) {
    if (!sources || sources.length === 0) return;
    
    const container = document.getElementById('barChart');
    if (!container) return;
    
    container.innerHTML = '';
    const maxScore = Math.max(...sources.map(s => s.score || 0), 1);
    
    sources.forEach(source => {
        const bar = document.createElement('div');
        bar.style.cssText = `
            display: flex;
            align-items: center;
            margin-bottom: 12px;
            gap: 12px;
        `;
        
        const label = document.createElement('div');
        label.textContent = source.name;
        label.style.cssText = 'min-width: 120px; font-size: 13px;';
        
        const barContainer = document.createElement('div');
        barContainer.style.cssText = 'flex: 1; height: 24px; background: rgba(99, 102, 241, 0.1); border-radius: 4px; overflow: hidden;';
        
        const barFill = document.createElement('div');
        const width = (source.score || 0) / maxScore * 100;
        const color = source.score >= 70 ? 'var(--color-danger)' : 
                     source.score >= 40 ? 'var(--color-warning)' : 'var(--color-success)';
        barFill.style.cssText = `
            height: 100%;
            width: ${width}%;
            background: ${color};
            transition: width 0.5s ease;
        `;
        
        const value = document.createElement('div');
        value.textContent = `${source.score || 0}/100`;
        value.style.cssText = 'min-width: 60px; text-align: right; font-size: 13px; font-weight: 600;';
        
        barContainer.appendChild(barFill);
        bar.appendChild(label);
        bar.appendChild(barContainer);
        bar.appendChild(value);
        container.appendChild(bar);
    });
}

// Update pie chart
function updatePieChart(findings) {
    if (!findings) return;
    
    const container = document.getElementById('pieChart');
    if (!container) return;
    
    const highCount = findings.filter(f => f.severity === 'High' || f.severity === 'Critical').length;
    const mediumCount = findings.filter(f => f.severity === 'Medium').length;
    const lowCount = findings.filter(f => f.severity === 'Low').length;
    
    document.getElementById('highCount').textContent = highCount;
    document.getElementById('mediumCount').textContent = mediumCount;
    document.getElementById('lowCount').textContent = lowCount;
    document.getElementById('pieValue').textContent = findings.length;
    
    const total = findings.length || 1;
    const highPercent = (highCount / total) * 100;
    const mediumPercent = (mediumCount / total) * 100;
    const lowPercent = (lowCount / total) * 100;
    
    // Create SVG pie chart
    let svg = container.querySelector('svg');
    if (!svg) {
        svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 200 200');
        svg.style.cssText = 'width: 200px; height: 200px; transform: rotate(-90deg);';
        container.insertBefore(svg, container.firstChild);
    }
    
    svg.innerHTML = '';
    let currentPercent = 0;
    
    if (highPercent > 0) {
        const path = createPieSlice(currentPercent, highPercent, 'var(--color-danger)');
        svg.appendChild(path);
        currentPercent += highPercent;
    }
    if (mediumPercent > 0) {
        const path = createPieSlice(currentPercent, mediumPercent, 'var(--color-warning)');
        svg.appendChild(path);
        currentPercent += mediumPercent;
    }
    if (lowPercent > 0) {
        const path = createPieSlice(currentPercent, lowPercent, 'var(--color-success)');
        svg.appendChild(path);
    }
}

function createPieSlice(startPercent, percent, color) {
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    const startAngle = (startPercent / 100) * 360;
    const endAngle = ((startPercent + percent) / 100) * 360;
    
    const startRad = (startAngle * Math.PI) / 180;
    const endRad = (endAngle * Math.PI) / 180;
    
    const x1 = 100 + 80 * Math.cos(startRad);
    const y1 = 100 + 80 * Math.sin(startRad);
    const x2 = 100 + 80 * Math.cos(endRad);
    const y2 = 100 + 80 * Math.sin(endRad);
    
    const largeArc = percent > 50 ? 1 : 0;
    
    const d = `M 100 100 L ${x1} ${y1} A 80 80 0 ${largeArc} 1 ${x2} ${y2} Z`;
    path.setAttribute('d', d);
    path.setAttribute('fill', color);
    
    return path;
}

// Update heatmap
function updateHeatmap() {
    const container = document.getElementById('heatmap');
    if (!container) return;
    
    container.innerHTML = '';
    
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const hours = Array.from({length: 24}, (_, i) => i);
    
    days.forEach(day => {
        const dayRow = document.createElement('div');
        dayRow.style.cssText = 'display: flex; gap: 4px; margin-bottom: 4px;';
        
        const dayLabel = document.createElement('div');
        dayLabel.textContent = day;
        dayLabel.style.cssText = 'width: 40px; font-size: 11px; text-align: right; padding-right: 8px;';
        dayRow.appendChild(dayLabel);
        
        hours.forEach(hour => {
            const cell = document.createElement('div');
            const intensity = Math.random() * 100; // Simulated data
            const color = intensity > 70 ? 'var(--color-danger)' :
                         intensity > 40 ? 'var(--color-warning)' :
                         intensity > 10 ? 'var(--color-success)' : 'rgba(99, 102, 241, 0.1)';
            cell.style.cssText = `
                width: 12px;
                height: 12px;
                background: ${color};
                border-radius: 2px;
            `;
            dayRow.appendChild(cell);
        });
        
        container.appendChild(dayRow);
    });
}

// Update monitoring stats
function updateMonitoringStats() {
    // This can be enhanced with real data
    const threats = analysisHistory.filter(h => h.results.malicious).length;
    document.getElementById('threatsDetected').textContent = threats;
    
    const correlations = analysisHistory.reduce((sum, h) => 
        sum + (h.results.correlations ? h.results.correlations.length : 0), 0);
    document.getElementById('correlations').textContent = correlations;
}

// Update correlation matrix
function updateCorrelationMatrix() {
    const container = document.getElementById('correlationMatrix');
    if (!container) return;
    
    if (analysisHistory.length === 0) {
        container.innerHTML = '<p style="color: var(--color-text-secondary);">No correlations yet. Perform analysis to see correlations.</p>';
        return;
    }
    
    // Simple correlation display
    const recent = analysisHistory.slice(-5);
    container.innerHTML = '';
    const wrapper = document.createElement('div');
    wrapper.style.cssText = 'display: grid; gap: 8px;';
    recent.forEach(item => {
        const div = document.createElement('div');
        div.style.cssText = 'padding: 8px; background: rgba(99, 102, 241, 0.1); border-radius: 4px; font-size: 13px;';
        div.textContent = `${item.target} - Score: ${item.results.overallScore}/100`;
        wrapper.appendChild(div);
    });
    container.appendChild(wrapper);
}

// Add to timeline
function addToTimeline(target, type, score) {
    const container = document.getElementById('timeline');
    if (!container) return;
    
    const item = document.createElement('div');
    item.style.cssText = `
        padding: 8px;
        margin-bottom: 8px;
        background: rgba(99, 102, 241, 0.1);
        border-radius: 4px;
        font-size: 12px;
        border-left: 3px solid ${score >= 70 ? 'var(--color-danger)' : score >= 40 ? 'var(--color-warning)' : 'var(--color-success)'};
    `;
    item.textContent = `${new Date().toLocaleTimeString()} - ${target} (${type}) - Score: ${score}`;
    
    container.insertBefore(item, container.firstChild);
    
    // Keep only last 10 items
    while (container.children.length > 10) {
        container.removeChild(container.lastChild);
    }
}

// Export results
function exportResults() {
    if (analysisHistory.length === 0) {
        alert('No results to export');
        return;
    }
    
    const dataStr = JSON.stringify(analysisHistory, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `tice-analysis-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
}
