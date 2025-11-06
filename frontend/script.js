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
        const response = await fetch("http://127.0.0.1:5000/api/analyze", {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                target: target,
                type: type
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
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
        container.innerHTML = `
            <div style="padding: 20px; text-align: center; color: var(--color-danger);">
                <h3>❌ Analysis Failed</h3>
                <p>Error: ${error.message}</p>
                <p style="font-size: 13px; color: var(--color-text-secondary);">
                    Make sure the backend server is running at ${API_BASE_URL}
                </p>
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

// ... rest of JS remains the same (updateMonitoringStats, updateCorrelationMatrix, updateBarChart, updatePieChart, etc.)
