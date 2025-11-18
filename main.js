// Variables globales
let vulnerabilities = [];
let riskChart, riskDistributionChart, owaspDistributionChart;
let currentTheme = 'light';

// Categorías OWASP TOP 10 2021
const owaspCategories = [
    "A01:2021 - Broken Access Control",
    "A02:2021 - Cryptographic Failures", 
    "A03:2021 - Injection",
    "A04:2021 - Insecure Design",
    "A05:2021 - Security Misconfiguration",
    "A06:2021 - Vulnerable Components",
    "A07:2021 - Authentication Failures",
    "A08:2021 - Software Integrity Failures",
    "A09:2021 - Security Logging Failures",
    "A10:2021 - Server-Side Request Forgery"
];

// Colores para cada categoría OWASP
const categoryColors = [
    'rgba(255, 99, 132, 0.8)',   // A01 - Rojo
    'rgba(54, 162, 235, 0.8)',   // A02 - Azul
    'rgba(255, 206, 86, 0.8)',   // A03 - Amarillo
    'rgba(75, 192, 192, 0.8)',   // A04 - Verde azulado
    'rgba(153, 102, 255, 0.8)',  // A05 - Púrpura
    'rgba(255, 159, 64, 0.8)',   // A06 - Naranja
    'rgba(199, 199, 199, 0.8)',  // A07 - Gris
    'rgba(83, 102, 255, 0.8)',   // A08 - Azul índigo
    'rgba(40, 159, 64, 0.8)',    // A09 - Verde
    'rgba(210, 105, 30, 0.8)'    // A10 - Marrón
];

// ========== INICIALIZACIÓN ==========
document.addEventListener('DOMContentLoaded', function() {
    loadTheme();
    document.getElementById('theme-toggle').addEventListener('click', toggleTheme);
    loadVulnerabilities();
    document.getElementById('calculate-btn').addEventListener('click', calculateRisk);
    document.getElementById('save-btn').addEventListener('click', saveVulnerability);
    
    document.querySelectorAll('select').forEach(select => {
        select.addEventListener('change', calculateRisk);
    });
    
    calculateRisk();
    initializeExportButton();
});

// ========== FUNCIONES DE TEMA ==========
function toggleTheme() {
    const themeToggle = document.getElementById('theme-toggle');
    const themeIcon = themeToggle.querySelector('.theme-icon');
    
    if (currentTheme === 'light') {
        document.documentElement.setAttribute('data-theme', 'dark');
        currentTheme = 'dark';
        themeIcon.textContent = '☀️';
        localStorage.setItem('theme', 'dark');
    } else {
        document.documentElement.removeAttribute('data-theme');
        currentTheme = 'light';
        themeIcon.textContent = '🌙';
        localStorage.setItem('theme', 'light');
    }
}

function loadTheme() {
    const savedTheme = localStorage.getItem('theme');
    const themeToggle = document.getElementById('theme-toggle');
    const themeIcon = themeToggle.querySelector('.theme-icon');
    
    if (savedTheme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
        currentTheme = 'dark';
        themeIcon.textContent = '☀️';
    } else {
        document.documentElement.removeAttribute('data-theme');
        currentTheme = 'light';
        themeIcon.textContent = '🌙';
    }
}

// ========== CÁLCULO DE RIESGO ==========
function calculateRisk() {
    const sl = parseFloat(document.getElementById('sl').value);
    const m = parseFloat(document.getElementById('m').value);
    const o = parseFloat(document.getElementById('o').value);
    const s = parseFloat(document.getElementById('s').value);
    
    const lc = parseFloat(document.getElementById('lc').value);
    const li = parseFloat(document.getElementById('li').value);
    const lav = parseFloat(document.getElementById('lav').value);
    const lac = parseFloat(document.getElementById('lac').value);
    
    const ed = parseFloat(document.getElementById('ed').value);
    const ee = parseFloat(document.getElementById('ee').value);
    const a = parseFloat(document.getElementById('a').value);
    const id = parseFloat(document.getElementById('id').value);
    
    const fd = parseFloat(document.getElementById('fd').value);
    const rd = parseFloat(document.getElementById('rd').value);
    const nc = parseFloat(document.getElementById('nc').value);
    const pv = parseFloat(document.getElementById('pv').value);
    
    const likelihood = (sl + m + o + s + ed + ee + a + id) / 8;
    const impact = (lc + li + lav + lac + fd + rd + nc + pv) / 8;
    const risk = likelihood * impact;
    
    document.querySelector('.LS').textContent = likelihood.toFixed(2);
    document.querySelector('.IS').textContent = impact.toFixed(2);
    
    let riskLevel, riskClass;
    if (risk >= 60) {
        riskLevel = 'CRÍTICO';
        riskClass = 'risk-critico';
    } else if (risk >= 40) {
        riskLevel = 'ALTO';
        riskClass = 'risk-alto';
    } else if (risk >= 20) {
        riskLevel = 'MEDIO';
        riskClass = 'risk-medio';
    } else if (risk >= 10) {
        riskLevel = 'BAJO';
        riskClass = 'risk-bajo';
    } else {
        riskLevel = 'INFORMATIVO';
        riskClass = 'risk-info';
    }
    
    const riskElement = document.getElementById('risk-result');
    riskElement.textContent = `Riesgo: ${riskLevel} (${risk.toFixed(2)})`;
    riskElement.className = `risk-indicator ${riskClass}`;
    
    updateRiskChart(likelihood, impact, risk);
    
    return { likelihood, impact, risk, riskLevel, riskClass };
}

function updateRiskChart(likelihood, impact, risk) {
    const ctx = document.getElementById('riskChart').getContext('2d');
    
    if (riskChart) riskChart.destroy();
    
    riskChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Probabilidad', 'Impacto', 'Riesgo'],
            datasets: [{
                label: 'Puntuación',
                data: [likelihood, impact, risk],
                backgroundColor: [
                    'rgba(54, 162, 235, 0.7)',
                    'rgba(255, 99, 132, 0.7)',
                    risk >= 60 ? 'rgba(255, 0, 0, 0.7)' : 
                    risk >= 40 ? 'rgba(255, 107, 107, 0.7)' : 
                    risk >= 20 ? 'rgba(255, 209, 102, 0.7)' : 
                    risk >= 10 ? 'rgba(6, 214, 160, 0.7)' : 'rgba(17, 138, 178, 0.7)'
                ],
                borderColor: [
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 99, 132, 1)',
                    risk >= 60 ? 'rgba(255, 0, 0, 1)' : 
                    risk >= 40 ? 'rgba(255, 107, 107, 1)' : 
                    risk >= 20 ? 'rgba(255, 209, 102, 1)' : 
                    risk >= 10 ? 'rgba(6, 214, 160, 1)' : 'rgba(17, 138, 178, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { y: { beginAtZero: true, max: 100 } },
            plugins: { legend: { display: false } }
        }
    });
}

// ========== GESTIÓN DE VULNERABILIDADES ==========
function saveVulnerability() {
    const riskData = calculateRisk();
    const formData = getFormData();
    
    const vulnerability = {
        id: Date.now(),
        name: formData.name || `Vulnerabilidad ${vulnerabilities.length + 1}`,
        ...riskData,
        ...formData,
        date: new Date().toISOString()
    };
    
    vulnerabilities.push(vulnerability);
    saveVulnerabilities();
    renderVulnerabilitiesList();
    updateDashboard();
    
    showNotification(`Vulnerabilidad "${vulnerability.name}" guardada con nivel de riesgo: ${riskData.riskLevel}`, 'success');
}

function getFormData() {
    return {
        name: document.getElementById('vulnerability-name').value,
        owasp: document.getElementById('owasp-category').value,
        mitre: document.getElementById('mitre-id').value,
        toolCriticity: document.getElementById('tool-criticity').value,
        threatAgent: document.getElementById('threat-agent').value,
        attackVector: document.getElementById('attack-vector').value,
        securityWeakness: document.getElementById('security-weakness').value,
        securityControls: document.getElementById('security-controls').value,
        technicalBusinessImpact: document.getElementById('technical-business-impact').value,
        detail: document.getElementById('detail').value,
        description: document.getElementById('description').value,
        recommendation: document.getElementById('recommendation').value,
        mitreDetection: document.getElementById('mitre-detection').value,
        mitreMitigation: document.getElementById('mitre-mitigation').value
    };
}

function renderVulnerabilitiesList() {
    const listElement = document.getElementById('vulnerabilities-list');
    const countElement = document.getElementById('vulnerability-count');
    
    countElement.textContent = `${vulnerabilities.length} vulnerabilidad(es)`;
    
    if (vulnerabilities.length === 0) {
        listElement.innerHTML = '<div class="alert alert-info text-center">No hay vulnerabilidades guardadas</div>';
        return;
    }
    
    listElement.innerHTML = '';
    
    vulnerabilities.forEach(vuln => {
        const item = document.createElement('div');
        item.className = 'vulnerability-item';
        item.innerHTML = `
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <h5>${vuln.name}</h5>
                    <p class="mb-1"><strong>OWASP:</strong> ${vuln.owasp || 'No especificado'} | <strong>MITRE:</strong> ${vuln.mitre || 'No especificado'}</p>
                    <p class="mb-1"><strong>Riesgo:</strong> ${vuln.risk.toFixed(2)} | <strong>Probabilidad:</strong> ${vuln.likelihood.toFixed(2)} | <strong>Impacto:</strong> ${vuln.impact.toFixed(2)}</p>
                    <small class="text-muted">Guardado: ${new Date(vuln.date).toLocaleDateString()}</small>
                </div>
                <div>
                    <span class="risk-badge ${vuln.riskClass}-badge">${vuln.riskLevel}</span>
                </div>
            </div>
        `;
        
        item.addEventListener('click', () => showVulnerabilityDetails(vuln.id));
        listElement.appendChild(item);
    });
}

// ========== DASHBOARD ==========
function updateDashboard() {
    document.getElementById('total-vulnerabilities').textContent = vulnerabilities.length;
    
    const criticalCount = vulnerabilities.filter(v => v.riskLevel === 'CRÍTICO').length;
    const highCount = vulnerabilities.filter(v => v.riskLevel === 'ALTO').length;
    const mediumCount = vulnerabilities.filter(v => v.riskLevel === 'MEDIO').length;
    const lowCount = vulnerabilities.filter(v => v.riskLevel === 'BAJO').length;
    const infoCount = vulnerabilities.filter(v => v.riskLevel === 'INFORMATIVO').length;
    
    document.getElementById('critical-count').textContent = criticalCount;
    document.getElementById('high-count').textContent = highCount;
    document.getElementById('medium-count').textContent = mediumCount;
    
    updateRiskDistributionChart(criticalCount, highCount, mediumCount, lowCount, infoCount);
    updateOwaspDistributionChart();
    updateDashboardTable();
}

function updateRiskDistributionChart(critical, high, medium, low, info) {
    const ctx = document.getElementById('riskDistributionChart').getContext('2d');
    
    if (riskDistributionChart) riskDistributionChart.destroy();
    
    riskDistributionChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Crítico', 'Alto', 'Medio', 'Bajo', 'Informativo'],
            datasets: [{
                data: [critical, high, medium, low, info],
                backgroundColor: [
                    'rgba(255, 0, 0, 0.8)',
                    'rgba(255, 107, 107, 0.8)',
                    'rgba(255, 209, 102, 0.8)',
                    'rgba(6, 214, 160, 0.8)',
                    'rgba(17, 138, 178, 0.8)'
                ],
                borderColor: [
                    'rgba(255, 0, 0, 1)',
                    'rgba(255, 107, 107, 1)',
                    'rgba(255, 209, 102, 1)',
                    'rgba(6, 214, 160, 1)',
                    'rgba(17, 138, 178, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom' } }
        }
    });
}

function updateOwaspDistributionChart() {
    const ctx = document.getElementById('owaspDistributionChart').getContext('2d');
    
    const owaspCounts = Array(owaspCategories.length).fill(0);
    vulnerabilities.forEach(vuln => {
        if (vuln.owasp) {
            const index = owaspCategories.findIndex(cat => cat.startsWith(vuln.owasp));
            if (index !== -1) owaspCounts[index]++;
        }
    });
    
    if (owaspDistributionChart) owaspDistributionChart.destroy();
    
    owaspDistributionChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: owaspCategories,
            datasets: [{
                data: owaspCounts,
                backgroundColor: categoryColors,
                borderColor: categoryColors.map(color => color.replace('0.8', '1')),
                borderWidth: 2,
                hoverOffset: 15
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total > 0 ? Math.round((value / total) * 100) : 0;
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            },
            cutout: '55%',
            animation: { animateScale: true, animateRotate: true }
        }
    });
    
    updateLegend(owaspCounts);
}

function updateLegend(owaspCounts) {
    const legendElement = document.getElementById('chart-legend');
    legendElement.innerHTML = '';
    
    owaspCategories.forEach((category, index) => {
        const legendItem = document.createElement('div');
        legendItem.className = 'legend-item';
        legendItem.innerHTML = `
            <div class="legend-color" style="background-color: ${categoryColors[index]}"></div>
            <span>${category.split('-')[0].trim()}: ${owaspCounts[index]}</span>
        `;
        legendElement.appendChild(legendItem);
    });
}

function updateDashboardTable() {
    const tableBody = document.getElementById('dashboard-vulnerabilities-list');
    tableBody.innerHTML = '';
    
    if (vulnerabilities.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="4" style="text-align: center;">No hay vulnerabilidades registradas</td></tr>';
        return;
    }
    
    const vulnerabilitiesByCategory = {};
    owaspCategories.forEach((_, index) => {
        vulnerabilitiesByCategory[index] = vulnerabilities.filter(v => {
            if (!v.owasp) return false;
            return owaspCategories[index].startsWith(v.owasp);
        });
    });
    
    owaspCategories.forEach((category, index) => {
        const categoryVulns = vulnerabilitiesByCategory[index];
        
        if (categoryVulns.length > 0) {
            const categoryRow = document.createElement('tr');
            categoryRow.className = `risk-${index}`;
            categoryRow.innerHTML = `
                <td colspan="4" style="font-weight: bold; background-color: ${categoryColors[index].replace('0.8', '0.2')}">
                    ${category} (${categoryVulns.length})
                </td>
            `;
            tableBody.appendChild(categoryRow);
            
            categoryVulns.forEach(vuln => {
                const row = document.createElement('tr');
                row.className = `risk-${index}`;
                row.innerHTML = `
                    <td></td>
                    <td>${vuln.name}</td>
                    <td>${vuln.attackVector || 'No especificado'}</td>
                    <td><span class="risk-badge ${vuln.riskClass}-badge">${vuln.riskLevel}</span></td>
                `;
                tableBody.appendChild(row);
            });
        }
    });
}

// ========== EXPORTACIÓN A WORD ==========
function initializeExportButton() {
    const exportBtn = document.getElementById('export-all-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportToWord);
        console.log('Botón de exportación inicializado');
    } else {
        console.log('Botón de exportación no encontrado, reintentando...');
        setTimeout(initializeExportButton, 1000);
    }
}

function exportToWord() {
    console.log('Ejecutando exportToWord...');
    
    if (vulnerabilities.length === 0) {
        showNotification('No hay vulnerabilidades para exportar', 'error');
        return;
    }

    try {
        let htmlContent = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Reporte de Vulnerabilidades OWASP</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.4; }
                    .vulnerability { margin-bottom: 30px; border: 1px solid #ccc; padding: 15px; }
                    .title { font-size: 18px; font-weight: bold; color: #2c3e50; margin-bottom: 10px; }
                    .section { margin-bottom: 15px; }
                    .section-title { font-weight: bold; color: #34495e; margin-bottom: 5px; }
                    .risk-badge { display: inline-block; padding: 3px 8px; border-radius: 4px; color: white; font-weight: bold; margin-left: 10px; }
                    .risk-critico { background-color: #FF0000; }
                    .risk-alto { background-color: #FF6B6B; }
                    .risk-medio { background-color: #FFD166; color: #333; }
                    .risk-bajo { background-color: #06D6A0; }
                    .risk-info { background-color: #118AB2; }
                    table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                </style>
            </head>
            <body>
                <h1>Reporte de Vulnerabilidades OWASP</h1>
                <p><strong>Generado:</strong> ${new Date().toLocaleDateString()}</p>
                <p><strong>Total de vulnerabilidades:</strong> ${vulnerabilities.length}</p>
        `;

        vulnerabilities.forEach((vuln, index) => {
            htmlContent += `
                <div class="vulnerability">
                    <div class="title">${vuln.name} <span class="risk-badge ${vuln.riskClass}">${vuln.riskLevel}</span></div>
                    
                    <div class="section">
                        <div class="section-title">Resultados del análisis</div>
                        Puntuación: ${vuln.risk.toFixed(2)} | Probabilidad: ${vuln.likelihood.toFixed(2)} | Impacto: ${vuln.impact.toFixed(2)}
                    </div>

                    <table>
                        <tr><th>Host/Vector de Ataque</th><td>${vuln.attackVector || 'No especificado'}</td></tr>
                        <tr><th>ID OWASP top 10</th><td>${vuln.owasp || 'No especificado'}</td></tr>
                        <tr><th>MITRE ID</th><td>${vuln.mitre || 'No especificado'}</td></tr>
                        <tr><th>Criticidad según Herramienta</th><td>${vuln.toolCriticity || 'No especificado'}</td></tr>
                    </table>

                    <div class="section">
                        <div class="section-title">Detalle</div>
                        ${vuln.detail || vuln.description || 'No especificado'}
                    </div>

                    <div class="section">
                        <div class="section-title">Descripción del análisis</div>
                        ${vuln.description || vuln.securityWeakness || 'No especificado'}
                    </div>

                    <div class="section">
                        <div class="section-title">Recomendación</div>
                        ${vuln.recommendation || 'No especificado'}
                    </div>

                    <div class="section">
                        <div class="section-title">Estrategia de detección MITRE</div>
                        ${vuln.mitreDetection || 'No especificado'}
                    </div>

                    <div class="section">
                        <div class="section-title">Estrategia de mitigación MITRE</div>
                        ${vuln.mitreMitigation || 'No especificado'}
                    </div>
                </div>
            `;
        });

        htmlContent += `</body></html>`;

        const blob = new Blob([htmlContent], { type: 'application/msword' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `reporte_vulnerabilidades_${new Date().toISOString().split('T')[0]}.doc`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showNotification(`Reporte exportado con ${vulnerabilities.length} vulnerabilidades`, 'success');
        
    } catch (error) {
        console.error('Error al exportar:', error);
        showNotification('Error al exportar el reporte', 'error');
    }
}

// ========== UTILIDADES ==========
function showVulnerabilityDetails(id) {
    const vuln = vulnerabilities.find(v => v.id === id);
    if (!vuln) return;
    
    const modalBody = document.getElementById('modal-body');
    modalBody.innerHTML = `
        <div class="vulnerability-details">
            <div class="detail-item">
                <div class="detail-label">Nombre</div>
                <div class="detail-value">${vuln.name}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Nivel de Riesgo</div>
                <div class="detail-value"><span class="risk-badge ${vuln.riskClass}-badge">${vuln.riskLevel}</span> (${vuln.risk.toFixed(2)})</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">OWASP 2021</div>
                <div class="detail-value">${vuln.owasp || 'No especificado'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">MITRE ID</div>
                <div class="detail-value">${vuln.mitre || 'No especificado'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Criticidad según Herramienta</div>
                <div class="detail-value">${vuln.toolCriticity || 'No especificado'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Agente de Amenazas</div>
                <div class="detail-value">${vuln.threatAgent || 'No especificado'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Vector de Ataque</div>
                <div class="detail-value">${vuln.attackVector || 'No especificado'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Debilidad de Seguridad</div>
                <div class="detail-value">${vuln.securityWeakness || 'No especificado'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Controles de Seguridad</div>
                <div class="detail-value">${vuln.securityControls || 'No especificado'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Impacto Técnico - Negocio</div>
                <div class="detail-value">${vuln.technicalBusinessImpact || 'No especificado'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Detalle</div>
                <div class="detail-value">${vuln.detail || 'No especificado'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Descripción</div>
                <div class="detail-value">${vuln.description || 'No especificado'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Recomendación</div>
                <div class="detail-value">${vuln.recommendation || 'No especificado'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Estrategia de Detección MITRE</div>
                <div class="detail-value">${vuln.mitreDetection || 'No especificado'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Estrategia de Mitigación MITRE</div>
                <div class="detail-value">${vuln.mitreMitigation || 'No especificado'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Métricas de Riesgo</div>
                <div class="detail-value">
                    <strong>Probabilidad:</strong> ${vuln.likelihood.toFixed(2)}<br>
                    <strong>Impacto:</strong> ${vuln.impact.toFixed(2)}<br>
                    <strong>Riesgo Total:</strong> ${vuln.risk.toFixed(2)}
                </div>
            </div>
        </div>
    `;
    
    const modal = new bootstrap.Modal(document.getElementById('vulnerabilityModal'));
    modal.show();
}

function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.textContent = message;
    notification.className = `notification ${type}`;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => document.body.removeChild(notification), 300);
    }, 3000);
}

function saveVulnerabilities() {
    localStorage.setItem('owaspVulnerabilities', JSON.stringify(vulnerabilities));
}

function loadVulnerabilities() {
    const saved = localStorage.getItem('owaspVulnerabilities');
    if (saved) {
        vulnerabilities = JSON.parse(saved);
        renderVulnerabilitiesList();
        updateDashboard();
    }
}