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
    console.log('Inicializando aplicación...');
    loadTheme();
    
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }
    
    loadVulnerabilities();
    
    const calculateBtn = document.getElementById('calculate-btn');
    const saveBtn = document.getElementById('save-btn');
    const exportWordBtn = document.getElementById('export-all-btn'); // Modificado el ID a 'export-all-btn'
    const exportPdfBtn = document.getElementById('export-pdf-btn');
    const exportJsonBtn = document.getElementById('export-json-btn');
    // Botón de exportación ejecutiva
    const exportExecutiveBtn = document.getElementById('export-executive-btn');
    
    if (calculateBtn) {
        calculateBtn.addEventListener('click', calculateRisk);
    }
    
    if (saveBtn) {
        saveBtn.addEventListener('click', saveVulnerability);
    }

    if (exportWordBtn) {
        exportWordBtn.addEventListener('click', exportToWord);
    }
    
    if (exportPdfBtn) {
        exportPdfBtn.addEventListener('click', exportToPDF);
    }
    
    if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', exportToJson);
    } 
    
    // VINCULACIÓN: Informe Ejecutivo
    if (exportExecutiveBtn) {
        exportExecutiveBtn.addEventListener('click', exportExecutiveReport);
    } else {
        console.warn('Botón exportar informe ejecutivo (export-executive-btn) no encontrado.');
    }

    const importFileInput = document.getElementById('import-file-input');
    if (importFileInput) {
        importFileInput.addEventListener('change', importJson);
    }
    
    document.querySelectorAll('select').forEach(select => {
        select.addEventListener('change', calculateRisk);
    });
    
    setTimeout(calculateRisk, 100);

    console.log('Aplicación inicializada correctamente');
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
    
    if (themeToggle) {
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
}

// ========== CÁLCULO DE RIESGO ==========
function calculateRisk() {
    console.log('Calculando riesgo...');
    
    try {
        // Obtener valores de los selects con valores por defecto
        const sl = parseFloat(document.getElementById('sl')?.value) || 1;
        const m = parseFloat(document.getElementById('m')?.value) || 1;
        const o = parseFloat(document.getElementById('o')?.value) || 0;
        const s = parseFloat(document.getElementById('s')?.value) || 2;
        
        const lc = parseFloat(document.getElementById('lc')?.value) || 2;
        const li = parseFloat(document.getElementById('li')?.value) || 1;
        const lav = parseFloat(document.getElementById('lav')?.value) || 1;
        const lac = parseFloat(document.getElementById('lac')?.value) || 1;
        
        const ed = parseFloat(document.getElementById('ed')?.value) || 1;
        const ee = parseFloat(document.getElementById('ee')?.value) || 1;
        const a = parseFloat(document.getElementById('a')?.value) || 1;
        const id = parseFloat(document.getElementById('id')?.value) || 1;
        
        const fd = parseFloat(document.getElementById('fd')?.value) || 1;
        const rd = parseFloat(document.getElementById('rd')?.value) || 1;
        const nc = parseFloat(document.getElementById('nc')?.value) || 2;
        const pv = parseFloat(document.getElementById('pv')?.value) || 3;
        
        // Calcular promedios (Risk 0-10)
        const likelihood = (sl + m + o + s + ed + ee + a + id) / 8;
        const impact = (lc + li + lav + lac + fd + rd + nc + pv) / 8;
        const risk = (likelihood + impact) / 2; // Promedio entre probabilidad e impacto (0-10)
        
        // Escalar el riesgo de 0-10 a 0-81
        const scaledRisk = risk * 8.1;
        
        // Actualizar UI
        const lsElement = document.querySelector('.LS');
        const isElement = document.querySelector('.IS');
        
        if (lsElement) lsElement.textContent = likelihood.toFixed(2);
        if (isElement) isElement.textContent = impact.toFixed(2);
        
        let riskLevel, riskClass;
        // Aplicar la clasificación (0-81)
        if (scaledRisk > 75) {
            riskLevel = 'CRÍTICO';
            riskClass = 'risk-critico';
        } else if (scaledRisk > 50) {
            riskLevel = 'ALTO';
            riskClass = 'risk-alto';
        } else if (scaledRisk > 25) {
            riskLevel = 'MEDIO';
            riskClass = 'risk-medio';
        } else if (scaledRisk > 1) {
            riskLevel = 'BAJO';
            riskClass = 'risk-bajo';
        } else {
            riskLevel = 'INFORMATIVO';
            riskClass = 'risk-info';
        }
        
        const riskElement = document.getElementById('risk-result');
        if (riskElement) {
            riskElement.textContent = `Riesgo: ${riskLevel} (${scaledRisk.toFixed(2)})`;
            riskElement.className = `risk-indicator ${riskClass}`;
        }
        
        updateRiskChart(likelihood, impact, risk, riskLevel); 
        
        return { 
            likelihood: parseFloat(likelihood.toFixed(2)), 
            impact: parseFloat(impact.toFixed(2)), 
            risk: parseFloat(scaledRisk.toFixed(2)), 
            riskLevel, 
            riskClass 
        };
    } catch (error) {
        console.error('Error en calculateRisk:', error);
        return { likelihood: 0, impact: 0, risk: 0, riskLevel: 'INFORMATIVO', riskClass: 'risk-info' };
    }
}

// Funciones auxiliares para color del Chart.js
function getRiskChartColor(riskLevel) {
    switch(riskLevel.toUpperCase()) {
        case 'CRÍTICO': return 'rgba(255, 0, 0, 0.7)'; // Rojo
        case 'ALTO': return 'rgba(255, 107, 107, 0.7)'; // Naranja
        case 'MEDIO': return 'rgba(255, 209, 102, 0.7)'; // Amarillo
        case 'BAJO': return 'rgba(6, 214, 160, 0.7)'; // Verde
        case 'INFORMATIVO': return 'rgba(17, 138, 178, 0.7)'; // Azul
        default: return 'rgba(170, 170, 170, 0.7)'; // Gris
    }
}

function getRiskChartBorder(riskLevel) {
    switch(riskLevel.toUpperCase()) {
        case 'CRÍTICO': return 'rgba(255, 0, 0, 1)'; // Rojo
        case 'ALTO': return 'rgba(255, 107, 107, 1)'; // Naranja
        case 'MEDIO': return 'rgba(255, 209, 102, 1)'; // Amarillo
        case 'BAJO': return 'rgba(6, 214, 160, 1)'; // Verde
        case 'INFORMATIVO': return 'rgba(17, 138, 178, 1)'; // Azul
        default: return 'rgba(170, 170, 170, 1)'; // Gris
    }
}

function updateRiskChart(likelihood, impact, risk, riskLevel) {
    const ctx = document.getElementById('riskChart');
    if (!ctx) {
        return;
    }
    
    try {
        const context = ctx.getContext('2d');
        
        if (riskChart) riskChart.destroy();
        
        const chartColor = getRiskChartColor(riskLevel);
        const chartBorder = getRiskChartBorder(riskLevel);

        riskChart = new Chart(context, {
            type: 'bar',
            data: {
                labels: ['Probabilidad', 'Impacto', 'Riesgo'],
                datasets: [{
                    label: 'Puntuación',
                    data: [likelihood, impact, risk],
                    backgroundColor: [
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(255, 99, 132, 0.7)',
                        chartColor
                    ],
                    borderColor: [
                        'rgba(54, 162, 235, 1)',
                        'rgba(255, 99, 132, 1)',
                        chartBorder
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: { 
                    y: { 
                        beginAtZero: true, 
                        max: 10,
                        ticks: {
                            stepSize: 1
                        }
                    } 
                },
                plugins: { 
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `${context.dataset.label}: ${context.parsed.y.toFixed(2)}`;
                            }
                        }
                    }
                }
            }
        });
    } catch (error) {
        console.error('Error actualizando gráfico:', error);
    }
}

// ========== GESTIÓN DE VULNERABILIDADES ==========
function saveVulnerability() {
    console.log('Guardando vulnerabilidad...');
    
    try {
        const riskData = calculateRisk();
        const formData = getFormData();
        
        if (!formData.name || formData.name.trim() === '') {
            showNotification('El campo "Nombre de la Vulnerabilidad" es obligatorio.', 'error');
            return;
        }
        if (!formData.host || formData.host.trim() === '') {
            showNotification('El campo "Host" o Dominio es obligatorio.', 'error');
            return;
        }
        if (!formData.owasp || formData.owasp.trim() === '') {
            showNotification('Selecciona una "Categoría OWASP 2021".', 'error');
            return;
        }
        
        const vulnerability = {
            id: Date.now(),
            name: formData.name.trim(),
            ...riskData,
            ...formData,
            date: new Date().toISOString()
        };
        
        vulnerabilities.push(vulnerability);
        saveVulnerabilities();
        renderVulnerabilitiesList();
        updateDashboard();
        
        // Limpiar formulario
        document.getElementById('vulnerability-name').value = '';
        
        showNotification(`Vulnerabilidad "${vulnerability.name}" guardada con nivel de riesgo: ${riskData.riskLevel}`, 'success');
        
    } catch (error) {
        console.error('Error guardando vulnerabilidad:', error);
        showNotification('Error al guardar la vulnerabilidad', 'error');
    }
}

function getFormData() {
    const getValue = (id) => {
        const element = document.getElementById(id);
        return element ? element.value : '';
    };
    
    return {
        name: getValue('vulnerability-name'),
        host: getValue('host'),
        rutaAfectada: getValue('ruta-afectada'),
        owasp: getValue('owasp-category'),
        mitre: getValue('mitre-id'),
        toolCriticity: getValue('tool-criticity'),
        threatAgent: getValue('threat-agent'),
        attackVector: getValue('attack-vector'),
        securityWeakness: getValue('security-weakness'),
        securityControls: getValue('security-controls'),
        technicalBusinessImpact: getValue('technical-business-impact'),
        detail: getValue('detail'),
        description: getValue('description'),
        recommendation: getValue('recommendation'),
        mitreDetection: getValue('mitre-detection'),
        mitreMitigation: getValue('mitre-mitigation')
    };
}

function renderVulnerabilitiesList() {
    const listElement = document.getElementById('vulnerabilities-list');
    const countElement = document.getElementById('vulnerability-count');
    
    if (!listElement || !countElement) {
        return;
    }
    
    countElement.textContent = `${vulnerabilities.length} vulnerabilidad(es)`;
    
    if (vulnerabilities.length === 0) {
        listElement.innerHTML = '<div class="alert alert-info text-center">No hay vulnerabilidades guardadas</div>';
        return;
    }
    
    listElement.innerHTML = '';
    
    // Ordenar por fecha (más reciente primero) o por ID
    const sortedVulnerabilities = [...vulnerabilities].sort((a, b) => b.id - a.id);
    
    sortedVulnerabilities.forEach((vuln, index) => {
        const item = document.createElement('div');
        item.className = 'vulnerability-item';
        item.innerHTML = `
            <div class="vulnerability-header">
                <div class="vulnerability-number">${sortedVulnerabilities.length - index}</div>
                <div class="vulnerability-content">
                    <h5 class="mb-2">${vuln.name}</h5>
                </div>
            </div>
            <div class="d-flex justify-content-between align-items-start">
                <div style="flex: 1;">
                    <p class="mb-1"><strong>Host:</strong> ${vuln.host || 'No especificado'}</p>
                    <p class="mb-1"><strong>OWASP:</strong> ${vuln.owasp || 'No especificado'} | <strong>MITRE:</strong> ${vuln.mitre || 'No especificado'}</p>
                    <p class="mb-1"><strong>Riesgo:</strong> ${vuln.risk.toFixed(2)} | <strong>Probabilidad:</strong> ${vuln.likelihood.toFixed(2)} | <strong>Impacto:</strong> ${vuln.impact.toFixed(2)}</p>
                    <small class="text-muted">Guardado: ${new Date(vuln.date).toLocaleDateString()} ${new Date(vuln.date).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</small>
                </div>
                <div class="ms-3">
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
    console.log('Actualizando dashboard...');
    
    try {
        const totalElement = document.getElementById('total-vulnerabilities');
        const criticalElement = document.getElementById('critical-count');
        const highElement = document.getElementById('high-count');
        const mediumElement = document.getElementById('medium-count');
        
        if (totalElement) totalElement.textContent = vulnerabilities.length;
        
        const criticalCount = vulnerabilities.filter(v => v.riskLevel === 'CRÍTICO').length;
        const highCount = vulnerabilities.filter(v => v.riskLevel === 'ALTO').length;
        const mediumCount = vulnerabilities.filter(v => v.riskLevel === 'MEDIO').length;
        const lowCount = vulnerabilities.filter(v => v.riskLevel === 'BAJO').length;
        const infoCount = vulnerabilities.filter(v => v.riskLevel === 'INFORMATIVO').length;
        
        if (criticalElement) criticalElement.textContent = criticalCount;
        if (highElement) highElement.textContent = highCount;
        if (mediumElement) mediumElement.textContent = mediumCount;
        
        updateRiskDistributionChart(criticalCount, highCount, mediumCount, lowCount, infoCount);
        updateOwaspDistributionChart();
        updateDashboardTable();
    } catch (error) {
        console.error('Error actualizando dashboard:', error);
    }
}

function updateRiskDistributionChart(critical, high, medium, low, info) {
    const ctx = document.getElementById('riskDistributionChart');
    if (!ctx) return;
    
    try {
        const context = ctx.getContext('2d');
        
        if (riskDistributionChart) riskDistributionChart.destroy();
        
        riskDistributionChart = new Chart(context, {
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
                backgroundColor: 'white', // Esto ayuda, pero la exportación final se fuerza en exportExecutiveReport
                plugins: { 
                    legend: { 
                        position: 'bottom',
                        labels: {
                            padding: 20,
                            usePointStyle: true
                        }
                    } 
                }
            }
        });
    } catch (error) {
        console.error('Error actualizando gráfico de distribución:', error);
    }
}

function updateOwaspDistributionChart() {
    const ctx = document.getElementById('owaspDistributionChart');
    if (!ctx) return;
    
    try {
        const context = ctx.getContext('2d');
        
        const owaspCounts = Array(owaspCategories.length).fill(0);
        vulnerabilities.forEach(vuln => {
            if (vuln.owasp) {
                const index = owaspCategories.findIndex(cat => cat.startsWith(vuln.owasp));
                if (index !== -1) owaspCounts[index]++;
            }
        });
        
        if (owaspDistributionChart) owaspDistributionChart.destroy();
        
        owaspDistributionChart = new Chart(context, {
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
                backgroundColor: 'white', // Esto ayuda, pero la exportación final se fuerza en exportExecutiveReport
                plugins: {
                    legend: { 
                        display: true, 
                        position: 'right', 
                        labels: {
                            font: {
                                size: 14 // <-- Modificación anterior para tamaño de letra
                            },
                            filter: function (legendItem, data) {
                                return data.datasets[0].data[legendItem.index] > 0;
                            },
                            generateLabels: function(chart) {
                                const data = chart.data;
                                return data.labels.map((label, i) => {
                                    const count = data.datasets[0].data[i];
                                    const categoryId = label.split(' - ')[0].trim(); // Obtiene "A01:2021"
                                    
                                    if (count > 0) {
                                        return {
                                            text: `${categoryId}: ${count}`, 
                                            fillStyle: data.datasets[0].backgroundColor[i],
                                            strokeStyle: data.datasets[0].borderColor[i],
                                            lineWidth: data.datasets[0].borderWidth,
                                            hidden: false,
                                            index: i
                                        };
                                    }
                                    return null;
                                }).filter(item => item !== null); 
                            }
                        }
                    },
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
    } catch (error) {
        console.error('Error actualizando gráfico OWASP:', error);
    }
}

function updateDashboardTable() {
    const tableBody = document.getElementById('dashboard-vulnerabilities-list');
    if (!tableBody) return;
    
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
    
    // Ordenar categorías por número de vulnerabilidades (mayor a menor)
    const sortedCategories = [...owaspCategories].map((cat, idx) => ({
        category: cat,
        index: idx,
        count: vulnerabilitiesByCategory[idx].length
    })).filter(item => item.count > 0)
      .sort((a, b) => b.count - a.count);
    
    let globalCounter = 1;
    
    sortedCategories.forEach((catItem, catIndex) => {
        const categoryVulns = vulnerabilitiesByCategory[catItem.index];
        
        // Encabezado de categoría
        const categoryRow = document.createElement('tr');
        categoryRow.className = `risk-${catItem.index}`;
        categoryRow.innerHTML = `
            <td colspan="4" style="font-weight: bold; background-color: ${categoryColors[catItem.index].replace('0.8', '0.2')}">
                ${catItem.category} (${categoryVulns.length} vulnerabilidad${categoryVulns.length !== 1 ? 'es' : ''})
            </td>
        `;
        tableBody.appendChild(categoryRow);
        
        // Ordenar vulnerabilidades dentro de la categoría por riesgo (mayor a menor)
        const sortedVulns = categoryVulns.sort((a, b) => b.risk - a.risk);
        
        sortedVulns.forEach((vuln, vulnIndex) => {
            const row = document.createElement('tr');
            row.className = `risk-${catItem.index}`;
            row.innerHTML = `
                <td style="font-weight: bold; text-align: center; width: 50px;">
                    ${globalCounter++}
                </td>
                <td>${vuln.name}</td>
                <td>${vuln.host || vuln.attackVector || 'No especificado'}</td>
                <td><span class="risk-badge ${vuln.riskClass}-badge">${vuln.riskLevel}</span></td>
            `;
            tableBody.appendChild(row);
        });
    });
}

// ========== EXPORTACIÓN A WORD (COMPLETO) ==========
function exportToWord() {
    console.log('Ejecutando exportToWord (Completo)...');
    
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
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Reporte de Vulnerabilidades</title>
                <style>
                    body { 
                        font-family: Arial, sans-serif; 
                        margin: 0;
                        padding: 20px;
                        line-height: 1.4;
                        color: #333;
                        font-size: 12px;
                        min-height: 100vh;
                        width: 100%;
                        background-color: #ffffff;
                    }
                    .report-header {
                        text-align: center;
                        margin-bottom: 20px;
                        border-bottom: 2px solid #2c3e50;
                        padding-bottom: 15px;
                        width: 80%;
                        max-width: 800px;
                        margin-left: auto; 
                        margin-right: auto;
                    }

                    .vulnerability-title {
                        font-size: 14px;
                        font-weight: bold;
                        color: #333;
                        margin-bottom: 15px;
                        padding: 8px;
                        border-radius: 0;
                        width: 80%;
                        max-width: 800px;
                        text-align: center;
                        margin-left: auto;
                        margin-right: auto;
                        border: 1px solid #000;
                        background-color: #f8f9fa;
                        line-height: 1.4;
                    }

                    .vulnerability-table tr:first-child .header-cell {
                        font-size: 28px !important;
                        font-weight: bold;
                        text-align: center !important;
                        background-color: #e9ecef;
                        padding: 30px 35px;
                        line-height: 1.2;
                        height: 100px;
                    }

                    .report-header h1 {
                        font-size: 18px;
                        margin-bottom: 10px;
                    }
                    
                    .report-header p {
                        font-size: 12px;
                        margin-bottom: 5px;
                    }

                    .vulnerability-container {
                        margin-bottom: 80px; 
                        page-break-after: always; 
                        width: 100%;
                        max-width: 1400px;
                    }
                    
                    .vulnerability-table {
                        width: 100%; 
                        border-collapse: collapse;
                        margin: 40px auto;
                        font-size: 16px;
                        border: 3px solid #000;
                        max-width: 1400px;
                        background-color: white;
                    }
                    
                    .vulnerability-table td {
                        border: 3px solid #000;
                        padding: 25px 30px;
                        vertical-align: top;
                        font-size: 16px;
                        text-align: left;
                        line-height: 1.8;
                        min-height: 60px;
                    }

                    .vulnerability-table tr td:first-child {
                        width: 30% !important;
                        font-weight: bold;
                        font-size: 17px;
                    }
                    
                    .vulnerability-table tr td:not(:first-child) {
                        width: 70% !important;
                    }

                    .vulnerability-table tr:nth-child(-n+3) td:first-child {
                        width: 25% !important;
                    }

                    .vulnerability-table tr:nth-child(-n+3) td:not(:first-child) {
                        width: 75% !important;
                    }

                    .header-cell {
                        background-color: #f2f2f2; 
                        font-weight: bold;
                        font-size: 17px;
                        text-align: left;
                        padding: 25px 30px;
                        min-height: 60px;
                    }

                    .data-cell {
                        background-color: #ffffff;
                        font-weight: normal;
                        font-size: 16px;
                        text-align: left;
                        min-height: 60px;
                    }

                    .vulnerability-table tr:nth-child(1) td:nth-child(3),
                    .vulnerability-table tr:nth-child(2) td:nth-child(3),
                    .vulnerability-table tr:nth-child(3) td:nth-child(3) {
                        text-align: center !important;
                        font-size: 22px;
                        font-weight: bold;
                        padding: 30px 35px;
                        min-height: 70px;
                    }

                    .vulnerability-table tr:first-child td {
                        font-size: 20px !important;
                        padding: 30px 35px !important;
                        height: 100px;
                    }

                    .list-item {
                        margin-bottom: 12px;
                        padding-left: 20px;
                        font-size: 16px;
                        text-align: left;
                        line-height: 1.8;
                    }

                    .vulnerability-table tr {
                        height: 80px;
                    }
                </style>
            </head>
            <body>
                <div class="report-header">
                    <h1 style="font-size: 16px;">Reporte de Vulnerabilidades de Seguridad</h1>
                    <p style="font-size: 10px;"><strong>Fecha de generación:</strong> ${new Date().toLocaleDateString()} ${new Date().toLocaleTimeString()}</p>
                    <p style="font-size: 10px;"><strong>Total de vulnerabilidades:</strong> ${vulnerabilities.length}</p>
                </div>
        `;

        vulnerabilities.forEach((vuln, index) => {
            const titleColor = getRiskHeaderColor(vuln.riskLevel);
            const riskHighlightColor = titleColor;
            
            htmlContent += `
                <div class="vulnerability-container">
                    <div class="vulnerability-title" style="background-color: ${titleColor}; color: ${vuln.riskLevel === 'MEDIO' ? '#333' : 'white'};">
                        Vulnerabilidad ${index + 1}: ${vuln.name || 'No especificado'}
                    </div>
                    
                    <table class="vulnerability-table" align="center">
                        <tr>
                            <td rowspan="3" class="header-cell" style="font-weight: bold; width: 25%; background-color: #ffffff; text-align: justify;">
                                <strong>ID:</strong> ${index + 1}<br>
                                ${vuln.name || 'No especificado'}
                            </td>
                            
                            <td class="header-cell" style="width: 15%; background-color: #f2f2f2; font-weight: bold; text-align: center;">
                                Resultados del análisis
                            </td>
                            <td class="data-cell" style="width: 60%; background-color: ${riskHighlightColor}; color: ${vuln.riskLevel === 'MEDIO' ? '#333' : 'white'}; font-weight: bold; text-align: center;">
                                ${vuln.riskLevel || 'No especificado'}
                            </td>
                        </tr>

                        <tr>
                            <td class="header-cell" style="background-color: #f2f2f2; font-weight: bold; text-align: center;">
                                Nivel de Riesgo
                            </td>
                            <td class="data-cell" style="background-color: ${riskHighlightColor}; color: ${vuln.riskLevel === 'MEDIO' ? '#333' : 'white'}; font-weight: bold; text-align: center;">
                                ${vuln.riskLevel || 'No especificado'}
                            </td>
                        </tr>

                        <tr>
                            <td class="header-cell" style="background-color: #f2f2f2; font-weight: bold; text-align: center;">
                                Resultado del Escáner
                            </td>
                            <td class="data-cell" style="background-color: #ffffff; text-align: center;">
                                -
                            </td>
                        </tr>

                        <tr>
                            <td class="header-cell" style="font-weight: bold; width: 25%;">Host</td>
                            <td colspan="2" class="data-cell" style="width: 75%;">${vuln.host || vuln.attackVector || vuln.threatAgent || 'No especificado'}</td>
                        </tr>
                        
                        <tr>
                            <td class="header-cell" style="font-weight: bold; width: 25%;">Ruta afectada</td>
                            <td colspan="2" class="data-cell" style="width: 75%;">${vuln.rutaAfectada || vuln.securityWeakness || 'No especificado'}</td>
                        </tr>

                        <tr>
                            <td class="header-cell" style="font-weight: bold;">Detalle</td>
                            <td colspan="2" class="data-cell">${vuln.detail || 'No especificado'}</td>
                        </tr>

                        <tr>
                            <td class="header-cell" style="font-weight: bold;">Descripción del análisis</td>
                            <td colspan="2" class="data-cell">${vuln.description || 'No especificado'}</td>
                        </tr>

                        <tr>
                            <td class="header-cell" style="font-weight: bold;">Recomendación</td>
                            <td colspan="2" class="data-cell">${vuln.recommendation || 'No especificado'}</td>
                        </tr>

                        <tr>
                            <td class="header-cell" style="font-weight: bold;">ID OWASP top 10</td>
                            <td colspan="2" class="data-cell">${vuln.owasp || 'No especificado'}</td>
                        </tr>
                        
                        <tr>
                            <td class="header-cell" style="font-weight: bold;">MITRE ID</td>
                            <td colspan="2" class="data-cell">${formatMitreIds(vuln.mitre)}</td>
                        </tr>
                        
                        <tr>
                            <td class="header-cell" style="font-weight: bold;">Estrategia de detección MITRE</td>
                            <td colspan="2" class="data-cell">${formatMitreStrategies(vuln.mitreDetection)}</td>
                        </tr>
                        
                        <tr>
                            <td class="header-cell" style="font-weight: bold;">Estrategia de mitigación MITRE</td>
                            <td colspan="2" class="data-cell">${formatMitreStrategies(vuln.mitreMitigation)}</td>
                        </tr>
                    </table>
                    <br></br>
                </div>
            `;
        });

        htmlContent += `</body></html>`;

        const blob = new Blob([htmlContent], { type: 'application/msword' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `reporte_completo_vulnerabilidades_${new Date().toISOString().split('T')[0]}.doc`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showNotification(`Reporte completo exportado con ${vulnerabilities.length} vulnerabilidad(es)`, 'success');
        
    } catch (error) {
        console.error('Error al exportar:', error);
        showNotification('Error al exportar el reporte', 'error');
    }
}


function exportExecutiveReport() {
    console.log('Ejecutando exportExecutiveReport (Informe Ejecutivo)...');

    if (vulnerabilities.length === 0) {
        showNotification('No hay vulnerabilidades para generar el informe ejecutivo.', 'error');
        return;
    }

    try {
        // Asegurarse de que los gráficos se hayan generado
        if (!riskDistributionChart || !owaspDistributionChart) {
             updateDashboard(); // Forzar la actualización de los gráficos si no existen
        }

        const totalVulnerabilities = vulnerabilities.length;
        const criticalCount = vulnerabilities.filter(v => v.riskLevel === 'CRÍTICO').length;
        const highCount = vulnerabilities.filter(v => v.riskLevel === 'ALTO').length;
        const mediumCount = vulnerabilities.filter(v => v.riskLevel === 'MEDIO').length;
        const lowCount = vulnerabilities.filter(v => v.riskLevel === 'BAJO').length;

        // **SOLUCIÓN MEJORADA: Crear canvas temporal con fondo blanco**
        const riskChartImage = createChartWithWhiteBackground(riskDistributionChart);
        const owaspChartImage = createChartWithWhiteBackground(owaspDistributionChart);
        
        // El resto del código permanece igual...
        let htmlContent = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Informe Ejecutivo de Riesgos</title>
                <style>
                    body { 
                        font-family: Arial, sans-serif; 
                        margin: 0;
                        padding: 30px;
                        line-height: 1.6;
                        color: #333;
                        font-size: 12pt;
                        width: 100%;
                        background-color: #ffffff;
                    }
                    .report-header {
                        text-align: center;
                        margin-bottom: 40px;
                        padding-bottom: 20px;
                        border-bottom: 3px solid #000080;
                    }
                    .report-header h1 {
                        font-size: 20pt;
                        color: #000080;
                        margin-bottom: 10px;
                    }
                    .section-title {
                        font-size: 16pt;
                        color: #2c3e50;
                        border-bottom: 2px solid #ccc;
                        padding-bottom: 5px;
                        margin-top: 30px;
                        margin-bottom: 20px;
                        page-break-before: auto;
                    }
                    .summary-table {
                        width: 80%;
                        border-collapse: collapse;
                        margin: 20px 0;
                        font-size: 11pt;
                        border: 1px solid #ddd;
                    }
                    .summary-table th, .summary-table td {
                        border: 1px solid #ddd;
                        padding: 10px;
                        text-align: left;
                    }
                    .summary-table th {
                        background-color: #f2f2f2;
                        font-weight: bold;
                    }
                    .chart-container {
                        text-align: center;
                        margin: 40px 0;
                        page-break-inside: avoid;
                    }
                    .chart-caption {
                        font-size: 10pt;
                        color: #666;
                        margin-top: 10px;
                    }
                    .total { background-color: #e6f3ff; font-weight: bold; }
                    .critical { color: #dc3545; font-weight: bold; }
                    .high { color: #fd7e14; font-weight: bold; }
                </style>
            </head>
            <body>
                <div class="report-header">
                    <h1>Informe Ejecutivo de Riesgos de Seguridad</h1>
                    <p><strong>Proyecto/Sistema:</strong> [Nombre del proyecto]</p>
                    <p><strong>Fecha de Evaluación:</strong> ${new Date().toLocaleDateString()}</p>
                    <p><strong>Total de Vulnerabilidades Identificadas:</strong> ${totalVulnerabilities}</p>
                </div>

                <div class="section-title">Resumen de Vulnerabilidades</div>
                <table class="summary-table">
                    <tr>
                        <th>Métrica</th>
                        <th>Valor</th>
                        <th>Descripción</th>
                    </tr>
                    <tr class="total">
                        <td>Total de Vulnerabilidades</td>
                        <td>${totalVulnerabilities}</td>
                        <td>Número total de hallazgos de seguridad identificados.</td>
                    </tr>
                    <tr>
                        <td>Vulnerabilidades Críticas</td>
                        <td class="critical">${criticalCount}</td>
                        <td>Requieren atención inmediata.</td>
                    </tr>
                    <tr>
                        <td>Vulnerabilidades Altas</td>
                        <td class="high">${highCount}</td>
                        <td>Deben ser mitigadas con alta prioridad.</td>
                    </tr>
                    <tr>
                        <td>Vulnerabilidades Medias</td>
                        <td>${mediumCount}</td>
                        <td>Riesgo moderado, mitigar en el ciclo de desarrollo actual.</td>
                    </tr>
                    <tr>
                        <td>Vulnerabilidades Bajas/Informativas</td>
                        <td>${lowCount + vulnerabilities.filter(v => v.riskLevel === 'INFORMATIVO').length}</td>
                        <td>Riesgo menor o informativo.</td>
                    </tr>
                </table>

                <div class="section-title">Distribución de Riesgos</div>
                <p>El siguiente gráfico representa la distribución de todas las vulnerabilidades según el nivel de riesgo calculado por el motor Intriga (OWASP Risk Rating Methodology, adaptado a escala 0-81).</p>
                <div class="chart-container">
                    <img src="${riskChartImage}" alt="Distribución por Nivel de Riesgo" style="width: 500px; height: 500px; border: 1px solid #ccc;"/>
                    <div class="chart-caption">Figura 1: Distribución por Nivel de Riesgo (Crítico, Alto, Medio, Bajo, Informativo).</div>
                </div>

                <div class="section-title">Distribución por Categoría OWASP Top 10 (2021)</div>
                <p>La siguiente gráfica muestra cómo se distribuyen los hallazgos según las categorías definidas por el OWASP Top 10 (2021), indicando las áreas más afectadas del sistema.</p>
                <div class="chart-container">
                    <img src="${owaspChartImage}" alt="Distribución por Categoría OWASP" style="width: 500px; height: 500px; border: 1px solid #ccc;"/>
                    <div class="chart-caption">Figura 2: Distribución por Categoría OWASP Top 10 (2021).</div>
                </div>
                
                <p style="page-break-before: always;">-- Fin del Informe Ejecutivo --</p>
            </body>
            </html>
        `;

        // Generación y descarga del archivo .doc
        const blob = new Blob([htmlContent], { type: 'application/msword' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `informe_ejecutivo_riesgos_${new Date().toISOString().split('T')[0]}.doc`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showNotification(`Informe Ejecutivo exportado exitosamente.`, 'success');
        
    } catch (error) {
        console.error('Error al exportar Informe Ejecutivo:', error);
        showNotification('Error al exportar el Informe Ejecutivo. Asegúrese de que los gráficos se hayan cargado.', 'error');
    }
}

// Función auxiliar para crear gráficos con fondo blanco
function createChartWithWhiteBackground(chart) {
    // Crear un canvas temporal
    const tempCanvas = document.createElement('canvas');
    tempCanvas.width = chart.width;
    tempCanvas.height = chart.height;
    const tempCtx = tempCanvas.getContext('2d');
    
    // Rellenar con fondo blanco
    tempCtx.fillStyle = 'white';
    tempCtx.fillRect(0, 0, tempCanvas.width, tempCanvas.height);
    
    // Dibujar el gráfico sobre el fondo blanco
    tempCtx.drawImage(chart.canvas, 0, 0);
    
    return tempCanvas.toDataURL('image/png');
}

// ========== EXPORTACIÓN A PDF (MEJORADA CON BORDES VISIBLES) ==========
function exportToPDF() {
    console.log('Ejecutando exportToPDF...');
    
    if (vulnerabilities.length === 0) {
        showNotification('No hay vulnerabilidades para exportar', 'error');
        return;
    }

    try {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        const pageWidth = doc.internal.pageSize.width;
        const margin = 15;
        
        doc.setFont('helvetica');
        
        vulnerabilities.forEach((vuln, index) => {
            if (index > 0) {
                doc.addPage();
            }
            
            let yPosition = 20;
            
            // Título principal MÁS DESTACADO - SOLO EL NOMBRE
            const riskColor = getRiskPdfColor(vuln.riskLevel);
            doc.setFillColor(riskColor.r, riskColor.g, riskColor.b);
            doc.rect(margin, yPosition, pageWidth - 2 * margin, 12, 'F');
            
            doc.setFontSize(12);
            doc.setFont(undefined, 'bold');
            doc.setTextColor(riskColor.textColor);
            
            const title = `${vuln.name || 'Vulnerabilidad'}`;
            const titleWidth = doc.getTextWidth(title);
            const titleX = margin + ((pageWidth - 2 * margin - titleWidth) / 2);
            doc.text(title, titleX, yPosition + 8);
            
            yPosition += 20;

            // Configuración de columnas
            const col1Width = 45;  // Ancho para etiquetas
            const col2Width = pageWidth - col1Width - 2 * margin; // Ancho restante para valores

            // Fila 1: Nombre de vulnerabilidad
            drawTwoColumnRowPDF(doc, margin, yPosition, col1Width, col2Width, 
                              'Nombre de vulnerabilidad', vuln.name || 'No especificado');
            yPosition += 10;

            // Fila 2: Resultados del análisis | ALTO
            drawTwoColumnRowPDF(doc, margin, yPosition, col1Width, col2Width, 
                              'Resultados del análisis', vuln.riskLevel, true, vuln.riskLevel);
            yPosition += 10;

            // Fila 3: Nivel de Riesgo | ALTO
            drawTwoColumnRowPDF(doc, margin, yPosition, col1Width, col2Width, 
                              'Nivel de Riesgo', vuln.riskLevel, true, vuln.riskLevel);
            yPosition += 10;

            // Fila 4: Host | [valor]
            drawTwoColumnRowPDF(doc, margin, yPosition, col1Width, col2Width, 
                              'Host', vuln.host || 'No especificado');
            yPosition += 10;

            // Fila 5: Ruta afectada | [valor]
            drawTwoColumnRowPDF(doc, margin, yPosition, col1Width, col2Width, 
                              'Ruta afectada:', vuln.rutaAfectada || 'No especificado');
            yPosition += 10;

            // Fila 6: Resultado del Escáner | -
            drawTwoColumnRowPDF(doc, margin, yPosition, col1Width, col2Width, 
                              'Resultado del Escáner', '-');
            yPosition += 10;

            // Fila 7: Detalle | [valor combinado]
            const detailHeight = drawCombinedRowPDF(doc, margin, yPosition, col1Width, col2Width,
                                                  'Detalle:', vuln.detail || 'No especificado');
            yPosition += detailHeight;

            // Fila 8: Descripción del análisis | [valor combinado]
            const descHeight = drawCombinedRowPDF(doc, margin, yPosition, col1Width, col2Width,
                                                'Descripción del análisis', vuln.description || 'No especificado');
            yPosition += descHeight;

            // Fila 9: Recomendación | [valor combinado]
            const recHeight = drawCombinedRowPDF(doc, margin, yPosition, col1Width, col2Width,
                                               'Recomendación', vuln.recommendation || 'No especificado');
            yPosition += recHeight;

            // Fila 10: ID OWASP top 10 | [valor combinado]
            const owaspHeight = drawCombinedRowPDF(doc, margin, yPosition, col1Width, col2Width,
                                                 'ID OWASP top 10', vuln.owasp || 'No especificado');
            yPosition += owaspHeight;

            // Fila 11: MITRE ID | [valor combinado]
            const mitreHeight = drawCombinedRowPDF(doc, margin, yPosition, col1Width, col2Width,
                                                 'MITRE ID', formatMitreForPdf(vuln.mitre));
            yPosition += mitreHeight;

            // Fila 12: Estrategia de detección MITRE | [valor combinado]
            const detectionHeight = drawCombinedRowPDF(doc, margin, yPosition, col1Width, col2Width,
                                                     'Estrategia de detección MITRE', formatMitreForPdf(vuln.mitreDetection));
            yPosition += detectionHeight;

            // Fila 13: Estrategia de mitigación MITRE | [valor combinado]
            const mitigationHeight = drawCombinedRowPDF(doc, margin, yPosition, col1Width, col2Width,
                                                      'Estrategia de mitigación MITRE', formatMitreForPdf(vuln.mitreMitigation));
            yPosition += mitigationHeight;

        });
        
        doc.save(`reporte_vulnerabilidades_${new Date().toISOString().split('T')[0]}.pdf`);
        showNotification(`PDF exportado con ${vulnerabilities.length} vulnerabilidad(es)`, 'success');
        
    } catch (error) {
        console.error('Error al exportar PDF:', error);
        showNotification('Error al exportar el PDF', 'error');
    }
}


// Función para dibujar filas de 2 columnas con bordes MÁS VISIBLES
function drawTwoColumnRowPDF(doc, x, y, col1Width, col2Width, label, value, isRiskCell = false, riskLevel = null) {
    doc.setDrawColor(0, 0, 0);
    doc.setLineWidth(0.8); // Línea más gruesa
    
    const totalWidth = col1Width + col2Width;
    const rowHeight = 10;
    
    // Dibujar rectángulo exterior con línea más gruesa
    doc.rect(x, y, totalWidth, rowHeight);
    
    // Dibujar línea vertical entre columnas MÁS GRUESA
    doc.line(x + col1Width, y, x + col1Width, y + rowHeight);
    
    // Fondos de celdas - gris más oscuro para mejor contraste
    doc.setFillColor(220, 220, 220); // Gris más oscuro para etiquetas
    doc.rect(x, y, col1Width, rowHeight, 'F');
    
    if (isRiskCell && riskLevel) {
        const color = getRiskPdfColor(riskLevel);
        doc.setFillColor(color.r, color.g, color.b);
        doc.rect(x + col1Width, y, col2Width, rowHeight, 'F');
    } else {
        doc.setFillColor(255, 255, 255); // Blanco para valores
        doc.rect(x + col1Width, y, col2Width, rowHeight, 'F');
    }
    
    // Textos - tamaño de fuente aumentado para mejor legibilidad
    doc.setFontSize(9);
    
    // Columna 1 (Etiqueta) - Negrita y más grande
    doc.setFont(undefined, 'bold');
    doc.setTextColor(0, 0, 0);
    const labelLines = doc.splitTextToSize(label, col1Width - 6);
    doc.text(labelLines, x + 3, y + 6);
    
    // Columna 2 (Valor)
    if (isRiskCell && riskLevel) {
        const color = getRiskPdfColor(riskLevel);
        doc.setTextColor(color.textColor);
    } else {
        doc.setTextColor(0, 0, 0);
    }
    
    doc.setFont(undefined, isRiskCell ? 'bold' : 'normal');
    const valueLines = doc.splitTextToSize(value, col2Width - 6);
    doc.text(valueLines, x + col1Width + 3, y + 6);
    
    // Reset color
    doc.setTextColor(0, 0, 0);
    
    return rowHeight;
}

// Función para filas combinadas (2 columnas) con bordes MÁS VISIBLES
function drawCombinedRowPDF(doc, x, y, col1Width, col2Width, label, value) {
    doc.setDrawColor(0, 0, 0);
    doc.setLineWidth(0.8); // Línea más gruesa
    
    const totalWidth = col1Width + col2Width;
    
    // Calcular altura dinámica basada en el contenido
    doc.setFontSize(9);
    const valueLines = doc.splitTextToSize(value || 'No especificado', col2Width - 6);
    const lineHeight = 5; // Más espacio entre líneas
    const minHeight = 12; // Altura mínima aumentada
    const contentHeight = Math.max(minHeight, valueLines.length * lineHeight);
    const rowHeight = contentHeight;
    
    // Dibujar bordes VISIBLES Y GRUESOS
    doc.rect(x, y, totalWidth, rowHeight);
    doc.line(x + col1Width, y, x + col1Width, y + rowHeight);
    
    // Fondo columna 1 (gris más oscuro)
    doc.setFillColor(220, 220, 220);
    doc.rect(x, y, col1Width, rowHeight, 'F');
    
    // Fondo columna 2 (blanco)
    doc.setFillColor(255, 255, 255);
    doc.rect(x + col1Width, y, col2Width, rowHeight, 'F');
    
    // Textos - tamaño aumentado para mejor legibilidad
    doc.setTextColor(0, 0, 0);
    
    // Etiqueta (negrita, centrada verticalmente)
    doc.setFont(undefined, 'bold');
    const labelLines = doc.splitTextToSize(label, col1Width - 6);
    const labelY = y + (rowHeight / 2) - ((labelLines.length * lineHeight) / 2) + 3;
    doc.text(labelLines, x + 3, labelY);
    
    // Valor (normal, centrado verticalmente)
    doc.setFont(undefined, 'normal');
    const valueY = y + (rowHeight / 2) - ((valueLines.length * lineHeight) / 2) + 3;
    doc.text(valueLines, x + col1Width + 3, valueY);
    
    return rowHeight;
}

// ========== EXPORTACIÓN E IMPORTACIÓN JSON ==========
function exportToJson() {
    console.log('Ejecutando exportToJson...');
    if (vulnerabilities.length === 0) {
        showNotification('No hay vulnerabilidades para exportar en JSON.', 'error');
        return;
    }
    
    try {
        const jsonContent = JSON.stringify(vulnerabilities, null, 2); 
        
        const blob = new Blob([jsonContent], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `owasp_vulnerabilities_export_${new Date().toISOString().split('T')[0]}.json`;
        
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        showNotification(`Exportación JSON de ${vulnerabilities.length} vulnerabilidad(es) completada.`, 'success');
        
    } catch (error) {
        console.error('Error al exportar a JSON:', error);
        showNotification('Error al exportar los datos a JSON.', 'error');
    }
}

function importJson(event) {
    console.log('Ejecutando importJson (Modo Fusión)...');
    const file = event.target.files[0];
    
    if (!file) {
        return;
    }
    
    if (file.type !== 'application/json') {
        showNotification('Tipo de archivo no válido. Se espera un archivo JSON.', 'error');
        return;
    }

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const content = e.target.result;
            let newVulnerabilities = JSON.parse(content);
            
            if (!Array.isArray(newVulnerabilities)) {
                showNotification('El archivo JSON debe contener un array de vulnerabilidades.', 'error');
                return;
            }
            if (newVulnerabilities.length > 0 && (!newVulnerabilities[0].name || !newVulnerabilities[0].riskLevel)) {
                showNotification('El archivo JSON no tiene el formato de vulnerabilidades esperado.', 'error');
                return;
            }
            
            const initialCount = vulnerabilities.length;

            const existingIds = new Set(vulnerabilities.map(v => v.id));

            const uniqueNewVulnerabilities = newVulnerabilities.filter(vuln => {
                if (vuln.id && existingIds.has(vuln.id)) {
                    return false;
                }
                return true;
            });
            
            const duplicatesCount = newVulnerabilities.length - uniqueNewVulnerabilities.length;

            vulnerabilities = vulnerabilities.concat(uniqueNewVulnerabilities);
            
            const mergedCount = vulnerabilities.length - initialCount;

            saveVulnerabilities();
            renderVulnerabilitiesList();
            updateDashboard();
            
            let message = `${mergedCount} vulnerabilidades únicas cargadas y fusionadas.`;
            if (duplicatesCount > 0) {
                 message += ` (${duplicatesCount} duplicado(s) omitido(s)).`;
            }
            showNotification(message, 'success');
            
        } catch (error) {
            console.error('Error procesando archivo JSON:', error);
            showNotification('Error al parsear el archivo JSON. Asegúrate de que el formato sea correcto.', 'error');
        }
        event.target.value = '';
    };
    
    reader.readAsText(file);
}

// ========== FUNCIONES AUXILIARES ==========
function getRiskPdfColor(riskLevel) {
    switch(riskLevel.toUpperCase()) {
        case 'CRÍTICO': return { r: 220, g: 53, b: 69, textColor: 255 };
        case 'ALTO': return { r: 253, g: 126, b: 20, textColor: 255 };
        case 'MEDIO': return { r: 255, g: 193, b: 7, textColor: 0 };
        case 'BAJO': return { r: 40, g: 167, b: 69, textColor: 255 };
        case 'INFORMATIVO': return { r: 23, g: 162, b: 184, textColor: 255 };
        default: return { r: 108, g: 117, b: 125, textColor: 255 };
    }
}

function formatMitreForPdf(text) {
    if (!text) return 'No especificado';
    const lines = text.split(/[,;\n]/).filter(line => line.trim());
    if (lines.length > 1) {
        return lines.map(line => `• ${line.trim()}`).join('\n');
    }
    if (text.includes('\n')) {
        return text.split('\n')
            .filter(line => line.trim())
            .map(line => `• ${line.trim()}`)
            .join('\n');
    }
    return text;
}

function getRiskHeaderColor(riskLevel) {
    switch(riskLevel.toUpperCase()) {
        case 'CRÍTICO':
            return '#dc3545'; // Rojo
        case 'ALTO':
            return '#fd7e14'; // Naranja
        case 'MEDIO':
            return '#ffc107'; // Amarillo
        case 'BAJO':
            return '#20c997'; // Verde
        case 'INFORMATIVO':
            return '#17a2b8'; // Azul
        default:
            return '#6c757d'; // Gris
    }
}

function formatMitreIds(mitreIds) {
    if (!mitreIds) return 'No especificado';
    
    const ids = mitreIds.split(/[,;\n]/).filter(id => id.trim());
    
    if (ids.length > 1) {
        return ids.map(id => `<div class="list-item">• ${id.trim()}</div>`).join('');
    }
    
    if (mitreIds.includes('\n')) {
        return mitreIds.split('\n')
            .filter(line => line.trim())
            .map(line => `<div class="list-item">• ${line.trim()}</div>`)
            .join('');
    }
    
    return mitreIds;
}

function formatMitreStrategies(strategies) {
    if (!strategies) return 'No especificado';
    
    const lines = strategies.split('\n').filter(line => line.trim());
    
    if (lines.length > 0) {
        return lines.map(line => {
            const cleanedLine = line.replace(/^(\-|\•)\s*/, '');
            return `<div class="list-item">• ${cleanedLine.trim()}</div>`;
        }).join('');
    }
    
    return strategies;
}

function showVulnerabilityDetails(id) {
    const vuln = vulnerabilities.find(v => v.id === id);
    if (!vuln) return;
    
    const modalBody = document.getElementById('modal-body');
    if (!modalBody) return;
    
    modalBody.innerHTML = `
        <div class="vulnerability-details">
            <div class="detail-item">
                <div class="detail-label">Número</div>
                <div class="detail-value">#${vulnerabilities.findIndex(v => v.id === id) + 1}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Nombre</div>
                <div class="detail-value">${vuln.name}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Host</div>
                <div class="detail-value">${vuln.host || 'No especificado'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Ruta Afectada</div>
                <div class="detail-value">${vuln.rutaAfectada || 'No especificado'}</div>
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
    
    const modalElement = document.getElementById('vulnerabilityModal');
    if (modalElement && typeof bootstrap !== 'undefined') {
        const modal = new bootstrap.Modal(modalElement);
        modal.show();
    }
}

function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.textContent = message;
    notification.className = `notification ${type}`;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 5px;
        color: white;
        font-weight: bold;
        z-index: 1000;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        transition: opacity 0.3s;
        background-color: ${type === 'success' ? '#2ecc71' : '#e74c3c'};
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => {
            if (document.body.contains(notification)) {
                document.body.removeChild(notification);
            }
        }, 300);
    }, 3000);
}

function saveVulnerabilities() {
    try {
        localStorage.setItem('owaspVulnerabilities', JSON.stringify(vulnerabilities));
    } catch (error) {
        console.error('Error guardando en localStorage:', error);
    }
}

function loadVulnerabilities() {
    try {
        const saved = localStorage.getItem('owaspVulnerabilities');
        if (saved) {
            vulnerabilities = JSON.parse(saved);
            renderVulnerabilitiesList();
            updateDashboard();
        }
    } catch (error) {
        console.error('Error cargando vulnerabilidades:', error);
        vulnerabilities = [];
    }
}