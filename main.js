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
// ========== INICIALIZACIÓN ==========
document.addEventListener('DOMContentLoaded', function() {
    console.log('Inicializando aplicación...');
    loadTheme();
    
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }
    
    loadVulnerabilities();
    
    // Event listeners corregidos
    const calculateBtn = document.getElementById('calculate-btn');
    const saveBtn = document.getElementById('save-btn');
    const exportWordBtn = document.getElementById('export-report-btn'); // Asumo este ID para Word
    const exportPdfBtn = document.getElementById('export-pdf-btn');     // Nuevo ID para PDF
    
    if (calculateBtn) {
        calculateBtn.addEventListener('click', function() {
            calculateRisk();
        });
    } else {
        console.error('Botón calcular no encontrado');
    }
    
    if (saveBtn) {
        saveBtn.addEventListener('click', function() {
            saveVulnerability();
        });
    } else {
        console.error('Botón guardar no encontrado');
    }

    // Vinculación de botón de Word (si existe)
    if (exportWordBtn && typeof exportToWord === 'function') {
        exportWordBtn.addEventListener('click', exportToWord);
    }
    
    // Vinculación del NUEVO botón de PDF
    if (exportPdfBtn && typeof exportToPdf === 'function') {
        exportPdfBtn.addEventListener('click', exportToPdf);
    } else if (exportPdfBtn) {
        console.error('Función exportToPdf no definida.');
    }
    
    // Event listeners para selects
    document.querySelectorAll('select').forEach(select => {
        select.addEventListener('change', calculateRisk);
    });
    
    // Calcular riesgo inicial
    setTimeout(calculateRisk, 100);

    // Inicializar botones de exportación
    setTimeout(initializeExportButton, 500);
    setTimeout(initializePdfExportButton, 500);
    
    // La línea 'setTimeout(initializeExportButton, 500);' fue reemplazada por la vinculación directa de los botones de exportación.
    
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
        
        console.log('Valores obtenidos:', {sl, m, o, s, lc, li, lav, lac, ed, ee, a, id, fd, rd, nc, pv});
        
        // Calcular promedios (Risk 0-10)
        const likelihood = (sl + m + o + s + ed + ee + a + id) / 8;
        const impact = (lc + li + lav + lac + fd + rd + nc + pv) / 8;
        const risk = (likelihood + impact) / 2; // Promedio entre probabilidad e impacto (0-10)
        
        // MODIFICACIÓN 1: Escalar el riesgo de 0-10 a 0-81
        const scaledRisk = risk * 8.1;
        
        console.log('Resultados:', {likelihood, impact, risk: scaledRisk.toFixed(2)});
        
        // Actualizar UI
        const lsElement = document.querySelector('.LS');
        const isElement = document.querySelector('.IS');
        
        if (lsElement) lsElement.textContent = likelihood.toFixed(2);
        if (isElement) isElement.textContent = impact.toFixed(2);
        
        let riskLevel, riskClass;
        // MODIFICACIÓN 2: Aplicar la nueva clasificación (0-81)
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
            // Mostrar la puntuación escalada (0-81)
            riskElement.textContent = `Riesgo: ${riskLevel} (${scaledRisk.toFixed(2)})`;
            riskElement.className = `risk-indicator ${riskClass}`;
        }
        
        // El chart sigue usando la puntuación original (0-10) para el eje Y, pero se le pasa el riskLevel para el color.
        updateRiskChart(likelihood, impact, risk, riskLevel); 
        
        return { 
            likelihood: parseFloat(likelihood.toFixed(2)), 
            impact: parseFloat(impact.toFixed(2)), 
            // Devolver el riesgo escalado para guardarlo en la vulnerabilidad
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


function updateRiskChart(likelihood, impact, risk, riskLevel) { // MODIFICADO: Agregado riskLevel
    const ctx = document.getElementById('riskChart');
    if (!ctx) {
        console.log('Canvas riskChart no encontrado, puede ser normal si no está en la pestaña activa');
        return;
    }
    
    try {
        const context = ctx.getContext('2d');
        
        if (riskChart) riskChart.destroy();
        
        const chartColor = getRiskChartColor(riskLevel); // MODIFICADO: Obtener color por nivel
        const chartBorder = getRiskChartBorder(riskLevel); // MODIFICADO: Obtener borde por nivel

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
                        chartColor // MODIFICADO
                    ],
                    borderColor: [
                        'rgba(54, 162, 235, 1)',
                        'rgba(255, 99, 132, 1)',
                        chartBorder // MODIFICADO
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
        
        // Validar que tenga al menos un nombre
        if (!formData.name || formData.name.trim() === '') {
            showNotification('Por favor ingresa un nombre para la vulnerabilidad', 'error');
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
    // Función helper para obtener valores seguros
    const getValue = (id) => {
        const element = document.getElementById(id);
        return element ? element.value : '';
    };
    
    return {
        name: getValue('vulnerability-name'),
        host: getValue('host'), // AGREGADO: Nuevo campo para Host
        rutaAfectada: getValue('ruta-afectada'), // AGREGADO: Nuevo campo para Ruta Afectada
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
        console.log('Elementos de lista no encontrados, puede ser normal si no está en la pestaña activa');
        return;
    }
    
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
                <div style="flex: 1;">
                    <h5>${vuln.name}</h5>
                    <p class="mb-1"><strong>Host:</strong> ${vuln.host || 'No especificado'}</p>
                    <p class="mb-1"><strong>OWASP:</strong> ${vuln.owasp || 'No especificado'} | <strong>MITRE:</strong> ${vuln.mitre || 'No especificado'}</p>
                    <p class="mb-1"><strong>Riesgo:</strong> ${vuln.risk.toFixed(2)} | <strong>Probabilidad:</strong> ${vuln.likelihood.toFixed(2)} | <strong>Impacto:</strong> ${vuln.impact.toFixed(2)}</p>
                    <small class="text-muted">Guardado: ${new Date(vuln.date).toLocaleDateString()}</small>
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
    } catch (error) {
        console.error('Error actualizando gráfico OWASP:', error);
    }
}

function updateLegend(owaspCounts) {
    const legendElement = document.getElementById('chart-legend');
    if (!legendElement) return;
    
    legendElement.innerHTML = '';
    
    owaspCategories.forEach((category, index) => {
        if (owaspCounts[index] > 0) {
            const legendItem = document.createElement('div');
            legendItem.className = 'legend-item';
            legendItem.innerHTML = `
                <div class="legend-color" style="background-color: ${categoryColors[index]}"></div>
                <span>${category.split('-')[0].trim()}: ${owaspCounts[index]}</span>
            `;
            legendElement.appendChild(legendItem);
        }
    });
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
                    <td>${vuln.host || vuln.attackVector || 'No especificado'}</td>
                    <td><span class="risk-badge ${vuln.riskClass}-badge">${vuln.riskLevel}</span></td>
                `;
                tableBody.appendChild(row);
            });
        }
    });
}

// ========== EXPORTACIÓN A WORD (MODIFICADA: Separación y Estilo) ==========
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

                    /* Título FUERA de la tabla - PEQUEÑO */
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

                    /* Título DENTRO de la tabla - MUY GRANDE */
                    .vulnerability-table tr:first-child .header-cell {
                        font-size: 28px !important;
                        font-weight: bold;
                        text-align: center !important;
                        background-color: #e9ecef;
                        padding: 30px 35px;
                        line-height: 1.2;
                        height: 100px;
                    }

                    /* Header del reporte pequeño */
                    .report-header h1 {
                        font-size: 18px;
                        margin-bottom: 10px;
                    }
                    
                    .report-header p {
                        font-size: 12px;
                        margin-bottom: 5px;
                    }

                    /* CLASE QUE GENERA LA SEPARACIÓN Y EL SALTO DE PÁGINA */
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

                    /* Ancho de columnas 40%/60% */
                    .vulnerability-table tr td:first-child {
                        width: 30% !important; /* ANCHO MODIFICADO: 30% para las etiquetas (Host, Detalle, etc.) */
                        font-weight: bold;
                        font-size: 17px;
                    }
                    
                    .vulnerability-table tr td:not(:first-child) {
                        width: 70% !important; /* ANCHO MODIFICADO: 70% para los valores de los datos */
                    }

                    /* Excepción para las primeras 3 filas que tienen estructura diferente */
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

                    /* Celdas de riesgo grandes */
                    .vulnerability-table tr:nth-child(1) td:nth-child(3),
                    .vulnerability-table tr:nth-child(2) td:nth-child(3),
                    .vulnerability-table tr:nth-child(3) td:nth-child(3) {
                        text-align: center !important;
                        font-size: 22px;
                        font-weight: bold;
                        padding: 30px 35px;
                        min-height: 70px;
                    }

                    /* Primera fila más grande */
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
                        Vulnerabilidad ${index + 1}: **${vuln.name || 'No especificado'}**
                    </div>
                    
                    <table class="vulnerability-table" align="center">
                        <tr>
                            <td rowspan="3" class="header-cell" style="font-weight: bold; width: 25%; background-color: #ffffff; text-align: justify;">
                                ${vuln.name || 'No especificado'}
                            </td>
                            
                            <td class="header-cell" style="width: 15%; background-color: #f2f2f2; font-weight: bold; text-align: center;">
                                Resultados del Análisis
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

        // Generación y descarga del archivo .doc
        const blob = new Blob([htmlContent], { type: 'application/msword' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `reporte_vulnerabilidades_${new Date().toISOString().split('T')[0]}.doc`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showNotification(`Reporte exportado con ${vulnerabilities.length} vulnerabilidad(es)`, 'success');
        
    } catch (error) {
        console.error('Error al exportar:', error);
        showNotification('Error al exportar el reporte', 'error');
    }
}

/**
 * Abre el reporte en una nueva ventana para que el usuario pueda usar 'Imprimir a PDF' del navegador.
 */
function exportToPdf() {
    const reportHtml = generateReportHtml(); // Usa la misma función que genera el HTML del reporte

    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <title>Reporte de Vulnerabilidades (PDF)</title>
            <style>
                /* Estilos básicos para impresión, puedes añadir más si lo deseas */
                body { font-family: 'Arial', sans-serif; margin: 20px; color: #333; }
                h1 { color: #2c3e50; border-bottom: 2px solid #ddd; padding-bottom: 10px; }
                .risk-critico { background-color: #FF0000; color: white; }
                /* Agrega aquí los estilos .risk-badge, .risk-alto, etc. si no están en style.css */
            </style>
            <link rel="stylesheet" href="style.css" media="print">
        </head>
        <body>
            ${reportHtml}
        </body>
        </html>
    `);
    printWindow.document.close();

    // Abrir el diálogo de impresión después de que la ventana cargue
    printWindow.onload = function() {
        printWindow.print();
    };
}


// Función auxiliar para obtener color del header según riesgo
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

// Función auxiliar para formatear IDs MITRE
function formatMitreIds(mitreIds) {
    if (!mitreIds) return 'No especificado';
    
    // Si hay múltiples IDs separados por comas o saltos de línea
    const ids = mitreIds.split(/[,;\n]/).filter(id => id.trim());
    
    if (ids.length > 1) {
        return ids.map(id => `<div class="list-item">• ${id.trim()}</div>`).join('');
    }
    
    // Si contiene múltiples IDs separados por salto de línea sin viñetas
    if (mitreIds.includes('\n')) {
        return mitreIds.split('\n')
            .filter(line => line.trim())
            .map(line => `<div class="list-item">• ${line.trim()}</div>`)
            .join('');
    }
    
    return mitreIds;
}

// Función auxiliar para formatear estrategias MITRE
function formatMitreStrategies(strategies) {
    if (!strategies) return 'No especificado';
    
    // Si es texto plano, convertirlo en lista. Asume que cada línea es un elemento.
    const lines = strategies.split('\n').filter(line => line.trim());
    
    if (lines.length > 0) {
        return lines.map(line => {
            // Reemplazar guiones o asteriscos iniciales por un punto de lista HTML
            const cleanedLine = line.replace(/^(\-|\•)\s*/, '');
            return `<div class="list-item">• ${cleanedLine.trim()}</div>`;
        }).join('');
    }
    
    return strategies;
}

// ========== INICIALIZACIÓN DEL BOTÓN DE EXPORTACIÓN ==========
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

// ========== FUNCIONES FALTANTES ==========
function showVulnerabilityDetails(id) {
    const vuln = vulnerabilities.find(v => v.id === id);
    if (!vuln) return;
    
    const modalBody = document.getElementById('modal-body');
    if (!modalBody) return;
    
    modalBody.innerHTML = `
        <div class="vulnerability-details">
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
    
    // Usar Bootstrap modal si está disponible
    const modalElement = document.getElementById('vulnerabilityModal');
    if (modalElement && typeof bootstrap !== 'undefined') {
        const modal = new bootstrap.Modal(modalElement);
        modal.show();
    }
}

function showNotification(message, type) {
    // Crear elemento de notificación
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
    
    // Remover después de 3 segundos
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
        console.log('Vulnerabilidades guardadas en localStorage');
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
            console.log('Vulnerabilidades cargadas:', vulnerabilities.length);
        }
    } catch (error) {
        console.error('Error cargando vulnerabilidades:', error);
        vulnerabilities = [];
    }
}


// ========== EXPORTACIÓN A PDF ==========
function exportToPDF() {
    console.log('Ejecutando exportToPDF...');
    
    if (vulnerabilities.length === 0) {
        showNotification('No hay vulnerabilidades para exportar', 'error');
        return;
    }

    try {
        // Crear un nuevo documento PDF
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        let yPosition = 20;
        const pageHeight = doc.internal.pageSize.height;
        const margin = 20;
        const lineHeight = 7;
        
        // Encabezado del reporte
        doc.setFontSize(16);
        doc.setFont(undefined, 'bold');
        doc.text('Reporte de Vulnerabilidades de Seguridad', margin, yPosition);
        
        yPosition += 10;
        doc.setFontSize(10);
        doc.setFont(undefined, 'normal');
        doc.text(`Fecha de generación: ${new Date().toLocaleDateString()} ${new Date().toLocaleTimeString()}`, margin, yPosition);
        
        yPosition += 5;
        doc.text(`Total de vulnerabilidades: ${vulnerabilities.length}`, margin, yPosition);
        
        yPosition += 15;
        
        // Iterar sobre cada vulnerabilidad
        vulnerabilities.forEach((vuln, index) => {
            // Verificar si necesitamos una nueva página
            if (yPosition > pageHeight - 50) {
                doc.addPage();
                yPosition = 20;
            }
            
            // Título de la vulnerabilidad con color según riesgo
            const riskColor = getRiskPdfColor(vuln.riskLevel);
            
            doc.setFillColor(riskColor.r, riskColor.g, riskColor.b);
            doc.rect(margin, yPosition, doc.internal.pageSize.width - 2 * margin, 8, 'F');
            
            doc.setFontSize(12);
            doc.setFont(undefined, 'bold');
            doc.setTextColor(riskColor.textColor);
            doc.text(`Vulnerabilidad ${index + 1}: ${vuln.name || 'No especificado'}`, margin + 2, yPosition + 5);
            
            yPosition += 15;
            doc.setTextColor(0, 0, 0); // Reset to black
            
            // Función helper para agregar campo
            const addField = (label, value, isBold = false) => {
                if (yPosition > pageHeight - 20) {
                    doc.addPage();
                    yPosition = 20;
                }
                
                doc.setFont(undefined, 'bold');
                doc.setFontSize(9);
                doc.text(`${label}:`, margin, yPosition);
                
                doc.setFont(undefined, isBold ? 'bold' : 'normal');
                
                // Dividir texto largo en múltiples líneas
                const lines = doc.splitTextToSize(value || 'No especificado', doc.internal.pageSize.width - 2 * margin - 40);
                doc.text(lines, margin + 40, yPosition);
                
                yPosition += (lines.length * lineHeight) + 2;
            };
            
            // Campos principales
            addField('Host', vuln.host || vuln.attackVector || vuln.threatAgent || 'No especificado');
            addField('Ruta afectada', vuln.rutaAfectada || vuln.securityWeakness || 'No especificado');
            addField('Nivel de Riesgo', `${vuln.riskLevel} (${vuln.risk.toFixed(2)})`, true);
            addField('OWASP 2021', vuln.owasp || 'No especificado');
            addField('MITRE ID', formatMitreForPdf(vuln.mitre));
            addField('Criticidad según Herramienta', vuln.toolCriticity || 'No especificado');
            addField('Detalle', vuln.detail || 'No especificado');
            addField('Descripción', vuln.description || 'No especificado');
            addField('Recomendación', vuln.recommendation || 'No especificado');
            addField('Estrategia de Detección MITRE', formatMitreForPdf(vuln.mitreDetection));
            addField('Estrategia de Mitigación MITRE', formatMitreForPdf(vuln.mitreMitigation));
            addField('Métricas', `Probabilidad: ${vuln.likelihood.toFixed(2)} | Impacto: ${vuln.impact.toFixed(2)} | Riesgo: ${vuln.risk.toFixed(2)}`);
            
            // Espacio entre vulnerabilidades
            yPosition += 10;
            
            // Línea separadora
            if (index < vulnerabilities.length - 1) {
                doc.setDrawColor(200, 200, 200);
                doc.line(margin, yPosition, doc.internal.pageSize.width - margin, yPosition);
                yPosition += 15;
            }
        });
        
        // Guardar el PDF
        doc.save(`reporte_vulnerabilidades_${new Date().toISOString().split('T')[0]}.pdf`);
        
        showNotification(`PDF exportado con ${vulnerabilities.length} vulnerabilidad(es)`, 'success');
        
    } catch (error) {
        console.error('Error al exportar PDF:', error);
        showNotification('Error al exportar el PDF. Asegúrate de que jsPDF esté cargado.', 'error');
    }
}

// Función auxiliar para colores en PDF
function getRiskPdfColor(riskLevel) {
    switch(riskLevel.toUpperCase()) {
        case 'CRÍTICO':
            return { r: 220, g: 53, b: 69, textColor: 255 }; // Rojo, texto blanco
        case 'ALTO':
            return { r: 253, g: 126, b: 20, textColor: 255 }; // Naranja, texto blanco
        case 'MEDIO':
            return { r: 255, g: 193, b: 7, textColor: 0 }; // Amarillo, texto negro
        case 'BAJO':
            return { r: 32, g: 201, b: 151, textColor: 255 }; // Verde, texto blanco
        case 'INFORMATIVO':
            return { r: 23, g: 162, b: 184, textColor: 255 }; // Azul, texto blanco
        default:
            return { r: 108, g: 117, b: 125, textColor: 255 }; // Gris, texto blanco
    }
}

// Función auxiliar para formatear MITRE en PDF
function formatMitreForPdf(text) {
    if (!text) return 'No especificado';
    
    // Limpiar y formatear texto para PDF
    const lines = text.split(/[,;\n]/).filter(line => line.trim());
    if (lines.length > 1) {
        return lines.map(line => `• ${line.trim()}`).join('\n');
    }
    
    return text;
}

// ========== INICIALIZACIÓN DEL BOTÓN DE EXPORTACIÓN PDF ==========
function initializePdfExportButton() {
    const pdfExportBtn = document.getElementById('export-pdf-btn');
    if (pdfExportBtn) {
        pdfExportBtn.addEventListener('click', exportToPDF);
        console.log('Botón de exportación PDF inicializado');
    } else {
        console.log('Botón de exportación PDF no encontrado');
    }
}