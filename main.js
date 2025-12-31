// Variables globales
let vulnerabilities = [];
let riskChart, riskDistributionChart, owaspDistributionChart;
let currentTheme = 'light';
let vulnerabilityToDelete = null;

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

    // Configurar el select de agente de amenazas
    setupThreatAgentSelect();
    
    // Configurar todos los botones
    setupEventListeners();
    
    document.querySelectorAll('select').forEach(select => {
        select.addEventListener('change', calculateRisk);
    });
    
    setTimeout(calculateRisk, 100);

    console.log('Aplicación inicializada correctamente');
});

function setupEventListeners() {
    const calculateBtn = document.getElementById('calculate-btn');
    const saveBtn = document.getElementById('save-btn');
    const updateBtn = document.getElementById('update-btn');
    const cancelEditBtn = document.getElementById('cancel-edit-btn');
    const clearFormBtn = document.getElementById('clear-form-btn');
    const deleteAllBtn = document.getElementById('delete-all-btn');
    const exportWordBtn = document.getElementById('export-all-btn');
    const exportPdfBtn = document.getElementById('export-pdf-btn');
    const exportJsonBtn = document.getElementById('export-json-btn');
    const exportExecutiveBtn = document.getElementById('export-executive-btn');
    const importFileInput = document.getElementById('import-file-input');
    const confirmDeleteBtn = document.getElementById('confirm-delete-btn');
    
    if (calculateBtn) calculateBtn.addEventListener('click', calculateRisk);
    if (saveBtn) saveBtn.addEventListener('click', saveVulnerability);
    if (updateBtn) updateBtn.addEventListener('click', updateVulnerability);
    if (cancelEditBtn) cancelEditBtn.addEventListener('click', cancelEdit);
    if (clearFormBtn) clearFormBtn.addEventListener('click', clearForm);
    if (deleteAllBtn) deleteAllBtn.addEventListener('click', confirmDeleteAll);
    if (exportWordBtn) exportWordBtn.addEventListener('click', exportToWord);
    if (exportPdfBtn) exportPdfBtn.addEventListener('click', exportToPDF);
    if (exportJsonBtn) exportJsonBtn.addEventListener('click', exportToJson);
    if (exportExecutiveBtn) exportExecutiveBtn.addEventListener('click', exportExecutiveReport);
    if (importFileInput) importFileInput.addEventListener('change', importJson);
    if (confirmDeleteBtn) confirmDeleteBtn.addEventListener('click', deleteVulnerability);
}

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
        
        const likelihood = (sl + m + o + s + ed + ee + a + id) / 8;
        const impact = (lc + li + lav + lac + fd + rd + nc + pv) / 8;
        const risk = (likelihood + impact) / 2;
        const scaledRisk = risk * 8.1;
        
        const lsElement = document.querySelector('.LS');
        const isElement = document.querySelector('.IS');
        
        if (lsElement) lsElement.textContent = likelihood.toFixed(2);
        if (isElement) isElement.textContent = impact.toFixed(2);
        
        let riskLevel, riskClass;
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

// ========== FUNCIONES CRUD ==========

// CREAR - Guardar nueva vulnerabilidad
function saveVulnerability() {
    console.log('Guardando vulnerabilidad...');
    
    try {
        if (!validateRequiredFields()) {
            return;
        }
        
        const riskData = calculateRisk();
        const formData = getFormData();
        
        const vulnerability = {
            id: Date.now(),
            name: formData.name.trim(),
            ...riskData,
            ...formData,
            date: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        
        vulnerabilities.push(vulnerability);
        saveVulnerabilities();
        renderVulnerabilitiesList();
        updateDashboard();
        
        clearForm();
        showNotification(`Vulnerabilidad "${vulnerability.name}" guardada con nivel de riesgo: ${riskData.riskLevel}`, 'success');
        
    } catch (error) {
        console.error('Error guardando vulnerabilidad:', error);
        showNotification('Error al guardar la vulnerabilidad', 'error');
    }
}

// LEER - Cargar vulnerabilidad para editar
function loadVulnerabilityForEdit(id) {
    const vulnerability = vulnerabilities.find(v => v.id === id);
    if (!vulnerability) {
        showNotification('Vulnerabilidad no encontrada', 'error');
        return;
    }
    
    // Configurar modo edición
    document.getElementById('edit-vulnerability-id').value = id;
    document.getElementById('save-btn').style.display = 'none';
    document.getElementById('update-btn').style.display = 'inline-block';
    document.getElementById('cancel-edit-btn').style.display = 'inline-block';
    
    // Llenar formulario con los datos
    document.getElementById('vulnerability-name').value = vulnerability.name || '';
    document.getElementById('host').value = vulnerability.host || '';
    document.getElementById('ruta-afectada').value = vulnerability.rutaAfectada || '';
    document.getElementById('owasp-category').value = vulnerability.owasp || '';
    document.getElementById('mitre-id').value = vulnerability.mitre || '';
    document.getElementById('tool-criticity').value = vulnerability.toolCriticity || '';
    
    // Manejar agente de amenazas
    if (vulnerability.threatAgent) {
        if (vulnerability.threatAgent.startsWith('Otro:')) {
            document.getElementById('threat-agent').value = 'Otro';
            document.getElementById('other-threat-agent').value = vulnerability.threatAgent.replace('Otro: ', '');
            document.getElementById('other-threat-agent-container').style.display = 'block';
        } else {
            document.getElementById('threat-agent').value = vulnerability.threatAgent;
        }
    }
    
    document.getElementById('attack-vector').value = vulnerability.attackVector || '';
    document.getElementById('detail').value = vulnerability.detail || '';
    document.getElementById('description').value = vulnerability.description || '';
    document.getElementById('recommendation').value = vulnerability.recommendation || '';
    document.getElementById('mitre-detection').value = vulnerability.mitreDetection || '';
    document.getElementById('mitre-mitigation').value = vulnerability.mitreMitigation || '';
    document.getElementById('security-weakness').value = vulnerability.securityWeakness || '';
    document.getElementById('security-controls').value = vulnerability.securityControls || '';
    document.getElementById('technical-business-impact').value = vulnerability.technicalBusinessImpact || '';
    
    // Llenar selects de factores
    const factorIds = ['sl', 'm', 'o', 's', 'lc', 'li', 'lav', 'lac', 'ed', 'ee', 'a', 'id', 'fd', 'rd', 'nc', 'pv'];
    factorIds.forEach(factorId => {
        const element = document.getElementById(factorId);
        if (element && vulnerability[factorId]) {
            element.value = vulnerability[factorId];
        }
    });
    
    // Recalcular riesgo
    setTimeout(() => calculateRisk(), 100);
    
    // Cambiar a pestaña de calculadora
    const calculatorTab = document.getElementById('calculator-tab');
    if (calculatorTab) {
        calculatorTab.click();
    }
    
    showNotification(`Editando vulnerabilidad: ${vulnerability.name}`, 'info');
}

// ACTUALIZAR - Guardar cambios de edición
function updateVulnerability() {
    const id = parseInt(document.getElementById('edit-vulnerability-id').value);
    if (!id) {
        showNotification('No hay vulnerabilidad para actualizar', 'error');
        return;
    }
    
    try {
        if (!validateRequiredFields()) {
            return;
        }
        
        const riskData = calculateRisk();
        const formData = getFormData();
        
        const vulnerabilityIndex = vulnerabilities.findIndex(v => v.id === id);
        if (vulnerabilityIndex === -1) {
            showNotification('Vulnerabilidad no encontrada', 'error');
            return;
        }
        
        // Actualizar vulnerabilidad
        vulnerabilities[vulnerabilityIndex] = {
            ...vulnerabilities[vulnerabilityIndex],
            name: formData.name.trim(),
            ...riskData,
            ...formData,
            updatedAt: new Date().toISOString()
        };
        
        saveVulnerabilities();
        renderVulnerabilitiesList();
        updateDashboard();
        
        // Salir del modo edición
        cancelEdit();
        
        showNotification(`Vulnerabilidad "${formData.name.trim()}" actualizada correctamente`, 'success');
        
    } catch (error) {
        console.error('Error actualizando vulnerabilidad:', error);
        showNotification('Error al actualizar la vulnerabilidad', 'error');
    }
}

// ELIMINAR - Confirmar eliminación
function confirmDeleteVulnerability(id) {
    const vulnerability = vulnerabilities.find(v => v.id === id);
    if (!vulnerability) return;
    
    vulnerabilityToDelete = id;
    
    // Configurar mensaje del modal
    document.getElementById('delete-modal-message').textContent = 
        `¿Está seguro que desea eliminar la vulnerabilidad "${vulnerability.name}"?`;
    
    // Mostrar modal
    const modal = new bootstrap.Modal(document.getElementById('confirmDeleteModal'));
    modal.show();
}

function deleteVulnerability() {
    if (!vulnerabilityToDelete) return;
    
    const vulnerabilityIndex = vulnerabilities.findIndex(v => v.id === vulnerabilityToDelete);
    if (vulnerabilityIndex === -1) {
        showNotification('Vulnerabilidad no encontrada', 'error');
        return;
    }
    
    const vulnerabilityName = vulnerabilities[vulnerabilityIndex].name;
    vulnerabilities.splice(vulnerabilityIndex, 1);
    
    saveVulnerabilities();
    renderVulnerabilitiesList();
    updateDashboard();
    
    // Cerrar modal
    const modal = bootstrap.Modal.getInstance(document.getElementById('confirmDeleteModal'));
    modal.hide();
    
    // Resetear variable
    vulnerabilityToDelete = null;
    
    showNotification(`Vulnerabilidad "${vulnerabilityName}" eliminada correctamente`, 'success');
}

// ELIMINAR TODAS - Confirmar
function confirmDeleteAll() {
    if (vulnerabilities.length === 0) {
        showNotification('No hay vulnerabilidades para eliminar', 'info');
        return;
    }
    
    vulnerabilityToDelete = 'all';
    
    document.getElementById('delete-modal-message').textContent = 
        `¿Está seguro que desea eliminar TODAS las vulnerabilidades (${vulnerabilities.length})? Esta acción no se puede deshacer.`;
    
    const modal = new bootstrap.Modal(document.getElementById('confirmDeleteModal'));
    modal.show();
}

// CANCELAR edición
function cancelEdit() {
    document.getElementById('edit-vulnerability-id').value = '';
    document.getElementById('save-btn').style.display = 'inline-block';
    document.getElementById('update-btn').style.display = 'none';
    document.getElementById('cancel-edit-btn').style.display = 'none';
    
    clearForm();
    showNotification('Edición cancelada', 'info');
}

// LIMPIAR formulario
function clearForm() {
    // Limpiar campos básicos
    const basicFields = [
        'vulnerability-name', 'host', 'ruta-afectada', 'mitre-id', 'tool-criticity',
        'attack-vector', 'security-weakness', 'security-controls', 'technical-business-impact',
        'detail', 'description', 'recommendation', 'mitre-detection', 'mitre-mitigation'
    ];
    
    basicFields.forEach(id => {
        const element = document.getElementById(id);
        if (element) element.value = '';
    });
    
    // Limpiar selects
    const selects = ['owasp-category', 'threat-agent', 'sl', 'm', 'o', 's', 'lc', 'li', 'lav', 'lac', 'ed', 'ee', 'a', 'id', 'fd', 'rd', 'nc', 'pv'];
    selects.forEach(id => {
        const element = document.getElementById(id);
        if (element) element.value = element.querySelector('option[value=""]') ? '' : element.options[0].value;
    });
    
    // Limpiar campo "Otro"
    const otherContainer = document.getElementById('other-threat-agent-container');
    const otherInput = document.getElementById('other-threat-agent');
    if (otherContainer) otherContainer.style.display = 'none';
    if (otherInput) otherInput.value = '';
    
    // Limpiar validación visual
    clearFormValidation();
    
    // Resetear gráfico
    setTimeout(() => calculateRisk(), 100);
}

// ========== FUNCIONES AUXILIARES ==========
function getFormData() {
    const getValue = (id) => {
        const element = document.getElementById(id);
        return element ? element.value : '';
    };
    
    let threatAgentValue = getValue('threat-agent');
    if (threatAgentValue === 'Otro') {
        const otherValue = getValue('other-threat-agent');
        if (otherValue.trim()) {
            threatAgentValue = `Otro: ${otherValue.trim()}`;
        }
    }
    
    return {
        name: getValue('vulnerability-name'),
        host: getValue('host'),
        rutaAfectada: getValue('ruta-afectada'),
        owasp: getValue('owasp-category'),
        mitre: getValue('mitre-id'),
        toolCriticity: getValue('tool-criticity'),
        threatAgent: threatAgentValue,
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

// ========== VALIDACIÓN ==========
function validateRequiredFields() {
    const requiredFields = [
        { id: 'vulnerability-name', name: 'Nombre de la Vulnerabilidad' },
        { id: 'host', name: 'Host' },
        { id: 'owasp-category', name: 'Categoría OWASP 2021' },
        { id: 'ruta-afectada', name: 'Ruta Afectada' },
        { id: 'mitre-id', name: 'MITRE ID' },
        { id: 'tool-criticity', name: 'Criticidad según Herramienta' },
        { id: 'threat-agent', name: 'Agente de Amenazas' },
        { id: 'attack-vector', name: 'Vector de Ataque' },
        { id: 'detail', name: 'Detalle' },
        { id: 'description', name: 'Descripción' },
        { id: 'recommendation', name: 'Recomendación' },
        { id: 'mitre-detection', name: 'Estrategia de Detección MITRE' },
        { id: 'mitre-mitigation', name: 'Estrategia de Mitigación MITRE' },
        { id: 'security-weakness', name: 'Debilidad de Seguridad' },
        { id: 'security-controls', name: 'Controles de Seguridad' },
        { id: 'technical-business-impact', name: 'Impacto Técnico - Negocio' }
    ];
    
    const requiredSelects = [
        { id: 'sl', name: 'Nivel de habilidad' },
        { id: 'm', name: 'Motivo Economico del agente' },
        { id: 'o', name: 'Oportunidad de Ataque' },
        { id: 's', name: 'Tamaño del Agente de Amenaza' },
        { id: 'lc', name: 'Pérdida de confidencialidad' },
        { id: 'li', name: 'Pérdida de integridad' },
        { id: 'lav', name: 'Impacto en la Disponibilidad' },
        { id: 'lac', name: 'Rastreabilidad del Ataque' },
        { id: 'ed', name: 'Facilidad de descubrimiento' },
        { id: 'ee', name: 'Facilidad de explotación' },
        { id: 'a', name: 'Conocimiento de la Vulnerabilidad' },
        { id: 'id', name: 'Detección de intrusiones' },
        { id: 'fd', name: 'Daño financiero' },
        { id: 'rd', name: 'Daño a la reputación' },
        { id: 'nc', name: 'Incumplimiento' },
        { id: 'pv', name: 'Violación de privacidad' }
    ];
    
    let isValid = true;
    let firstEmptyField = null;
    let emptyFieldsCount = 0;
    
    const allInputs = document.querySelectorAll('.form-control, select.form-control');
    allInputs.forEach(element => {
        element.classList.remove('is-invalid', 'is-valid');
        const existingError = element.parentElement.querySelector('.invalid-feedback');
        if (existingError) {
            existingError.remove();
        }
    });
    
    function validateField(fieldInfo, element) {
        if (!element) return false;
        
        let value;
        if (element.tagName === 'SELECT') {
            value = element.value;
        } else if (element.tagName === 'TEXTAREA') {
            value = element.value.trim();
        } else {
            value = element.value.trim();
        }
        
        if (!value || value === '') {
            isValid = false;
            emptyFieldsCount++;
            
            element.classList.add('is-invalid');
            
            const errorDiv = document.createElement('div');
            errorDiv.className = 'invalid-feedback';
            errorDiv.textContent = `El campo "${fieldInfo.name}" es obligatorio.`;
            
            element.parentElement.appendChild(errorDiv);
            
            if (!firstEmptyField) {
                firstEmptyField = element;
            }
            return false;
        } else {
            element.classList.add('is-valid');
            return true;
        }
    }
    
    requiredFields.forEach(field => {
        const element = document.getElementById(field.id);
        validateField(field, element);
    });
    
    requiredSelects.forEach(field => {
        const element = document.getElementById(field.id);
        validateField(field, element);
    });
    
    const threatAgentSelect = document.getElementById('threat-agent');
    const otherThreatAgentInput = document.getElementById('other-threat-agent');
    
    if (threatAgentSelect && threatAgentSelect.value === 'Otro') {
        if (!otherThreatAgentInput || !otherThreatAgentInput.value.trim()) {
            isValid = false;
            emptyFieldsCount++;
            
            if (otherThreatAgentInput) {
                otherThreatAgentInput.classList.add('is-invalid');
                
                const errorDiv = document.createElement('div');
                errorDiv.className = 'invalid-feedback';
                errorDiv.textContent = 'Debe especificar el tipo de agente cuando selecciona "Otro"';
                
                otherThreatAgentInput.parentElement.appendChild(errorDiv);
                
                if (!firstEmptyField) {
                    firstEmptyField = otherThreatAgentInput;
                }
            }
        } else {
            otherThreatAgentInput.classList.add('is-valid');
            otherThreatAgentInput.classList.remove('is-invalid');
            
            const existingError = otherThreatAgentInput.parentElement.querySelector('.invalid-feedback');
            if (existingError) {
                existingError.remove();
            }
        }
    } else if (otherThreatAgentInput) {
        otherThreatAgentInput.classList.remove('is-invalid', 'is-valid');
        const existingError = otherThreatAgentInput.parentElement.querySelector('.invalid-feedback');
        if (existingError) {
            existingError.remove();
        }
    }
    
    if (firstEmptyField) {
        firstEmptyField.scrollIntoView({ 
            behavior: 'smooth', 
            block: 'center' 
        });
        firstEmptyField.focus();
        
        const message = emptyFieldsCount > 1 
            ? `Hay ${emptyFieldsCount} campos obligatorios sin completar.`
            : `Hay 1 campo obligatorio sin completar.`;
        
        showNotification(message, 'error');
    }
    
    return isValid;
}

function clearFormValidation() {
    const allElements = document.querySelectorAll('.form-control, select.form-control');
    allElements.forEach(element => {
        element.classList.remove('is-invalid', 'is-valid');
        const existingError = element.parentElement.querySelector('.invalid-feedback');
        if (existingError) {
            existingError.remove();
        }
    });
}

// ========== MANEJO DEL SELECT "AGENTE DE AMENAZAS" ==========
function setupThreatAgentSelect() {
    const threatAgentSelect = document.getElementById('threat-agent');
    const otherContainer = document.getElementById('other-threat-agent-container');
    const otherInput = document.getElementById('other-threat-agent');
    
    if (threatAgentSelect && otherContainer && otherInput) {
        threatAgentSelect.addEventListener('change', function() {
            if (this.value === 'Otro') {
                otherContainer.style.display = 'block';
                otherInput.required = true;
                otherInput.focus();
            } else {
                otherContainer.style.display = 'none';
                otherInput.required = false;
                otherInput.value = '';
            }
        });
        
        otherInput.addEventListener('blur', function() {
            if (threatAgentSelect.value === 'Otro' && !this.value.trim()) {
                this.classList.add('is-invalid');
                
                let errorDiv = this.parentElement.querySelector('.invalid-feedback');
                if (!errorDiv) {
                    errorDiv = document.createElement('div');
                    errorDiv.className = 'invalid-feedback';
                    this.parentElement.appendChild(errorDiv);
                }
                errorDiv.textContent = 'Debe especificar el tipo de agente cuando selecciona "Otro"';
            }
        });
        
        otherInput.addEventListener('input', function() {
            if (this.value.trim()) {
                this.classList.remove('is-invalid');
                const errorDiv = this.parentElement.querySelector('.invalid-feedback');
                if (errorDiv) {
                    errorDiv.remove();
                }
            }
        });
    }
}

// ========== RENDERIZADO DE LISTAS ==========
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
    
    const sortedVulnerabilities = [...vulnerabilities].sort((a, b) => b.id - a.id);
    
    sortedVulnerabilities.forEach((vuln, index) => {
        const item = document.createElement('div');
        item.className = 'vulnerability-item';
        item.innerHTML = `
            <div class="vulnerability-header">
                <div class="vulnerability-number">${sortedVulnerabilities.length - index}</div>
                <div class="vulnerability-content">
                    <div class="d-flex justify-content-between align-items-start">
                        <div style="flex: 1;">
                            <h5 class="mb-2">${vuln.name}</h5>
                            <p class="mb-1"><strong>Host:</strong> ${vuln.host || 'No especificado'}</p>
                            <p class="mb-1"><strong>OWASP:</strong> ${vuln.owasp || 'No especificado'} | <strong>MITRE:</strong> ${vuln.mitre || 'No especificado'}</p>
                            <p class="mb-1"><strong>Riesgo:</strong> ${vuln.risk.toFixed(2)} | <strong>Probabilidad:</strong> ${vuln.likelihood.toFixed(2)} | <strong>Impacto:</strong> ${vuln.impact.toFixed(2)}</p>
                            <small class="text-muted">Actualizado: ${new Date(vuln.updatedAt || vuln.date).toLocaleDateString()} ${new Date(vuln.updatedAt || vuln.date).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</small>
                        </div>
                        <div class="ms-3">
                            <span class="risk-badge ${vuln.riskClass}-badge">${vuln.riskLevel}</span>
                        </div>
                    </div>
                </div>
            </div>
            <div class="d-flex justify-content-end mt-3 gap-2">
                <button class="btn btn-sm btn-primary edit-btn" data-id="${vuln.id}">
                    ✏️ Editar
                </button>
                <button class="btn btn-sm btn-info view-btn" data-id="${vuln.id}">
                    👁️ Ver Detalles
                </button>
                <button class="btn btn-sm btn-danger delete-btn" data-id="${vuln.id}">
                    🗑️ Eliminar
                </button>
            </div>
        `;
        
        // Agregar event listeners a los botones
        const editBtn = item.querySelector('.edit-btn');
        const viewBtn = item.querySelector('.view-btn');
        const deleteBtn = item.querySelector('.delete-btn');
        
        editBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            loadVulnerabilityForEdit(vuln.id);
        });
        
        viewBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            showVulnerabilityDetails(vuln.id);
        });
        
        deleteBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            confirmDeleteVulnerability(vuln.id);
        });
        
        listElement.appendChild(item);
    });
}

function updateDashboardTable() {
    const tableBody = document.getElementById('dashboard-vulnerabilities-list');
    if (!tableBody) return;
    
    tableBody.innerHTML = '';
    
    if (vulnerabilities.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="6" style="text-align: center;">No hay vulnerabilidades registradas</td></tr>';
        return;
    }
    
    const vulnerabilitiesByCategory = {};
    owaspCategories.forEach((_, index) => {
        vulnerabilitiesByCategory[index] = vulnerabilities.filter(v => {
            if (!v.owasp) return false;
            return owaspCategories[index].startsWith(v.owasp);
        });
    });
    
    const sortedCategories = [...owaspCategories].map((cat, idx) => ({
        category: cat,
        index: idx,
        count: vulnerabilitiesByCategory[idx].length
    })).filter(item => item.count > 0)
      .sort((a, b) => b.count - a.count);
    
    let globalCounter = 1;
    
    sortedCategories.forEach((catItem, catIndex) => {
        const categoryVulns = vulnerabilitiesByCategory[catItem.index];
        
        const categoryRow = document.createElement('tr');
        categoryRow.className = `risk-${catItem.index}`;
        categoryRow.innerHTML = `
            <td colspan="6" style="font-weight: bold; background-color: ${categoryColors[catItem.index].replace('0.8', '0.2')}">
                ${catItem.category} (${categoryVulns.length} vulnerabilidad${categoryVulns.length !== 1 ? 'es' : ''})
            </td>
        `;
        tableBody.appendChild(categoryRow);
        
        const sortedVulns = categoryVulns.sort((a, b) => b.risk - a.risk);
        
        sortedVulns.forEach((vuln, vulnIndex) => {
            const row = document.createElement('tr');
            row.className = `risk-${catItem.index}`;
            row.innerHTML = `
                <td style="font-weight: bold; text-align: center; width: 50px;">
                    ${globalCounter++}
                </td>
                <td>${vuln.owasp || 'No especificado'}</td>
                <td>${vuln.name}</td>
                <td>${vuln.host || 'No especificado'}</td>
                <td><span class="risk-badge ${vuln.riskClass}-badge">${vuln.riskLevel}</span></td>
                <td>
                    <div class="d-flex gap-1">
                        <button class="btn btn-sm btn-primary edit-dashboard-btn" data-id="${vuln.id}" title="Editar">
                            ✏️
                        </button>
                        <button class="btn btn-sm btn-info view-dashboard-btn" data-id="${vuln.id}" title="Ver Detalles">
                            👁️
                        </button>
                        <button class="btn btn-sm btn-danger delete-dashboard-btn" data-id="${vuln.id}" title="Eliminar">
                            🗑️
                        </button>
                    </div>
                </td>
            `;
            
            // Agregar event listeners a los botones del dashboard
            row.querySelector('.edit-dashboard-btn').addEventListener('click', () => {
                loadVulnerabilityForEdit(vuln.id);
            });
            
            row.querySelector('.view-dashboard-btn').addEventListener('click', () => {
                showVulnerabilityDetails(vuln.id);
            });
            
            row.querySelector('.delete-dashboard-btn').addEventListener('click', () => {
                confirmDeleteVulnerability(vuln.id);
            });
            
            tableBody.appendChild(row);
        });
    });
}

// ========== FUNCIONES DE VISUALIZACIÓN ==========
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
            <div class="detail-item">
                <div class="detail-label">Fecha de Creación</div>
                <div class="detail-value">${new Date(vuln.date).toLocaleDateString()} ${new Date(vuln.date).toLocaleTimeString()}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Última Actualización</div>
                <div class="detail-value">${new Date(vuln.updatedAt || vuln.date).toLocaleDateString()} ${new Date(vuln.updatedAt || vuln.date).toLocaleTimeString()}</div>
            </div>
        </div>
    `;
    
    const modalElement = document.getElementById('vulnerabilityModal');
    if (modalElement && typeof bootstrap !== 'undefined') {
        const modal = new bootstrap.Modal(modalElement);
        modal.show();
    }
}

// ========== GRÁFICOS ==========
function getRiskChartColor(riskLevel) {
    switch(riskLevel.toUpperCase()) {
        case 'CRÍTICO': return 'rgba(255, 0, 0, 0.7)';
        case 'ALTO': return 'rgba(255, 107, 107, 0.7)';
        case 'MEDIO': return 'rgba(255, 209, 102, 0.7)';
        case 'BAJO': return 'rgba(6, 214, 160, 0.7)';
        case 'INFORMATIVO': return 'rgba(17, 138, 178, 0.7)';
        default: return 'rgba(170, 170, 170, 0.7)';
    }
}

function getRiskChartBorder(riskLevel) {
    switch(riskLevel.toUpperCase()) {
        case 'CRÍTICO': return 'rgba(255, 0, 0, 1)';
        case 'ALTO': return 'rgba(255, 107, 107, 1)';
        case 'MEDIO': return 'rgba(255, 209, 102, 1)';
        case 'BAJO': return 'rgba(6, 214, 160, 1)';
        case 'INFORMATIVO': return 'rgba(17, 138, 178, 1)';
        default: return 'rgba(170, 170, 170, 1)';
    }
}

function updateRiskChart(likelihood, impact, risk, riskLevel) {
    const ctx = document.getElementById('riskChart');
    if (!ctx) return;
    
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
                        ticks: { stepSize: 1 }
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

// ========== DASHBOARD ==========
function updateDashboard() {
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
                        labels: { padding: 20, usePointStyle: true }
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
                    legend: { 
                        display: true, 
                        position: 'right', 
                        labels: {
                            font: { size: 14 },
                            filter: function (legendItem, data) {
                                return data.datasets[0].data[legendItem.index] > 0;
                            },
                            generateLabels: function(chart) {
                                const data = chart.data;
                                return data.labels.map((label, i) => {
                                    const count = data.datasets[0].data[i];
                                    const categoryId = label.split(' - ')[0].trim();
                                    
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

// ========== EXPORTACIÓN ==========
function exportToWord() {
    // ... (código de exportación a Word existente) ...
    console.log('Exportando a Word...');
    // Implementación existente
}

function exportExecutiveReport() {
    // ... (código de exportación ejecutiva existente) ...
    console.log('Exportando informe ejecutivo...');
    // Implementación existente
}

function exportToPDF() {
    // ... (código de exportación a PDF existente) ...
    console.log('Exportando a PDF...');
    // Implementación existente
}

function exportToJson() {
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
    const file = event.target.files[0];
    if (!file) return;
    
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
            
            const initialCount = vulnerabilities.length;
            const existingIds = new Set(vulnerabilities.map(v => v.id));
            
            const uniqueNewVulnerabilities = newVulnerabilities.filter(vuln => {
                if (vuln.id && existingIds.has(vuln.id)) {
                    return false;
                }
                if (!vuln.id) {
                    vuln.id = Date.now() + Math.random();
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

// ========== ALMACENAMIENTO ==========
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

// ========== NOTIFICACIONES ==========
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
        background-color: ${type === 'success' ? '#2ecc71' : 
                         type === 'error' ? '#e74c3c' : 
                         type === 'info' ? '#3498db' : '#f39c12'};
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
