// Variables globales
let vulnerabilities = [];
let riskChart, riskDistributionChart, owaspDistributionChart;
let currentTheme = 'light';

// Categorías OWASP TOP 10 WEB 2025 (español)
const owaspWebCategories = [
    "A01:2025 - Control de Acceso Roto",
    "A02:2025 - Configuración de Seguridad Incorrecta",
    "A03:2025 - Fallas en la Cadena de Suministro de Software",
    "A04:2025 - Fallas Criptográficas",
    "A05:2025 - Inyección",
    "A06:2025 - Diseño Inseguro",
    "A07:2025 - Fallas de Autenticación",
    "A08:2025 - Fallas de Integridad de Software o Datos",
    "A09:2025 - Fallas de Registro y Alertas de Seguridad",
    "A10:2025 - Manejo Inadecuado de Condiciones Excepcionales"
];

// Categorías OWASP TOP 10 API 2023 (español)
const owaspApiCategories = [
    "API1:2023 - Autorización Robusta a Nivel de Objeto",
    "API2:2023 - Autenticación Robusta",
    "API3:2023 - Autorización Robusta a Nivel de Propiedades del Objeto",
    "API4:2023 - Consumo de Recursos sin Restricciones",
    "API5:2023 - Autorización Robusta a Nivel de Función",
    "API6:2023 - Acceso sin Restricciones a Flujos de Negocio Sensibles",
    "API7:2023 - Falsificación de Solicitudes del Lado del Servidor (SSRF)",
    "API8:2023 - Configuración de Seguridad Incorrecta",
    "API9:2023 - Gestión Inadecuada del Inventario",
    "API10:2023 - Consumo Inseguro de APIs"
];

// Categorías OWASP TOP 10 MOBILE 2024 (español)
const owaspMobileCategories = [
    "M1:2024 - Uso Inadecuado de Credenciales",
    "M2:2024 - Cadena de Suministro Insegura",
    "M3:2024 - Autenticación/Autorización Insegura",
    "M4:2024 - Validación de Entrada/Salida Insuficiente",
    "M5:2024 - Comunicación Insegura",
    "M6:2024 - Controles de Privacidad Inadecuados",
    "M7:2024 - Protecciones Binarias Insuficientes",
    "M8:2024 - Configuración de Seguridad Incorrecta",
    "M9:2024 - Almacenamiento de Datos Inseguro",
    "M10:2024 - Criptografía Insuficiente"
];

// Colores para cada categoría
const categoryColors = {
    web: [
        'rgba(54, 162, 235, 0.8)',   // Azul
        'rgba(54, 162, 235, 0.8)',
        'rgba(54, 162, 235, 0.8)',
        'rgba(54, 162, 235, 0.8)',
        'rgba(54, 162, 235, 0.8)',
        'rgba(54, 162, 235, 0.8)',
        'rgba(54, 162, 235, 0.8)',
        'rgba(54, 162, 235, 0.8)',
        'rgba(54, 162, 235, 0.8)',
        'rgba(54, 162, 235, 0.8)'
    ],
    api: [
        'rgba(255, 99, 132, 0.8)',   // Rojo
        'rgba(255, 99, 132, 0.8)',
        'rgba(255, 99, 132, 0.8)',
        'rgba(255, 99, 132, 0.8)',
        'rgba(255, 99, 132, 0.8)',
        'rgba(255, 99, 132, 0.8)',
        'rgba(255, 99, 132, 0.8)',
        'rgba(255, 99, 132, 0.8)',
        'rgba(255, 99, 132, 0.8)',
        'rgba(255, 99, 132, 0.8)'
    ],
    mobile: [
        'rgba(75, 192, 192, 0.8)',   // Verde azulado
        'rgba(75, 192, 192, 0.8)',
        'rgba(75, 192, 192, 0.8)',
        'rgba(75, 192, 192, 0.8)',
        'rgba(75, 192, 192, 0.8)',
        'rgba(75, 192, 192, 0.8)',
        'rgba(75, 192, 192, 0.8)',
        'rgba(75, 192, 192, 0.8)',
        'rgba(75, 192, 192, 0.8)',
        'rgba(75, 192, 192, 0.8)'
    ]
};

// ========== FUNCIÓN PARA CONFIGURAR SELECTOR DE ESTÁNDAR OWASP ==========
function setupOwaspStandardSelector() {
    const standardSelect = document.getElementById('owasp-standard');
    const categorySelect = document.getElementById('owasp-category');
    
    if (standardSelect && categorySelect) {
        standardSelect.addEventListener('change', function() {
            const standard = this.value;
            let categories = [];
            
            switch(standard) {
                case 'web':
                    categories = owaspWebCategories;
                    break;
                case 'api':
                    categories = owaspApiCategories;
                    break;
                case 'mobile':
                    categories = owaspMobileCategories;
                    break;
                default:
                    categories = [];
            }
            
            // Limpiar y llenar el select de categorías
            categorySelect.innerHTML = '<option value="">Seleccione categoría OWASP</option>';
            categories.forEach(cat => {
                const option = document.createElement('option');
                option.value = cat;
                option.textContent = cat;
                categorySelect.appendChild(option);
            });
        });
        
        // Trigger inicial para cargar las categorías por defecto (web)
        standardSelect.dispatchEvent(new Event('change'));
    }
}

// ========== FUNCIÓN PARA MIGRAR VULNERABILIDADES EXISTENTES ==========
function migrateVulnerabilities() {
    let migrated = false;
    vulnerabilities = vulnerabilities.map(vuln => {
        if (!vuln.owaspStandard) {
            migrated = true;
            // Detectar si es una categoría API o Mobile basado en el texto
            let standard = 'web';
            if (vuln.owasp) {
                if (vuln.owasp.startsWith('API')) {
                    standard = 'api';
                } else if (vuln.owasp.startsWith('M')) {
                    standard = 'mobile';
                }
            }
            return {
                ...vuln,
                owaspStandard: standard
            };
        }
        return vuln;
    });
    
    if (migrated) {
        saveVulnerabilities();
        console.log('Vulnerabilidades migradas al nuevo formato con estándar OWASP');
    }
}

// ========== FUNCIÓN PARA OBTENER TEXTO COMPLETO DE OWASP ==========
function getOwaspFullText(value) {
    if (!value) return '';
    return value; // Ahora el valor ya es el texto completo
}

// ========== FUNCIONES PARA OBTENER TEXTO DE FACTORES ==========
function getSkillLevelText(value) {
    const options = {
        '1': 'Habilidades de penetración de seguridad',
        '3': 'Habilidades de red y programación',
        '5': 'Usuario avanzado de computadora',
        '6': 'Algunas habilidades técnicas',
        '8': 'Usuario básico de computadora',
        '10': 'Sin habilidades técnicas'
    };
    return options[value] || 'No especificado';
}

function getMotivoEconomicoText(value) {
    const options = {
        '1': 'Baja o ninguna recompensa',
        '2': 'Recompensa moderadamente baja',
        '4': 'Posible recompensa',
        '6': 'Recompensa significativa',
        '8': 'Alto incentivo económico',
        '10': 'Alta recompensa'
    };
    return options[value] || 'No especificado';
}

function getOportunidadAtaqueText(value) {
    const options = {
        '1': 'Acceso completo o recursos requeridos',
        '4': 'Acceso especial o recursos requeridos',
        '7': 'Algún acceso o recursos requeridos',
        '8': 'Acceso público con restricciones',
        '10': 'Sin acceso o recursos requeridos'
    };
    return options[value] || 'No especificado';
}

function getTamanoAgenteText(value) {
    const options = {
        '2': 'Desarrolladores, administradores de sistemas',
        '3': 'Personal interno autorizado',
        '4': 'Usuarios de intranet',
        '5': 'Socios',
        '6': 'Usuarios autenticados',
        '8': 'Clientes registrados',
        '10': 'Usuarios anónimos de Internet'
    };
    return options[value] || 'No especificado';
}

function getPerdidaConfidencialidadText(value) {
    const options = {
        '2': 'Datos no sensibles mínimos divulgados',
        '4': 'Datos internos no críticos',
        '6': 'Datos críticos mínimos divulgados',
        '7': 'Datos críticos extensos divulgados',
        '8': 'Información confidencial crítica',
        '10': 'Todos los datos divulgados'
    };
    return options[value] || 'No especificado';
}

function getPerdidaIntegridadText(value) {
    const options = {
        '1': 'Datos mínimamente corruptos',
        '3': 'Datos mínimamente muy corruptos',
        '5': 'Datos extensamente corruptos',
        '7': 'Datos extensamente muy corruptos',
        '8': 'Datos críticos alterados',
        '10': 'Todos los datos totalmente corruptos'
    };
    return options[value] || 'No especificado';
}

function getImpactoDisponibilidadText(value) {
    const options = {
        '1': 'Servicios secundarios mínimos interrumpidos',
        '5': 'Servicios primarios mínimos interrumpidos / Servicios secundarios extensos interrumpidos',
        '6': 'Múltiples servicios afectados',
        '7': 'Servicios primarios extensos interrumpidos',
        '8': 'Operación crítica interrumpida',
        '10': 'Todos los servicios completamente perdidos'
    };
    return options[value] || 'No especificado';
}

function getRastreabilidadAtaqueText(value) {
    const options = {
        '1': 'Completamente rastreable',
        '7': 'Posiblemente rastreable',
        '8': 'Difícilmente rastreable',
        '10': 'Completamente anónimo'
    };
    return options[value] || 'No especificado';
}

function getFacilidadDescubrimientoText(value) {
    const options = {
        '1': 'Prácticamente imposible',
        '3': 'Difícil',
        '4': 'Moderadamente difícil',
        '7': 'Fácil',
        '10': 'Herramientas automatizadas disponibles'
    };
    return options[value] || 'No especificado';
}

function getFacilidadExplotacionText(value) {
    const options = {
        '1': 'Teórico',
        '3': 'Difícil',
        '4': 'Moderadamente difícil',
        '5': 'Fácil',
        '10': 'Herramientas automatizadas disponibles'
    };
    return options[value] || 'No especificado';
}

function getConocimientoVulnerabilidadText(value) {
    const options = {
        '1': 'Desconocido',
        '4': 'Oculto',
        '6': 'Obvio',
        '8': 'Ampliamente conocido',
        '10': 'Conocimiento público'
    };
    return options[value] || 'No especificado';
}

function getDeteccionIntrusionText(value) {
    const options = {
        '1': 'Alta Detección - Alertas activas y revisión constante',
        '3': 'Buena Detección - Se registra y se revisa periódicamente',
        '8': 'Baja Detección - Se registra, pero no se revisa activamente',
        '10': 'Sin Detección - No se registra o es imposible de detectar'
    };
    return options[value] || 'No especificado';
}

function getDanioFinancieroText(value) {
    const options = {
        '1': 'Menos que el costo de arreglar la vulnerabilidad',
        '3': 'Efecto menor en las ganancias anuales',
        '5': 'Impacto moderado en ganancias',
        '7': 'Efecto significativo en las ganancias anuales',
        '9': 'Impacto financiero severo',
        '10': 'Bancarrota'
    };
    return options[value] || 'No especificado';
}

function getDanioReputacionText(value) {
    const options = {
        '1': 'Daño mínimo',
        '4': 'Pérdida de cuentas principales',
        '5': 'Pérdida de buena voluntad',
        '7': 'Crisis de confianza en la marca',
        '10': 'Daño a la marca'
    };
    return options[value] || 'No especificado';
}

function getIncumplimientoText(value) {
    const options = {
        '2': 'Violación menor',
        '5': 'Violación clara',
        '6': 'Incumplimiento grave',
        '7': 'Violación de alto perfil'
    };
    return options[value] || 'No especificado';
}

function getViolacionPrivacidadText(value) {
    const options = {
        '3': 'Un individuo',
        '4': 'Decenas de personas',
        '5': 'Cientos de personas',
        '7': 'Miles de personas',
        '10': 'Millones de personas'
    };
    return options[value] || 'No especificado';
}

// ========== FUNCIÓN PARA DIBUJAR "TOTAL" EN EL CENTRO DEL GRÁFICO ==========
function drawTotalInCenter(canvasElement, total) {
    if (!canvasElement) return;
    
    const ctx = canvasElement.getContext('2d');
    if (!ctx) return;
    
    const centerX = canvasElement.width / 2;
    const centerY = canvasElement.height / 2;
    
    // Limpiar área central
    const radius = 45;
    ctx.save();
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
    ctx.clip();
    ctx.clearRect(centerX - radius, centerY - radius, radius * 2, radius * 2);
    ctx.restore();
    
    const isDarkTheme = document.documentElement.getAttribute('data-theme') === 'dark';
    const textColor = isDarkTheme ? '#e0e0e0' : '#333';
    
    ctx.save();
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = textColor;
    ctx.font = 'bold 24px "Segoe UI", Tahoma, Geneva, Verdana, sans-serif';
    
    const fullText = `Total: ${total}`;
    ctx.fillText(fullText, centerX, centerY);
    
    ctx.restore();
}

// ========== FUNCIÓN AUXILIAR PARA BADGE DE ESTÁNDAR ==========
function getStandardBadgeClass(standard) {
    switch(standard) {
        case 'web':
            return 'bg-primary';
        case 'api':
            return 'bg-danger';
        case 'mobile':
            return 'bg-success';
        default:
            return 'bg-secondary';
    }
}

// ========== FUNCIÓN AUXILIAR PARA DETERMINAR ESTÁNDAR DE CATEGORÍA ==========
function getStandardFromCategory(category) {
    if (owaspWebCategories.includes(category)) return 'web';
    if (owaspApiCategories.includes(category)) return 'api';
    if (owaspMobileCategories.includes(category)) return 'mobile';
    return 'web';
}

// ========== INICIALIZACIÓN ==========
document.addEventListener('DOMContentLoaded', function() {
    console.log('Inicializando aplicación...');
    loadTheme();
    
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }
    
    loadVulnerabilities();
    migrateVulnerabilities(); // Migrar vulnerabilidades existentes
    updateOldVulnerabilities();
    
    // Configurar el select de agente de amenazas
    setupThreatAgentSelect();
    
    // Configurar el selector de estándar OWASP
    setupOwaspStandardSelector();
    
    const calculateBtn = document.getElementById('calculate-btn');
    const saveBtn = document.getElementById('save-btn');    
    const exportPdfBtn = document.getElementById('export-pdf-btn');
    const exportJsonBtn = document.getElementById('export-json-btn');
    const exportExecutiveBtn = document.getElementById('export-executive-btn');
    
    if (calculateBtn) {
        calculateBtn.addEventListener('click', calculateRisk);
    }
    
    if (saveBtn) {
        saveBtn.addEventListener('click', saveVulnerability);
    }
    
    if (exportPdfBtn) {
        exportPdfBtn.addEventListener('click', exportToPDF);
    }
    
    if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', exportToJson);
    } 
    
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

    // Listeners para actualizar gráficos
    const dashboardTab = document.getElementById('dashboard-tab');
    if (dashboardTab) {
        dashboardTab.addEventListener('click', function() {
            console.log('Cambiando a pestaña Dashboard...');
            setTimeout(() => {
                const total = vulnerabilities.length;
                const canvas = document.getElementById('riskDistributionChart');
                
                if (canvas && riskDistributionChart) {
                    const data = riskDistributionChart.data.datasets[0]?.data || [];
                    const chartTotal = data.reduce((a, b) => a + b, 0);
                    drawTotalInCenter(canvas, chartTotal || total);
                } else if (canvas) {
                    drawTotalInCenter(canvas, total);
                }
            }, 500);
        });
    }
    
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            setTimeout(() => {
                if (riskDistributionChart) {
                    const canvas = document.getElementById('riskDistributionChart');
                    const data = riskDistributionChart.data.datasets[0]?.data || [];
                    const chartTotal = data.reduce((a, b) => a + b, 0);
                    
                    if (canvas) {
                        drawTotalInCenter(canvas, chartTotal);
                    }
                }
            }, 300);
        });
    }
    
    let resizeTimeout;
    window.addEventListener('resize', function() {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(function() {
            if (riskDistributionChart) {
                riskDistributionChart.resize();
                
                const canvas = document.getElementById('riskDistributionChart');
                const data = riskDistributionChart.data.datasets[0]?.data || [];
                const chartTotal = data.reduce((a, b) => a + b, 0);
                
                if (canvas) {
                    setTimeout(() => {
                        drawTotalInCenter(canvas, chartTotal);
                    }, 200);
                }
            }
        }, 250);
    });
    
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
        const sl = parseFloat(document.getElementById('sl')?.value) || 1;
        const m = parseFloat(document.getElementById('m')?.value) || 1;
        const o = parseFloat(document.getElementById('opp')?.value) || 0;
        const s = parseFloat(document.getElementById('s')?.value) || 2;
        
        const lc = parseFloat(document.getElementById('lc')?.value) || 2;
        const li = parseFloat(document.getElementById('li')?.value) || 1;
        const lav = parseFloat(document.getElementById('lav')?.value) || 1;
        const lac = parseFloat(document.getElementById('lac')?.value) || 1;
        
        const ed = parseFloat(document.getElementById('ed')?.value) || 1;
        const ee = parseFloat(document.getElementById('ee')?.value) || 1;
        const a = parseFloat(document.getElementById('a')?.value) || 1;
        const id = parseFloat(document.getElementById('intrusion')?.value) || 1;
        
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

// ========== VALIDACIÓN DE TODOS LOS CAMPOS OBLIGATORIOS ==========
function validateRequiredFields() {
    const requiredFields = [
        { id: 'vulnerability-name', name: 'Nombre de la Vulnerabilidad' },
        { id: 'host', name: 'Host' },
        { id: 'owasp-standard', name: 'Estándar OWASP' },
        { id: 'owasp-category', name: 'Categoría OWASP' },
        { id: 'ruta-afectada', name: 'Ruta Afectada' },
        { id: 'mitre-id', name: 'MITRE ID' },
        { id: 'tool-criticity', name: 'Criticidad según Herramienta' },
        { id: 'threat-agent', name: 'Agente de Amenazas' },
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
        { id: 'opp', name: 'Oportunidad de Ataque' },
        { id: 's', name: 'Tamaño del Agente de Amenaza' },
        { id: 'lc', name: 'Pérdida de confidencialidad' },
        { id: 'li', name: 'Pérdida de integridad' },
        { id: 'lav', name: 'Impacto en la Disponibilidad' },
        { id: 'lac', name: 'Rastreabilidad del Ataque' },
        { id: 'ed', name: 'Facilidad de descubrimiento' },
        { id: 'ee', name: 'Facilidad de explotación' },
        { id: 'a', name: 'Conocimiento de la Vulnerabilidad' },
        { id: 'intrusion', name: 'Detección de intrusiones' },
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
            ? `Hay ${emptyFieldsCount} campos obligatorios sin completar. Por favor, revisa los campos marcados en rojo.`
            : `Hay 1 campo obligatorio sin completar. Por favor, revisa el campo marcado en rojo.`;
        
        showNotification(message, 'error');
    }
    
    return isValid;
}

// ========== FUNCIÓN saveVulnerability MODIFICADA ==========
function saveVulnerability() {
    console.log('Guardando vulnerabilidad...');
    
    try {
        if (!validateRequiredFields()) {
            return;
        }
        
        const riskData = calculateRisk();
        const formData = getFormData();
        
        const getFactorValue = (id) => {
            const element = document.getElementById(id);
            if (element && element.value) {
                return parseFloat(element.value);
            }
            return 0;
        };
        
        const vulnerability = {
            id: Date.now(),
            name: formData.name.trim(),
            ...riskData,
            ...formData,
            sl: getFactorValue('sl'),
            m: getFactorValue('m'),
            o: getFactorValue('opp'),
            s: getFactorValue('s'),
            lc: getFactorValue('lc'),
            li: getFactorValue('li'),
            lav: getFactorValue('lav'),
            lac: getFactorValue('lac'),
            ed: getFactorValue('ed'),
            ee: getFactorValue('ee'),
            a: getFactorValue('a'),
            intrusion: getFactorValue('intrusion'),
            fd: getFactorValue('fd'),
            rd: getFactorValue('rd'),
            nc: getFactorValue('nc'),
            pv: getFactorValue('pv'),
            date: new Date().toISOString()
        };
        
        vulnerabilities.push(vulnerability);
        saveVulnerabilities();
        renderVulnerabilitiesList();
        updateDashboard();
        
        clearFormValidation();
        
        showNotification(`Vulnerabilidad "${vulnerability.name}" guardada con nivel de riesgo: ${riskData.riskLevel}`, 'success');
        
    } catch (error) {
        console.error('Error guardando vulnerabilidad:', error);
        showNotification('Error al guardar la vulnerabilidad', 'error');
    }
}

// ========== FUNCIÓN PARA LIMPIAR VALIDACIÓN ==========
function clearFormValidation() {
    const allFormElements = [
        'vulnerability-name', 'host', 'ruta-afectada', 'mitre-id', 'tool-criticity',
        'threat-agent', 'attack-vector', 'security-weakness', 'security-controls',
        'technical-business-impact', 'owasp-standard', 'owasp-category',
        'detail', 'description', 'recommendation', 'mitre-detection', 'mitre-mitigation',
        'sl', 'm', 'opp', 's',
        'lc', 'li', 'lav', 'lac',
        'ed', 'ee', 'a', 'intrusion',
        'fd', 'rd', 'nc', 'pv'
    ];
    
    allFormElements.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            if (element.tagName === 'SELECT') {
                if (id === 'owasp-standard') {
                    element.value = 'web';
                    element.dispatchEvent(new Event('change'));
                } else {
                    element.value = element.querySelector('option[value=""]') ? '' : element.options[0].value;
                }
            } else {
                element.value = '';
            }
            
            element.classList.remove('is-valid', 'is-invalid');
            
            const existingError = element.parentElement.querySelector('.invalid-feedback');
            if (existingError) {
                existingError.remove();
            }
        }
    });

    const threatAgentSelect = document.getElementById('threat-agent');
    if (threatAgentSelect) {
        threatAgentSelect.value = '';
    }
    
    const otherContainer = document.getElementById('other-threat-agent-container');
    const otherInput = document.getElementById('other-threat-agent');
    if (otherContainer) {
        otherContainer.style.display = 'none';
    }
    if (otherInput) {
        otherInput.value = '';
        otherInput.classList.remove('is-invalid', 'is-valid');
        const errorDiv = otherInput.parentElement.querySelector('.invalid-feedback');
        if (errorDiv) {
            errorDiv.remove();
        }
    }
    
    const updateBtn = document.getElementById('update-current-btn');
    const cancelBtn = document.getElementById('cancel-edit-btn');
    const saveBtn = document.getElementById('save-btn');

    if (updateBtn) updateBtn.remove();
    if (cancelBtn) cancelBtn.remove();
    if (saveBtn) saveBtn.style.display = 'inline-block';
}

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
        owaspStandard: getValue('owasp-standard') || 'web',
        owasp: getValue('owasp-category'),
        mitre: getValue('mitre-id'),
        toolCriticity: getValue('tool-criticity'),
        threatAgent: threatAgentValue,
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
    
    const sortedVulnerabilities = [...vulnerabilities].sort((a, b) => b.id - a.id);
    
    sortedVulnerabilities.forEach((vuln, index) => {
        const standardText = vuln.owaspStandard === 'web' ? 'Web' : 
                            vuln.owaspStandard === 'api' ? 'API' : 'Mobile';
        
        const item = document.createElement('div');
        item.className = 'vulnerability-item';
        item.dataset.id = vuln.id;
        
        item.innerHTML = `
            <div class="vulnerability-header">
                <div class="vulnerability-number">${sortedVulnerabilities.length - index}</div>
                <div class="vulnerability-content">
                    <div class="d-flex justify-content-between align-items-start">
                        <div style="flex: 1;">
                            <h5 class="mb-2">${vuln.name}</h5>
                            <p class="mb-1"><strong>Host:</strong> ${vuln.host || 'No especificado'}</p>
                            <p class="mb-1">
                                <strong>OWASP:</strong> 
                                <span class="badge ${getStandardBadgeClass(vuln.owaspStandard)} me-1">${standardText}</span>
                                ${vuln.owasp || 'No especificado'} | 
                                <strong>MITRE:</strong> ${vuln.mitre || 'No especificado'}
                            </p>
                            <p class="mb-1"><strong>Riesgo:</strong> ${vuln.risk.toFixed(2)} | <strong>Probabilidad:</strong> ${vuln.likelihood.toFixed(2)} | <strong>Impacto:</strong> ${vuln.impact.toFixed(2)}</p>
                            <small class="text-muted">Guardado: ${new Date(vuln.date).toLocaleDateString()} ${new Date(vuln.date).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</small>
                        </div>
                        <div class="ms-3 text-end">
                            <span class="risk-badge ${vuln.riskClass}-badge mb-2 d-inline-block">${vuln.riskLevel}</span>
                            <div class="btn-group btn-group-sm">
                                <button class="btn btn-outline-info view-btn" data-id="${vuln.id}">
                                    <i class="bi bi-eye"></i> Ver
                                </button>
                                <button class="btn btn-outline-warning edit-btn" data-id="${vuln.id}">
                                    <i class="bi bi-pencil"></i> Editar
                                </button>
                                <button class="btn btn-outline-danger delete-btn" data-id="${vuln.id}">
                                    <i class="bi bi-trash"></i> Eliminar
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        listElement.appendChild(item);
    });
    
    setTimeout(() => {
        document.querySelectorAll('.view-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const id = parseInt(btn.dataset.id);
                showVulnerabilityDetails(id);
            });
        });
        
        document.querySelectorAll('.edit-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const id = parseInt(btn.dataset.id);
                openEditModal(id);
            });
        });
        
        document.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const id = parseInt(btn.dataset.id);
                deleteVulnerability(id);
            });
        });
        
        document.querySelectorAll('.vulnerability-item').forEach(item => {
            item.addEventListener('click', (e) => {
                if (!e.target.closest('.btn')) {
                    const id = parseInt(item.dataset.id);
                    showVulnerabilityDetails(id);
                }
            });
        });
    }, 100);
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
        
        // Obtener dimensiones del contenedor antes de crear los charts
        const riskChartContainer = document.querySelector('#riskDistributionChart').parentElement;
        const owaspChartContainer = document.querySelector('#owaspDistributionChart').parentElement;
        
        // Forzar dimensiones explícitas en los canvas
        const riskCanvas = document.getElementById('riskDistributionChart');
        const owaspCanvas = document.getElementById('owaspDistributionChart');
        
        if (riskCanvas && riskChartContainer) {
            // Establecer dimensiones explícitas basadas en el contenedor
            riskCanvas.style.width = '100%';
            riskCanvas.style.height = '300px';
            riskCanvas.width = riskChartContainer.clientWidth || 400;
            riskCanvas.height = 300;
        }
        
        if (owaspCanvas && owaspChartContainer) {
            owaspCanvas.style.width = '100%';
            owaspCanvas.style.height = '300px';
            owaspCanvas.width = owaspChartContainer.clientWidth || 400;
            owaspCanvas.height = 300;
        }
        
        // Actualizar los charts
        updateRiskDistributionChart(criticalCount, highCount, mediumCount, lowCount, infoCount);
        updateOwaspDistributionChart();
        updateDashboardTable();
        
        // Dibujar el total en el centro después de un pequeño retraso
        setTimeout(() => {
            const total = vulnerabilities.length;
            const canvas = document.getElementById('riskDistributionChart');
            if (canvas && riskDistributionChart) {
                drawTotalInCenter(canvas, total);
            }
        }, 300);
        
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
        
        const total = critical + high + medium + low + info;
        
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
                backgroundColor: 'white',
                plugins: { 
                    legend: { 
                        position: 'bottom',
                        labels: {
                            padding: 15,
                            usePointStyle: true,
                            pointStyle: 'circle',
                            pointRadius: 5,
                            font: {
                                size: 12,
                                weight: 'normal',
                                family: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif"
                            },
                            color: 'var(--text-color)',
                            generateLabels: function(chart) {
                                const data = chart.data;
                                const total = data.datasets[0].data.reduce((a, b) => a + b, 0);
                                
                                return data.labels.map((label, i) => {
                                    const value = data.datasets[0].data[i];
                                    const percentage = total > 0 ? Math.round((value / total) * 100) : 0;
                                    
                                    return {
                                        text: `${label}: ${value} (${percentage}%)`,
                                        fillStyle: data.datasets[0].backgroundColor[i],
                                        strokeStyle: data.datasets[0].borderColor[i],
                                        lineWidth: 1,
                                        hidden: false,
                                        index: i,
                                        fontColor: 'var(--text-color)',
                                        fontSize: 12,
                                        fontStyle: 'normal'
                                    };
                                });
                            }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'var(--card-bg)',
                        titleColor: 'var(--text-color)',
                        bodyColor: 'var(--text-color)',
                        borderColor: 'var(--border-color)',
                        borderWidth: 1,
                        titleFont: {
                            size: 12,
                            weight: 'normal'
                        },
                        bodyFont: {
                            size: 12
                        },
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
                cutout: '65%',
                animation: {
                    animateScale: true,
                    animateRotate: true,
                    duration: 1000,
                    easing: 'easeOutQuart',
                    onComplete: function() {
                        setTimeout(() => {
                            drawTotalInCenter(ctx, total);
                        }, 100);
                    }
                }
            }
        });
        
        setTimeout(() => {
            if (ctx) {
                ctx.canvas.style.width = '100%';
                ctx.canvas.style.height = '100%';
                drawTotalInCenter(ctx, total);
            }
        }, 300);
        
    } catch (error) {
        console.error('Error actualizando gráfico de distribución:', error);
    }
}

function updateOwaspDistributionChart() {
    const ctx = document.getElementById('owaspDistributionChart');
    if (!ctx) return;
    
    try {
        const context = ctx.getContext('2d');
        
        // Crear un array con todas las categorías de los tres estándares
        const allCategories = [...owaspWebCategories, ...owaspApiCategories, ...owaspMobileCategories];
        
        // Colores simples y consistentes para todas las categorías (30 colores únicos)
        const allColors = [
            // Web - Colores simples (10 colores)
            'rgba(255, 99, 132, 0.9)',   // A01 - Rojo
            'rgba(54, 162, 235, 0.9)',   // A02 - Azul
            'rgba(255, 206, 86, 0.9)',   // A03 - Amarillo
            'rgba(75, 192, 192, 0.9)',   // A04 - Verde azulado
            'rgba(153, 102, 255, 0.9)',  // A05 - Púrpura
            'rgba(255, 159, 64, 0.9)',   // A06 - Naranja
            'rgba(199, 199, 199, 0.9)',  // A07 - Gris
            'rgba(83, 102, 255, 0.9)',   // A08 - Azul índigo
            'rgba(40, 159, 64, 0.9)',    // A09 - Verde
            'rgba(210, 105, 30, 0.9)',   // A10 - Marrón
            
            // API - Repetimos los mismos colores pero en diferente orden
            'rgba(255, 99, 132, 0.8)',   // API1 - Rojo
            'rgba(54, 162, 235, 0.8)',   // API2 - Azul
            'rgba(255, 206, 86, 0.8)',   // API3 - Amarillo
            'rgba(75, 192, 192, 0.8)',   // API4 - Verde azulado
            'rgba(153, 102, 255, 0.8)',  // API5 - Púrpura
            'rgba(255, 159, 64, 0.8)',   // API6 - Naranja
            'rgba(199, 199, 199, 0.8)',  // API7 - Gris
            'rgba(83, 102, 255, 0.8)',   // API8 - Azul índigo
            'rgba(40, 159, 64, 0.8)',    // API9 - Verde
            'rgba(210, 105, 30, 0.8)',   // API10 - Marrón
            
            // Mobile - Mismos colores pero con diferente opacidad/saturación
            'rgba(255, 99, 132, 0.7)',   // M1 - Rojo
            'rgba(54, 162, 235, 0.7)',   // M2 - Azul
            'rgba(255, 206, 86, 0.7)',   // M3 - Amarillo
            'rgba(75, 192, 192, 0.7)',   // M4 - Verde azulado
            'rgba(153, 102, 255, 0.7)',  // M5 - Púrpura
            'rgba(255, 159, 64, 0.7)',   // M6 - Naranja
            'rgba(199, 199, 199, 0.7)',  // M7 - Gris
            'rgba(83, 102, 255, 0.7)',   // M8 - Azul índigo
            'rgba(40, 159, 64, 0.7)',    // M9 - Verde
            'rgba(210, 105, 30, 0.7)'    // M10 - Marrón
        ];
        
        // Colores para los bordes (más intensos)
        const allBorderColors = [
            // Web
            'rgba(255, 99, 132, 1)',
            'rgba(54, 162, 235, 1)',
            'rgba(255, 206, 86, 1)',
            'rgba(75, 192, 192, 1)',
            'rgba(153, 102, 255, 1)',
            'rgba(255, 159, 64, 1)',
            'rgba(199, 199, 199, 1)',
            'rgba(83, 102, 255, 1)',
            'rgba(40, 159, 64, 1)',
            'rgba(210, 105, 30, 1)',
            
            // API
            'rgba(255, 99, 132, 1)',
            'rgba(54, 162, 235, 1)',
            'rgba(255, 206, 86, 1)',
            'rgba(75, 192, 192, 1)',
            'rgba(153, 102, 255, 1)',
            'rgba(255, 159, 64, 1)',
            'rgba(199, 199, 199, 1)',
            'rgba(83, 102, 255, 1)',
            'rgba(40, 159, 64, 1)',
            'rgba(210, 105, 30, 1)',
            
            // Mobile
            'rgba(255, 99, 132, 1)',
            'rgba(54, 162, 235, 1)',
            'rgba(255, 206, 86, 1)',
            'rgba(75, 192, 192, 1)',
            'rgba(153, 102, 255, 1)',
            'rgba(255, 159, 64, 1)',
            'rgba(199, 199, 199, 1)',
            'rgba(83, 102, 255, 1)',
            'rgba(40, 159, 64, 1)',
            'rgba(210, 105, 30, 1)'
        ];
        
        // Contar vulnerabilidades por categoría
        const counts = Array(allCategories.length).fill(0);
        
        vulnerabilities.forEach(vuln => {
            if (vuln.owasp) {
                // Buscar coincidencia exacta o parcial
                const index = allCategories.findIndex(cat => {
                    if (cat === vuln.owasp) return true;
                    const catCode = cat.split(' - ')[0];
                    const vulnCode = vuln.owasp.split(' - ')[0];
                    return catCode === vulnCode;
                });
                
                if (index !== -1) {
                    counts[index]++;
                }
            }
        });
        
        // Filtrar categorías sin vulnerabilidades
        const nonZeroIndices = counts
            .map((count, index) => ({ count, index }))
            .filter(item => item.count > 0)
            .map(item => item.index);
        
        // Si no hay datos, mostrar mensaje
        if (nonZeroIndices.length === 0) {
            if (owaspDistributionChart) owaspDistributionChart.destroy();
            context.clearRect(0, 0, ctx.width, ctx.height);
            context.font = '14px Arial';
            context.fillStyle = '#999';
            context.textAlign = 'center';
            context.fillText('No hay datos para mostrar', ctx.width/2, ctx.height/2);
            return;
        }
        
        // Preparar datos filtrados
        const filteredLabels = nonZeroIndices.map(i => {
            const cat = allCategories[i];
            const code = cat.split(' - ')[0];
            if (cat.startsWith('A')) return `${code} (Web)`;
            if (cat.startsWith('API')) return `${code} (API)`;
            if (cat.startsWith('M')) return `${code} (Mobile)`;
            return cat;
        });
        
        const filteredData = nonZeroIndices.map(i => counts[i]);
        const filteredColors = nonZeroIndices.map(i => allColors[i]);
        const filteredBorderColors = nonZeroIndices.map(i => allBorderColors[i]);
        
        // Destruir gráfico anterior si existe
        if (owaspDistributionChart) owaspDistributionChart.destroy();
        
        // Crear nuevo gráfico
        owaspDistributionChart = new Chart(context, {
            type: 'doughnut',
            data: {
                labels: filteredLabels,
                datasets: [{
                    data: filteredData,
                    backgroundColor: filteredColors,
                    borderColor: filteredBorderColors,
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
                            font: {
                                size: 11,
                                family: "'Segoe UI', Arial, sans-serif"
                            },
                            padding: 15,
                            usePointStyle: true,
                            pointStyle: 'circle',
                            generateLabels: function(chart) {
                                const data = chart.data;
                                return data.labels.map((label, i) => {
                                    const value = data.datasets[0].data[i];
                                    return {
                                        text: `${label}: ${value}`,
                                        fillStyle: data.datasets[0].backgroundColor[i],
                                        strokeStyle: data.datasets[0].borderColor[i],
                                        lineWidth: 2,
                                        hidden: false,
                                        index: i
                                    };
                                });
                            }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0,0,0,0.8)',
                        titleFont: { size: 12, weight: 'bold' },
                        bodyFont: { size: 11 },
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                
                                const fullCategory = allCategories[nonZeroIndices[context.dataIndex]];
                                return [
                                    `${fullCategory}`,
                                    `Cantidad: ${value} (${percentage}%)`
                                ];
                            }
                        }
                    }
                },
                cutout: '65%',
                animation: { 
                    animateScale: true, 
                    animateRotate: true,
                    duration: 1000
                }
            }
        });
        
        // Agregar texto central con el total después de la animación
        setTimeout(() => {
            const total = filteredData.reduce((a, b) => a + b, 0);
            if (total > 0 && ctx) {
                const centerX = ctx.width / 2;
                const centerY = ctx.height / 2;
                
                // Limpiar área central
                context.save();
                context.beginPath();
                context.arc(centerX, centerY, 40, 0, Math.PI * 2);
                context.clip();
                context.clearRect(centerX - 40, centerY - 40, 80, 80);
                
                // Dibujar texto
                context.textAlign = 'center';
                context.textBaseline = 'middle';
                context.font = 'bold 22px "Segoe UI", Arial, sans-serif';
                
                const isDarkTheme = document.documentElement.getAttribute('data-theme') === 'dark';
                context.fillStyle = isDarkTheme ? '#e0e0e0' : '#333';
                
                context.fillText(total.toString(), centerX, centerY);
                context.restore();
            }
        }, 500);
        
    } catch (error) {
        console.error('Error actualizando gráfico OWASP:', error);
    }
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
    
    const allCategories = [...owaspWebCategories, ...owaspApiCategories, ...owaspMobileCategories];
    
    allCategories.forEach((_, index) => {
        vulnerabilitiesByCategory[index] = vulnerabilities.filter(v => {
            if (!v.owasp) return false;
            return allCategories[index] === v.owasp;
        });
    });
    
    const sortedCategories = allCategories.map((cat, idx) => ({
        category: cat,
        index: idx,
        count: vulnerabilitiesByCategory[idx].length,
        standard: getStandardFromCategory(cat)
    })).filter(item => item.count > 0)
      .sort((a, b) => b.count - a.count);
    
    let globalCounter = 1;
    
    sortedCategories.forEach((catItem) => {
        const categoryVulns = vulnerabilitiesByCategory[catItem.index];
        
        let categoryColor;
        if (catItem.standard === 'web') {
            categoryColor = 'rgba(54, 162, 235, 0.2)';
        } else if (catItem.standard === 'api') {
            categoryColor = 'rgba(255, 99, 132, 0.2)';
        } else {
            categoryColor = 'rgba(75, 192, 192, 0.2)';
        }
        
        const categoryRow = document.createElement('tr');
        categoryRow.innerHTML = `
            <td colspan="6" style="font-weight: bold; background-color: ${categoryColor}">
                ${catItem.category} (${categoryVulns.length} vulnerabilidad${categoryVulns.length !== 1 ? 'es' : ''})
            </td>
        `;
        tableBody.appendChild(categoryRow);
        
        const sortedVulns = categoryVulns.sort((a, b) => b.risk - a.risk);
        
        sortedVulns.forEach((vuln) => {
            const row = document.createElement('tr');
            
            const standardText = vuln.owaspStandard === 'web' ? 'Web' : 
                                vuln.owaspStandard === 'api' ? 'API' : 'Mobile';
            
            row.innerHTML = `
                <td style="font-weight: bold; text-align: center; width: 50px;">
                    ${globalCounter++}
                </td>
                <td>${vuln.owasp || 'No especificado'}</td>
                <td>
                    <span class="badge ${getStandardBadgeClass(vuln.owaspStandard)}">${standardText}</span>
                </td>
                <td>${vuln.name || 'No especificado'}</td>
                <td>${vuln.host || vuln.attackVector || 'No especificado'}</td>
                <td><span class="risk-badge ${vuln.riskClass}-badge">${vuln.riskLevel}</span></td>
            `;
            tableBody.appendChild(row);
        });
    });
}



function exportExecutiveReport() {
    console.log('Ejecutando exportExecutiveReport...');

    if (vulnerabilities.length === 0) {
        showNotification('No hay vulnerabilidades para generar el informe ejecutivo.', 'error');
        return;
    }

    try {
        if (!riskDistributionChart || !owaspDistributionChart) {
            updateDashboard();
        }

        const totalVulnerabilities = vulnerabilities.length;
        const criticalCount = vulnerabilities.filter(v => v.riskLevel === 'CRÍTICO').length;
        const highCount = vulnerabilities.filter(v => v.riskLevel === 'ALTO').length;
        const mediumCount = vulnerabilities.filter(v => v.riskLevel === 'MEDIO').length;
        const lowCount = vulnerabilities.filter(v => v.riskLevel === 'BAJO').length;
        const infoCount = vulnerabilities.filter(v => v.riskLevel === 'INFORMATIVO').length;
        
        const webCount = vulnerabilities.filter(v => v.owaspStandard === 'web').length;
        const apiCount = vulnerabilities.filter(v => v.owaspStandard === 'api').length;
        const mobileCount = vulnerabilities.filter(v => v.owaspStandard === 'mobile').length;
        
        const riskChartImage = createChartWithWhiteBackground(riskDistributionChart);
        const owaspChartImage = createChartWithWhiteBackground(owaspDistributionChart);
        
        let htmlContent = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Informe Ejecutivo de Riesgos</title>
                <style>
                    body { font-family: Arial; margin: 30px; }
                    .header { text-align: center; margin-bottom: 40px; border-bottom: 2px solid #000080; }
                    h1 { color: #000080; }
                    .section { margin: 30px 0; }
                    table { width: 80%; border-collapse: collapse; margin: 20px 0; }
                    th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
                    th { background-color: #f2f2f2; }
                    .chart { text-align: center; margin: 40px 0; }
                    .badge { display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; }
                    .bg-primary { background-color: #007bff; }
                    .bg-danger { background-color: #dc3545; }
                    .bg-success { background-color: #28a745; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Informe Ejecutivo de Riesgos de Seguridad</h1>
                    <p><strong>Fecha:</strong> ${new Date().toLocaleDateString()}</p>
                    <p><strong>Total de Vulnerabilidades:</strong> ${totalVulnerabilities}</p>
                </div>

                <div class="section">
                    <h2>Resumen por Estándar OWASP</h2>
                    <table>
                        <tr><th>Estándar</th><th>Cantidad</th><th>Porcentaje</th></tr>
                        <tr><td><span class="badge bg-primary">Web</span></td><td>${webCount}</td><td>${Math.round(webCount/totalVulnerabilities*100)}%</td></tr>
                        <tr><td><span class="badge bg-danger">API</span></td><td>${apiCount}</td><td>${Math.round(apiCount/totalVulnerabilities*100)}%</td></tr>
                        <tr><td><span class="badge bg-success">Mobile</span></td><td>${mobileCount}</td><td>${Math.round(mobileCount/totalVulnerabilities*100)}%</td></tr>
                    </table>
                </div>

                <div class="section">
                    <h2>Resumen por Nivel de Riesgo</h2>
                    <table>
                        <tr><th>Nivel</th><th>Cantidad</th><th>Porcentaje</th></tr>
                        <tr><td>Crítico</td><td>${criticalCount}</td><td>${Math.round(criticalCount/totalVulnerabilities*100)}%</td></tr>
                        <tr><td>Alto</td><td>${highCount}</td><td>${Math.round(highCount/totalVulnerabilities*100)}%</td></tr>
                        <tr><td>Medio</td><td>${mediumCount}</td><td>${Math.round(mediumCount/totalVulnerabilities*100)}%</td></tr>
                        <tr><td>Bajo</td><td>${lowCount}</td><td>${Math.round(lowCount/totalVulnerabilities*100)}%</td></tr>
                        <tr><td>Informativo</td><td>${infoCount}</td><td>${Math.round(infoCount/totalVulnerabilities*100)}%</td></tr>
                    </table>
                </div>

                <div class="chart">
                    <h2>Distribución por Nivel de Riesgo</h2>
                    <img src="${riskChartImage}" style="width: 500px;"/>
                </div>

                <div class="chart">
                    <h2>Distribución por Categoría OWASP</h2>
                    <img src="${owaspChartImage}" style="width: 500px;"/>
                </div>
            </body>
            </html>
        `;

        const blob = new Blob([htmlContent], { type: 'application/msword' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `informe_ejecutivo_${new Date().toISOString().split('T')[0]}.doc`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showNotification(`Informe Ejecutivo exportado exitosamente.`, 'success');
        
    } catch (error) {
        console.error('Error al exportar Informe Ejecutivo:', error);
        showNotification('Error al exportar el Informe Ejecutivo.', 'error');
    }
}

function createChartWithWhiteBackground(chart) {
    const tempCanvas = document.createElement('canvas');
    tempCanvas.width = chart.width;
    tempCanvas.height = chart.height;
    const tempCtx = tempCanvas.getContext('2d');
    
    tempCtx.fillStyle = 'white';
    tempCtx.fillRect(0, 0, tempCanvas.width, tempCanvas.height);
    tempCtx.drawImage(chart.canvas, 0, 0);
    
    return tempCanvas.toDataURL('image/png');
}

// ========== EXPORTACIÓN A PDF CON FORMATO DE TABLA UNIFICADA ==========
function exportToPDF() {
    console.log('Ejecutando exportToPDF con formato de tabla unificada...');
    
    if (vulnerabilities.length === 0) {
        showNotification('No hay vulnerabilidades para exportar', 'error');
        return;
    }

    try {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        const pageWidth = doc.internal.pageSize.width;
        const margin = 15;
        const maxWidth = pageWidth - (margin * 2);
        let yPosition = 20;
        
        // Recorrer todas las vulnerabilidades
        vulnerabilities.forEach((vuln, index) => {
            // Si no es la primera página, agregar página nueva
            if (index > 0) {
                doc.addPage();
                yPosition = 20;
            }
            
            // ========== TÍTULO DE LA VULNERABILIDAD ==========
            doc.setFontSize(14);
            doc.setFont(undefined, 'bold');
            doc.setTextColor(0, 0, 0);
            
            const title = vuln.name || 'Vulnerabilidad sin nombre';
            const titleLines = doc.splitTextToSize(title, maxWidth);
            doc.text(titleLines, margin, yPosition);
            yPosition += (titleLines.length * 7) + 8;
            
            // ========== TABLA UNIFICADA ==========
            const col1Width = 45;
            const col2Width = maxWidth - col1Width;
            
            // Guardar posición inicial de la tabla
            const tableStartY = yPosition;
            let currentY = yPosition;
            
            // Colección de filas
            const rows = [];
            
            // Función para agregar fila simple
            function addRow(label, value, isRisk = false) {
                rows.push({ type: 'simple', label, value, isRisk });
            }
            
            // Función para agregar fila multilínea
            function addMultiRow(label, value) {
                rows.push({ type: 'multi', label, value });
            }
            
            // Construir todas las filas
            addRow('Host', vuln.host || 'No especificado');
            addRow('Ruta afectada', vuln.rutaAfectada || 'No especificado');
            addRow('Nivel de Riesgo', vuln.riskLevel, true);
            
            if (vuln.toolCriticity) {
                addRow('Resultado del Escáner', vuln.toolCriticity);
            }
            
            addMultiRow('Detalle', vuln.detail);
            addMultiRow('Descripción del análisis', vuln.description);
            addMultiRow('Recomendación', vuln.recommendation);
            addRow('ID OWASP top 10', vuln.owasp || 'No especificado');
            addRow('MITRE ID', vuln.mitre || 'No especificado');
            addMultiRow('Estrategia de detección MITRE', vuln.mitreDetection);
            addMultiRow('Estrategia de mitigación MITRE', vuln.mitreMitigation);
            
            // Calcular altura total de todas las filas con padding adicional
            let totalHeight = 0;
            const rowHeights = [];
            const padding = 4; // Padding adicional entre filas
            
            rows.forEach(row => {
                let rowHeight;
                if (row.type === 'simple') {
                    rowHeight = 10; // Aumentado de 8 a 10
                } else {
                    const valueLines = doc.splitTextToSize(row.value || 'No especificado', col2Width - 6);
                    rowHeight = Math.max(12, valueLines.length * 5 + 4); // Aumentado el mínimo
                }
                rowHeights.push(rowHeight);
                totalHeight += rowHeight;
            });
            
            // Verificar si cabe en la página
            if (currentY + totalHeight > doc.internal.pageSize.height - 25) {
                doc.addPage();
                currentY = 20;
            }
            
            // Dibujar todas las filas de la tabla como un bloque unificado
            let tempY = currentY;
            
            rows.forEach((row, i) => {
                const rowHeight = rowHeights[i];
                
                // Dibujar borde izquierdo y derecho de la fila
                doc.rect(margin, tempY, col1Width, rowHeight);
                doc.rect(margin + col1Width, tempY, col2Width, rowHeight);
                
                // Texto de la etiqueta
                doc.setFontSize(9);
                doc.setFont(undefined, 'bold');
                doc.setTextColor(0, 0, 0);
                const labelLines = doc.splitTextToSize(row.label, col1Width - 6);
                // Centrar verticalmente el texto de la etiqueta
                const labelTotalHeight = labelLines.length * 5;
                const labelY = tempY + (rowHeight / 2) - (labelTotalHeight / 2) + 2;
                doc.text(labelLines, margin + 3, labelY);
                
                // Texto del valor
                if (row.isRisk) {
                    const riskColor = getRiskPdfColor(row.value);
                    doc.setTextColor(riskColor.r, riskColor.g, riskColor.b);
                    doc.setFont(undefined, 'bold');
                } else {
                    doc.setTextColor(0, 0, 0);
                    doc.setFont(undefined, 'normal');
                }
                
                let valueLines;
                if (row.type === 'simple') {
                    valueLines = doc.splitTextToSize(row.value, col2Width - 6);
                } else {
                    valueLines = doc.splitTextToSize(row.value || 'No especificado', col2Width - 6);
                }
                
                // Centrar verticalmente el texto del valor
                const valueTotalHeight = valueLines.length * 5;
                const valueY = tempY + (rowHeight / 2) - (valueTotalHeight / 2) + 2;
                doc.text(valueLines, margin + col1Width + 3, valueY);
                
                tempY += rowHeight;
            });
            
            // Dibujar borde inferior de la última fila
            doc.line(margin, tempY, margin + maxWidth, tempY);
            
            // Actualizar posición Y después de la tabla con más espacio
            yPosition = tempY + 12;
            
            // Número de página
            doc.setFontSize(8);
            doc.setTextColor(150, 150, 150);
            doc.text(`Página ${index + 1} de ${vulnerabilities.length}`, pageWidth - margin - 15, doc.internal.pageSize.height - 10);
        });
        
        // Guardar un solo PDF con todas las vulnerabilidades
        doc.save(`reporte_vulnerabilidades_${new Date().toISOString().split('T')[0]}.pdf`);
        showNotification(`${vulnerabilities.length} vulnerabilidad(es) exportadas a PDF`, 'success');
        
    } catch (error) {
        console.error('Error al exportar PDF:', error);
        showNotification('Error al exportar el PDF', 'error');
    }
}

function drawTwoColumnRowPDF(doc, x, y, col1Width, col2Width, label, value, isRiskCell = false, riskLevel = null) {
    doc.setDrawColor(0, 0, 0);
    doc.setLineWidth(0.8);
    
    const totalWidth = col1Width + col2Width;
    const rowHeight = 10;
    
    doc.rect(x, y, totalWidth, rowHeight);
    doc.line(x + col1Width, y, x + col1Width, y + rowHeight);
    
    doc.setFillColor(220, 220, 220);
    doc.rect(x, y, col1Width, rowHeight, 'F');
    
    if (isRiskCell && riskLevel) {
        const color = getRiskPdfColor(riskLevel);
        doc.setFillColor(color.r, color.g, color.b);
        doc.rect(x + col1Width, y, col2Width, rowHeight, 'F');
    } else {
        doc.setFillColor(255, 255, 255);
        doc.rect(x + col1Width, y, col2Width, rowHeight, 'F');
    }
    
    doc.setFontSize(9);
    doc.setFont(undefined, 'bold');
    doc.setTextColor(0, 0, 0);
    const labelLines = doc.splitTextToSize(label, col1Width - 6);
    doc.text(labelLines, x + 3, y + 6);
    
    if (isRiskCell && riskLevel) {
        const color = getRiskPdfColor(riskLevel);
        doc.setTextColor(color.textColor);
    } else {
        doc.setTextColor(0, 0, 0);
    }
    
    doc.setFont(undefined, isRiskCell ? 'bold' : 'normal');
    const valueLines = doc.splitTextToSize(value, col2Width - 6);
    doc.text(valueLines, x + col1Width + 3, y + 6);
    
    doc.setTextColor(0, 0, 0);
    
    return rowHeight;
}

function drawCombinedRowPDF(doc, x, y, col1Width, col2Width, label, value) {
    doc.setDrawColor(0, 0, 0);
    doc.setLineWidth(0.8);
    
    const totalWidth = col1Width + col2Width;
    
    doc.setFontSize(9);
    const valueLines = doc.splitTextToSize(value || 'No especificado', col2Width - 6);
    const lineHeight = 5;
    const minHeight = 12;
    const contentHeight = Math.max(minHeight, valueLines.length * lineHeight);
    const rowHeight = contentHeight;
    
    doc.rect(x, y, totalWidth, rowHeight);
    doc.line(x + col1Width, y, x + col1Width, y + rowHeight);
    
    doc.setFillColor(220, 220, 220);
    doc.rect(x, y, col1Width, rowHeight, 'F');
    doc.setFillColor(255, 255, 255);
    doc.rect(x + col1Width, y, col2Width, rowHeight, 'F');
    
    doc.setTextColor(0, 0, 0);
    doc.setFont(undefined, 'bold');
    const labelLines = doc.splitTextToSize(label, col1Width - 6);
    const labelY = y + (rowHeight / 2) - ((labelLines.length * lineHeight) / 2) + 3;
    doc.text(labelLines, x + 3, labelY);
    
    doc.setFont(undefined, 'normal');
    const valueY = y + (rowHeight / 2) - ((valueLines.length * lineHeight) / 2) + 3;
    doc.text(valueLines, x + col1Width + 3, valueY);
    
    return rowHeight;
}

function drawFactorsRowPDF(doc, x, y, col1Width, col2Width, vuln) {
    const factorsText = 
        `SL: ${vuln.sl || 1} | M: ${vuln.m || 1} | O: ${vuln.o || 0} | S: ${vuln.s || 2} | ` +
        `LC: ${vuln.lc || 2} | LI: ${vuln.li || 1} | LAV: ${vuln.lav || 1} | LAC: ${vuln.lac || 1} | ` +
        `ED: ${vuln.ed || 1} | EE: ${vuln.ee || 1} | A: ${vuln.a || 1} | ID: ${vuln.intrusion || 1} | ` +
        `FD: ${vuln.fd || 1} | RD: ${vuln.rd || 1} | NC: ${vuln.nc || 2} | PV: ${vuln.pv || 3}`;
    
    return drawCombinedRowPDF(doc, x, y, col1Width, col2Width, 'Factores de Riesgo', factorsText);
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
    console.log('Ejecutando importJson...');
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
            
            // Migrar vulnerabilidades importadas si no tienen owaspStandard
            newVulnerabilities = newVulnerabilities.map(vuln => {
                if (!vuln.owaspStandard) {
                    let standard = 'web';
                    if (vuln.owasp) {
                        if (vuln.owasp.startsWith('API')) {
                            standard = 'api';
                        } else if (vuln.owasp.startsWith('M')) {
                            standard = 'mobile';
                        }
                    }
                    return { ...vuln, owaspStandard: standard };
                }
                return vuln;
            });
            
            const existingIds = new Set(vulnerabilities.map(v => v.id));
            const uniqueNewVulnerabilities = newVulnerabilities.filter(vuln => !existingIds.has(vuln.id));
            const duplicatesCount = newVulnerabilities.length - uniqueNewVulnerabilities.length;

            vulnerabilities = vulnerabilities.concat(uniqueNewVulnerabilities);
            
            saveVulnerabilities();
            renderVulnerabilitiesList();
            
            // --- INICIO DE LAS CORRECCIONES PARA LOS CHARTS ---
            
            // Destruir los charts existentes explícitamente
            if (riskDistributionChart) {
                riskDistributionChart.destroy();
                riskDistributionChart = null;
            }
            
            if (owaspDistributionChart) {
                owaspDistributionChart.destroy();
                owaspDistributionChart = null;
            }
            
            // Forzar un reflow del DOM antes de actualizar el dashboard
            // Esto ayuda a que los contenedores recuperen sus dimensiones correctas
            setTimeout(() => {
                // Actualizar el dashboard (esto recreará los charts)
                updateDashboard();
                
                // Forzar el redimensionamiento de los charts después de un pequeño retraso
                setTimeout(() => {
                    // Obtener los elementos canvas
                    const riskCanvas = document.getElementById('riskDistributionChart');
                    const owaspCanvas = document.getElementById('owaspDistributionChart');
                    
                    if (riskCanvas && riskDistributionChart) {
                        // Forzar el redimensionamiento del chart
                        riskDistributionChart.resize();
                        
                        // Redibujar el texto central
                        const total = vulnerabilities.length;
                        drawTotalInCenter(riskCanvas, total);
                    }
                    
                    if (owaspCanvas && owaspDistributionChart) {
                        // Forzar el redimensionamiento del chart
                        owaspDistributionChart.resize();
                        
                        // Para el chart OWASP, también necesitamos el total
                        const canvas = owaspCanvas;
                        const ctx = canvas.getContext('2d');
                        if (ctx) {
                            setTimeout(() => {
                                const total = vulnerabilities.length;
                                const centerX = canvas.width / 2;
                                const centerY = canvas.height / 2;
                                
                                // Limpiar área central
                                ctx.save();
                                ctx.beginPath();
                                ctx.arc(centerX, centerY, 40, 0, Math.PI * 2);
                                ctx.clip();
                                ctx.clearRect(centerX - 40, centerY - 40, 80, 80);
                                
                                // Dibujar texto
                                ctx.textAlign = 'center';
                                ctx.textBaseline = 'middle';
                                ctx.font = 'bold 22px "Segoe UI", Arial, sans-serif';
                                
                                const isDarkTheme = document.documentElement.getAttribute('data-theme') === 'dark';
                                ctx.fillStyle = isDarkTheme ? '#e0e0e0' : '#333';
                                
                                ctx.fillText(total.toString(), centerX, centerY);
                                ctx.restore();
                            }, 100);
                        }
                    }
                    
                    // Mostrar notificación de éxito después de que los charts se hayan ajustado
                    let message = `${uniqueNewVulnerabilities.length} vulnerabilidades únicas cargadas y fusionadas.`;
                    if (duplicatesCount > 0) {
                        message += ` (${duplicatesCount} duplicado(s) omitido(s)).`;
                    }
                    showNotification(message, 'success');
                    
                }, 300); // Pequeño retraso para permitir que los charts se rendericen
                
            }, 100); // Pequeño retraso para permitir la actualización del DOM
            
            // --- FIN DE LAS CORRECCIONES ---
            
        } catch (error) {
            console.error('Error procesando archivo JSON:', error);
            showNotification('Error al parsear el archivo JSON.', 'error');
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

function getRiskHeaderColor(riskLevel) {
    switch(riskLevel.toUpperCase()) {
        case 'CRÍTICO': return '#dc3545';
        case 'ALTO': return '#fd7e14';
        case 'MEDIO': return '#ffc107';
        case 'BAJO': return '#20c997';
        case 'INFORMATIVO': return '#17a2b8';
        default: return '#6c757d';
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
    
    const standardText = vuln.owaspStandard === 'web' ? 'Web' : 
                        vuln.owaspStandard === 'api' ? 'API' : 'Mobile';
    
    const factoresHTML = `
        <div class="detail-section">
            <h5 class="detail-section-title">Factores de Riesgo - Agente de Amenaza</h5>
            <div class="detail-item">
                <div class="detail-label">Nivel de habilidad</div>
                <div class="detail-value">${getSkillLevelText(vuln.sl)} (Valor: ${vuln.sl})</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Motivo Económico del agente</div>
                <div class="detail-value">${getMotivoEconomicoText(vuln.m)} (Valor: ${vuln.m})</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Oportunidad de Ataque</div>
                <div class="detail-value">${getOportunidadAtaqueText(vuln.o)} (Valor: ${vuln.o})</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Tamaño del Agente de Amenaza</div>
                <div class="detail-value">${getTamanoAgenteText(vuln.s)} (Valor: ${vuln.s})</div>
            </div>
        </div>
        
        <div class="detail-section">
            <h5 class="detail-section-title">Factores de Riesgo - Impacto Técnico</h5>
            <div class="detail-item">
                <div class="detail-label">Pérdida de confidencialidad</div>
                <div class="detail-value">${getPerdidaConfidencialidadText(vuln.lc)} (Valor: ${vuln.lc})</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Pérdida de integridad</div>
                <div class="detail-value">${getPerdidaIntegridadText(vuln.li)} (Valor: ${vuln.li})</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Impacto en la Disponibilidad</div>
                <div class="detail-value">${getImpactoDisponibilidadText(vuln.lav)} (Valor: ${vuln.lav})</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Rastreabilidad del Ataque</div>
                <div class="detail-value">${getRastreabilidadAtaqueText(vuln.lac)} (Valor: ${vuln.lac})</div>
            </div>
        </div>
        
        <div class="detail-section">
            <h5 class="detail-section-title">Factores de Riesgo - Vulnerabilidad</h5>
            <div class="detail-item">
                <div class="detail-label">Facilidad de descubrimiento</div>
                <div class="detail-value">${getFacilidadDescubrimientoText(vuln.ed)} (Valor: ${vuln.ed})</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Facilidad de explotación</div>
                <div class="detail-value">${getFacilidadExplotacionText(vuln.ee)} (Valor: ${vuln.ee})</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Conocimiento de la Vulnerabilidad</div>
                <div class="detail-value">${getConocimientoVulnerabilidadText(vuln.a)} (Valor: ${vuln.a})</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Detección de intrusiones</div>
                <div class="detail-value">${getDeteccionIntrusionText(vuln.intrusion)} (Valor: ${vuln.intrusion})</div>
            </div>
        </div>
        
        <div class="detail-section">
            <h5 class="detail-section-title">Factores de Riesgo - Impacto de Negocio</h5>
            <div class="detail-item">
                <div class="detail-label">Daño financiero</div>
                <div class="detail-value">${getDanioFinancieroText(vuln.fd)} (Valor: ${vuln.fd})</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Daño a la reputación</div>
                <div class="detail-value">${getDanioReputacionText(vuln.rd)} (Valor: ${vuln.rd})</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Incumplimiento</div>
                <div class="detail-value">${getIncumplimientoText(vuln.nc)} (Valor: ${vuln.nc})</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Violación de privacidad</div>
                <div class="detail-value">${getViolacionPrivacidadText(vuln.pv)} (Valor: ${vuln.pv})</div>
            </div>
        </div>
    `;
    
    modalBody.innerHTML = `
        <div class="vulnerability-details">
            <div class="detail-item">
                <div class="detail-label">Número</div>
                <div class="detail-value">${vulnerabilities.findIndex(v => v.id === id) + 1}</div>
            </div>
            
            <div class="detail-item">
                <div class="detail-label">ID</div>
                <div class="detail-value">${vuln.id}</div>
            </div>
            
            <div class="detail-item">
                <div class="detail-label">Estándar OWASP</div>
                <div class="detail-value">
                    <span class="badge ${getStandardBadgeClass(vuln.owaspStandard)}">${standardText}</span>
                </div>
            </div>
            
            <div class="detail-item">
                <div class="detail-label">Categoría OWASP</div>
                <div class="detail-value">${vuln.owasp || 'No especificado'}</div>
            </div>
            
            <div class="detail-item">
                <div class="detail-label">Vector de Ataque (Vulnerabilidad)</div>
                <div class="detail-value">${vuln.name || 'No especificado'}</div>
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
                <div class="detail-value">
                    <span class="risk-badge ${vuln.riskClass}-badge">${vuln.riskLevel}</span> 
                    (${vuln.risk ? vuln.risk.toFixed(2) : '0.00'})
                </div>
            </div>
            
            <div class="detail-item">
                <div class="detail-label">Probabilidad Calculada</div>
                <div class="detail-value">${vuln.likelihood ? vuln.likelihood.toFixed(2) : '0.00'}</div>
            </div>
            
            <div class="detail-item">
                <div class="detail-label">Impacto Calculado</div>
                <div class="detail-value">${vuln.impact ? vuln.impact.toFixed(2) : '0.00'}</div>
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
            
            ${factoresHTML}
            
            <div class="detail-item">
                <div class="detail-label">Fecha de Creación</div>
                <div class="detail-value">${new Date(vuln.date).toLocaleString()}</div>
            </div>
            
            ${vuln.lastUpdated ? `
            <div class="detail-item">
                <div class="detail-label">Última Actualización</div>
                <div class="detail-value">${new Date(vuln.lastUpdated).toLocaleString()}</div>
            </div>
            ` : ''}
        </div>
        
        <div class="text-center mt-4">
            <button class="btn btn-warning me-2" id="edit-from-details" data-id="${vuln.id}">
                <i class="bi bi-pencil"></i> Editar esta Vulnerabilidad
            </button>
            <button class="btn btn-danger" id="delete-from-details" data-id="${vuln.id}">
                <i class="bi bi-trash"></i> Eliminar
            </button>
        </div>
    `;
    
    setTimeout(() => {
        const editBtn = document.getElementById('edit-from-details');
        const deleteBtn = document.getElementById('delete-from-details');
        
        if (editBtn) {
            editBtn.addEventListener('click', () => {
                const detailsModalElement = document.getElementById('vulnerabilityModal');
                if (detailsModalElement && typeof bootstrap !== 'undefined') {
                    const modal = bootstrap.Modal.getInstance(detailsModalElement);
                    if (modal) modal.hide();
                }
                
                setTimeout(() => openEditModal(vuln.id), 300);
            });
        }
        
        if (deleteBtn) {
            deleteBtn.addEventListener('click', () => {
                const detailsModalElement = document.getElementById('vulnerabilityModal');
                if (detailsModalElement && typeof bootstrap !== 'undefined') {
                    const modal = bootstrap.Modal.getInstance(detailsModalElement);
                    if (modal) modal.hide();
                }
                
                setTimeout(() => deleteVulnerability(vuln.id), 300);
            });
        }
    }, 100);
    
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
            
            vulnerabilities = vulnerabilities.map(vuln => {
                return {
                    sl: vuln.sl !== undefined ? vuln.sl : 1,
                    m: vuln.m !== undefined ? vuln.m : 1,
                    o: vuln.o !== undefined ? vuln.o : 0,
                    s: vuln.s !== undefined ? vuln.s : 2,
                    lc: vuln.lc !== undefined ? vuln.lc : 2,
                    li: vuln.li !== undefined ? vuln.li : 1,
                    lav: vuln.lav !== undefined ? vuln.lav : 1,
                    lac: vuln.lac !== undefined ? vuln.lac : 1,
                    ed: vuln.ed !== undefined ? vuln.ed : 1,
                    ee: vuln.ee !== undefined ? vuln.ee : 1,
                    a: vuln.a !== undefined ? vuln.a : 1,
                    intrusion: vuln.intrusion !== undefined ? vuln.intrusion : 
                              (vuln.id !== undefined && typeof vuln.id === 'number' ? vuln.id : 1),
                    fd: vuln.fd !== undefined ? vuln.fd : 1,
                    rd: vuln.rd !== undefined ? vuln.rd : 1,
                    nc: vuln.nc !== undefined ? vuln.nc : 2,
                    pv: vuln.pv !== undefined ? vuln.pv : 3,
                    
                    id: vuln.id,
                    name: vuln.name,
                    likelihood: vuln.likelihood || 0,
                    impact: vuln.impact || 0,
                    risk: vuln.risk || 0,
                    riskLevel: vuln.riskLevel || 'INFORMATIVO',
                    riskClass: vuln.riskClass || 'risk-info',
                    
                    host: vuln.host || '',
                    rutaAfectada: vuln.rutaAfectada || '',
                    owaspStandard: vuln.owaspStandard || 'web',
                    owasp: vuln.owasp || '',
                    mitre: vuln.mitre || '',
                    toolCriticity: vuln.toolCriticity || '',
                    
                    threatAgent: vuln.threatAgent || '',
                    securityWeakness: vuln.securityWeakness || '',
                    securityControls: vuln.securityControls || '',
                    technicalBusinessImpact: vuln.technicalBusinessImpact || '',
                    detail: vuln.detail || '',
                    description: vuln.description || '',
                    recommendation: vuln.recommendation || '',
                    mitreDetection: vuln.mitreDetection || '',
                    mitreMitigation: vuln.mitreMitigation || '',
                    
                    date: vuln.date || new Date().toISOString(),
                    lastUpdated: vuln.lastUpdated
                };
            });
            
            console.log(`Cargadas ${vulnerabilities.length} vulnerabilidades`);
            renderVulnerabilitiesList();
            updateDashboard();
        } else {
            console.log('No hay vulnerabilidades guardadas');
            vulnerabilities = [];
        }
    } catch (error) {
        console.error('Error cargando vulnerabilidades:', error);
        showNotification('Error al cargar las vulnerabilidades guardadas', 'error');
        vulnerabilities = [];
    }
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

function openEditModal(id) {
    const vuln = vulnerabilities.find(v => v.id === id);
    if (!vuln) return;
    
    const calculatorTab = document.getElementById('calculator-tab');
    if (calculatorTab && calculatorTab.click) {
        calculatorTab.click();
    }
    
    window.scrollTo({ top: 0, behavior: 'smooth' });
    
    function setValue(id, value, defaultValue = '') {
        const element = document.getElementById(id);
        if (element) {
            if (element.tagName === 'SELECT') {
                const stringValue = value !== undefined && value !== null ? value.toString() : defaultValue.toString();
                element.value = stringValue;
                
                // Trigger change event para selects dependientes
                if (id === 'owasp-standard') {
                    element.dispatchEvent(new Event('change'));
                }
            } else {
                element.value = value !== undefined && value !== null ? value : defaultValue;
            }
        }
    }
    
    function setTextarea(id, value) {
        const element = document.getElementById(id);
        if (element) {
            element.value = value || '';
        }
    }
    
    setValue('vulnerability-name', vuln.name);
    setValue('host', vuln.host);
    setValue('ruta-afectada', vuln.rutaAfectada);
    setValue('owasp-standard', vuln.owaspStandard || 'web');
    
    // Esperar a que se carguen las categorías antes de seleccionar
    setTimeout(() => {
        setValue('owasp-category', vuln.owasp);
    }, 100);
    
    setValue('mitre-id', vuln.mitre);
    setValue('tool-criticity', vuln.toolCriticity);
    setValue('threat-agent', vuln.threatAgent);
    setTextarea('security-weakness', vuln.securityWeakness);
    setTextarea('security-controls', vuln.securityControls);
    setTextarea('technical-business-impact', vuln.technicalBusinessImpact);
    setTextarea('detail', vuln.detail);
    setTextarea('description', vuln.description);
    setTextarea('recommendation', vuln.recommendation);
    setTextarea('mitre-detection', vuln.mitreDetection);
    setTextarea('mitre-mitigation', vuln.mitreMitigation);
    
    setValue('sl', vuln.sl, 1);
    setValue('m', vuln.m, 1);
    setValue('opp', vuln.o, 0);
    setValue('s', vuln.s, 2);
    setValue('lc', vuln.lc, 2);
    setValue('li', vuln.li, 1);
    setValue('lav', vuln.lav, 1);
    setValue('lac', vuln.lac, 1);
    setValue('ed', vuln.ed, 1);
    setValue('ee', vuln.ee, 1);
    setValue('a', vuln.a, 1);
    setValue('intrusion', vuln.intrusion || vuln.id, 1);
    setValue('fd', vuln.fd, 1);
    setValue('rd', vuln.rd, 1);
    setValue('nc', vuln.nc, 2);
    setValue('pv', vuln.pv, 3);
    
    const saveBtn = document.getElementById('save-btn');
    if (saveBtn) {
        const updateBtn = document.createElement('button');
        updateBtn.className = 'btn btn-warning btn-lg';
        updateBtn.id = 'update-current-btn';
        updateBtn.innerHTML = '<i class="bi bi-arrow-clockwise"></i> Actualizar Vulnerabilidad';
        updateBtn.style.marginLeft = '10px';
        
        saveBtn.style.display = 'none';
        saveBtn.parentNode.insertBefore(updateBtn, saveBtn.nextSibling);
        
        updateBtn.onclick = function() {
            updateVulnerabilityInCalculator(vuln.id);
        };
        
        const cancelBtn = document.createElement('button');
        cancelBtn.className = 'btn btn-secondary btn-lg';
        cancelBtn.id = 'cancel-edit-btn';
        cancelBtn.innerHTML = '<i class="bi bi-x-circle"></i> Cancelar Edición';
        cancelBtn.style.marginLeft = '10px';
        
        updateBtn.parentNode.insertBefore(cancelBtn, updateBtn.nextSibling);
        
        cancelBtn.onclick = function() {
            saveBtn.style.display = 'inline-block';
            updateBtn.remove();
            cancelBtn.remove();
            clearFormValidation();
            showNotification('Edición cancelada', 'info');
        };
    }
    
    showNotification(`Editando: ${vuln.name}. Los cambios se guardarán al hacer clic en "Actualizar Vulnerabilidad".`, 'info');
    
    setTimeout(calculateRisk, 100);
}

function updateVulnerabilityInCalculator(id) {
    const vulnIndex = vulnerabilities.findIndex(v => v.id === id);
    if (vulnIndex === -1) return;
    
    try {
        if (!validateRequiredFields()) {
            return;
        }
        
        const riskData = calculateRisk();
        const formData = getFormData();
        
        const getFactorValue = (id) => {
            const element = document.getElementById(id);
            if (element && element.value) {
                return parseFloat(element.value);
            }
            return 0;
        };
        
        vulnerabilities[vulnIndex] = {
            ...vulnerabilities[vulnIndex],
            ...riskData,
            ...formData,
            id: id,
            sl: getFactorValue('sl'),
            m: getFactorValue('m'),
            o: getFactorValue('opp'),
            s: getFactorValue('s'),
            lc: getFactorValue('lc'),
            li: getFactorValue('li'),
            lav: getFactorValue('lav'),
            lac: getFactorValue('lac'),
            ed: getFactorValue('ed'),
            ee: getFactorValue('ee'),
            a: getFactorValue('a'),
            intrusion: getFactorValue('intrusion'),
            fd: getFactorValue('fd'),
            rd: getFactorValue('rd'),
            nc: getFactorValue('nc'),
            pv: getFactorValue('pv'),
            lastUpdated: new Date().toISOString(),
            date: vulnerabilities[vulnIndex].date
        };
        
        saveVulnerabilities();
        renderVulnerabilitiesList();
        updateDashboard();
        
        const saveBtn = document.getElementById('save-btn');
        const updateBtn = document.getElementById('update-current-btn');
        const cancelBtn = document.getElementById('cancel-edit-btn');
        
        if (saveBtn) saveBtn.style.display = 'inline-block';
        if (updateBtn) updateBtn.remove();
        if (cancelBtn) cancelBtn.remove();
        
        showNotification(`Vulnerabilidad "${formData.name}" actualizada correctamente`, 'success');
        
        setTimeout(() => {
            clearFormValidation();
        }, 500);
        
    } catch (error) {
        console.error('Error actualizando vulnerabilidad:', error);
        showNotification('Error al actualizar la vulnerabilidad', 'error');
    }
}

function deleteVulnerability(id) {
    const vuln = vulnerabilities.find(v => v.id === id);
    if (!vuln) return;
    
    if (confirm(`¿Estás seguro de eliminar la vulnerabilidad "${vuln.name}"?\n\nEsta acción no se puede deshacer.`)) {
        vulnerabilities = vulnerabilities.filter(v => v.id !== id);
        saveVulnerabilities();
        renderVulnerabilitiesList();
        updateDashboard();
        
        showNotification(`Vulnerabilidad "${vuln.name}" eliminada correctamente`, 'success');
    }
}

function updateOldVulnerabilities() {
    if (vulnerabilities.length === 0) {
        console.log('No hay vulnerabilidades para actualizar');
        return;
    }
    
    let updatedCount = 0;
    
    vulnerabilities = vulnerabilities.map(vuln => {
        const needsUpdate = (
            vuln.sl === undefined || 
            vuln.o === undefined || 
            vuln.intrusion === undefined ||
            vuln.owaspStandard === undefined
        );
        
        if (!needsUpdate) {
            return vuln;
        }
        
        updatedCount++;
        
        let standard = vuln.owaspStandard || 'web';
        if (!vuln.owaspStandard && vuln.owasp) {
            if (vuln.owasp.startsWith('API')) {
                standard = 'api';
            } else if (vuln.owasp.startsWith('M')) {
                standard = 'mobile';
            }
        }
        
        return {
            id: vuln.id,
            name: vuln.name,
            date: vuln.date,
            
            likelihood: vuln.likelihood || 0,
            impact: vuln.impact || 0,
            risk: vuln.risk || 0,
            riskLevel: vuln.riskLevel || 'INFORMATIVO',
            riskClass: vuln.riskClass || 'risk-info',
            
            host: vuln.host || '',
            rutaAfectada: vuln.rutaAfectada || '',
            owaspStandard: standard,
            owasp: vuln.owasp || '',
            mitre: vuln.mitre || '',
            toolCriticity: vuln.toolCriticity || '',
            
            threatAgent: vuln.threatAgent || '',
            securityWeakness: vuln.securityWeakness || '',
            securityControls: vuln.securityControls || '',
            technicalBusinessImpact: vuln.technicalBusinessImpact || '',
            detail: vuln.detail || '',
            description: vuln.description || '',
            recommendation: vuln.recommendation || '',
            mitreDetection: vuln.mitreDetection || '',
            mitreMitigation: vuln.mitreMitigation || '',
            lastUpdated: vuln.lastUpdated || new Date().toISOString(),
            
            sl: vuln.sl !== undefined ? vuln.sl : 1,
            m: vuln.m !== undefined ? vuln.m : 1,
            o: vuln.o !== undefined ? vuln.o : 0,
            s: vuln.s !== undefined ? vuln.s : 2,
            lc: vuln.lc !== undefined ? vuln.lc : 2,
            li: vuln.li !== undefined ? vuln.li : 1,
            lav: vuln.lav !== undefined ? vuln.lav : 1,
            lac: vuln.lac !== undefined ? vuln.lac : 1,
            ed: vuln.ed !== undefined ? vuln.ed : 1,
            ee: vuln.ee !== undefined ? vuln.ee : 1,
            a: vuln.a !== undefined ? vuln.a : 1,
            intrusion: vuln.intrusion !== undefined ? vuln.intrusion : 
                      (vuln.id !== undefined && typeof vuln.id === 'number' ? vuln.id : 1),
            fd: vuln.fd !== undefined ? vuln.fd : 1,
            rd: vuln.rd !== undefined ? vuln.rd : 1,
            nc: vuln.nc !== undefined ? vuln.nc : 2,
            pv: vuln.pv !== undefined ? vuln.pv : 3
        };
    });
    
    if (updatedCount > 0) {
        console.log(`Actualizadas ${updatedCount} vulnerabilidades antiguas`);
        saveVulnerabilities();
        renderVulnerabilitiesList();
        updateDashboard();
        showNotification(`${updatedCount} vulnerabilidades actualizadas`, 'success');
    }
}