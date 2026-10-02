// ============================================================
// evidences.js - Sistema de evidencias con IndexedDB + ZIP + Manifest
// Intriga Risk Map
// ============================================================

const EVIDENCES_DB_NAME = 'IntrigaRiskMapDB';
const EVIDENCES_DB_VERSION = 1;
const EVIDENCES_STORE = 'evidences';

// ---------- INDEXEDDB ----------
function openEvidencesDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(EVIDENCES_DB_NAME, EVIDENCES_DB_VERSION);
        req.onupgradeneeded = (e) => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains(EVIDENCES_STORE)) {
                const store = db.createObjectStore(EVIDENCES_STORE, { keyPath: 'id' });
                store.createIndex('vulnId', 'vulnId', { unique: false });
            }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function saveEvidence(vulnId, file) {
    const db = await openEvidencesDB();
    const id = `${vulnId}_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    return new Promise((resolve, reject) => {
        const tx = db.transaction(EVIDENCES_STORE, 'readwrite');
        const store = tx.objectStore(EVIDENCES_STORE);
        store.put({
            id,
            vulnId,
            name: file.name,
            type: file.type,
            size: file.size,
            blob: file,
            uploadedAt: new Date().toISOString()
        });
        tx.oncomplete = () => resolve(id);
        tx.onerror = () => reject(tx.error);
    });
}

async function getEvidencesByVuln(vulnId) {
    if (!vulnId) return [];
    const db = await openEvidencesDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(EVIDENCES_STORE, 'readonly');
        const index = tx.objectStore(EVIDENCES_STORE).index('vulnId');
        const req = index.getAll(vulnId);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function deleteEvidence(id) {
    const db = await openEvidencesDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(EVIDENCES_STORE, 'readwrite');
        tx.objectStore(EVIDENCES_STORE).delete(id);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
}

async function deleteEvidencesByVuln(vulnId) {
    const db = await openEvidencesDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(EVIDENCES_STORE, 'readwrite');
        const index = tx.objectStore(EVIDENCES_STORE).index('vulnId');
        const req = index.openCursor(vulnId);
        req.onsuccess = (e) => {
            const cursor = e.target.result;
            if (cursor) {
                cursor.delete();
                cursor.continue();
            }
        };
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
}

async function getAllEvidences() {
    const db = await openEvidencesDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(EVIDENCES_STORE, 'readonly');
        const req = tx.objectStore(EVIDENCES_STORE).getAll();
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

// ---------- UTILIDADES ----------
function sanitizeFilename(str) {
    if (!str) return 'archivo';
    return String(str)
        .toLowerCase()
        .normalize('NFD').replace(/[\u0300-\u036f]/g, '') // quitar acentos
        .replace(/[^a-z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '')
        .substring(0, 40) || 'archivo';
}

function blobToDataURL(blob) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = reject;
        reader.readAsDataURL(blob);
    });
}

function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function generateVulnId() {
    const date = new Date().toISOString().split('T')[0].replace(/-/g, '');
    const prefix = `VULN-${date}`;
    const todays = vulnerabilities.filter(v => v.vulnId && v.vulnId.startsWith(prefix));
    const nextNum = todays.length + 1;
    return `${prefix}-${String(nextNum).padStart(3, '0')}`;
}

function buildPackageName(projectName, clientName = '') {
    const date = new Date().toISOString().split('T')[0];
    const project = sanitizeFilename(projectName || 'SinProyecto');
    const client = clientName ? sanitizeFilename(clientName) : '';

    // Clave única por cliente+proyecto+fecha para contar versiones
    const keyBase = client ? `${client}_${project}` : project;
    const key = `zipVersion_${keyBase}_${date}`;
    const currentVersion = parseInt(localStorage.getItem(key) || '0') + 1;
    localStorage.setItem(key, currentVersion.toString());
    const version = `v${String(currentVersion).padStart(2, '0')}`;

    // Nombre: IntrigaRiskMap_Cliente_Proyecto_Fecha_vXX.zip
    // Si no hay cliente: IntrigaRiskMap_Proyecto_Fecha_vXX.zip
    const parts = ['IntrigaRiskMap'];
    if (client) parts.push(client);
    parts.push(project);
    parts.push(date);
    parts.push(version);

    return `${parts.join('_')}.zip`;
}

// ---------- PREVIEW EN EL FORMULARIO ----------
async function renderEvidencePreview(vulnId) {
    const container = document.getElementById('evidence-preview');
    if (!container) return;

    if (!vulnId) {
        container.innerHTML = '';
        return;
    }

    const evidences = await getEvidencesByVuln(vulnId);
    if (evidences.length === 0) {
        container.innerHTML = '';
        return;
    }

    container.innerHTML = evidences.map(ev => {
        const url = URL.createObjectURL(ev.blob);
        return `
            <div class="evidence-thumb" data-id="${ev.id}">
                <img src="${url}" alt="${ev.name}">
                <button class="evidence-delete" data-id="${ev.id}" title="Eliminar">✕</button>
                <div class="evidence-name">${ev.name}</div>
            </div>
        `;
    }).join('');

    // Listeners de eliminar
    container.querySelectorAll('.evidence-delete').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const evId = btn.dataset.id;
            if (confirm('¿Eliminar esta evidencia?')) {
                await deleteEvidence(evId);
                await renderEvidencePreview(vulnId);
                showNotification('Evidencia eliminada', 'success');
            }
        });
    });
}

// ---------- GALERÍA EN EL MODAL ----------
async function renderEvidenceGallery(vulnId) {
    const evidences = await getEvidencesByVuln(vulnId);
    if (evidences.length === 0) {
        return `
            <div class="detail-section">
                <h5 class="detail-section-title">Evidencias</h5>
                <p class="text-muted">Sin evidencias adjuntas</p>
            </div>
        `;
    }

    return `
        <div class="detail-section">
            <h5 class="detail-section-title">Evidencias (${evidences.length})</h5>
            <div class="evidence-gallery">
                ${evidences.map(ev => {
                    const url = URL.createObjectURL(ev.blob);
                    const isImage = ev.type && ev.type.startsWith('image/');
                    return `
                        <div class="evidence-gallery-item" data-id="${ev.id}">
                            ${isImage 
                                ? `<img src="${url}" alt="${ev.name}" onclick="openEvidenceFullscreen('${ev.id}')">`
                                : `<div class="evidence-file">📎</div>`
                            }
                            <div class="evidence-gallery-name">${ev.name}</div>
                        </div>
                    `;
                }).join('')}
            </div>
        </div>
    `;
}

window.openEvidenceFullscreen = async function(evidenceId) {
    const all = await getAllEvidences();
    const ev = all.find(e => e.id === evidenceId);
    if (!ev) return;

    const url = URL.createObjectURL(ev.blob);
    const overlay = document.createElement('div');
    overlay.className = 'evidence-fullscreen-overlay';
    overlay.style.cssText = `
        position: fixed;
        inset: 0;
        background: rgba(0, 0, 0, 0.95);
        z-index: 99999;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-direction: column;
        cursor: zoom-out;
        padding: 20px;
        animation: fadeIn 0.2s ease;
    `;
    
    // Botón de cerrar
    const closeBtn = document.createElement('button');
    closeBtn.innerHTML = '✕';
    closeBtn.style.cssText = `
        position: absolute;
        top: 20px;
        right: 20px;
        width: 40px;
        height: 40px;
        border-radius: 50%;
        background: rgba(255, 255, 255, 0.15);
        color: white;
        border: none;
        font-size: 20px;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: background 0.2s ease;
    `;
    closeBtn.onmouseenter = () => closeBtn.style.background = 'rgba(255, 255, 255, 0.3)';
    closeBtn.onmouseleave = () => closeBtn.style.background = 'rgba(255, 255, 255, 0.15)';

    // Imagen
    const img = document.createElement('img');
    img.src = url;
    img.alt = ev.name;
    img.style.cssText = `
        max-width: 90vw;
        max-height: 82vh;
        object-fit: contain;
        border-radius: 8px;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
    `;

    // Nombre del archivo
    const caption = document.createElement('p');
    caption.textContent = ev.name;
    caption.style.cssText = `
        color: white;
        margin-top: 15px;
        font-size: 14px;
        opacity: 0.85;
        text-align: center;
        max-width: 90vw;
        word-break: break-all;
    `;

    overlay.appendChild(closeBtn);
    overlay.appendChild(img);
    overlay.appendChild(caption);

    // Cerrar al hacer clic en cualquier parte
    overlay.addEventListener('click', () => {
        document.body.removeChild(overlay);
        URL.revokeObjectURL(url);
    });

    // Cerrar con Escape
    const escHandler = (e) => {
        if (e.key === 'Escape') {
            if (document.body.contains(overlay)) {
                document.body.removeChild(overlay);
                URL.revokeObjectURL(url);
            }
            document.removeEventListener('keydown', escHandler);
        }
    };
    document.addEventListener('keydown', escHandler);

    document.body.appendChild(overlay);
};

// Animación de fade
const style = document.createElement('style');
style.textContent = `
    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }
`;
document.head.appendChild(style);


// ========== CONSTRUCCIÓN DEL NOMBRE DE CARPETA POR VULNERABILIDAD ==========
// Genera un nombre tipo: "001_SQL_Injection_Login"
// - Prefijo: número secuencial derivado del sufijo del vulnId (001, 002, 003...)
// - Descripción: el campo "name" (Vector de Ataque) sanitizado a snake_case
function buildEvidenceFolderName(vuln, orderIndex) {
    // 1. Extraer el número secuencial del vulnId
    //    Ej: "VULN-20250115-007" → "007"
    //    Si no se puede, usar el orderIndex pasado
    let seq = String(orderIndex).padStart(3, '0');
    if (vuln.vulnId) {
        const match = String(vuln.vulnId).match(/(\d+)$/);
        if (match) {
            seq = match[1].padStart(3, '0');
        }
    }

    // 2. Sanitizar el nombre de la vulnerabilidad (Vector de Ataque)
    //    - Quitar acentos
    //    - Reemplazar espacios y caracteres no alfanuméricos por "_"
    //    - Truncar a 60 caracteres para que el path no sea enorme
    const rawName = (vuln.name || 'Sin_Vector').trim();
    let safeName = rawName
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')      // quitar acentos
        .replace(/[^a-zA-Z0-9\s_-]/g, '')     // quitar símbolos peligrosos
        .replace(/\s+/g, '_')                 // espacios → guion bajo
        .replace(/_+/g, '_')                  // colapsar múltiples guiones
        .replace(/^_+|_+$/g, '');             // quitar guiones al inicio/final

    if (safeName.length > 60) {
        safeName = safeName.substring(0, 60).replace(/_+$/, '');
    }
    if (!safeName) {
        safeName = 'Sin_Vector';
    }

    return `${seq}_${safeName}`;
}


// ---------- EXPORTAR PAQUETE ZIP ----------
async function exportPackage() {
    if (vulnerabilities.length === 0) {
        showNotification('No hay vulnerabilidades para exportar', 'error');
        return;
    }

    // Detectar cliente y proyecto desde los datos ya guardados
    const clientDetected = vulnerabilities.find(v => v.client)?.client || '';
    const projectDetected = vulnerabilities.find(v => v.project)?.project || '';

    if (!clientDetected && !projectDetected) {
        const fallback = prompt(
            'No se detectó Cliente ni Proyecto en las vulnerabilidades. Ingrese un nombre para el ZIP:',
            'SinProyecto'
        );
        if (fallback === null) return;
        var projectName = fallback;
        var clientName = '';
    } else {
        var clientName = clientDetected;
        var projectName = projectDetected;
        const ok = confirm(
            `Se exportará el paquete para:\n\nCliente: ${clientName || '(sin cliente)'}\nProyecto: ${projectName || '(sin proyecto)'}\n\n¿Continuar?`
        );
        if (!ok) return;
    }

    // Loading
    const loading = document.createElement('div');
    loading.id = 'zip-loading-overlay';
    loading.innerHTML = `
        <div style="position: fixed; inset: 0; background: rgba(0,0,0,0.85); z-index: 9999;
                    display: flex; justify-content: center; align-items: center; flex-direction: column;">
            <div style="background: white; padding: 35px; border-radius: 20px; text-align: center;">
                <div style="font-size: 52px; margin-bottom: 15px;">📦</div>
                <div style="font-size: 18px; font-weight: bold; color: #1a2a6c; margin-bottom: 10px;">
                    Empaquetando hallazgos...
                </div>
                <div class="spinner-border text-primary" style="width: 40px; height: 40px;"></div>
            </div>
        </div>
    `;
    document.body.appendChild(loading);

    try {
        const zip = new JSZip();
        const manifest = {
            version: '1.0',
            product: 'IntrigaRiskMap',
            client: clientName,
            project: projectName,
            exportedAt: new Date().toISOString(),
            totalVulnerabilities: vulnerabilities.length,
            totalEvidences: 0,
            evidences: []
        };

        const evidenciasRoot = zip.folder('evidencias');

        // Ordenar vulnerabilidades para que el prefijo numérico sea secuencial
        // (se ordenan por vulnId si existe; si no, por id)
        const sortedVulns = [...vulnerabilities].sort((a, b) => {
            const aId = a.vulnId || `VULN-${String(a.id).padStart(12, '0')}`;
            const bId = b.vulnId || `VULN-${String(b.id).padStart(12, '0')}`;
            return aId.localeCompare(bId);
        });

        // Recorrer cada vulnerabilidad y crear su carpeta
        for (let i = 0; i < sortedVulns.length; i++) {
            const vuln = sortedVulns[i];
            const vulnId = vuln.vulnId || `VULN-SINID-${vuln.id}`;
            const evidenceFiles = await getEvidencesByVuln(vulnId);

            // Nombre de la carpeta: 001_Vector_de_Ataque
            const folderName = buildEvidenceFolderName(vuln, i + 1);
            const vulnFolder = evidenciasRoot.folder(folderName);

            const vulnManifest = {
                vulnId: vulnId,
                vector: vuln.name || 'Sin vector',
                folder: folderName,
                files: []
            };

            // Si no hay evidencias, no creamos carpeta (evitamos carpetas vacías)
            if (evidenceFiles.length === 0) {
                manifest.evidences.push(vulnManifest);
                continue;
            }

            // Numerar las capturas dentro de la carpeta: 01_, 02_, ...
            for (let j = 0; j < evidenceFiles.length; j++) {
                const ev = evidenceFiles[j];
                const seq = String(j + 1).padStart(2, '0');

                // Extraer la extensión original
                const ext = (ev.name.split('.').pop() || 'png').toLowerCase();

                // Construir un nombre limpio y descriptivo a partir del nombre original
                // Ej: "IMG_1234.png" → "01_img_1234.png"
                //     "captura login.png" → "01_captura_login.png"
                const baseName = ev.name
                    .replace(/\.[^.]+$/, '')  // quitar extensión
                    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')  // quitar acentos
                    .replace(/[^a-zA-Z0-9\s_-]/g, '')  // quitar símbolos
                    .replace(/\s+/g, '_')  // espacios → _
                    .replace(/_+/g, '_')
                    .replace(/^_+|_+$/g, '')
                    .substring(0, 40) || 'captura';

                const newName = `${seq}_${baseName}.${ext}`;

                vulnFolder.file(newName, ev.blob);

                vulnManifest.files.push({
                    name: newName,
                    originalName: ev.name,
                    type: ev.type,
                    size: ev.size
                });
                manifest.totalEvidences++;
            }

            manifest.evidences.push(vulnManifest);
        }

        // Guardar JSON de vulnerabilidades y manifest
        zip.file('vulns.json', JSON.stringify(vulnerabilities, null, 2));
        zip.file('manifest.json', JSON.stringify(manifest, null, 2));

        // Generar ZIP
        const blob = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' });

        // Nombre del archivo
        const filename = buildPackageName(projectName, clientName);
        downloadBlob(blob, filename);

        document.body.removeChild(loading);
        showNotification(`✅ Paquete exportado: ${filename}`, 'success');

    } catch (error) {
        console.error('Error generando ZIP:', error);
        if (document.getElementById('zip-loading-overlay')) {
            document.body.removeChild(document.getElementById('zip-loading-overlay'));
        }
        showNotification('❌ Error al generar el paquete ZIP', 'error');
    }
}


// ---------- IMPORTAR PAQUETE ZIP ----------
async function importPackage(file) {
    if (!file) return;

    const loading = document.createElement('div');
    loading.id = 'zip-loading-overlay';
    loading.innerHTML = `
        <div style="position: fixed; inset: 0; background: rgba(0,0,0,0.85); z-index: 9999;
                    display: flex; justify-content: center; align-items: center; flex-direction: column;">
            <div style="background: white; padding: 35px; border-radius: 20px; text-align: center;">
                <div style="font-size: 52px; margin-bottom: 15px;">📥</div>
                <div style="font-size: 18px; font-weight: bold; color: #1a2a6c; margin-bottom: 10px;">
                    Importando paquete...
                </div>
                <div class="spinner-border text-primary" style="width: 40px; height: 40px;"></div>
            </div>
        </div>
    `;
    document.body.appendChild(loading);

    try {
        const zip = await JSZip.loadAsync(file);

        // 1. Leer manifest
        const manifestFile = zip.file('manifest.json');
        if (!manifestFile) {
            throw new Error('El ZIP no contiene manifest.json');
        }
        const manifest = JSON.parse(await manifestFile.async('string'));

        // 2. Leer vulnerabilidades
        const vulnsFile = zip.file('vulns.json');
        if (!vulnsFile) {
            throw new Error('El ZIP no contiene vulns.json');
        }
        const importedVulns = JSON.parse(await vulnsFile.async('string'));

        // 3. Fusionar vulnerabilidades (sin duplicar por vulnId)
        const existingVulnIds = new Set(vulnerabilities.map(v => v.vulnId).filter(Boolean));
        const newVulns = importedVulns.filter(v => v.vulnId && !existingVulnIds.has(v.vulnId));
        const duplicates = importedVulns.length - newVulns.length;
        vulnerabilities = vulnerabilities.concat(newVulns);

        // 4. Importar evidencias
        let importedEvidences = 0;
        let missingEvidences = 0;
        for (const evEntry of manifest.evidences || []) {
            // Solo importar evidencias de vulnerabilidades nuevas (evitar duplicados)
            if (existingVulnIds.has(evEntry.vulnId)) continue;

            for (const fileInfo of evEntry.files || []) {
                // Construir la ruta: evidencias/{folder}/{name}
                // Si el manifest es viejo y no trae folder, usar fallback al formato anterior
                let zipPath;
                if (evEntry.folder) {
                    zipPath = `evidencias/${evEntry.folder}/${fileInfo.name}`;
                } else {
                    // Compatibilidad con paquetes exportados antes del cambio
                    zipPath = `evidencias/${fileInfo.name}`;
                }

                const zipEntry = zip.file(zipPath);
                if (!zipEntry) {
                    console.warn(`Evidencia no encontrada en el ZIP: ${zipPath}`);
                    missingEvidences++;
                    continue;
                }
                const blob = await zipEntry.async('blob');
                const file = new File([blob], fileInfo.originalName || fileInfo.name, {
                    type: fileInfo.type || 'image/png'
                });
                await saveEvidence(evEntry.vulnId, file);
                importedEvidences++;
            }
        }

        // 5. Persistir y actualizar
        saveVulnerabilities();
        renderVulnerabilitiesList();
        updateDashboard();

        document.body.removeChild(loading);

        let msg = `✅ Importadas ${newVulns.length} vulnerabilidades y ${importedEvidences} evidencias.`;
        if (duplicates > 0) msg += ` (${duplicates} duplicadas omitidas)`;
        if (missingEvidences > 0) msg += ` ⚠️ ${missingEvidences} evidencias faltantes en el ZIP`;
        showNotification(msg, 'success');

    } catch (error) {
        console.error('Error importando ZIP:', error);
        if (document.getElementById('zip-loading-overlay')) {
            document.body.removeChild(document.getElementById('zip-loading-overlay'));
        }
        showNotification(`❌ Error al importar: ${error.message}`, 'error');
    }
}

// ---------- VALIDACIÓN ANTES DE EXPORTAR ----------
async function validatePackage() {
    const issues = [];
    for (const vuln of vulnerabilities) {
        if (!vuln.vulnId) {
            issues.push(`⚠️ "${vuln.name}" no tiene vulnId`);
            continue;
        }
        const evs = await getEvidencesByVuln(vuln.vulnId);
        if (evs.length === 0 && ['CRÍTICO', 'ALTO'].includes(vuln.riskLevel)) {
            issues.push(`📷 "${vuln.name}" (${vuln.riskLevel}) no tiene evidencias`);
        }
    }
    return issues;
}

// ---------- INICIALIZACIÓN ----------
document.addEventListener('DOMContentLoaded', () => {
    // Input de archivos de evidencia
    const evidenceInput = document.getElementById('evidence-files');
    if (evidenceInput) {
        evidenceInput.addEventListener('change', async (e) => {
            const files = Array.from(e.target.files || []);
            if (files.length === 0) return;

            // El vulnId se guarda en un input oculto
            let vulnId = document.getElementById('current-vuln-id')?.value;

            // Si no hay vulnId asignado todavía, se genera uno temporal
            if (!vulnId) {
                vulnId = generateVulnId();
                let hiddenInput = document.getElementById('current-vuln-id');
                if (!hiddenInput) {
                    hiddenInput = document.createElement('input');
                    hiddenInput.type = 'hidden';
                    hiddenInput.id = 'current-vuln-id';
                    document.body.appendChild(hiddenInput);
                }
                hiddenInput.value = vulnId;
            }

            for (const file of files) {
                await saveEvidence(vulnId, file);
            }

            await renderEvidencePreview(vulnId);
            showNotification(`${files.length} evidencia(s) añadida(s)`, 'success');
            e.target.value = '';
        });
    }

    // Botón exportar paquete
    const exportZipBtn = document.getElementById('export-zip-btn');
    if (exportZipBtn) {
        exportZipBtn.addEventListener('click', exportPackage);
    }

    // Botón validar paquete
    const validateBtn = document.getElementById('validate-package-btn');
    if (validateBtn) {
        validateBtn.addEventListener('click', async () => {
            const issues = await validatePackage();
            if (issues.length === 0) {
                showNotification('✅ Paquete válido. Todo listo para exportar.', 'success');
            } else {
                alert('Problemas detectados:\n\n' + issues.join('\n'));
            }
        });
    }

    // Input importar ZIP
    const importZipInput = document.getElementById('import-zip-input');
    if (importZipInput) {
        importZipInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) importPackage(file);
            e.target.value = '';
        });
    }
});