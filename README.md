# 🛡️ Intriga Risk Map

![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-blue)
![Network](https://img.shields.io/badge/Pentest-Red%20Interna%2FExterna-darkgreen)
![AI](https://img.shields.io/badge/Powered%20by-DeepSeek-purple)

> Calcula y gestiona vulnerabilidades OWASP y de Pentest de Red con asistencia de IA.

Gestor completo de vulnerabilidades para **OWASP Web, API, Mobile** y **Pentest de Red (Interna/Externa)**, con calculadora de riesgo, dashboard interactivo, gestión de evidencias en ZIP y el asistente **Lovecraft** 🤖 que redacta informes técnicos automáticos.

---

## ✨ Características

| Característica | Descripción |
|----------------|-------------|
| 🧮 Calculadora de Riesgo | 16 factores CVSS |
| 🎯 OWASP Top 10 | Web 2025 / API 2023 / Mobile 2024 |
| 🌐 Pentest Red Externa | 10 categorías (EXT-01 a EXT-10) |
| 🏢 Pentest Red Interna | 10 categorías (INT-01 a INT-10) |
| ➕ Categorías personalizadas | Agrega tus propias categorías por estándar |
| 🤖 Asistente Lovecraft | IA que redacta desde una frase |
| 📊 Dashboard | Gráficos interactivos + tablas separadas OWASP/Red |
| 💾 LocalStorage | Persistencia en navegador |
| 🗜️ Exportación ZIP | Hallazgos + evidencias + manifest |
| 📄 Exportaciones | JSON / PDF técnico / PDF ejecutivo |
| 🌙 Tema oscuro | Interfaz adaptativa |

---

## 📚 Estándares soportados

| Estándar | Categorías | Color del badge |
|---|---|---|
| OWASP Top 10 Web 2025 | A01 a A10 | Azul (`bg-primary`) |
| OWASP Top 10 API 2023 | API1 a API10 | Rojo (`bg-danger`) |
| OWASP Top 10 Mobile 2024 | M1 a M10 | Verde (`bg-success`) |
| Pentest Red Externa | EXT-01 a EXT-10 | Negro (`bg-dark`) |
| Pentest Red Interna | INT-01 a INT-10 | Amarillo (`bg-warning`) |

Además, en cada estándar puedes:

- Elegir **"Otro (especificar...)"** para una categoría puntual que no esté en la lista.
- Usar **"+ Guardar en mi lista"** para persistir esa categoría personalizada en `localStorage`. Aparecerá en el dropdown del estándar para futuras sesiones.

---

## ⚪ Riesgo Informativo

Los 16 factores de la calculadora inician en **"Riesgo Informativo" (valor 0)**.
Si no se evalúa ningún factor, el riesgo resultante es `INFORMATIVO (0.00)`.
Esto permite guardar hallazgos sin evaluar (notas, observaciones, reconocimiento inicial) sin que distorsionen el dashboard ni las estadísticas de riesgo.

---

## 🗜️ Paquete de hallazgos (ZIP)

Al exportar, se genera un ZIP con:
