import os
import json
import logging
import re
from typing import Dict, Any, List, Tuple

from flask import Flask, request, render_template
from openai import OpenAI
from werkzeug.exceptions import HTTPException

# -----------------------
# Configuración básica
# -----------------------
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB, por si agregas archivos en el futuro
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("auditoria-app")

# Cliente OpenAI
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise RuntimeError("Falta la variable de entorno OPENAI_API_KEY")
client = OpenAI(api_key=OPENAI_API_KEY)

# Constantes de formato
HALLAZGO_PREFIXES = [
    "No se ha", "No se encuentran", "No se cuenta con"
]
SECCIONES_PERMITIDAS = [
    "Antecedente",
    "Qué se identificó",
    "Qué se realiza correctamente",
    "Riesgos asociados",
    "Recomendaciones",
    "Referencias",
    "Plan de remediación propuesto"
]


def _validar_y_normalizar_hallazgo(texto: str) -> str:
    """Valida que el hallazgo cumpla: <= 3 líneas y empiece con los prefijos exigidos.
    Si excede 3 líneas, recorta. Si no inicia con prefijo válido, intenta forzar la forma.
    """
    if not texto:
        return "No se cuenta con información suficiente para redactar el hallazgo, debido a falta de datos proporcionados, lo que pudiera dificultar la evaluación del control."

    # Normalizar espacios
    texto = re.sub(r"\s+", " ", texto).strip()

    # Verificar prefijos
    if not any(texto.startswith(p) for p in HALLAZGO_PREFIXES):
        # Forzar forma estándar sin inventar contenido
        texto = f"No se cuenta con {texto[0].lower() + texto[1:] if len(texto) > 1 else 'información'}, debido a causas no confirmadas, lo que pudiera derivar en riesgos de cumplimiento y operativos."

    # Limitar a 3 líneas (medido por puntos finales aproximados o longitud)
    # Aquí optamos por longitud/aproximación: máx 3 frases o ~350 caracteres
    frases = re.split(r'(?<=[.!?])\s+', texto)
    if len(frases) > 3:
        texto = " ".join(frases[:3]).strip()

    if len(texto) > 350:
        texto = texto[:350].rstrip() + "..."

    return texto


def _limpiar_y_validar_anexo(anexo: Dict[str, Any]) -> Dict[str, Any]:
    """Garantiza que solo existan las secciones permitidas y con tipos esperados."""
    limpio = {}

    for clave in SECCIONES_PERMITIDAS:
        valor = anexo.get(clave)
        if valor is None:
            continue

        # Normalización básica
        if isinstance(valor, str):
            valor = re.sub(r"\s+", " ", valor).strip()
        elif isinstance(valor, list):
            # Limitar tamaño de cada elemento, remover vacíos
            nuevo_list = []
            for item in valor:
                if isinstance(item, str):
                    txt = re.sub(r"\s+", " ", item).strip()
                    if txt:
                        nuevo_list.append(txt[:500])
                elif isinstance(item, dict):
                    # Para plan de remediación con {"accion": ..., "evidencia": ...}
                    safe_item = {}
                    for k in ("accion", "evidencia"):
                        v = item.get(k)
                        if isinstance(v, str):
                            v = re.sub(r"\s+", " ", v).strip()[:500]
                            safe_item[k] = v
                    if safe_item:
                        nuevo_list.append(safe_item)
            valor = nuevo_list

        # Límite de longitud razonable
        if isinstance(valor, str):
            valor = valor[:2000]

        limpio[clave] = valor

    # Garantía de no-secciones extra: ignoramos otras claves
    return limpio


def _render_data_a_texto(data_json: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Convierte la respuesta en JSON a texto final:
    - hallazgo (1 bloque)
    - anexo (diccionario con secciones)
    """
    hallazgo = data_json.get("hallazgo", "")
    hallazgo = _validar_y_normalizar_hallazgo(hallazgo)

    anexo_bruto = data_json.get("anexo", {})
    anexo = _limpiar_y_validar_anexo(anexo_bruto if isinstance(anexo_bruto, dict) else {})

    return hallazgo, anexo


def generar_redaccion(data: Dict[str, str]) -> Dict[str, Any]:
    """Genera la redacción en formato JSON y produce datos listos para renderizar.
    Devuelve un diccionario con keys: hallazgo (str) y anexo (dict).
    """
    # Validaciones de entrada (anticipo de errores comunes)
    for k, v in data.items():
        if isinstance(v, str):
            data[k] = v.strip()
        if not data[k]:
            logger.warning(f"Campo vacío o faltante: {k}")

    prompt_usuario = f"""
Eres un experto en Auditoría Interna y Ciberseguridad.

INSTRUCCIONES ESTRICTAS:

1) REDACCIÓN DEL HALLAZGO:
- Máximo 3 líneas.
- Redacción corrida.
- Estructura obligatoria tipo:
"No se ha / No se encuentran / No se cuenta con..., debido a..., lo que pudiera..."

2) REDACCIÓN DEL ANEXO
Debes entregar **EXACTAMENTE** este JSON y nada más (sin texto adicional fuera del JSON):

{{
  "hallazgo": "texto de máximo 3 líneas, con la estructura indicada",
  "anexo": {{
    "Antecedente": "Breve contexto considerando control, objetivo y alcance",
    "Qué se identificó": "Desarrollo técnico-profesional del hallazgo",
    "Qué se realiza correctamente": "Controles o prácticas que sí operan adecuadamente",
    "Riesgos asociados": "Impactos potenciales derivados del hallazgo",
    "Recomendaciones": [
      "Recomendación basada en estándar reconocido, citando referencia específica (ej. ISO/IEC 27001:2022 cláusula 5.3; NIST CSF PR.IP-12; COBIT DSS05.04)"
    ],
    "Referencias": [
      "ISO/IEC 27001:2022 cláusula X.X",
      "NIST CSF PR.XX-YY",
      "COBIT DSSXX.XX"
    ],
    "Plan de remediación propuesto": [
      {{
        "accion": "Se designará/Se actualizará/Se implementará...",
        "evidencia": "Evidencia esperada..."
      }}
    ]
  }}
}}

No agregar secciones adicionales.
No dividir en subtemas extra.
No inventar información fuera de lo proporcionado.

Información base:

Control: {data.get('control', '')}
Objetivo: {data.get('objetivo', '')}
Alcance: {data.get('alcance', '')}
Qué se identificó: {data.get('identificado', '')}
Qué sí se hace correctamente: {data.get('correcto', '')}
Causa raíz: {data.get('causa', '')}
Consecuencia: {data.get('consecuencia', '')}
"""

    try:
        # Llamada al modelo
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Eres especialista senior en auditoría interna y ciberseguridad. Responde en español neutro."},
                {"role": "user", "content": prompt_usuario}
            ],
            temperature=0.2,
            max_tokens=1000,
            top_p=1.0,
            n=1
        )

        raw = resp.choices[0].message.content if resp and resp.choices else ""
        if not raw:
            raise ValueError("Respuesta vacía del modelo.")

        # Intentar parsear JSON directo
        parsed = None
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            # Fallback: extraer bloque JSON del texto (si viniera enmarcado)
            match = re.search(r"\{.*\}", raw, flags=re.DOTALL)
            if match:
                try:
                    parsed = json.loads(match.group(0))
                except Exception:
                    parsed = None

        if not isinstance(parsed, dict):
            logger.warning("No se obtuvo un JSON válido. Se aplicará fallback mínimo.")
            # Fallback básico para no romper UX
            parsed = {
                "hallazgo": raw.strip()[:350],
                "anexo": {}
            }

        hallazgo, anexo = _render_data_a_texto(parsed)
        return {"hallazgo": hallazgo, "anexo": anexo}

    except HTTPException as http_err:
        logger.exception("Error HTTP en la app")
        raise http_err
    except Exception as e:
        logger.exception("Error generando redacción")
        # Mensaje genérico al usuario, sin filtrar detalles sensibles
        return {
            "hallazgo": "No se cuenta con la redacción del hallazgo, debido a un error en el servicio, lo que pudiera retrasar la entrega del informe.",
            "anexo": {
                "Riesgos asociados": "Demora operativa y de cumplimiento en la formalización del hallazgo.",
                "Recomendaciones": [
                    "Reintentar la generación y, si persiste, escalar a soporte técnico interno."
                ]
            }
        }


@app.route("/", methods=["GET", "POST"])
def index():
    resultado = None
    errores = []

    if request.method == "POST":
        try:
            # Recoger datos
            campos = ("control", "objetivo", "alcance", "identificado", "correcto", "causa", "consecuencia")
            data = {k: (request.form.get(k, "") or "").strip() for k in campos}

            # Validación mínima de entradas
            for k in campos:
                if not data[k]:
                    errores.append(f"El campo '{k}' es obligatorio.")

            if errores:
                return render_template("index.html", resultado=resultado, errores=errores, data=data)

            # Generar
            resultado = generar_redaccion(data)
            return render_template("index.html", resultado=resultado, errores=errores, data=data)
        except Exception as e:
            logger.exception("Error en POST /")
            errores.append("Ocurrió un error inesperado. Intenta nuevamente.")
            return render_template("index.html", resultado=resultado, errores=errores, data=request.form)

    # GET
    return render_template("index.html", resultado=resultado, errores=errores, data={})


@app.route("/healthz", methods=["GET"])
def healthz():
    return {"status": "ok"}, 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    # En producción: usar un servidor WSGI (gunicorn/uwsgi)
    app.run(host="0.0.0.0", port=port, debug=False)
``
