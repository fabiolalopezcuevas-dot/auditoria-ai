import os
from flask import Flask, request, render_template
from openai import OpenAI

app = Flask(__name__)

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def generar_redaccion(data):

    prompt = f"""
Eres un experto en Auditoría Interna y Ciberseguridad.

INSTRUCCIONES ESTRICTAS:

1) REDACCIÓN DEL HALLAZGO:
- Máximo 3 líneas.
- Redacción corrida.
- Estructura obligatoria tipo:
"No se ha / No se encuentran / No se cuenta con..., debido a..., lo que pudiera..."

2) REDACCIÓN DEL ANEXO
Debe contener EXACTAMENTE las siguientes secciones:

Antecedente:
(Breve contexto considerando control, objetivo y alcance)

Qué se identificó:
(Desarrollo técnico-profesional del hallazgo)

Qué se realiza correctamente:
(Mencionar controles o prácticas que sí operan adecuadamente)

Riesgos asociados:
(Explicar impactos potenciales derivados del hallazgo)

Recomendaciones:
- En formato bullet
- Basadas en estándares reconocidos
- Citar referencias específicas (ejemplo: ISO/IEC 27001:2022 cláusula 5.3; NIST CSF PR.IP-12; COBIT DSS05.04)

Referencias:
(Listar de forma específica los numerales utilizados)

Plan de remediación propuesto:
1. Acción usando verbos como: Se designará, Se actualizará, Se implementará...
   Evidencia esperada:
2. ...
   Evidencia esperada:

No agregar secciones adicionales.
No dividir en subtemas extra.
No inventar información fuera de lo proporcionado.

Información base:

Control: {data['control']}
Objetivo: {data['objetivo']}
Alcance: {data['alcance']}
Qué se identificó: {data['identificado']}
Qué sí se hace correctamente: {data['correcto']}
Causa raíz: {data['causa']}
Consecuencia: {data['consecuencia']}
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "Eres especialista senior en auditoría interna y ciberseguridad."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.2
    )

    return response.choices[0].message.content


@app.route("/", methods=["GET", "POST"])
def index():
    resultado = None

    if request.method == "POST":
        data = {
            "control": request.form["control"],
            "objetivo": request.form["objetivo"],
            "alcance": request.form["alcance"],
            "identificado": request.form["identificado"],
            "correcto": request.form["correcto"],
            "causa": request.form["causa"],
            "consecuencia": request.form["consecuencia"]
        }

        resultado = generar_redaccion(data)

    return render_template("index.html", resultado=resultado)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
