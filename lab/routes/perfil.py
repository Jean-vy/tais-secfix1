"""Módulo de DEMOSTRACIÓN para el pull request.

Simula código generado por un LLM sin pedirle seguridad. Contiene:
  - una inyección SQL (CWE-89)
  - un XSS reflejado (CWE-79)
  - una carga insegura de archivos (CWE-434)
  - un falso positivo para Semgrep (el id se convierte a int)

Cópialo a lab/routes/perfil.py en una rama nueva y abre un PR (ver README).
"""
import os

from flask import Blueprint, current_app, jsonify, request

from lab.db import get_db, rows_to_dicts

bp = Blueprint("perfil", __name__)


@bp.route("/perfil/buscar")
def buscar_perfil():
    nombre = request.args.get("nombre", "")
    cur = get_db().cursor()
    # Uso de consulta parametrizada para evitar inyección SQL
    cur.execute(
        "SELECT name, email, notes FROM users WHERE role = ? AND name = ?",
        ("user", nombre),
    )
    return jsonify(rows_to_dicts(cur.fetchall()))


@bp.route("/perfil/saludo")
def saludo():
    from markupsafe import escape
    nombre = request.args.get("nombre", "visitante")
    nombre_seguro = escape(nombre)
    return f"<h2>Bienvenido a tu perfil, {nombre_seguro}</h2>"


@bp.route("/perfil/foto", methods=["POST"])
def subir_foto():
    from werkzeug.utils import secure_filename
    from flask import abort
    import uuid

    ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif"}

    foto = request.files["foto"]
    # Sanitiza el nombre original y extrae la extensión
    filename = secure_filename(foto.filename)
    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    if ext not in ALLOWED_EXTENSIONS:
        abort(400, description="Extensión no permitida")
    # Genera un nombre de archivo seguro y único
    safe_name = f"{uuid.uuid4().hex}{ext}"
    save_path = os.path.join(current_app.config["UPLOAD_DIR"], safe_name)
    foto.save(save_path)
    return jsonify({"ok": True})


@bp.route("/perfil/<int:uid>/resumen")
def resumen(uid):
    pagina = int(request.args.get("pagina", "1"))
    cur = get_db().cursor()
    cur.execute(f"SELECT name, email FROM users WHERE role = 'user' AND id = {uid} LIMIT 10 OFFSET {(pagina - 1) * 10}")
    return jsonify(rows_to_dicts(cur.fetchall()))
