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
    cur.execute(f"SELECT name, email, notes FROM users WHERE role = 'user' AND name = '{nombre}'")
    return jsonify(rows_to_dicts(cur.fetchall()))


@bp.route("/perfil/saludo")
def saludo():
    nombre = request.args.get("nombre", "visitante")
    return f"<h2>Bienvenido a tu perfil, {nombre}</h2>"


@bp.route("/perfil/foto", methods=["POST"])
def subir_foto():
    foto = request.files["foto"]
    foto.save(os.path.join(current_app.config["UPLOAD_DIR"], foto.filename))
    return jsonify({"ok": True})


@bp.route("/perfil/<int:uid>/resumen")
def resumen(uid):
    pagina = int(request.args.get("pagina", "1"))
    cur = get_db().cursor()
    cur.execute(f"SELECT name, email FROM users WHERE role = 'user' AND id = {uid} LIMIT 10 OFFSET {(pagina - 1) * 10}")
    return jsonify(rows_to_dicts(cur.fetchall()))
