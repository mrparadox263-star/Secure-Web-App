from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required

from ..extensions import db
from ..models import Task
from ..security import roles_required


api_bp = Blueprint("api", __name__)


@api_bp.get("/tasks")
@jwt_required()
def list_tasks():
    owner_id = int(get_jwt_identity())
    tasks = Task.query.filter_by(owner_id=owner_id).order_by(Task.created_at.desc()).all()
    return jsonify(tasks=[task.to_dict() for task in tasks])


@api_bp.post("/tasks")
@jwt_required()
def create_task():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="validation_error", message="JSON body required"), 400
    title = str(body.get("title", "")).strip()
    description = str(body.get("description", "")).strip()
    if not 1 <= len(title) <= 200:
        return jsonify(error="validation_error", message="title must be 1-200 characters"), 400
    if len(description) > 5000:
        return jsonify(error="validation_error", message="description is too long"), 400
    task = Task(title=title, description=description, owner_id=int(get_jwt_identity()))
    db.session.add(task)
    db.session.commit()
    return jsonify(task=task.to_dict()), 201


@api_bp.patch("/tasks/<int:task_id>")
@jwt_required()
def update_task(task_id):
    task = Task.query.filter_by(id=task_id, owner_id=int(get_jwt_identity())).first()
    if not task:
        return jsonify(error="not_found", message="Task not found"), 404
    body = request.get_json(silent=True) or {}
    if "title" in body:
        title = str(body["title"]).strip()
        if not 1 <= len(title) <= 200:
            return jsonify(error="validation_error", message="title must be 1-200 characters"), 400
        task.title = title
    if "description" in body:
        description = str(body["description"]).strip()
        if len(description) > 5000:
            return jsonify(error="validation_error", message="description is too long"), 400
        task.description = description
    if "completed" in body:
        if not isinstance(body["completed"], bool):
            return jsonify(error="validation_error", message="completed must be boolean"), 400
        task.completed = body["completed"]
    db.session.commit()
    return jsonify(task=task.to_dict())


@api_bp.delete("/tasks/<int:task_id>")
@jwt_required()
def delete_task(task_id):
    task = Task.query.filter_by(id=task_id, owner_id=int(get_jwt_identity())).first()
    if not task:
        return jsonify(error="not_found", message="Task not found"), 404
    db.session.delete(task)
    db.session.commit()
    return "", 204


@api_bp.get("/admin/health")
@roles_required("admin")
def admin_health():
    return jsonify(status="ok", area="admin")
