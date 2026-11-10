from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from .models import EmployeeRole

DEFAULT_EMPLOYEE_ROLES={
    "ADMIN":"Workspace administrator designation.",
    "Unassigned":"Employee awaiting role assignment by an administrator.",
    "Senior Software Engineer":"Senior engineering role.",
    "Software Engineer":"Engineering role.",
    "HR":"Human resources role.",
    "HR Manager":"Human resources management role.",
    "Finance Manager":"Finance management role.",
    "Finance Executive":"Finance operations role.",
    "Team Lead":"Team leadership role.",
    "Manager":"People management role.",
}

async def ensure_default_employee_roles(db:AsyncSession,workspace_id):
    values=[{"workspace_id":workspace_id,"name":name,"description":description,"is_active":True} for name,description in DEFAULT_EMPLOYEE_ROLES.items()]
    await db.execute(insert(EmployeeRole).values(values).on_conflict_do_nothing(index_elements=["workspace_id","name"]))
    rows=(await db.scalars(select(EmployeeRole).where(EmployeeRole.workspace_id==workspace_id))).all()
    return {row.name:row for row in rows}
