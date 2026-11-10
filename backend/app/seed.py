"""Create the initial administrator. Run with: python -m app.seed"""
import asyncio, os
from sqlalchemy import select
from .db import Base, engine, SessionLocal
from .models import User, UserRole, Workspace, EmployeeRole
from .employee_roles import ensure_default_employee_roles
from .config import settings
from .security import hash_password

async def main():
    email=os.environ.get("ADMIN_EMAIL"); password=os.environ.get("ADMIN_PASSWORD")
    if not email or not password: raise SystemExit("Set ADMIN_EMAIL and ADMIN_PASSWORD before seeding")
    async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
    async with SessionLocal() as db:
        if not await db.get(Workspace,settings.workspace_id):
            db.add(Workspace(id=settings.workspace_id,name=settings.workspace_name));await db.commit()
        roles=await ensure_default_employee_roles(db,settings.workspace_id)
        await db.commit()
    async with SessionLocal() as db:
        if await db.scalar(select(User).where(User.email==email)): raise SystemExit("That administrator already exists")
        admin_role=await db.scalar(select(EmployeeRole).where(EmployeeRole.workspace_id==settings.workspace_id,EmployeeRole.name=="ADMIN",EmployeeRole.is_active.is_(True)))
        if not admin_role:raise SystemExit("The ADMIN employee role is unavailable")
        db.add(User(workspace_id=settings.workspace_id,employee_role_id=admin_role.id,email=email,hashed_password=hash_password(password),full_name=os.getenv("ADMIN_NAME","Workspace Admin"),role=UserRole.ADMIN,department=os.getenv("ADMIN_DEPARTMENT","Engineering"),is_active=True));await db.commit()
    await engine.dispose()
asyncio.run(main())
