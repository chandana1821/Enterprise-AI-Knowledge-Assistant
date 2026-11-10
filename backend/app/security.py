import uuid
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select, and_, or_, exists
from sqlalchemy.ext.asyncio import AsyncSession
from .config import settings
from .config import embedding_space_fingerprint
from .db import get_db
from .models import User, Document, DocumentACL, EmployeeRole, Freshness, Ingestion, UserRole, DocumentAccessType

pwd=CryptContext(schemes=["bcrypt"],deprecated="auto"); bearer=HTTPBearer(auto_error=False)
def hash_password(value:str)->str:return pwd.hash(value)
def verify_password(value:str,hashed:str)->bool:return pwd.verify(value,hashed)
def issue_token(user:User)->str:return jwt.encode({"sub":str(user.id),"ver":user.auth_version,"exp":datetime.now(timezone.utc)+timedelta(minutes=settings.access_token_minutes)},settings.jwt_secret,algorithm="HS256")

def can_user_access_document(user:User):
    """SQL authorization predicate shared by listing, viewing, and RAG queries."""
    workspace=Document.workspace_id==user.workspace_id
    alive=Document.freshness_status!=Freshness.DELETED
    if user.role==UserRole.ADMIN:
        return and_(workspace,alive)
    active_role=exists(select(EmployeeRole.id).where(EmployeeRole.id==user.employee_role_id,
        EmployeeRole.workspace_id==user.workspace_id,EmployeeRole.is_active.is_(True)))
    role_grant=and_(active_role,Document.acls.any(and_(DocumentACL.workspace_id==user.workspace_id,
        DocumentACL.grantee_type=="EMPLOYEE_ROLE",DocumentACL.grantee_id==str(user.employee_role_id),DocumentACL.can_read.is_(True))))
    user_grant=Document.acls.any(and_(DocumentACL.workspace_id==user.workspace_id,
        DocumentACL.grantee_type=="USER",DocumentACL.grantee_id==str(user.id),DocumentACL.can_read.is_(True)))
    return and_(workspace,alive,or_(
        Document.access_type==DocumentAccessType.ALL_EMPLOYEES,
        and_(Document.access_type==DocumentAccessType.ADMIN_ONLY,user.role==UserRole.ADMIN),
        and_(Document.access_type==DocumentAccessType.SPECIFIC_EMPLOYEE_ROLES,role_grant),
        and_(Document.access_type==DocumentAccessType.SPECIFIC_USERS,user_grant)))

def readable_document_predicate(user:User):
    return can_user_access_document(user)

def indexed_document_predicate(user:User):
    """Use the last complete vector snapshot while a replacement is being prepared.

    The worker switches embeddings and indexed metadata atomically. A document can
    therefore be STALE/PROCESSING/FAILED while its previous snapshot remains valid.
    Initial uploads have no indexed version/chunks and are never admitted here.
    """
    current=and_(Document.freshness_status==Freshness.FRESH,
                 Document.ingestion_status==Ingestion.INDEXED,
                 Document.indexed_version==Document.version,
                 Document.indexed_content_hash==Document.content_hash)
    previous=and_(Document.freshness_status.in_([Freshness.STALE,Freshness.QUEUED,Freshness.PROCESSING,Freshness.RETRYING,Freshness.FAILED]),
                  Document.indexed_version.is_not(None),Document.indexed_content_hash.is_not(None),
                  Document.chunk_count>0)
    # A document is eligible only when its active vector snapshot was made in the
    # same provider/model/dimension space as the current query embedding.
    return and_(can_user_access_document(user),
                Document.indexed_embedding_fingerprint==embedding_space_fingerprint(),
                or_(current,previous))
async def current_user(request:Request,auth:HTTPAuthorizationCredentials|None=Depends(bearer),db:AsyncSession=Depends(get_db))->User:
    if not auth: raise HTTPException(401,"Authentication required")
    try:
        payload=jwt.decode(auth.credentials,settings.jwt_secret,algorithms=["HS256"])
        uid=payload.get("sub")
        if not uid:raise JWTError("Token subject is missing")
        uid=uuid.UUID(str(uid))
        token_version=int(payload.get("ver",0))
    except (JWTError,ValueError,TypeError): raise HTTPException(401,"Invalid or expired token")
    user=await db.get(User,uid)
    if not user or not user.is_active: raise HTTPException(401,"Account is inactive")
    if token_version!=user.auth_version:raise HTTPException(401,"Session is no longer valid. Sign in again.")
    if user.must_change_password and request.url.path not in {"/api/auth/me","/api/profile/change-password","/api/auth/profile/change-password"}:
        raise HTTPException(403,detail={"code":"PASSWORD_CHANGE_REQUIRED","message":"Change your temporary password before continuing."})
    return user
async def admin_user(user:User=Depends(current_user))->User:
    if user.role.value!="ADMIN": raise HTTPException(403,"Administrator access required")
    return user
