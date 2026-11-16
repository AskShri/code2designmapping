from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI
from sqlmodel import Field, Session, SQLModel, select

engine = None


class Item(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    title: str
    owner_email: str


def get_session():
    with Session(engine) as session:
        yield session


def get_current_user(session: Annotated[Session, Depends(get_session)]):
    return session.get(Item, 1)


SessionDep = Annotated[Session, Depends(get_session)]
CurrentUser = Annotated[Item, Depends(get_current_user)]

router = APIRouter(prefix="/items")


@router.get("/")
def list_items(session: SessionDep, user: CurrentUser):
    statement = select(Item).where(Item.owner_email == user.owner_email)
    return session.exec(statement).all()


@router.get("/public")
def public_items(session: SessionDep):
    return session.exec(select(Item)).all()


app = FastAPI()
app.include_router(router, prefix="/api/v1")
