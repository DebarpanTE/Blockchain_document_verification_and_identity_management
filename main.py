"""
BlockID - Blockchain Identity Management System
Main FastAPI application entry point.
"""
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from contextlib import asynccontextmanager

from config import get_settings
from app.models.database import init_db
from app.routers import auth, identity, access, chain

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Blockchain-Based Digital Identity Management System with RSA digital signatures, "
                "SHA-256 document hashing, and selective field disclosure.",
    lifespan=lifespan,
)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Simplify validation errors for the frontend."""
    errors = []
    for error in exc.errors():
        loc = ".".join([str(l) for l in error["loc"] if l != "body"])
        msg = error["msg"]
        errors.append(f"{loc}: {msg}" if loc else msg)
    
    return JSONResponse(
        status_code=422,
        content={"detail": "; ".join(errors)},
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files & templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# API Routers
app.include_router(auth.router)
app.include_router(identity.router)
app.include_router(access.router)
app.include_router(chain.router)


# ── Frontend routes ──────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/explorer", response_class=HTMLResponse)
async def explorer(request: Request):
    return templates.TemplateResponse("explorer.html", {"request": request})


@app.get("/health")
async def health():
    return {"status": "ok", "version": settings.APP_VERSION}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)