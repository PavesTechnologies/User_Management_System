import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from .....Data_Access_Layer.utils.database import (
    set_db_session,
    remove_db_session,
)

logger = logging.getLogger(__name__)


class DBSessionMiddleware(BaseHTTPMiddleware):

    SKIP_PATHS = [
        "/.well-known/jwks.json",
        "/.well-known/openid-configuration",
    ]

    async def dispatch(self, request: Request, call_next):

        if any(request.url.path.startswith(p) for p in self.SKIP_PATHS):
            return await call_next(request)

        t_start = time.time()

        logger.info("🟢 DB Middleware - ENTERING")

        db = None

        try:
            # Create DB session
            db = set_db_session()

            request.state.db = db

            logger.info("🟢 DB Middleware - DB session initialized")

            response = await call_next(request)

            return response

        except SQLAlchemyError:

            logger.exception("🔴 DB Middleware - SQLAlchemyError")

            if db:
                db.rollback()

            return JSONResponse(
                {"detail": "Database error occurred"},
                status_code=500,
            )

        except Exception as e:

            logger.exception("🔴 DB Middleware - Unexpected Error")

            return JSONResponse(
                {"detail": str(e)},
                status_code=500,
            )

        finally:

            try:
                remove_db_session()
                logger.info("🟢 DB session removed")

            except Exception:
                logger.exception("🔴 Failed removing DB session")

            elapsed = (time.time() - t_start) * 1000

            logger.info(f"⏱ DB Middleware: {elapsed:.2f}ms")
            logger.info("🟢 DB Middleware - EXITING")
