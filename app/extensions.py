from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate


# =====================================
# Database
# =====================================

db = SQLAlchemy()



# =====================================
# Authentication
# =====================================

login_manager = LoginManager()

login_manager.login_view = "auth.login"

login_manager.login_message = (
    "Please login to access Jicho Cyber."
)



# =====================================
# Database Migration System
# =====================================

migrate = Migrate()