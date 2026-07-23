import os

from dotenv import load_dotenv


# Load environment variables
load_dotenv()


class Config:
    """
    Base configuration for Jicho Cyber
    """


    # =====================================
    # Application Security
    # =====================================

    SECRET_KEY = os.getenv(
        "FLASK_SECRET_KEY",
        "temporary-development-key"
    )


    # =====================================
    # Database
    # =====================================

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "sqlite:///database/jicho.db"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False



    # =====================================
    # Scanner Configuration
    # =====================================

    SCAN_TIMEOUT = int(
        os.getenv(
            "SCAN_TIMEOUT",
            2
        )
    )


    MAX_SCAN_THREADS = int(
        os.getenv(
            "MAX_SCAN_THREADS",
            100
        )
    )



    # =====================================
    # Logging
    # =====================================

    LOG_LEVEL = os.getenv(
        "LOG_LEVEL",
        "INFO"
    )



    # =====================================
    # Vulnerability Intelligence
    # =====================================

    CVE_API_KEY = os.getenv(
        "CVE_API_KEY",
        ""
    )



class DevelopmentConfig(Config):
    """
    Development environment
    """

    DEBUG = True



class ProductionConfig(Config):
    """
    Production environment
    """

    DEBUG = False



class TestingConfig(Config):
    """
    Automated testing environment
    """

    TESTING = True

    SQLALCHEMY_DATABASE_URI = (
        "sqlite:///:memory:"
    )
    