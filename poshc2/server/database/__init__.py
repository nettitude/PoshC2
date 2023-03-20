#!/usr/bin/env python3

from poshc2.server.Config import Database
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base

database_engine = create_engine(Database, connect_args={"check_same_thread": False}, echo=False) # set echo=True to get database debug output
Base = declarative_base()

from .Model import *

Base.metadata.create_all(database_engine)
session_factory = sessionmaker(bind=database_engine)
Session = scoped_session(session_factory)
