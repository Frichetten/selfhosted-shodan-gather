import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
 
Base = declarative_base()

class System(Base):
    __tablename__ = 'systems'
    id = Column(Integer, primary_key=True)
    software_name = Column(String(20))
    ip_str = Column(String(12))
    ip = Column(String(12))
    hostname = Column(String(255))
    timestamp = Column(String(28))
    asn = Column(String(10))
    port = Column(Integer)
    location = Column(String(100))
    title = Column(String(100))
    shodan_id = Column(String(100))
    ssl = Column(Boolean)
    ssl_cn = Column(String(255))