"""Filename: ./models/profile.py"""

from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey
from sqlalchemy.orm import relationship
from database import Base


class UserProfile(Base):
    __tablename__ = "user_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    first_name = Column(String)
    last_name = Column(String)
    date_of_birth = Column(DateTime)
    preferred_language = Column(Enum("vi", "en", name="language_enum"))

    user = relationship("User", back_populates="profile")
