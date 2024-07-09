""" ./routers/feedbacks.py"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from database import get_db
from models import UserFeedback, User, GeneratedAudio
from schemas.feedback import (
    UserFeedbackCreate,
    UserFeedbackUpdate,
    UserFeedbackResponse,
)

router = APIRouter()


@router.post("/users/{user_id}/feedbacks/", response_model=UserFeedbackResponse)
def create_feedback(
    user_id: int, feedback: UserFeedbackCreate, db: Session = Depends(get_db)
):
    audio = (
        db.query(GeneratedAudio).filter(GeneratedAudio.id == feedback.audio_id).first()
    )
    if audio is None:
        raise HTTPException(status_code=404, detail="Audio not found")

    existing_feedback = (
        db.query(UserFeedback)
        .filter(
            UserFeedback.user_id == user_id, UserFeedback.audio_id == feedback.audio_id
        )
        .first()
    )

    if existing_feedback:
        raise HTTPException(
            status_code=400, detail="Feedback already exists for this audio"
        )

    db_feedback = UserFeedback(**feedback.dict(), user_id=user_id)
    db.add(db_feedback)
    db.commit()
    db.refresh(db_feedback)
    return db_feedback


@router.put(
    "/users/{user_id}/feedbacks/{audio_id}", response_model=UserFeedbackResponse
)
def update_feedback(
    user_id: int,
    audio_id: int,
    feedback: UserFeedbackUpdate,
    db: Session = Depends(get_db),
):
    db_feedback = (
        db.query(UserFeedback)
        .filter(UserFeedback.user_id == user_id, UserFeedback.audio_id == audio_id)
        .first()
    )

    if db_feedback is None:
        raise HTTPException(status_code=404, detail="Feedback not found")

    for key, value in feedback.dict(exclude_unset=True).items():
        setattr(db_feedback, key, value)

    db.commit()
    db.refresh(db_feedback)
    return db_feedback


@router.get("/users/{user_id}/feedbacks/", response_model=List[UserFeedbackResponse])
def read_user_feedbacks(
    user_id: int, skip: int = 0, limit: int = 10, db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    feedbacks = (
        db.query(UserFeedback)
        .filter(UserFeedback.user_id == user_id)
        .offset(skip)
        .limit(limit)
        .all()
    )
    return feedbacks


@router.get("/audio/{audio_id}/feedbacks/", response_model=List[UserFeedbackResponse])
def read_audio_feedbacks(
    audio_id: int, skip: int = 0, limit: int = 10, db: Session = Depends(get_db)
):
    audio = db.query(GeneratedAudio).filter(GeneratedAudio.id == audio_id).first()
    if audio is None:
        raise HTTPException(status_code=404, detail="Audio not found")
    feedbacks = (
        db.query(UserFeedback)
        .filter(UserFeedback.audio_id == audio_id)
        .offset(skip)
        .limit(limit)
        .all()
    )
    return feedbacks


@router.delete(
    "/users/{user_id}/feedbacks/{audio_id}", status_code=status.HTTP_204_NO_CONTENT
)
def delete_feedback(user_id: int, audio_id: int, db: Session = Depends(get_db)):
    db_feedback = (
        db.query(UserFeedback)
        .filter(UserFeedback.user_id == user_id, UserFeedback.audio_id == audio_id)
        .first()
    )
    if db_feedback is None:
        raise HTTPException(status_code=404, detail="Feedback not found")
    db.delete(db_feedback)
    db.commit()
    return {"ok": True}
