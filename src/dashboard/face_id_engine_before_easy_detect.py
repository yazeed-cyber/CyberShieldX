import hashlib
from pathlib import Path

import cv2
import numpy as np
import streamlit as st
from PIL import Image


FACE_DIR = Path("outputs/face_id")
FACE_DIR.mkdir(parents=True, exist_ok=True)


def _user_face_path(user_id):
    safe = hashlib.sha256(str(user_id).encode()).hexdigest()[:16]
    return FACE_DIR / f"{safe}_face.png"


def _image_to_cv(uploaded_file):
    img = Image.open(uploaded_file).convert("RGB")
    arr = np.array(img)
    return cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)


def _detect_face(img):
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    detector = cv2.CascadeClassifier(
        cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    )

    faces = detector.detectMultiScale(
        gray,
        scaleFactor=1.05,
        minNeighbors=3,
        minSize=(40, 40)
    )

    if len(faces) == 0:
        return None

    x, y, w, h = sorted(faces, key=lambda f: f[2] * f[3], reverse=True)[0]
    face = gray[y:y + h, x:x + w]
    face = cv2.resize(face, (200, 200))
    return face


def _compare_faces(face1, face2):
    face1 = cv2.equalizeHist(face1)
    face2 = cv2.equalizeHist(face2)

    diff = cv2.absdiff(face1, face2)
    mean_diff = float(np.mean(diff))

    score = max(0, min(100, int(100 - mean_diff)))
    return score


def face_id_gate(user_id):
    st.markdown("### 🙂 Face ID Verification")
    st.caption("Real Face ID using OpenCV face detection and image similarity matching.")

    face_path = _user_face_path(user_id)

    if not face_path.exists():
        st.warning("No Face ID profile found. Enroll your face first.")

        enroll_img = st.camera_input(
            "Capture reference face",
            key=f"face_enroll_{user_id}"
        )

        if enroll_img is not None:
            img = _image_to_cv(enroll_img)
            face = _detect_face(img)

            if face is None:
                st.error("No clear face detected. Move closer to the camera and improve lighting.")
                return False

            cv2.imwrite(str(face_path), face)
            st.success("Face ID enrolled successfully. Please verify your face now.")
            st.stop()

        return False

    verify_img = st.camera_input(
        "Capture your face to verify",
        key=f"face_verify_{user_id}"
    )

    if verify_img is None:
        return False

    img = _image_to_cv(verify_img)
    face = _detect_face(img)

    if face is None:
        st.error("No clear face detected. Move closer to the camera and improve lighting.")
        return False

    stored_face = cv2.imread(str(face_path), cv2.IMREAD_GRAYSCALE)

    if stored_face is None:
        st.error("Stored Face ID profile is corrupted. Delete the profile and enroll again.")
        return False

    score = _compare_faces(stored_face, face)

    st.write(f"Face Match Score: {score}%")

    if score >= 45:
        st.success("Face ID verified successfully.")
        return True

    st.error("Face ID verification failed.")
    return False
