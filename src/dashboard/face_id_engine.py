import hashlib
from pathlib import Path
import cv2
import numpy as np
from PIL import Image
import streamlit as st

FACE_DIR = Path("outputs/face_id")
FACE_DIR.mkdir(parents=True, exist_ok=True)

def face_path(identity):
    safe = hashlib.sha256(str(identity).lower().encode()).hexdigest()[:18]
    return FACE_DIR / f"{safe}_face.png"

def img_to_cv(uploaded):
    img = Image.open(uploaded).convert("RGB")
    arr = np.array(img)
    return cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)

def detect_face(img):
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    detector = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
    faces = detector.detectMultiScale(gray, scaleFactor=1.05, minNeighbors=3, minSize=(40, 40))
    if len(faces) == 0:
        return None
    x, y, w, h = sorted(faces, key=lambda f: f[2]*f[3], reverse=True)[0]
    face = gray[y:y+h, x:x+w]
    return cv2.resize(face, (200, 200))

def match_faces(saved, current):
    orb = cv2.ORB_create(nfeatures=700)
    kp1, des1 = orb.detectAndCompute(saved, None)
    kp2, des2 = orb.detectAndCompute(current, None)
    if des1 is None or des2 is None:
        return 0
    matcher = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    matches = matcher.match(des1, des2)
    if not matches:
        return 0
    good = [m for m in matches if m.distance < 70]
    return int((len(good) / max(len(matches), 1)) * 100)

def face_id_auth_ui(identity, mode):
    st.markdown("### 🙂 Face ID Verification")

    path = face_path(identity)

    if mode == "sign_in":
        st.info("First time registration: capture your reference face.")
        img_file = st.camera_input("Take Face ID reference photo", key=f"face_enroll_{identity}")
        if img_file is None:
            return False

        img = img_to_cv(img_file)
        face = detect_face(img)
        if face is None:
            st.error("No clear face detected. Try again.")
            return False

        cv2.imwrite(str(path), face)
        st.success("Face ID enrolled successfully.")
        return True

    if mode == "login":
        if not path.exists():
            st.error("No Face ID profile found for this email/phone. Please Sign in first.")
            return False

        st.info("Login verification: capture your face.")
        img_file = st.camera_input("Take Face ID verification photo", key=f"face_verify_{identity}")
        if img_file is None:
            return False

        img = img_to_cv(img_file)
        current_face = detect_face(img)
        if current_face is None:
            st.error("No clear face detected. Try again.")
            return False

        saved_face = cv2.imread(str(path), cv2.IMREAD_GRAYSCALE)
        score = match_faces(saved_face, current_face)

        st.write(f"Face Match Score: {score}%")

        if score >= 25:
            st.success("Face ID verified successfully.")
            return True

        st.error("Face ID does not match. Please Sign in again.")
        return False

    return False
