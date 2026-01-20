import json
import os
import streamlit as st
from datetime import datetime
import pandas as pd
import hashlib
import random

# ---------------- CONFIG ----------------
st.set_page_config(
    page_title="USMLE Question Bank",
    layout="centered",
    initial_sidebar_state="expanded"
)

# ---------------- USER AUTH ----------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    try:
        with open("users.json", "r") as f:
            return json.load(f)
    except:
        return {}

def save_users(users):
    with open("users.json", "w") as f:
        json.dump(users, f, indent=2)

def create_user(username, password):
    users = load_users()
    if username in users:
        return False, "Username already exists"

    users[username] = {
        "password_hash": hash_password(password),
        "created_at": datetime.now().isoformat(),
        "progress": {
            "questions_attempted": [],
            "correct_questions": [],
            "incorrect_questions": [],
            "marked_questions": [],
            "performance_by_system": {},
            "performance_by_subject": {}
        }
    }
    save_users(users)
    return True, "User created successfully"

def authenticate_user(username, password):
    users = load_users()
    if username not in users:
        return False, "User not found"
    if users[username]["password_hash"] == hash_password(password):
        return True, "Login successful"
    return False, "Invalid password"

def load_user_progress(username):
    users = load_users()
    p = users.get(username, {}).get("progress", {})
    return {
        "questions_attempted": set(p.get("questions_attempted", [])),
        "correct_questions": set(p.get("correct_questions", [])),
        "incorrect_questions": set(p.get("incorrect_questions", [])),
        "marked_questions": set(p.get("marked_questions", [])),
        "performance_by_system": p.get("performance_by_system", {}),
        "performance_by_subject": p.get("performance_by_subject", {})
    }

def save_user_progress(username):
    users = load_users()
    if username not in users:
        return

    p = st.session_state.user_progress
    users[username]["progress"] = {
        "questions_attempted": list(p["questions_attempted"]),
        "correct_questions": list(p["correct_questions"]),
        "incorrect_questions": list(p["incorrect_questions"]),
        "marked_questions": list(p["marked_questions"]),
        "performance_by_system": p["performance_by_system"],
        "performance_by_subject": p["performance_by_subject"],
        "last_saved": datetime.now().isoformat()
    }
    save_users(users)

# ---------------- LOAD QUESTIONS ----------------
@st.cache_data
def load_questions():
    if not os.path.exists("questions.json"):
        st.error("❌ questions.json not found")
        return []
    with open("questions.json", "r", encoding="utf-8") as f:
        return json.load(f)

questions = load_questions()

# ---------------- SESSION STATE INIT ----------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.show_analysis = False

if "user_progress" not in st.session_state:
    st.session_state.user_progress = {
        "questions_attempted": set(),
        "correct_questions": set(),
        "incorrect_questions": set(),
        "marked_questions": set(),
        "performance_by_system": {},
        "performance_by_subject": {}
    }

if "quiz_config" not in st.session_state:
    st.session_state.quiz_config = {"quiz_started": False}

if "quiz_state" not in st.session_state:
    st.session_state.quiz_state = {}

# ---------------- HOME ----------------
def show_home():
    st.title("🏠 USMLE Question Bank")

    st.write(f"Welcome back, **{st.session_state.username}**!")

    attempted = len(st.session_state.user_progress["questions_attempted"])
    correct = len(st.session_state.user_progress["correct_questions"])
    accuracy = (correct / attempted * 100) if attempted else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Questions", len(questions))
    c2.metric("Attempted", attempted)
    c3.metric("Accuracy", f"{accuracy:.1f}%")
    c4.metric("Marked", len(st.session_state.user_progress["marked_questions"]))

    st.divider()
    st.subheader("📝 Configure Quiz")

    num_q = st.slider("Number of questions", 5, min(100, len(questions)), 20, 5)

    systems = sorted(set(q.get("system", "General") for q in questions))
    subjects = sorted(set(q.get("subject", "General") for q in questions))

    sel_sys = st.multiselect("Systems", systems)
    sel_sub = st.multiselect("Subjects", subjects)

    filter_opt = st.radio(
        "Question selection",
        ["Unused", "Marked", "Incorrect", "All"],
        horizontal=True
    )

    if st.button("🚀 Start Quiz", type="primary", use_container_width=True):
        pool = questions.copy()

        if sel_sys:
            pool = [q for q in pool if q.get("system") in sel_sys]
        if sel_sub:
            pool = [q for q in pool if q.get("subject") in sel_sub]

        p = st.session_state.user_progress
        if filter_opt == "Unused":
            pool = [q for q in pool if q["id"] not in p["questions_attempted"]]
        elif filter_opt == "Marked":
            pool = [q for q in pool if q["id"] in p["marked_questions"]]
        elif filter_opt == "Incorrect":
            pool = [q for q in pool if q["id"] in p["incorrect_questions"]]

        if not pool:
            st.error("No questions match selection")
            return

        quiz = random.sample(pool, min(num_q, len(pool)))

        # RANDOMIZE OPTIONS SAFELY
        for q in quiz:
            opts = list(enumerate(q["options"]))
            random.shuffle(opts)
            q["shuffled"] = opts
            q["correct_letter"] = chr(65 + [i for i, (idx, _) in enumerate(opts) if chr(65 + idx) == q["answer"]][0])

        st.session_state.quiz_config = {
            "quiz_started": True,
            "questions": quiz
        }

        st.session_state.quiz_state = {
            "idx": 0,
            "score": 0,
            "answered": False,
            "selected": None,
            "marked": set(),
            "start": datetime.now()
        }
        st.rerun()

# ---------------- QUIZ ----------------
def show_quiz():
    quiz = st.session_state.quiz_config["questions"]
    s = st.session_state.quiz_state

    if s["idx"] >= len(quiz):
        show_results()
        return

    q = quiz[s["idx"]]
    qid = q["id"]

    st.markdown(f"### Question {s['idx'] + 1} / {len(quiz)}")
    st.progress((s["idx"] + 1) / len(quiz))

    st.markdown(f"**{q['question']}**")

    for i, (orig_idx, text) in enumerate(q["shuffled"]):
        letter = chr(65 + i)
        if st.button(
            f"{letter}. {text}",
            key=f"{qid}_{i}",
            disabled=s["answered"],
            use_container_width=True
        ):
            s["selected"] = letter
            s["answered"] = True

            p = st.session_state.user_progress
            p["questions_attempted"].add(qid)

            if letter == q["correct_letter"]:
                s["score"] += 1
                p["correct_questions"].add(qid)
                p["incorrect_questions"].discard(qid)
            else:
                p["incorrect_questions"].add(qid)
                p["correct_questions"].discard(qid)

    if s["answered"]:
        st.divider()
        if s["selected"] == q["correct_letter"]:
            st.success("✅ Correct")
        else:
            st.error(f"❌ Correct answer: {q['correct_letter']}")
        st.markdown(q.get("explanation", ""))

    c1, c2, c3 = st.columns(3)
    if c1.button("◀ Previous") and s["idx"] > 0:
        s["idx"] -= 1
        s["answered"] = False
        st.rerun()

    if c3.button("Next ▶") and s["answered"]:
        s["idx"] += 1
        s["answered"] = False
        st.rerun()

    if st.button("🏁 End Quiz"):
        st.session_state.user_progress["marked_questions"].update(s["marked"])
        save_user_progress(st.session_state.username)
        show_results()

# ---------------- RESULTS ----------------
def show_results():
    s = st.session_state.quiz_state
    total = len(st.session_state.quiz_config["questions"])

    st.title("📊 Results")
    st.metric("Score", f"{s['score']} / {total}")

    if st.button("🏠 Back Home"):
        save_user_progress(st.session_state.username)
        st.session_state.quiz_config["quiz_started"] = False
        st.rerun()

# ---------------- AUTH ----------------
def show_auth():
    st.title("🔐 USMLE Question Bank")
    t1, t2 = st.tabs(["Login", "Sign Up"])

    with t1:
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Login"):
            ok, msg = authenticate_user(u, p)
            if ok:
                st.session_state.logged_in = True
                st.session_state.username = u
                st.session_state.user_progress = load_user_progress(u)
                st.rerun()
            else:
                st.error(msg)

    with t2:
        u = st.text_input("New username")
        p = st.text_input("New password", type="password")
        if st.button("Create Account"):
            ok, msg = create_user(u, p)
            st.success(msg) if ok else st.error(msg)

# ---------------- ROUTER ----------------
if not st.session_state.logged_in:
    show_auth()
elif st.session_state.quiz_config.get("quiz_started"):
    show_quiz()
else:
    show_home()