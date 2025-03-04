import streamlit as st
import random

def determine_winner(user, computer):
    if user == computer:
        return "It's a draw!"
    elif (user == "Snake" and computer == "Water") or \
         (user == "Water" and computer == "Gun") or \
         (user == "Gun" and computer == "Snake"):
        return "You win!"
    else:
        return "Computer wins!"

st.title("Snake Water Gun")
st.markdown("""
<style>
.stButton>button {
    padding: 20px;
    margin: 10px;
}
.big-font {
    font-size:20px !important;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

choice = st.radio("Choose your move:", ("Snake", "Water", "Gun"))

if st.button("Play"):
    comp_choice = random.choice(["Snake", "Water", "Gun"])
    result = determine_winner(choice, comp_choice)
    
    st.markdown(f"**You chose:** {choice}", unsafe_allow_html=True)
    st.markdown(f"**Computer chose:** {comp_choice}", unsafe_allow_html=True)
    st.markdown(f"<p class='big-font'>{result}</p>", unsafe_allow_html=True)

    # Visual feedback
    if "win" in result.lower():
        st.balloons()
    elif "computer wins" in result.lower():
        st.error("Better luck next time!")

# Optional: Add a score tracker
if 'user_score' not in st.session_state:
    st.session_state.user_score = 0
    st.session_state.computer_score = 0

if st.button("View Scores"):
    st.write(f"Your Score: {st.session_state.user_score}")
    st.write(f"Computer Score: {st.session_state.computer_score}")

# Update scores after each game
if 'result' in locals():
    if "You win" in result:
        st.session_state.user_score += 1
    elif "Computer wins" in result:
        st.session_state.computer_score += 1
# ssh-keygen -t ed25519 -C "tarunkumars2050@gmail.com"
