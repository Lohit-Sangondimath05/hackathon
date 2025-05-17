import customtkinter as ctk
import requests
from tkinter import messagebox
import firebase_admin
from firebase_admin import credentials

# Initialize Firebase Admin SDK (optional, for admin features)
cred = credentials.Certificate("cc.json")
firebase_admin.initialize_app(cred)

API_KEY = "AIzaSyDzEEuBlyeSfEgAT5yuL9dUkFZjXzRdpeo"

def firebase_sign_in(email, password):
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def firebase_register(email, password):
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={API_KEY}"
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        return response.json()
    else:
        try:
            error_message = response.json()["error"]["message"]
        except (KeyError, ValueError):
            error_message = "Unknown error occurred."
        return {"error": error_message}

class LoginScreen(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🔐 Firebase Login")
        self.geometry("400x350")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.create_widgets()

    def create_widgets(self):
        ctk.CTkLabel(self, text="Login to your account", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20)

        ctk.CTkLabel(self, text="Email").pack(pady=(10,0))
        self.email_entry = ctk.CTkEntry(self, width=300)
        self.email_entry.pack(pady=5)

        ctk.CTkLabel(self, text="Password").pack(pady=(10,0))
        self.password_entry = ctk.CTkEntry(self, width=300, show="*")
        self.password_entry.pack(pady=5)

        self.login_btn = ctk.CTkButton(self, text="Login", command=self.login)
        self.login_btn.pack(pady=15)

        self.register_btn = ctk.CTkButton(self, text="Create new account", fg_color="transparent", hover_color="#357EDD", command=self.open_register)
        self.register_btn.pack()

    def login(self):
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()
        if not email or not password:
            messagebox.showwarning("Input Error", "Please enter both email and password.")
            return
        result = firebase_sign_in(email, password)
        if result:
            messagebox.showinfo("Success", "Login successful!")
            self.destroy()
            print("User ID Token:", result["idToken"])
            # TODO: Launch main app here
        else:
            messagebox.showerror("Login Failed", "Invalid email or password.")

    def open_register(self):
        self.destroy()
        RegisterScreen()

class RegisterScreen(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("📝 Register new account")
        self.geometry("400x400")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.create_widgets()
        self.mainloop()

    def create_widgets(self):
        ctk.CTkLabel(self, text="Create a new account", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20)

        ctk.CTkLabel(self, text="Email").pack(pady=(10,0))
        self.email_entry = ctk.CTkEntry(self, width=300)
        self.email_entry.pack(pady=5)

        ctk.CTkLabel(self, text="Password").pack(pady=(10,0))
        self.password_entry = ctk.CTkEntry(self, width=300, show="*")
        self.password_entry.pack(pady=5)

        ctk.CTkLabel(self, text="Confirm Password").pack(pady=(10,0))
        self.confirm_password_entry = ctk.CTkEntry(self, width=300, show="*")
        self.confirm_password_entry.pack(pady=5)

        self.register_btn = ctk.CTkButton(self, text="Register", command=self.register)
        self.register_btn.pack(pady=20)

        self.back_btn = ctk.CTkButton(self, text="Back to Login", fg_color="transparent", hover_color="#357EDD", command=self.back_to_login)
        self.back_btn.pack()

    def register(self):
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()
        confirm_password = self.confirm_password_entry.get().strip()

        if not email or not password or not confirm_password:
            messagebox.showwarning("Input Error", "Please fill in all fields.")
            return
        if password != confirm_password:
            messagebox.showwarning("Input Error", "Passwords do not match.")
            return

        result = firebase_register(email, password)
        if result and "error" not in result:
            messagebox.showinfo("Success", "Registration successful! You can now log in.")
            self.destroy()
            LoginScreen().mainloop()
        else:
            error_code = result.get("error", "Unknown error")
            friendly_msg = {
                "EMAIL_EXISTS": "This email is already registered.",
                "INVALID_EMAIL": "The email address is badly formatted.",
                "WEAK_PASSWORD : Password should be at least 6 characters": "Password should be at least 6 characters.",
                "OPERATION_NOT_ALLOWED": "Password sign-in is disabled for this project."
            }.get(error_code, error_code)
            messagebox.showerror("Registration Failed", f"Error: {friendly_msg}")

    def back_to_login(self):
        self.destroy()
        LoginScreen().mainloop()

if __name__ == "__main__":
    app = LoginScreen()
    app.mainloop()
