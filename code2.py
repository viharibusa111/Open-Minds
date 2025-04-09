import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
import os
import hashlib
import re
from io import StringIO
import sys
import traceback
import time

class CodingPracticeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Coding Practice Platform")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Define color scheme
        self.colors = {
            "yellow" : "#fff203",    # Yellow
            "black": "#000000",    # Black
            "white": "#ffffff",    # White
            "primary": "#3498db",    # Blue
            "secondary": "#2ecc71",  # Green
            "accent": "#e74c3c",     # Red
            "warning": "#f39c12",    # Orange
            "light": "#ecf0f1",      # Light Gray
            "dark": "#2c3e50"        # Dark Blue
        }
        
        # Configure default styles
        style = ttk.Style()
        style.configure("TButton", font=("Arial", 10))
        style.configure("TTreeview", font=("Arial", 10))
        style.configure("TTreeview.Heading", font=("Arial", 10, "bold"))
            
        # Initialize data
        self.current_user = None
        self.users_file = "users.json"
        self.challenges_file = "challenges.json"
        self.load_data()
        
        # Create main container
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Start with login screen
        self.show_login_screen()
    
    def validate_challenge(self, challenge):
        required_fields = ["title", "description", "test_cases", "difficulty", 
                          "function_name", "parameters"]
        for field in required_fields:
            if field not in challenge:
                return False
        return True

    def load_data(self):
        # Load users data
        
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as file:
                self.users = json.load(file)
        else:
            self.users = {
                "admin": {
                    "username": "admin123",
                    "email": "admin@gmail.com",
                    "password": self.hash_password("admin123"),
                    "completed_challenges": [],
                    "is_admin": True
                }
            }
            self.save_users()
        
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as file:
                self.users = json.load(file)
                
            for username in self.users:
                if "completion_times" not in self.users[username]:
                 self.users[username]["completion_times"] = {}
                 
            self.save_users()   
        else:
            self.users = {}
            self.save_users()
        
        # Load challenges data
        if os.path.exists(self.challenges_file):
            with open(self.challenges_file, 'r') as file:
                self.challenges = json.load(file)
        else:
            # Create default challenges with function names
            self.challenges = {
                "1": {
                    "title": "Hello World",
                    "description": "Write a function that returns 'Hello, World!'",
                    "test_cases": [
                        {"input": "", "expected": "Hello, World!"}
                    ],
                    "difficulty": "Easy",
                    "function_name": "hello_world",  # Add function name
                    "parameters": ""  # Add empty parameters
                },
                "2": {
                    "title": "Sum of Two Numbers",
                    "description": "Write a function that takes two numbers and returns their sum.",
                    "test_cases": [
                        {"input": "2, 3", "expected": 5},
                        {"input": "-1, 5", "expected": 4},
                        {"input": "0, 0", "expected": 0}
                    ],
                    "difficulty": "Easy",
                    "function_name": "add_numbers",  # Add function name
                    "parameters": "a, b"  # Add parameters
                }
            }
            self.save_challenges()
        
        # Validate challenges
        invalid_challenges = []
        for challenge_id, challenge in self.challenges.items():
            if not self.validate_challenge(challenge):
                invalid_challenges.append(challenge_id)
        
        # Remove invalid challenges
        for challenge_id in invalid_challenges:
            del self.challenges[challenge_id]
    
    def save_users(self):
        try:
            with open(self.users_file, 'w') as file:
                json.dump(self.users, file)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save user data: {str(e)}")

    def save_challenges(self):
        try:
            with open(self.challenges_file, 'w') as file:
                json.dump(self.challenges, file)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save challenge data: {str(e)}")
    
    def clear_frame(self):
        if hasattr(self, 'timer_running') and self.timer_running:
            self.stop_timer()
        if hasattr(self, 'timer_id') and self.timer_id:
            self.root.after_cancel(self.timer_id)
            self.timer_id = None
        for widget in self.main_frame.winfo_children():
            widget.destroy()
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def show_login_screen(self):
        self.clear_frame()
        
        # Create background
        background = tk.Frame(self.main_frame, bg=self.colors["light"])
        background.pack(fill=tk.BOTH, expand=True)
        
        # Create centered login form
        login_frame = tk.Frame(background, padx=30, pady=30, bg="white", 
                            highlightbackground=self.colors["black"], 
                            highlightthickness=2)
        login_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        # Title
        title_label = tk.Label(login_frame, text="Open Learn", 
                            font=("Legend", 20, "bold"), 
                            bg="white", fg=self.colors["black"])
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Subtitle
        subtitle = tk.Label(login_frame, text="Login to your account", 
                        bg="white", fg=self.colors["dark"])
        subtitle.grid(row=1, column=0, columnspan=2, pady=(0, 20))
        
        # Username
        username_label = tk.Label(login_frame, text="Username:", bg="white", fg=self.colors["dark"])
        username_label.grid(row=2, column=0, sticky="w", pady=5)
        self.username_entry = tk.Entry(login_frame, width=25, 
                                    highlightbackground=self.colors["black"], 
                                    highlightthickness=1)
        self.username_entry.grid(row=2, column=1, pady=5)
            
        # Password
        password_label = tk.Label(login_frame, text="Password:", bg="white", fg=self.colors["dark"])
        password_label.grid(row=3, column=0, sticky="w", pady=5)
        self.password_entry = tk.Entry(login_frame, show="*", width=25, 
                                    highlightbackground=self.colors["black"], 
                                    highlightthickness=1)
        self.password_entry.grid(row=3, column=1, pady=5)
        
        # Login button
        login_button = tk.Button(login_frame, text="Login", command=self.login,
                                bg=self.colors["black"], fg="white", 
                                padx=20, pady=5, border=0)
        login_button.grid(row=4, column=0, columnspan=2, pady=(15, 5))
        
         # Register link
        register_link = tk.Label(login_frame, text="Don't have an account? Register here", 
                                fg=self.colors["black"], cursor="hand2", bg="white")
        register_link.grid(row=5, column=0, columnspan=2, pady=5)
        register_link.bind("<Button-1>", lambda e: self.show_register_screen())
    
    def show_register_screen(self):
        self.clear_frame()
        
        # Create centered register form
        register_frame = tk.Frame(self.main_frame, padx=20, pady=20)
        register_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        # Title
        title_label = tk.Label(register_frame, text="Register New Account", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Username
        username_label = tk.Label(register_frame, text="Username:")
        username_label.grid(row=1, column=0, sticky="w", pady=5)
        self.reg_username_entry = tk.Entry(register_frame, width=25)
        self.reg_username_entry.grid(row=1, column=1, pady=5)
        
        # Email
        email_label = tk.Label(register_frame, text="Email:")
        email_label.grid(row=2, column=0, sticky="w", pady=5)
        self.reg_email_entry = tk.Entry(register_frame, width=25)
        self.reg_email_entry.grid(row=2, column=1, pady=5)
        
        # Password
        password_label = tk.Label(register_frame, text="Password:")
        password_label.grid(row=3, column=0, sticky="w", pady=5)
        self.reg_password_entry = tk.Entry(register_frame, show="*", width=25)
        self.reg_password_entry.grid(row=3, column=1, pady=5)
        
        # Confirm Password
        confirm_label = tk.Label(register_frame, text="Confirm Password:")
        confirm_label.grid(row=4, column=0, sticky="w", pady=5)
        self.reg_confirm_entry = tk.Entry(register_frame, show="*", width=25)
        self.reg_confirm_entry.grid(row=4, column=1, pady=5)
        
        # Register button
        register_button = tk.Button(register_frame, text="Register", command=self.register)
        register_button.grid(row=5, column=0, columnspan=2, pady=(15, 5))
        
        # Login link
        login_link = tk.Label(register_frame, text="Already have an account? Login here", fg="blue", cursor="hand2")
        login_link.grid(row=6, column=0, columnspan=2, pady=5)
        login_link.bind("<Button-1>", lambda e: self.show_login_screen())
    
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        hashed_password = self.hash_password(password)
        
        if username in self.users and self.users[username]["password"] == hashed_password:
            self.current_user = username
            
            #Check if Admin
            if self.users[username].get("is_admin", False):
                messagebox.showinfo("Success", "Welcome, Administrator!")
                self.show_admin_panel()
            else:
                messagebox.showinfo("Success", f"Welcome back, {username}!")
                self.show_challenges_screen()
            
        else:
            messagebox.showerror("Error", "Invalid username or password")
    
    def register(self):
        username = self.reg_username_entry.get()
        email = self.reg_email_entry.get()
        password = self.reg_password_entry.get()
        confirm = self.reg_confirm_entry.get()
        
        # Validate inputs
        if not username or not email or not password or not confirm:
            messagebox.showerror("Error", "All fields are required")
            return
        
        if username in self.users:
            messagebox.showerror("Error", "Username already exists")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        # Email validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            messagebox.showerror("Error", "Invalid email format")
            return
        
        # Password validation (at least 6 characters)
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long")
            return
        
        # Create new user
        self.users[username] = {
            "email": email,
            "password": self.hash_password(password),
            "completed_challenges": [],
            "completion_times": {}
        }
        
        self.save_users()
        messagebox.showinfo("Success", "Registration successful! You can now login.")
        self.show_login_screen()
    
    def show_admin_panel(self):
        self.clear_frame()
        
        # Create top navbar
        navbar = tk.Frame(self.main_frame, bg="#3498db", height=50)
        navbar.pack(fill=tk.X)
        
        # Title
        title_label = tk.Label(navbar, text="Admin Panel", font=("Arial", 14, "bold"), 
                            bg="#3498db", fg="white")
        title_label.pack(side=tk.LEFT, padx=10)
        
        # User info and logout
        user_frame = tk.Frame(navbar, bg="#3498db")
        user_frame.pack(side=tk.RIGHT, padx=10)
        
        user_label = tk.Label(user_frame, text=f"Admin: {self.current_user}", 
                            bg="#3498db", fg="white")
        user_label.pack(side=tk.LEFT, padx=10)
        
        logout_button = tk.Button(user_frame, text="Logout", 
                                command=self.logout, bg="#e74c3c", fg="white")
        logout_button.pack(side=tk.LEFT)
        
        back_button = tk.Button(user_frame, text="Back to Challenges", 
                            command=self.show_challenges_screen, bg="#2ecc71", fg="white")
        back_button.pack(side=tk.LEFT, padx=5)
        
        # Main content
        content_frame = tk.Frame(self.main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Left side - Challenge list
        list_frame = tk.LabelFrame(content_frame, text="Manage Challenges")
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Challenge list with scrollbar
        challenge_list_frame = tk.Frame(list_frame)
        challenge_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(challenge_list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        columns = ("id", "title", "difficulty")
        self.admin_challenge_tree = ttk.Treeview(challenge_list_frame, columns=columns, 
                                                show="headings", height=10)
        self.admin_challenge_tree.pack(fill=tk.BOTH, expand=True)
        
        # Configure scrollbar
        scrollbar.config(command=self.admin_challenge_tree.yview)
        self.admin_challenge_tree.config(yscrollcommand=scrollbar.set)
        
        # Set column headings
        self.admin_challenge_tree.heading("id", text="ID")
        self.admin_challenge_tree.heading("title", text="Challenge")
        self.admin_challenge_tree.heading("difficulty", text="Difficulty")
        
        # Set column widths
        self.admin_challenge_tree.column("id", width=50, anchor=tk.CENTER)
        self.admin_challenge_tree.column("title", width=300)
        self.admin_challenge_tree.column("difficulty", width=100, anchor=tk.CENTER)
        
        # Populate challenge list
        for challenge_id, challenge in self.challenges.items():
            self.admin_challenge_tree.insert("", tk.END, values=(
                challenge_id, challenge["title"], challenge["difficulty"]))
        
        # Buttons for challenge management
        btn_frame = tk.Frame(list_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        add_btn = tk.Button(btn_frame, text="Add Challenge", command=self.add_challenge,
                        bg="#2ecc71", fg="white")
        add_btn.pack(side=tk.LEFT, padx=5)
        
        edit_btn = tk.Button(btn_frame, text="Edit Challenge", 
                            command=lambda: self.edit_challenge(self.admin_challenge_tree.selection()),
                            bg="#3498db", fg="white")
        edit_btn.pack(side=tk.LEFT, padx=5)
        
        delete_btn = tk.Button(btn_frame, text="Delete Challenge", 
                            command=lambda: self.delete_challenge(self.admin_challenge_tree.selection()),
                            bg="#e74c3c", fg="white")
        delete_btn.pack(side=tk.LEFT, padx=5)
        
        # Right side - User management
        user_frame = tk.LabelFrame(content_frame, text="Manage Users")
        user_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        # User list with scrollbar
        user_list_frame = tk.Frame(user_frame)
        user_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        user_scrollbar = tk.Scrollbar(user_list_frame)
        user_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        columns = ("username", "email", "completed")
        self.admin_user_tree = ttk.Treeview(user_list_frame, columns=columns, 
                                        show="headings", height=10)
        self.admin_user_tree.pack(fill=tk.BOTH, expand=True)
        
        # Configure scrollbar
        user_scrollbar.config(command=self.admin_user_tree.yview)
        self.admin_user_tree.config(yscrollcommand=user_scrollbar.set)
        
        # Set column headings
        self.admin_user_tree.heading("username", text="Username")
        self.admin_user_tree.heading("email", text="Email")
        self.admin_user_tree.heading("completed", text="Completed")
        
        # Populate user list
        for username, user_data in self.users.items():
            if username != "admin":  # Skip admin in the list
                completed = len(user_data.get("completed_challenges", []))
                self.admin_user_tree.insert("", tk.END, values=(
                    username, user_data["email"], completed))
        
        # Buttons for user management
        user_btn_frame = tk.Frame(user_frame)
        user_btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        reset_btn = tk.Button(user_btn_frame, text="Reset Progress", 
                            command=lambda: self.reset_user_progress(self.admin_user_tree.selection()),
                            bg="#e67e22", fg="white")
        reset_btn.pack(side=tk.LEFT, padx=5)
        
        delete_user_btn = tk.Button(user_btn_frame, text="Delete User", 
                                command=lambda: self.delete_user(self.admin_user_tree.selection()),
                                bg="#e74c3c", fg="white")
        delete_user_btn.pack(side=tk.LEFT, padx=5)
    
    def add_challenge(self):
        # Create a new window for adding challenge
        add_window = tk.Toplevel(self.root)
        add_window.title("Add New Challenge")
        add_window.geometry("500x500")
        add_window.grab_set()  # Make window modal
        
        # Challenge form
        form_frame = tk.Frame(add_window, padx=20, pady=20)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        tk.Label(form_frame, text="Challenge Title:").grid(row=0, column=0, sticky="w", pady=5)
        title_entry = tk.Entry(form_frame, width=40)
        title_entry.grid(row=0, column=1, pady=5)
        
        # Difficulty
        tk.Label(form_frame, text="Difficulty:").grid(row=1, column=0, sticky="w", pady=5)
        difficulty_var = tk.StringVar(value="Easy")
        difficulty_combo = ttk.Combobox(form_frame, textvariable=difficulty_var, 
                                    values=["Easy", "Medium", "Hard"])
        difficulty_combo.grid(row=1, column=1, pady=5, sticky="w")
        
        # Description
        tk.Label(form_frame, text="Description:").grid(row=2, column=0, sticky="nw", pady=5)
        description_text = scrolledtext.ScrolledText(form_frame, height=8, width=40)
        description_text.grid(row=2, column=1, pady=5)
        
        # Function name
        tk.Label(form_frame, text="Function Name:").grid(row=3, column=0, sticky="w", pady=5)
        func_name_entry = tk.Entry(form_frame, width=40)
        func_name_entry.grid(row=3, column=1, pady=5)
        
        # Test cases frame
        test_frame = tk.LabelFrame(form_frame, text="Test Cases")
        test_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=10)
        
        # Initial test case
        test_cases = []
        
        def add_test_case(input_val="", expected_val=""):
            test_idx = len(test_cases)
            test_row = tk.Frame(test_frame)
            test_row.pack(fill=tk.X, pady=5)
            
            tk.Label(test_row, text=f"Test {test_idx+1} Input:").grid(row=0, column=0, sticky="w")
            input_entry = tk.Entry(test_row, width=20)
            input_entry.grid(row=0, column=1, padx=5)
            if input_val:
                input_entry.insert(0, input_val)
            
            tk.Label(test_row, text="Expected:").grid(row=0, column=2, sticky="w")
            expected_entry = tk.Entry(test_row, width=20)
            expected_entry.grid(row=0, column=3, padx=5)
            if expected_val:
                expected_entry.insert(0, str(expected_val))
            
            # Add parameter names entry
            tk.Label(test_row, text="Parameters:").grid(row=1, column=0, sticky="w")
            param_entry = tk.Entry(test_row, width=40)
            param_entry.grid(row=1, column=1, columnspan=3, padx=5, pady=2)
            param_entry.insert(0, "numbers")  # Default parameter name
            
            test_cases.append((input_entry, expected_entry, param_entry))
        
        # Add first test case
        add_test_case()
        
        # Button to add more test cases
        add_test_btn = tk.Button(test_frame, text="Add Test Case", 
                                command=add_test_case, bg="#3498db", fg="white")
        add_test_btn.pack(pady=10)
        
        # Save button
        def save_challenge():
            # Validate inputs
            title = title_entry.get().strip()
            difficulty = difficulty_var.get()
            description = description_text.get("1.0", tk.END).strip()
            func_name = func_name_entry.get().strip()  # Get function name
            
            if not title or not description or not func_name:
                messagebox.showerror("Error", "All fields are required")
                return
            
            # Get test cases
            final_test_cases = []
            parameters = ""
            for input_entry, expected_entry, param_entry in test_cases:
                test_input = input_entry.get().strip()
                test_expected = expected_entry.get().strip()
                test_params = param_entry.get().strip()
                parameters = param_entry.get().strip()
                
                if not test_input or not test_expected or not test_params:
                    messagebox.showerror("Error", "All test cases must be filled")
                    return
                
                # Try to convert expected to int or float if possible
                try:
                    if test_expected.isdigit():
                        test_expected = int(test_expected)
                    elif test_expected.replace('.', '', 1).isdigit():
                        test_expected = float(test_expected)
                except:
                    pass  # Keep as string if conversion fails
                    
                final_test_cases.append({
                    "input": test_input,
                    "expected": test_expected,
                    "parameters": test_params
                })
            
            if not final_test_cases:
                messagebox.showerror("Error", "At least one test case is required")
                return
            
            if not parameters:
                messagebox.showerror("Error", "Parameters field is required")
                return
            
            # Generate new challenge ID
            new_id = str(max([int(k) for k in self.challenges.keys()]) + 1)
            
            # Create new challenge
            self.challenges[new_id] = {
                "title": title,
                "description": description,
                "function_name": func_name,  # Add function name to challenge data
                "parameters": parameters,
                "test_cases": final_test_cases,
                "difficulty": difficulty
            }
            
            # Save challenges
            self.save_challenges()
            messagebox.showinfo("Success", "Challenge added successfully!")
            add_window.destroy()
            
            # Refresh admin panel
            self.show_admin_panel()
        
        save_btn = tk.Button(form_frame, text="Save Challenge", command=save_challenge,
                            bg="#2ecc71", fg="white")
        save_btn.grid(row=5, column=0, columnspan=2, pady=20)

    

    def delete_challenge(self, selection):
        if not selection:
            messagebox.showerror("Error", "No challenge selected")
            return
            
        challenge_id = self.admin_challenge_tree.item(selection[0], "values")[0]
        
        # Confirm deletion
        if messagebox.askyesno("Confirm Delete", 
                            f"Are you sure you want to delete challenge {challenge_id}?"):
            # Remove challenge
            del self.challenges[challenge_id]
            
            # Remove from users' completed challenges
            for username in self.users:
                if challenge_id in self.users[username]["completed_challenges"]:
                    self.users[username]["completed_challenges"].remove(challenge_id)
            
            # Save data
            self.save_challenges()
            self.save_users()
            messagebox.showinfo("Success", "Challenge deleted successfully!")
            
            # Refresh admin panel
            self.show_admin_panel()

    def reset_user_progress(self, selection):
        if not selection:
            messagebox.showerror("Error", "No user selected")
            return
            
        username = self.admin_user_tree.item(selection[0], "values")[0]
        
        # Confirm reset
        if messagebox.askyesno("Confirm Reset", 
                            f"Are you sure you want to reset progress for {username}?"):
            # Reset completed challenges
            self.users[username]["completed_challenges"] = []
            
            # Save users data
            self.save_users()
            messagebox.showinfo("Success", "User progress reset successfully!")
            
            # Refresh admin panel
            self.show_admin_panel()

    def delete_user(self, selection):
        if not selection:
            messagebox.showerror("Error", "No user selected")
            return
            
        username = self.admin_user_tree.item(selection[0], "values")[0]
        
        # Confirm deletion
        if messagebox.askyesno("Confirm Delete", 
                            f"Are you sure you want to delete user {username}?"):
            # Remove user
            del self.users[username]
            
            # Save users data
            self.save_users()
            messagebox.showinfo("Success", "User deleted successfully!")
            
            # Refresh admin panel
            self.show_admin_panel()
        
    def edit_challenge(self, selection):
        if not selection:
            messagebox.showerror("Error", "No challenge selected")
            return
            
        challenge_id = self.admin_challenge_tree.item(selection[0], "values")[0]
        challenge = self.challenges[challenge_id]
        
        # Create edit window
        edit_window = tk.Toplevel(self.root)
        edit_window.title("Edit Challenge")
        edit_window.geometry("500x500")
        edit_window.grab_set()  # Make window modal
        
        # Challenge form
        form_frame = tk.Frame(edit_window, padx=20, pady=20)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        tk.Label(form_frame, text="Challenge Title:").grid(row=0, column=0, sticky="w", pady=5)
        title_entry = tk.Entry(form_frame, width=40)
        title_entry.insert(0, challenge["title"])
        title_entry.grid(row=0, column=1, pady=5)
        
        # Difficulty
        tk.Label(form_frame, text="Difficulty:").grid(row=1, column=0, sticky="w", pady=5)
        difficulty_var = tk.StringVar(value=challenge["difficulty"])
        difficulty_combo = ttk.Combobox(form_frame, textvariable=difficulty_var, 
                                    values=["Easy", "Medium", "Hard"])
        difficulty_combo.grid(row=1, column=1, pady=5, sticky="w")
        
        # Description
        tk.Label(form_frame, text="Description:").grid(row=2, column=0, sticky="nw", pady=5)
        description_text = scrolledtext.ScrolledText(form_frame, height=8, width=40)
        description_text.insert("1.0", challenge["description"])
        description_text.grid(row=2, column=1, pady=5)
        
        # Function name
        tk.Label(form_frame, text="Function Name:").grid(row=3, column=0, sticky="w", pady=5)
        func_name_entry = tk.Entry(form_frame, width=40)
        func_name_entry.insert(0, challenge["function_name"])
        func_name_entry.grid(row=3, column=1, pady=5)
        
        # Test cases frame
        test_frame = tk.LabelFrame(form_frame, text="Test Cases")
        test_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=10)
        
        # Test cases list
        test_cases = []
        
        def add_test_case(input_val="", expected_val=""):
            test_idx = len(test_cases)
            test_row = tk.Frame(test_frame)
            test_row.pack(fill=tk.X, pady=5)
            
            tk.Label(test_row, text=f"Test {test_idx+1} Input:").grid(row=0, column=0, sticky="w")
            input_entry = tk.Entry(test_row, width=20)
            input_entry.grid(row=0, column=1, padx=5)
            if input_val:
                input_entry.insert(0, input_val)
            
            tk.Label(test_row, text="Expected:").grid(row=0, column=2, sticky="w")
            expected_entry = tk.Entry(test_row, width=20)
            expected_entry.grid(row=0, column=3, padx=5)
            if expected_val:
                expected_entry.insert(0, str(expected_val))
            
            test_cases.append((input_entry, expected_entry))
        
        # Add existing test cases
        for test_case in challenge["test_cases"]:
            add_test_case(test_case["input"], test_case["expected"])
        
        # Button to add more test cases
        add_test_btn = tk.Button(test_frame, text="Add Test Case", 
                                command=lambda: add_test_case(), 
                                bg="#3498db", fg="white")
        add_test_btn.pack(pady=10)
        
        def save_changes():
            # Validate inputs
            title = title_entry.get().strip()
            difficulty = difficulty_var.get()
            description = description_text.get("1.0", tk.END).strip()
            func_name = func_name_entry.get().strip()
            
            if not title or not description or not func_name:
                messagebox.showerror("Error", "Title, description, and function name are required")
                return
            
            # Get test cases
            final_test_cases = []
            for input_entry, expected_entry in test_cases:
                test_input = input_entry.get().strip()
                test_expected = expected_entry.get().strip()
                
                if not test_input or not test_expected:
                    messagebox.showerror("Error", "All test cases must be filled")
                    return
                
                # Try to convert expected to int or float if possible
                try:
                    if test_expected.isdigit():
                        test_expected = int(test_expected)
                    elif test_expected.replace('.', '', 1).isdigit():
                        test_expected = float(test_expected)
                except:
                    pass  # Keep as string if conversion fails
                    
                final_test_cases.append({
                    "input": test_input,
                    "expected": test_expected
                })
            
            if not final_test_cases:
                messagebox.showerror("Error", "At least one test case is required")
                return
            
            if not challenge.get("parameters", ""):
                messagebox.showerror("Error", "Parameters field is required")
                return
            
            # Update challenge
            self.challenges[challenge_id].update({
                "title": title,
                "description": description,
                "function_name": func_name,
                "test_cases": final_test_cases,
                "difficulty": difficulty
            })
            
            # Save changes
            self.save_challenges()
            messagebox.showinfo("Success", "Challenge updated successfully!")
            edit_window.destroy()
            
            # Refresh admin panel
            self.show_admin_panel()
        
        # Save button
        save_btn = tk.Button(form_frame, text="Save Changes", 
                            command=save_changes,
                            bg="#2ecc71", fg="white")
        save_btn.grid(row=5, column=0, columnspan=2, pady=20)
        
    def show_challenges_screen(self):
        self.clear_frame()
        
        # Create top navbar
        navbar = tk.Frame(self.main_frame, bg="#f0f0f0", height=50)
        navbar.pack(fill=tk.X)
        
        # Title
        title_label = tk.Label(navbar, text="Coding Challenges", font=("Arial", 14, "bold"), bg="#f0f0f0")
        title_label.pack(side=tk.LEFT, padx=10)
        
        # User info and logout
        user_frame = tk.Frame(navbar, bg="#f0f0f0")
        user_frame.pack(side=tk.RIGHT, padx=10)
        
        user_label = tk.Label(user_frame, text=f"Logged in as: {self.current_user}", bg="#f0f0f0")
        user_label.pack(side=tk.LEFT, padx=10)
        
        logout_button = tk.Button(user_frame, text="Logout", command=self.logout)
        logout_button.pack(side=tk.LEFT)
        
        content_frame = tk.Frame(self.main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Left side - Challenges
        challenge_frame = tk.Frame(content_frame)
        challenge_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Challenge list header
        header_frame = tk.Frame(challenge_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
    
        tk.Label(header_frame, text="Available Challenges", font=("Arial", 12, "bold")).pack(side=tk.LEFT)
        
        # Create challenge list container
        challenge_container = tk.Frame(self.main_frame)
        challenge_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Challenge list header
        header_frame = tk.Frame(challenge_container)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(header_frame, text="Available Challenges", font=("Arial", 12, "bold")).pack(side=tk.LEFT)
        
        # Create a frame for the challenges list with scrollbar
        list_frame = tk.Frame(challenge_container)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Challenge list (Treeview)
        columns = ("id", "title", "difficulty", "status")
        self.challenge_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=10)
        self.challenge_tree.pack(fill=tk.BOTH, expand=True)
        
        # Configure scrollbar
        scrollbar.config(command=self.challenge_tree.yview)
        self.challenge_tree.config(yscrollcommand=scrollbar.set)
        
        # Set column headings
        self.challenge_tree.heading("id", text="ID")
        self.challenge_tree.heading("title", text="Challenge")
        self.challenge_tree.heading("difficulty", text="Difficulty")
        self.challenge_tree.heading("status", text="Status")
        
        # Set column widths
        self.challenge_tree.column("id", width=50, anchor=tk.CENTER)
        self.challenge_tree.column("title", width=400)
        self.challenge_tree.column("difficulty", width=100, anchor=tk.CENTER)
        self.challenge_tree.column("status", width=100, anchor=tk.CENTER)
        
        # Right side - Leaderboard
        leaderboard_frame = tk.LabelFrame(content_frame, text="Leaderboard", padx=10, pady=10)
        leaderboard_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        # Calculate leaderboard data
        leaderboard_data = self.calculate_leaderboard()
        
        # Create leaderboard list
        columns = ("rank", "user", "completed", "score")
        self.leaderboard_tree = ttk.Treeview(leaderboard_frame, columns=columns, show="headings", height=10)
        self.leaderboard_tree.pack(fill=tk.BOTH, expand=True)
        
         # Set column headings
        self.leaderboard_tree.heading("rank", text="Rank")
        self.leaderboard_tree.heading("user", text="User")
        self.leaderboard_tree.heading("completed", text="Challenges")
        self.leaderboard_tree.heading("score", text="Score")
        
        # Set column widths
        self.leaderboard_tree.column("rank", width=50, anchor=tk.CENTER)
        self.leaderboard_tree.column("user", width=100)
        self.leaderboard_tree.column("completed", width=80, anchor=tk.CENTER)
        self.leaderboard_tree.column("score", width=70, anchor=tk.CENTER)
        
        # Populate challenge list
        for challenge_id, challenge in self.challenges.items():
            status = "Solved" if challenge_id in self.users[self.current_user]["completed_challenges"] else "Unsolved"
            self.challenge_tree.insert("", tk.END, values=(challenge_id, challenge["title"], challenge["difficulty"], status))
        
        # Bind double-click to open challenge
        self.challenge_tree.bind("<Double-1>", self.open_challenge)

        for i, (user, stats) in enumerate(leaderboard_data, 1):
            self.leaderboard_tree.insert("", tk.END, values=(
                i, 
                user, 
                stats["completed"], 
                stats["score"]
            ))
            
    def start_timer(self):
        """Start the coding timer"""
        self.start_time = time.time()
        self.timer_running = True
        self.update_timer()

    def update_timer(self):
        """Update the timer display"""
        if self.timer_running:
            import time
            elapsed = time.time() - self.start_time
            mins, secs = divmod(int(elapsed), 60)
            hours, mins = divmod(mins, 60)
            
            if hours > 0:
                time_str = f"{hours:02d}:{mins:02d}:{secs:02d}"
            else:
                time_str = f"{mins:02d}:{secs:02d}"
            
            self.timer_display.config(text=time_str)
            
            # Change color based on elapsed time
            if mins >= 10:  # Over 10 minutes
                self.timer_display.config(fg=self.colors["warning"])
            elif mins >= 5:  # Over 5 minutes
                self.timer_display.config(fg=self.colors["accent"])
            
            # Update every second
            self.timer_id = self.root.after(1000, self.update_timer)

    def stop_timer(self):
        """Stop the timer"""
        if self.timer_running:
            self.timer_running = False
            if self.timer_id:
                self.root.after_cancel(self.timer_id)
                self.timer_id = None
    
    def calculate_leaderboard(self):
        leaderboard = []
        
        for username, user_data in self.users.items():
            if username == "admin":  # Skip admin user
                continue
                
            completed = len(user_data.get("completed_challenges", []))
            
            # Calculate score based on challenge difficulty and completion time
            score = 0
            completion_times = user_data.get("completion_times", {})  # Use get() with default empty dict
            
            for challenge_id in user_data.get("completed_challenges", []):
                if challenge_id in self.challenges:
                    difficulty = self.challenges[challenge_id]["difficulty"]
                    
                    # Base scores by difficulty
                    if difficulty == "Easy":
                        base_score = 10
                    elif difficulty == "Medium":
                        base_score = 20
                    elif difficulty == "Hard":
                        base_score = 30
                    
                    # Time bonus calculation
                    time_bonus = 0
                    time_data = completion_times.get(challenge_id, {})
                    
                    if isinstance(time_data, dict) and "elapsed_seconds" in time_data:
                        # Get elapsed time in seconds
                        elapsed_time = time_data["elapsed_seconds"]
                        
                        # Bonus based on completion speed
                        if elapsed_time < 60:  # Under 1 minute
                            time_bonus = 10
                        elif elapsed_time < 300:  # Under 5 minutes
                            time_bonus = 5
                        elif elapsed_time < 600:  # Under 10 minutes
                            time_bonus = 3
                        else:  # Over 10 minutes
                            time_bonus = 1
                    
                    score += base_score + time_bonus
            
            leaderboard.append((username, {
                "completed": completed,
                "score": round(score, 1)
            }))
        
        # Sort by score (descending)
        leaderboard.sort(key=lambda x: x[1]["score"], reverse=True)
        
        return leaderboard
                        
    def open_challenge(self, event):
        # Get selected challenge
        selected_item = self.challenge_tree.selection()[0]
        challenge_id = self.challenge_tree.item(selected_item, "values")[0]
        
        # Show challenge screen
        self.show_challenge_screen(challenge_id)
    
    def show_challenge_screen(self, challenge_id):
        self.clear_frame()
        
        challenge = self.challenges[challenge_id]
        
        # Create main layout
        left_pane = tk.Frame(self.main_frame, width=400)
        left_pane.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        left_pane.pack_propagate(False)
        
        right_pane = tk.Frame(self.main_frame, width=500)
        right_pane.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Back button
        back_button = tk.Button(left_pane, text="← Back to Challenges", command=self.show_challenges_screen)
        back_button.pack(anchor=tk.W, pady=(0, 10))
        
        # Challenge title
        title_label = tk.Label(left_pane, text=challenge["title"], font=("Arial", 14, "bold"))
        title_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Difficulty 
        difficulty_label = tk.Label(left_pane, text=f"Difficulty: {challenge['difficulty']}")
        difficulty_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Description
        desc_frame = tk.LabelFrame(left_pane, text="Problem Description")
        desc_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        description = tk.Text(desc_frame, wrap=tk.WORD, height=10, padx=10, pady=10)
        description.insert(tk.END, challenge["description"])
        description.config(state=tk.DISABLED)
        description.pack(fill=tk.BOTH, expand=True)
        
        # Test cases
        test_frame = tk.LabelFrame(left_pane, text="Test Cases")
        test_frame.pack(fill=tk.BOTH, expand=True)
        
        test_text = tk.Text(test_frame, wrap=tk.WORD, height=6, padx=10, pady=10)
        for i, test in enumerate(challenge["test_cases"]):
            test_text.insert(tk.END, f"Test {i+1}:\n")
            test_text.insert(tk.END, f"  Input: {test['input']}\n")
            test_text.insert(tk.END, f"  Expected: {test['expected']}\n\n")
        test_text.config(state=tk.DISABLED)
        test_text.pack(fill=tk.BOTH, expand=True)
        
        # Create code editor with line numbers
        editor_frame = tk.Frame(right_pane)
        editor_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Line numbers
        line_numbers = tk.Text(editor_frame, width=4, padx=3, takefocus=0,
                              border=0, background='lightgray',
                              state='disabled', wrap='none')
        line_numbers.pack(side=tk.LEFT, fill=tk.Y)

        # Code editor
        self.code_editor = scrolledtext.ScrolledText(editor_frame, 
                                                   height=20, 
                                                   font=("Consolas", 11),
                                                   wrap=tk.NONE)
        self.code_editor.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Function template with parameters
        func_name = challenge.get("function_name", "solution")
        parameters = challenge.get("parameters", "")

        # Create default code template with proper indentation
        default_code = f"def {func_name}({parameters}):\n    # Write your code here\n    pass"
        self.code_editor.insert("1.0", default_code)

        # Add syntax highlighting
        def highlight_syntax(event=None):
            content = self.code_editor.get("1.0", tk.END)
            self.code_editor.tag_remove("keyword", "1.0", tk.END)
            self.code_editor.tag_remove("string", "1.0", tk.END)
            self.code_editor.tag_remove("comment", "1.0", tk.END)
            self.code_editor.tag_remove("function", "1.0", tk.END)
            
            # Python keywords
            keywords = ["def", "class", "if", "else", "elif", "for", "while", 
                       "try", "except", "finally", "with", "return", "import",
                       "from", "as", "pass", "break", "continue", "and", "or",
                       "not", "is", "in", "True", "False", "None"]
            
            for keyword in keywords:
                start = "1.0"
                while True:
                    pos = self.code_editor.search(r'\y' + keyword + r'\y', start, tk.END, regexp=True)
                    if not pos:
                        break
                    end = f"{pos}+{len(keyword)}c"
                    self.code_editor.tag_add("keyword", pos, end)
                    start = end

            # Strings
            start = "1.0"
            while True:
                pos = self.code_editor.search(r'["\'].*?["\']', start, tk.END, regexp=True)
                if not pos:
                    break
                line, col = pos.split('.')
                end = self.code_editor.search(r'["\']', f"{line}.{int(col)+1}", tk.END)
                if not end:
                    break
                self.code_editor.tag_add("string", pos, f"{end}+1c")
                start = f"{end}+1c"

            # Comments
            start = "1.0"
            while True:
                pos = self.code_editor.search(r'#.*$', start, tk.END, regexp=True)
                if not pos:
                    break
                line = pos.split('.')[0]
                self.code_editor.tag_add("comment", pos, f"{line}.end")
                start = f"{line}.end"

        # Update line numbers
        def update_line_numbers(event=None):
            lines = self.code_editor.get("1.0", tk.END).count("\n")
            line_numbers.config(state='normal')
            line_numbers.delete("1.0", tk.END)
            for i in range(1, lines + 1):
                line_numbers.insert(tk.END, f"{i}\n")
            line_numbers.config(state='disabled')

        # Smart indentation
        def handle_return(event):
            # Get current line
            current_line = self.code_editor.get("insert linestart", "insert")
            
            # Calculate indentation
            indentation = len(current_line) - len(current_line.lstrip())
            
            # Add extra indent if line ends with colon
            if current_line.rstrip().endswith(':'):
                indentation += 4
                
            # Insert newline with proper indentation
            self.code_editor.insert("insert", f"\n{' ' * indentation}")
            return "break"

        def handle_tab(event):
            self.code_editor.insert("insert", " " * 4)
            return "break"

        # Configure tags for syntax highlighting
        self.code_editor.tag_configure("keyword", foreground="blue")
        self.code_editor.tag_configure("string", foreground="green")
        self.code_editor.tag_configure("comment", foreground="gray")
        self.code_editor.tag_configure("function", foreground="purple")

        # Bind events
        self.code_editor.bind("<KeyRelease>", lambda e: (highlight_syntax(), update_line_numbers()))
        self.code_editor.bind("<Return>", handle_return)
        self.code_editor.bind("<Tab>", handle_tab)

        # Initial highlighting and line numbers
        highlight_syntax()
        update_line_numbers()

        if not hasattr(self, 'challenge_start_times'):
            self.challenge_start_times = {}
        
        timer_frame = tk.Frame(right_pane)
        timer_frame.pack(fill=tk.X, pady=(5, 10))

        timer_label = tk.Label(timer_frame, text="Time elapsed:", font=("Arial", 10))
        timer_label.pack(side=tk.LEFT, padx=5)

        self.timer_display = tk.Label(timer_frame, text="00:00", font=("Arial", 10, "bold"), fg=self.colors["primary"])
        self.timer_display.pack(side=tk.LEFT)

        # Initialize timer variables
        self.timer_running = False
        self.start_time = time.time()
        self.timer_id = None

        # Start the timer
        self.start_timer()
            
        # Buttons
        button_frame = tk.Frame(right_pane)
        button_frame.pack(fill=tk.X, pady=10)
        
        run_button = tk.Button(button_frame, text="Run Code", command=lambda: self.run_code(challenge_id))
        run_button.pack(side=tk.LEFT, padx=5)
        
        submit_button = tk.Button(button_frame, text="Submit Solution", command=lambda: self.submit_solution(challenge_id))
        submit_button.pack(side=tk.LEFT, padx=5)
        
        # Output area
        output_frame = tk.LabelFrame(right_pane, text="Output")
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, height=8, font=("Courier New", 10))
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
    
    def parse_input(self, input_str):
        if not input_str:
            return []
        
        try:
            # Handle list input
            if input_str.startswith('[') and input_str.endswith(']'):
                content = input_str[1:-1].strip()
                if not content:
                    return []
                return [eval(x.strip()) for x in content.split(',')]
            
            # Handle string input
            if input_str.startswith('"') or input_str.startswith("'"):
                return [eval(input_str)]
            
            # Handle multiple comma-separated values
            return [eval(x.strip()) for x in input_str.split(',')]
        except:
            return [input_str]  # Return as raw string if evaluation fails
    
    def run_code(self, challenge_id):
        code = self.code_editor.get("1.0", tk.END)
        challenge = self.challenges[challenge_id]
        
        # Create safe namespace
        namespace = {
            'print': print,
            'len': len,
            'range': range,
            'list': list,
            'dict': dict,
            'set': set,
            'sum': sum,
            'min': min,
            'max': max,
            'str': str,
            'int': int,
            'float': float,
            'bool': bool,
        }
        
        # Clear output
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        
        # Capture stdout
        old_stdout = sys.stdout
        redirected_output = sys.stdout = StringIO()
        
        try:
            # Execute code
            exec(code, namespace)
            
            func_name = challenge.get("function_name", "solution")
            test_case = challenge["test_cases"][0]  # Run first test case
            
            # Parse input
            args = self.parse_input(test_case["input"])
            
            # Run function
            if func_name in namespace:
                result = namespace[func_name](*args)
                self.output_text.insert(tk.END, f"Result: {result}\n")
                self.output_text.insert(tk.END, f"Expected: {test_case['expected']}\n")
            else:
                self.output_text.insert(tk.END, f"Error: Function '{func_name}' not found\n")
            
            # Show printed output
            output = redirected_output.getvalue()
            if output:
                self.output_text.insert(tk.END, "\nOutput:\n")
                self.output_text.insert(tk.END, output)
                
        except Exception as e:
            self.output_text.insert(tk.END, "Error:\n")
            self.output_text.insert(tk.END, traceback.format_exc())
        finally:
            sys.stdout = old_stdout
            self.output_text.config(state=tk.DISABLED)
    
    def submit_solution(self, challenge_id):
        code = self.code_editor.get("1.0", tk.END)
        challenge = self.challenges[challenge_id]
        
        # Get function name with default
        func_name = challenge.get("function_name", "solution")
        
        # Clear output
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        
        try:
            # Execute code
            namespace = {}
            exec(code, namespace)
            
            # Check if function exists
            if func_name not in namespace:
                self.output_text.insert(tk.END, f"Error: Function '{func_name}' not found. Please define the function.")
                return
            
            # Test all test cases
            all_tests_passed = True
            self.output_text.insert(tk.END, "Running all test cases:\n\n")
            
            for i, test_case in enumerate(challenge["test_cases"]):
                self.output_text.insert(tk.END, f"Test {i+1}: ")
                
                try:
                    args = self.parse_input(test_case["input"])
                    
                    result = namespace[func_name](*args)
                    
                    # Compare result with expected
                    if result == test_case["expected"]:
                        self.output_text.insert(tk.END, "PASSED ✓\n")
                    else:
                        self.output_text.insert(tk.END, "FAILED ✗\n")
                        self.output_text.insert(tk.END, f"  Expected: {test_case['expected']}\n")
                        self.output_text.insert(tk.END, f"  Got: {result}\n")
                        all_tests_passed = False
                
                except Exception as e:
                    self.output_text.insert(tk.END, "ERROR ✗\n")
                    self.output_text.insert(tk.END, f"  {str(e)}\n")
                    all_tests_passed = False
            
            # Summary
            if all_tests_passed:
                self.output_text.insert(tk.END, "\nAll tests passed! Congratulations! 🎉\n")
                
                self.stop_timer()
                
                import time
                current_time = time.time()
                elapsed_time = current_time - self.start_time

                
                # Display elapsed time
                minutes, seconds = divmod(elapsed_time, 60)
                self.output_text.insert(tk.END, f"\nTime taken: {int(minutes)}m {int(seconds)}s\n")
                
                # Mark challenge as completed
                if challenge_id not in self.users[self.current_user]["completed_challenges"]:
                    self.users[self.current_user]["completed_challenges"].append(challenge_id)
                    
                    if "completion_times" not in self.users[self.current_user]:
                        self.users[self.current_user]["completion_times"] = {}
                    
                    # Record completion time and elapsed time
                    self.users[self.current_user]["completion_times"][challenge_id] = {
                        "timestamp": current_time,
                        "elapsed_seconds": elapsed_time
                    }
                    
                    self.save_users()

                    
                # Show success message
                messagebox.showinfo("Success", "Challenge completed successfully!")
            else:
                self.output_text.insert(tk.END, "\nSome tests failed. Please review your solution.\n")
                
        except Exception as e:
            self.output_text.insert(tk.END, "Error:\n")
            self.output_text.insert(tk.END, traceback.format_exc())
        finally:
            self.output_text.config(state=tk.DISABLED)
    
    def logout(self):
        self.current_user = None
        messagebox.showinfo("Logout", "You have been logged out successfully.")
        self.show_login_screen()

def main():
    root = tk.Tk()
    app = CodingPracticeApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()