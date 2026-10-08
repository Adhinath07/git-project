🗳️ College Voting System

A web-based Voting System developed using Python Flask and SQLite3.
The system allows students to participate in elections digitally, while administrators can create and manage elections, candidates, and publish results.

📌 Features

👨‍🎓 Student/User

- User registration and login
- Secure password hashing
- View available elections
- View election details and candidates
- Cast votes
- Prevent duplicate voting
- View election results
- Manage user profile
- Logout

👨‍💼 Administrator

- Admin login
- Admin dashboard
- Create and manage elections
- Add, edit, and delete candidates
- Manage election status
- Publish election results
- View election information

🛠️ Technologies Used

- Python
- Flask – Web framework
- SQLite3 – Database
- HTML5 – Page structure
- CSS3 – Styling
- JavaScript – Client-side functionality
- Jinja2 – Flask templating
- Werkzeug – Password hashing

📂 Project Structure

Voting-System/
│
├── app.py
├── database.db
│
├── templates/
│   ├── base.html
│   ├── home.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── profile.html
│   ├── ballot.html
│   ├── vote.html
│   ├── result.html
│   ├── result_detail.html
│   ├── error.html
│   │
│   └── admin/
│       ├── dashboard.html
│       ├── manage_candidates.html
│       ├── manage_elections.html
│       └── publish_result.html
│
├── static/
│   ├── style.css
│   ├── app.js
│   
│   
│      
│
└── README.md

🗄️ Database

The project uses SQLite3 as its database.

Main tables include:

- "users" – Stores user and administrator accounts
- "elections" – Stores election information
- "candidates" – Stores candidate information
- "votes" – Stores votes submitted by users

User roles are managed using a "role" column, such as:

student
admin

Unique IDs are used for records to identify users, elections, candidates, and votes.

🔐 Security

The application includes basic security features such as:

- Password hashing using Werkzeug
- Session-based authentication
- Role-based access control
- Prevention of unauthorized admin-page access
- Prevention of duplicate voting
- Unique identifiers for database records

«This project is intended as a college/academic project and should be further security-tested before being used for a real-world election.»

🚀 Installation

1. Clone the repository

git clone <your-repository-url>

2. Open the project folder

cd Voting-System

3. Install Flask

pip install flask

If your project uses other Python packages, install them as required.

4. Run the application

python app.py

5. Open the application

Open your browser and visit:

http://127.0.0.1:5000/

👥 User Roles

Student

Students can:

1. Register an account
2. Log in
3. View ongoing elections
4. View candidates
5. Cast their vote
6. View published results

Administrator

Administrators can:

1. Log in through the same authentication system
2. Access the admin dashboard
3. Create elections
4. Manage candidates
5. Manage election information
6. Publish results

🔄 Basic Workflow

                ┌──────────────┐
                │    Home      │
                └──────┬───────┘
                       │
              ┌────────┴────────┐
              │                 │
          Register            Login
              │                 │
              └────────┬────────┘
                       │
                 Check User Role
                  /           \
                 /             \
            Student           Admin
               │                │
        User Dashboard    Admin Dashboard
               │                │
          View Elections    Manage Elections
               │                │
          View Results   Manage Candidates
               │                │
             Vote          Publish Results
               │                │
               └───────┬────────┘
                       │
                    Results

🎯 Project Objective

The main objective of this project is to develop a simple and efficient digital voting platform for colleges.

The system aims to reduce the need for manual voting and make the election process easier to manage by providing:

- Digital voting
- Centralized election management
- Candidate management
- Automated vote counting
- Result publication
- Role-based access

🔮 Future Improvements

Possible future improvements include:

- Email verification
- OTP-based authentication
- Election notifications
- Better vote auditing
- Advanced admin analytics
- Export election results
- Improved accessibility
- Deployment to a production server
- Additional security measures

👨‍💻 Team

Developed as a college project.

Technologies: Python • Flask • SQLite3 • HTML • CSS • JavaScript

---

⭐ If you find this project useful, consider giving the repository a star!