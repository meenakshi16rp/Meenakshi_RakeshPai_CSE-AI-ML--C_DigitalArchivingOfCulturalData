# 📚 Archive Mosaic - Cultural Heritage Digital Archiving Platform

### 👩‍💻 Developed by:

- **Meenakshi** - Roll No: 2301730144 
  
Mid term Presentation Video:
https://youtu.be/3DzJSfniYt4?si=Pk4NfO5igd1oIcNT

---
## 📌 Project Overview

**Archive Mosaic** is a secure, scalable, and user-friendly web application designed to preserve, organize, and share culturally significant materials such as traditional dances, music, art, manuscripts, and more. It is ideal for digital archiving platforms, art repositories, and cultural preservation initiatives. 
It allows users and organizations to **upload**, **categorize**, and **store** cultural assets with rich metadata, ensuring these treasures remain accessible, organized, and protected for future generations.

---

## 🛠️ Technologies Used
- **Frontend**: HTML, CSS, JavaScript (with Bootstrap for responsiveness)
- **Backend**: Python (Flask Framework)
- **Authentication**: Firebase Authentication (Role-based access control)
- **Database**: MongoDB with GridFS for file storage
- **AI Integration**: meta-llama/Llama-Vision-Free (via Together API) for automatic image captioning
- **Other Tools**: JSON Web Tokens (JWT) for secure session management

---

## 🚀 Features

### ✅ Completed

- 🔐 Firebase Authentication (Sign In, Sign Up, Forgot Password)
- 👥 Role-Based Access Control (Admin/User)
- 🖼️ Upload Page: Supports image, video, PDF uploads
- 📝 Metadata Entry: Title, description, date, language, state, tags, category, and uploader name
- 🧠 Integration with Meta-LLaMA Vision for AI-based Image Captioning
- 💾 MongoDB + GridFS to store files and metadata
- 📅 Automatic upload date recording
- 👩‍💼 Admin Dashboard:
  - View and manage all users
  - Edit/delete users or promote/demote roles
- 📤 User Dashboard:
  - View, edit, delete their own uploads
- 📚 About Us page and full frontend navigation
- 🖼️ Gallery to browse all uploaded content
- 🔍 Filtering by categories and metadata (for efficient discovery)

---

## 📋 Project Flow

1. **User signs up** → Role assigned → Login with secure session via JWT
2. **User uploads** a file + metadata → Stored securely in MongoDB using GridFS
3. **AI Model** automatically generates image captions (optional for user input)
4. **Gallery** displays uploads → Filters and search enable easy browsing
5. **Admin Management** → Full control over users and content

---

## 📦 Folder Structure

├── app.py                        # Main Flask application
├── serviceAccountKey.json       # Firebase Admin SDK service account key

├── static/                      # Static assets
│   ├── css/
│   │   ├── aboutus.css
│   │   └── upload.css
│   ├── images/
│   │   └── background.jpeg
│   └── javascript/
│       ├── signin.js
│       └── signup.js

├── templates/                   # HTML templates for rendering pages
│   ├── aboutus.html             # About Us page
│   ├── access_denied.html       # Role-restricted access page
│   ├── admin_dashboard.html     # Admin control panel
│   ├── gallery.html             # Public display of uploaded content
│   ├── main.html                # Home or landing page
│   ├── signin.html              # User login page
│   ├── signup.html              # User registration page
│   └── upload.html              # Upload form with metadata


## ⚙️ Installation and Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/ArchiveMosaic.git
   cd ArchiveMosaic
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up Firebase Authentication**
   - Create a Firebase project
   - Enable Email/Password Sign-In
   - Download your `serviceAccountKey.json` and include it in the project

4. **Set up MongoDB**
   - Create a MongoDB Atlas cluster or local MongoDB instance
   - Create a database and configure GridFS

5. **Configure API Keys**
   - Set Together API Key for AI model
   - Configure Firebase project credentials

6. **Run the application**
   ```bash
   python app.py
   ```

7. **Access the Web App**
   - Open `http://127.0.0.1:5000/` in your browser

---

## 📥 Future Scope

- Advanced search and sort options using AI.
- Export metadata as CSV/JSON for institutional use.
- Public user profiles and contribution history.
- Language localization for Indian regional languages.

---





## 🙌 Thank You!

We hope **Archive Mosaic** will contribute meaningfully to preserving our cultural heritage.


